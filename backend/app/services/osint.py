from __future__ import annotations

"""
osint.py — Advanced OSINT-based Suspicious Entity Detection Engine
==================================================================
This module powers the fraud investigation pipeline.  It does two things:

1. **Suspicious-entity detection** (local, instant):
   ``score_suspicious_entities()`` accepts raw text or a pre-built entity list,
   applies contextual fraud-keyword matching within a ±2-sentence window, scores
   every candidate on a weighted rubric, filters out clean entities, and returns
   only those with at least one fraud signal — ranked highest-risk first.

2. **Public-intelligence gathering** (async, network):
   ``run_osint()`` fans out across DuckDuckGo, Reddit, HackerNews, GDELT, RDAP
   etc. to collect external evidence, then folds that evidence back into the
   suspicious-entity scores for a final, enriched result.
"""

import asyncio
import html
import json
import re
from datetime import UTC, datetime
from urllib.parse import parse_qs, quote_plus, unquote, urlparse

import httpx

from app.utils.entities import (
    FREE_EMAIL_DOMAINS,
    FRAUD_KEYWORDS_PRIMARY,
    FRAUD_KEYWORDS_SECONDARY,
    SUSPICIOUS_TLDS,
    extract_suspicious_entities,
    find_fraud_keywords_in_context,
    get_sentence_window,
    has_free_email,
)


# ---------------------------------------------------------------------------
# Shared constants
# ---------------------------------------------------------------------------

SCAM_WORDS = re.compile(
    r"\b(scam|fraud|fraudulent|fake|complaint|warning|phishing|blacklist|"
    r"blacklisted|cheat|cheated|spam|reported|suspicious|illegitimate|impersonat)\b",
    re.IGNORECASE,
)

RELEVANCE_PATTERN = re.compile(
    r"\b("
    r"job|jobs|hiring|hire|recruit|recruitment|recruiter|career|careers|"
    r"employ|employee|employer|employment|vacancy|vacancies|position|opening|"
    r"salary|hr|human.?resource|interview|internship|fresher|placement|"
    r"staffing|headhunt|onboarding|resume|cv|work.?from.?home|wfh|"
    r"offer.?letter|joining|designation|"
    r"company|companies|firm|startup|business|organisation|organization|"
    r"corporation|enterprise|brand|"
    r"fraud|scam|fake|phishing|cheat|complaint|warning|blacklist|spam|"
    r"ponzi|pyramid|scheme|mislead|impersonat|fake.?offer|advance.?fee|"
    r"job.?scam|recruitment.?scam|"
    r"linkedin|glassdoor|indeed|naukri|monster|shine|apna|internshala|"
    r"review|rating|feedback|testimonial|employer.?review|work.?culture"
    r")\b",
    re.IGNORECASE,
)

DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; FraudLensAI/1.0; +https://example.local/osint)",
    "Accept-Language": "en-US,en;q=0.9",
}

DDG_RESULT_RE = re.compile(
    r'<a[^>]+class="[^"]*result__a[^"]*"[^>]+href="([^"]+)"[^>]*>(.*?)</a>',
    re.IGNORECASE | re.DOTALL,
)
DDG_GENERIC_LINK_RE = re.compile(
    r'<a[^>]+href="([^"]*uddg=[^"]+)"[^>]*>(.*?)</a>',
    re.IGNORECASE | re.DOTALL,
)
JINA_DDG_RESULT_RE = re.compile(r"^## \[(.*?)\]\((https?://[^\)]+)\)", re.MULTILINE)
DDG_SNIPPET_RE = re.compile(
    r'<a[^>]+class="[^"]*result__snippet[^"]*"[^>]*>(.*?)</a>'
    r'|<div[^>]+class="[^"]*result__snippet[^"]*"[^>]*>(.*?)</div>',
    re.IGNORECASE | re.DOTALL,
)
TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


# ---------------------------------------------------------------------------
# Score weights — centralised so they are easy to tune
# ---------------------------------------------------------------------------

WEIGHTS: dict[str, int] = {
    # Keyword category weights
    "primary_keyword": 18,       # "recruitment scam", "phishing", "blacklist" …
    "secondary_keyword": 8,      # "scam", "fraud", "fake", "spam" …
    "keyword_repeat_bonus": 4,   # each extra occurrence of any fraud keyword
    # Entity-type structural risks
    "free_email": 15,            # gmail/yahoo for a "corporate" contact
    "suspicious_tld": 14,        # .xyz .top .site .work etc.
    "multiple_keywords": 10,     # 3+ distinct fraud keywords in window
    # External evidence bonuses (applied after OSINT fetch)
    "external_scam_report": 12,  # scam-report site mentions this entity
    "external_complaint": 8,     # complaint / warning mention in public data
    "domain_young_180d": 20,     # domain < 180 days old
    "domain_young_365d": 10,     # domain < 1 year old
}

# Minimum score for an entity to appear in results
MIN_SCORE_THRESHOLD = 10


# ---------------------------------------------------------------------------
# Local suspicious-entity scoring
# ---------------------------------------------------------------------------

def _score_entity(candidate: dict) -> int:
    """
    Compute a 0-100 risk score for a single suspicious-entity candidate.

    ``candidate`` is produced by ``extract_suspicious_entities()`` and already
    has ``matched_keywords``, ``type``, ``entity``, and ``context``.
    """
    score = 0
    entity_val: str = candidate.get("entity", "")
    entity_type: str = candidate.get("type", "")
    matched: list[str] = candidate.get("matched_keywords", [])
    context: str = candidate.get("context", "")

    # --- Keyword scoring ---
    primary_matches = [kw for kw in matched if kw.lower() in [p.lower() for p in FRAUD_KEYWORDS_PRIMARY]]
    secondary_matches = [kw for kw in matched if kw.lower() in [s.lower() for s in FRAUD_KEYWORDS_SECONDARY]
                         and kw.lower() not in [p.lower() for p in FRAUD_KEYWORDS_PRIMARY]]

    score += len(primary_matches) * WEIGHTS["primary_keyword"]
    score += len(secondary_matches) * WEIGHTS["secondary_keyword"]

    # Bonus for keyword density (3+ unique fraud signals)
    if len(set(kw.lower() for kw in matched)) >= 3:
        score += WEIGHTS["multiple_keywords"]

    # Bonus for repeated mentions in the context window
    all_occurrences = SCAM_WORDS.findall(context)
    repeat_bonus = max(0, len(all_occurrences) - len(matched)) * WEIGHTS["keyword_repeat_bonus"]
    score += repeat_bonus

    # --- Structural entity risks ---
    if entity_type == "email":
        domain = entity_val.split("@", 1)[-1].lower() if "@" in entity_val else ""
        if domain in FREE_EMAIL_DOMAINS:
            score += WEIGHTS["free_email"]
        tld = domain.rsplit(".", 1)[-1] if "." in domain else ""
        if tld in SUSPICIOUS_TLDS:
            score += WEIGHTS["suspicious_tld"]

    if entity_type in ("url", "domain"):
        raw = entity_val.replace("https://", "").replace("http://", "").split("/")[0]
        tld = raw.rsplit(".", 1)[-1].lower() if "." in raw else ""
        if tld in SUSPICIOUS_TLDS:
            score += WEIGHTS["suspicious_tld"]

    return min(100, score)


def score_suspicious_entities(
    text: str,
    min_score: int = MIN_SCORE_THRESHOLD,
) -> list[dict]:
    """
    Full local pipeline:
      1. Extract entities from ``text``.
      2. Apply ±2-sentence contextual fraud-keyword matching.
      3. Drop entities with zero fraud signals.
      4. Score each surviving entity.
      5. Return sorted list (highest score first), each entry containing:
           entity, type, score, matched_keywords, context, evidence_summary.

    If no entity has even one fraud signal the function returns an empty list —
    the caller should treat that as "no suspicious entities detected".
    """
    candidates = extract_suspicious_entities(text)
    if not candidates:
        return []

    scored: list[dict] = []
    for candidate in candidates:
        raw_score = _score_entity(candidate)
        if raw_score < min_score:
            continue
        scored.append(
            {
                "entity": candidate["entity"],
                "type": candidate["type"],
                "score": raw_score,
                "matched_keywords": candidate["matched_keywords"],
                "context": candidate["context"][:400],
                "evidence_summary": _build_evidence_summary(candidate),
            }
        )

    # Sort: highest risk first; secondary sort by entity type priority
    TYPE_PRIORITY = {"email": 0, "phone": 1, "url": 2, "domain": 3, "company": 4, "recruiter": 5}
    scored.sort(key=lambda x: (-x["score"], TYPE_PRIORITY.get(x["type"], 99)))
    return scored


def _build_evidence_summary(candidate: dict) -> str:
    """Human-readable one-liner explaining why an entity is flagged."""
    kws = ", ".join(candidate.get("matched_keywords", [])[:4])
    entity_type = candidate.get("type", "entity")
    entity_val = candidate.get("entity", "")
    return (
        f'The {entity_type} "{entity_val}" appears in context containing '
        f"fraud-related terms: {kws}."
    )


def _enrich_with_external_evidence(
    scored: list[dict],
    external_evidence: list[dict],
) -> list[dict]:
    """
    Boost scores of already-suspicious entities when external OSINT evidence
    mentions the same entity value.  Re-sorts the list after boosting.
    """
    if not external_evidence or not scored:
        return scored

    # Build a lookup: entity_value_lower → list[evidence_item]
    evidence_by_entity: dict[str, list[dict]] = {}
    for item in external_evidence:
        text = f"{item.get('title', '')} {item.get('snippet', '')}".lower()
        for entry in scored:
            ev = entry["entity"].lower()
            if ev and ev in text:
                evidence_by_entity.setdefault(ev, []).append(item)

    for entry in scored:
        ev = entry["entity"].lower()
        ext_items = evidence_by_entity.get(ev, [])
        if not ext_items:
            continue
        boost = 0
        extra_keywords: list[str] = []
        for item in ext_items[:5]:
            item_text = f"{item.get('title', '')} {item.get('snippet', '')}".lower()
            if SCAM_WORDS.search(item_text):
                boost += WEIGHTS["external_scam_report"]
                extra_keywords.append("scam report (external)")
            else:
                boost += WEIGHTS["external_complaint"]
                extra_keywords.append("public mention (external)")
        entry["score"] = min(100, entry["score"] + boost)
        entry["matched_keywords"] = list(
            dict.fromkeys(entry["matched_keywords"] + extra_keywords)
        )
        entry["external_evidence_count"] = len(ext_items)

    TYPE_PRIORITY = {"email": 0, "phone": 1, "url": 2, "domain": 3, "company": 4, "recruiter": 5}
    scored.sort(key=lambda x: (-x["score"], TYPE_PRIORITY.get(x["type"], 99)))
    return scored


# ---------------------------------------------------------------------------
# Network helpers (unchanged logic, cleaned up)
# ---------------------------------------------------------------------------

def _is_relevant(item: dict) -> bool:
    text = f"{item.get('title', '')} {item.get('snippet', '')} {item.get('url', '')}"
    return bool(RELEVANCE_PATTERN.search(text))


def _query_from_entities(entities: dict) -> str:
    pieces: list[str] = []
    for key in ("companies", "domains", "emails", "recruiters", "positions", "phones"):
        pieces.extend(entities.get(key, [])[:2])
    if not pieces:
        return "job recruitment scam"
    return " ".join(pieces[:6]) + " job scam fraud"


def _domain_age_days(rdap: dict) -> int | None:
    events = rdap.get("events", []) if isinstance(rdap, dict) else []
    for event in events:
        if event.get("eventAction") in {"registration", "last changed"}:
            raw = event.get("eventDate")
            if not raw:
                continue
            try:
                created = datetime.fromisoformat(raw.replace("Z", "+00:00"))
                return max(0, (datetime.now(UTC) - created).days)
            except ValueError:
                continue
    return None


def _clean_html(value: str | None) -> str:
    if not value:
        return ""
    without_tags = re.sub(r"<[^>]+>", " ", value)
    return re.sub(r"\s+", " ", html.unescape(without_tags)).strip()


def _ddg_url(href: str) -> str:
    decoded = html.unescape(href)
    if decoded.startswith("//duckduckgo.com/"):
        decoded = "https:" + decoded
    elif decoded.startswith("/"):
        decoded = "https://duckduckgo.com" + decoded
    parsed = urlparse(decoded)
    uddg = parse_qs(parsed.query).get("uddg")
    if uddg:
        return unquote(uddg[0])
    return decoded


def _dedupe_results(results: list[dict], limit: int = 60) -> list[dict]:
    seen_urls: set[str] = set()
    seen_titles: set[str] = set()
    deduped: list[dict] = []
    for item in results:
        url = (item.get("url") or "").strip()
        title = re.sub(r"\s+", " ", (item.get("title") or "")).strip()
        if not url and not title:
            continue
        key = url.lower() if url else title.lower()
        title_key = title.lower()
        if key in seen_urls or title_key in seen_titles:
            continue
        seen_urls.add(key)
        if title_key:
            seen_titles.add(title_key)
        item["title"] = title[:180] or item.get("source", "Public result")
        item["snippet"] = re.sub(r"\s+", " ", (item.get("snippet") or "")).strip()[:700]
        deduped.append(item)
        if len(deduped) >= limit:
            break
    return deduped


def _clean_markdown(value: str) -> str:
    value = re.sub(r"!\[[^\]]*\]\([^\)]*\)", " ", value)
    value = re.sub(r"\[([^\]]+)\]\([^\)]*\)", r"\1", value)
    value = re.sub(r"[*_`#>\-]+", " ", value)
    return re.sub(r"\s+", " ", html.unescape(value)).strip()


def _parse_duckduckgo_html(markup: str, source_label: str) -> list[dict]:
    anchors = DDG_RESULT_RE.findall(markup)
    if not anchors:
        anchors = DDG_GENERIC_LINK_RE.findall(markup)
    snippets = [a or b for a, b in DDG_SNIPPET_RE.findall(markup)]
    results: list[dict] = []
    for index, (href, title_html) in enumerate(anchors):
        url = _ddg_url(href)
        if "duckduckgo.com" in urlparse(url).netloc:
            continue
        item = {
            "source": source_label,
            "title": _clean_html(title_html),
            "url": url,
            "snippet": _clean_html(snippets[index] if index < len(snippets) else ""),
        }
        if _is_relevant(item):
            results.append(item)
    return _dedupe_results(results, limit=20)


def _parse_jina_duckduckgo(markdown: str, source_label: str) -> list[dict]:
    matches = list(JINA_DDG_RESULT_RE.finditer(markdown))
    results: list[dict] = []
    for index, match in enumerate(matches):
        title = _clean_markdown(match.group(1))
        url = _ddg_url(match.group(2))
        if not title or "duckduckgo.com" in urlparse(url).netloc:
            continue
        next_start = matches[index + 1].start() if index + 1 < len(matches) else len(markdown)
        body = markdown[match.end(): next_start]
        snippet_lines = [
            line for line in body.splitlines()
            if line.strip()
            and not line.strip().startswith("[![")
            and "duckduckgo.com/l/?" not in line
            and "URL Source:" not in line
        ]
        item = {
            "source": source_label,
            "title": title,
            "url": url,
            "snippet": _clean_markdown(" ".join(snippet_lines))[:700],
        }
        if _is_relevant(item):
            results.append(item)
    return _dedupe_results(results, limit=20)


# ---------------------------------------------------------------------------
# Async data-source fetchers
# ---------------------------------------------------------------------------

async def _duckduckgo_instant(client: httpx.AsyncClient, query: str) -> dict:
    try:
        response = await client.get(
            "https://api.duckduckgo.com/",
            params={"q": query, "format": "json", "no_html": "1", "skip_disambig": "1"},
            headers=DEFAULT_HEADERS,
        )
        response.raise_for_status()
        data = response.json()
        results: list[dict] = []
        if data.get("AbstractURL"):
            item = {
                "source": "DuckDuckGo",
                "title": data.get("Heading") or "DuckDuckGo abstract",
                "url": data.get("AbstractURL"),
                "snippet": data.get("AbstractText") or "",
            }
            if _is_relevant(item):
                results.append(item)
        for topic in data.get("RelatedTopics", [])[:12]:
            nested = topic.get("Topics", [topic]) if "Topics" in topic else [topic]
            for t in nested[:3]:
                if t.get("FirstURL"):
                    entry = {
                        "source": "DuckDuckGo",
                        "title": t.get("Text", "")[:120] or "Related result",
                        "url": t["FirstURL"],
                        "snippet": t.get("Text", ""),
                    }
                    if _is_relevant(entry):
                        results.append(entry)
        return {"source": "duckduckgo_instant", "ok": True, "results": results[:10]}
    except Exception as exc:
        return {"source": "duckduckgo_instant", "ok": False, "error": str(exc), "results": []}


async def _duckduckgo_search(
    client: httpx.AsyncClient,
    query: str,
    source: str = "DuckDuckGo Web",
    limit: int = 12,
) -> dict:
    endpoints = [
        "https://html.duckduckgo.com/html/",
        "https://lite.duckduckgo.com/lite/",
    ]
    errors: list[str] = []
    source_key = source.lower().replace(" ", "_")
    empty_response = None
    for endpoint in endpoints:
        try:
            response = await client.get(endpoint, params={"q": query}, headers=DEFAULT_HEADERS, timeout=4.0)
            response.raise_for_status()
            results = _parse_duckduckgo_html(response.text, source)[:limit]
            if results:
                return {"source": source_key, "ok": True, "results": results, "query": query}
            empty_response = {"source": source_key, "ok": True, "results": [], "query": query}
        except Exception as exc:
            errors.append(str(exc))
    try:
        jina_response = await client.get(
            f"https://r.jina.ai/http://https://html.duckduckgo.com/html/?q={quote_plus(query)}",
            headers=DEFAULT_HEADERS,
            timeout=7.0,
        )
        jina_response.raise_for_status()
        results = _parse_jina_duckduckgo(jina_response.text, source)[:limit]
        if results:
            return {"source": source_key, "ok": True, "results": results, "query": query, "fallback": "jina_duckduckgo"}
    except Exception as exc:
        errors.append(str(exc))
    if empty_response:
        return empty_response
    return {"source": source_key, "ok": False, "error": "; ".join(errors[:2]), "results": [], "query": query}


async def _duckduckgo_site_bundle(
    client: httpx.AsyncClient,
    query: str,
    source: str,
    sites: list[str],
    limit: int = 16,
) -> dict:
    site_query = f"{query} " + " OR ".join(f"site:{site}" for site in sites)
    results = [await _duckduckgo_search(client, site_query, source, limit=limit)]
    evidence: list[dict] = []
    errors: list[str] = []
    for result in results:
        if isinstance(result, Exception):
            errors.append(str(result))
            continue
        evidence.extend(result.get("results", []))
        if not result.get("ok") and result.get("error"):
            errors.append(result["error"])
    return {
        "source": source.lower().replace(" ", "_"),
        "ok": len(evidence) > 0 or not errors,
        "error": "; ".join(errors[:2]) if errors and not evidence else None,
        "results": _dedupe_results(evidence, limit=limit),
    }


async def _reddit(client: httpx.AsyncClient, query: str) -> dict:
    try:
        response = await client.get(
            "https://www.reddit.com/search.json",
            params={"q": query, "sort": "relevance", "limit": 8},
            headers=DEFAULT_HEADERS,
        )
        response.raise_for_status()
        data = response.json()
        posts: list[dict] = []
        for child in data.get("data", {}).get("children", []):
            post = child.get("data", {})
            title = post.get("title") or "Reddit discussion"
            permalink = post.get("permalink") or ""
            item = {
                "source": "Reddit",
                "title": title,
                "url": f"https://www.reddit.com{permalink}" if permalink.startswith("/") else permalink,
                "snippet": (post.get("selftext") or title)[:500],
                "score": post.get("score", 0),
                "comments": post.get("num_comments", 0),
                "subreddit": post.get("subreddit"),
                "classified_as_scam_report": bool(SCAM_WORDS.search(title + " " + (post.get("selftext") or ""))),
            }
            if _is_relevant(item):
                posts.append(item)
        return {"source": "reddit", "ok": True, "results": posts}
    except Exception as exc:
        return {"source": "reddit", "ok": False, "error": str(exc), "results": []}


def _walk_json(value):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from _walk_json(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_json(child)


def _youtube_initial_data(markup: str) -> dict | None:
    for marker in ("var ytInitialData = ", "ytInitialData = "):
        start = markup.find(marker)
        if start != -1:
            start += len(marker)
            decoder = json.JSONDecoder()
            try:
                data, _ = decoder.raw_decode(markup[start:])
                return data
            except json.JSONDecodeError:
                pass
    return None


def _runs_text(value: dict) -> str:
    if not isinstance(value, dict):
        return ""
    if "simpleText" in value:
        return value["simpleText"]
    return "".join(run.get("text", "") for run in value.get("runs", []))


async def _youtube_search(client: httpx.AsyncClient, query: str) -> dict:
    try:
        response = await client.get(
            "https://www.youtube.com/results",
            params={"search_query": query},
            headers=DEFAULT_HEADERS,
        )
        response.raise_for_status()
        data = _youtube_initial_data(response.text)
        results: list[dict] = []
        if data:
            for node in _walk_json(data):
                renderer = node.get("videoRenderer") if isinstance(node, dict) else None
                if not renderer or not renderer.get("videoId"):
                    continue
                title = _runs_text(renderer.get("title", {}))
                snippet = _runs_text(renderer.get("descriptionSnippet", {}))
                channel = _runs_text(renderer.get("ownerText", {}))
                item = {
                    "source": "YouTube",
                    "title": title or "YouTube video",
                    "url": f"https://www.youtube.com/watch?v={renderer['videoId']}",
                    "snippet": snippet,
                    "channel": channel,
                }
                if _is_relevant(item):
                    results.append(item)
        return {"source": "youtube", "ok": True, "results": _dedupe_results(results, limit=10)}
    except Exception as exc:
        return {"source": "youtube", "ok": False, "error": str(exc), "results": []}


async def _hackernews(client: httpx.AsyncClient, query: str) -> dict:
    try:
        response = await client.get(
            "https://hn.algolia.com/api/v1/search",
            params={"query": query, "tags": "story", "hitsPerPage": 8},
            headers=DEFAULT_HEADERS,
        )
        response.raise_for_status()
        data = response.json()
        results: list[dict] = []
        for hit in data.get("hits", []):
            url = hit.get("url") or f"https://news.ycombinator.com/item?id={hit.get('objectID')}"
            item = {
                "source": "Hacker News",
                "title": hit.get("title") or hit.get("story_title") or "Hacker News discussion",
                "url": url,
                "snippet": hit.get("comment_text") or "",
                "points": hit.get("points"),
                "comments": hit.get("num_comments"),
            }
            if _is_relevant(item):
                results.append(item)
        return {"source": "hacker_news", "ok": True, "results": results}
    except Exception as exc:
        return {"source": "hacker_news", "ok": False, "error": str(exc), "results": []}


async def _gdelt(client: httpx.AsyncClient, query: str) -> dict:
    try:
        response = await client.get(
            "https://api.gdeltproject.org/api/v2/doc/doc",
            params={"query": query, "mode": "ArtList", "format": "json", "maxrecords": 12, "sort": "HybridRel"},
            headers=DEFAULT_HEADERS,
        )
        response.raise_for_status()
        data = response.json()
        results: list[dict] = []
        for article in data.get("articles", []):
            item = {
                "source": "GDELT News",
                "title": article.get("title") or "Public news article",
                "url": article.get("url"),
                "snippet": article.get("seendate", ""),
                "domain": article.get("domain"),
                "language": article.get("language"),
            }
            if _is_relevant(item):
                results.append(item)
        return {"source": "gdelt_news", "ok": True, "results": _dedupe_results(results, limit=12)}
    except Exception as exc:
        return {"source": "gdelt_news", "ok": False, "error": str(exc), "results": []}


async def _github(client: httpx.AsyncClient, query: str) -> dict:
    try:
        response = await client.get(
            "https://api.github.com/search/repositories",
            params={"q": query, "per_page": 5},
            headers={**DEFAULT_HEADERS, "Accept": "application/vnd.github+json"},
        )
        response.raise_for_status()
        data = response.json()
        results = [
            {
                "source": "GitHub",
                "title": item.get("full_name"),
                "url": item.get("html_url"),
                "snippet": item.get("description") or "",
                "stars": item.get("stargazers_count", 0),
            }
            for item in data.get("items", [])
            if _is_relevant({
                "title": item.get("full_name", ""),
                "snippet": item.get("description") or "",
                "url": item.get("html_url", ""),
            })
        ]
        return {"source": "github", "ok": True, "results": results}
    except Exception as exc:
        return {"source": "github", "ok": False, "error": str(exc), "results": []}


async def _company_homepages(client: httpx.AsyncClient, domains: list[str]) -> dict:
    results: list[dict] = []
    for domain in domains[:3]:
        for scheme in ("https", "http"):
            try:
                response = await client.get(f"{scheme}://{domain}", follow_redirects=True)
                if response.status_code >= 400:
                    continue
                title = TITLE_RE.search(response.text)
                results.append(
                    {
                        "source": "Company website",
                        "title": _clean_html(title.group(1)) if title else domain,
                        "url": str(response.url),
                        "snippet": _clean_html(response.text[:800]),
                    }
                )
                break
            except Exception:
                continue
    return {"source": "company_websites", "ok": True, "results": results}


async def _rdap_domain(client: httpx.AsyncClient, domain: str) -> dict:
    try:
        response = await client.get(f"https://rdap.org/domain/{domain}")
        response.raise_for_status()
        data = response.json()
        age_days = _domain_age_days(data)
        tld = domain.rsplit(".", 1)[-1].lower()
        return {
            "source": "rdap",
            "ok": True,
            "domain": domain,
            "age_days": age_days,
            "registrar": (
                data.get("registrar", {}).get("name")
                if isinstance(data.get("registrar"), dict)
                else None
            ),
            "suspicious_tld": tld in SUSPICIOUS_TLDS,
            "raw_status": data.get("status", []),
        }
    except Exception as exc:
        return {"source": "rdap", "ok": False, "domain": domain, "error": str(exc)}


# ---------------------------------------------------------------------------
# Risk score (OSINT-level, entity-aggregate)
# ---------------------------------------------------------------------------

def _classify_reports(evidence: list[dict]) -> dict:
    scam_reports: list[dict] = []
    neutral_mentions: list[dict] = []
    for item in evidence:
        text = f"{item.get('title', '')} {item.get('snippet', '')}"
        if SCAM_WORDS.search(text):
            scam_reports.append(item)
        else:
            neutral_mentions.append(item)
    return {
        "scam_reports": scam_reports,
        "neutral_mentions": neutral_mentions,
        "scam_report_count": len(scam_reports),
    }


def _risk_score(
    entities: dict,
    domain_results: list[dict],
    scam_report_count: int,
    initial_fraud_score: float,
) -> dict:
    score = min(35, initial_fraud_score * 0.35)
    reasons: list[str] = []

    if has_free_email(entities):
        score += 15
        reasons.append("Recruiting contact uses a free email provider")

    for domain in domain_results:
        if not domain.get("ok"):
            continue
        age = domain.get("age_days")
        if age is not None and age < 180:
            score += WEIGHTS["domain_young_180d"]
            reasons.append(f"{domain.get('domain')} is less than 180 days old")
        elif age is not None and age < 365:
            score += WEIGHTS["domain_young_365d"]
            reasons.append(f"{domain.get('domain')} is less than one year old")
        if domain.get("suspicious_tld"):
            score += WEIGHTS["suspicious_tld"]
            reasons.append(f"{domain.get('domain')} uses a higher-risk TLD")

    if scam_report_count:
        score += min(30, scam_report_count * 10)
        reasons.append(f"{scam_report_count} public scam-related mention(s) found")

    score = round(min(100, score), 2)
    if score >= 75:
        level = "critical"
    elif score >= 50:
        level = "high"
    elif score >= 25:
        level = "medium"
    elif score >= 10:
        level = "low"
    else:
        level = "minimal"

    return {"score": score, "level": level, "reasons": reasons}


def _search_urls(query: str) -> dict:
    return {
        "reddit": f"https://www.reddit.com/search/?q={quote_plus(query)}",
        "duckduckgo": f"https://duckduckgo.com/?q={quote_plus(query)}",
        "youtube": f"https://www.youtube.com/results?search_query={quote_plus(query)}",
        "linkedin_public": f"https://duckduckgo.com/?q={quote_plus(query + ' site:linkedin.com')}",
        "news": f"https://api.gdeltproject.org/api/v2/doc/doc?query={quote_plus(query)}&mode=ArtList&format=json",
    }


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

async def run_osint(
    entities: dict,
    initial_fraud_score: float,
    timeout: float,
    source_text: str = "",
) -> dict:
    """
    Main OSINT pipeline.

    Parameters
    ----------
    entities:            merged entity dict from the upload/analyse routes.
    initial_fraud_score: ML fraud score (0-100) from the model service.
    timeout:             per-request network timeout in seconds.
    source_text:         original document text (used for local entity scoring).

    Returns a dict containing:
    - suspicious_entities  – ranked list from local + external scoring
    - evidence             – deduplicated public-intelligence items
    - domain_intelligence  – RDAP domain age/registrar data
    - risk                 – aggregate OSINT risk score
    - scam_reports         – evidence items that matched scam keywords
    - source_status        – per-source ok/error status
    - search_urls          – manual investigation links
    """
    query = _query_from_entities(entities)
    domains = [d for d in entities.get("domains", []) if d.lower() not in FREE_EMAIL_DOMAINS]

    # ------------------------------------------------------------------
    # Step 1 — local contextual entity scoring (instant, no network)
    # ------------------------------------------------------------------
    locally_scored: list[dict] = []
    if source_text:
        locally_scored = score_suspicious_entities(source_text)

    # ------------------------------------------------------------------
    # Step 2 — fan-out async OSINT network requests
    # ------------------------------------------------------------------
    async with httpx.AsyncClient(timeout=httpx.Timeout(timeout), follow_redirects=True) as client:
        task_specs = [
            _duckduckgo_instant(client, query),
            _duckduckgo_search(client, query, "DuckDuckGo Web", limit=14),
            _duckduckgo_site_bundle(
                client, query, "LinkedIn public results",
                ["linkedin.com/company", "linkedin.com/in", "linkedin.com/jobs"], limit=12,
            ),
            _duckduckgo_site_bundle(
                client, query, "Reviews and job forums",
                ["glassdoor.com", "ambitionbox.com", "teamblind.com", "indeed.com/cmp", "fishbowlapp.com"],
                limit=14,
            ),
            _duckduckgo_site_bundle(
                client, query, "Scam report sites",
                ["scamadviser.com", "trustpilot.com", "complaintsboard.com", "consumercomplaints.in", "mouthshut.com"],
                limit=14,
            ),
            _duckduckgo_site_bundle(
                client, query, "Public posts and blogs",
                ["medium.com", "substack.com", "quora.com", "wordpress.com", "blogspot.com"],
                limit=14,
            ),
            _duckduckgo_search(client, f"{query} site:youtube.com/watch", "YouTube search results", limit=10),
            _youtube_search(client, query),
            _reddit(client, query),
            _hackernews(client, query),
            _gdelt(client, query),
            _github(client, query),
            _company_homepages(client, domains),
        ]
        domain_tasks = [_rdap_domain(client, domain) for domain in domains[:5]]
        scheduled = [asyncio.create_task(t) for t in [*task_specs, *domain_tasks]]
        done, pending = await asyncio.wait(scheduled, timeout=timeout + 2)
        for task in pending:
            task.cancel()

        raw_results: list = []
        for task in done:
            try:
                raw_results.append(task.result())
            except Exception as exc:
                raw_results.append(exc)
        if pending:
            raw_results.append({
                "source": "pending_sources",
                "ok": False,
                "error": f"{len(pending)} source task(s) timed out",
                "results": [],
            })

    # ------------------------------------------------------------------
    # Step 3 — collate evidence & domain intelligence
    # ------------------------------------------------------------------
    source_status: list[dict] = []
    evidence: list[dict] = []
    domain_results: list[dict] = []

    for result in raw_results:
        if isinstance(result, Exception):
            source_status.append({"source": "unknown", "ok": False, "error": str(result)})
            continue
        source_status.append({k: result.get(k) for k in ("source", "ok", "error") if k in result})
        if result.get("source") == "rdap":
            domain_results.append(result)
        else:
            evidence.extend(result.get("results", []))

    evidence = _dedupe_results(evidence, limit=80)
    evidence = [item for item in evidence if _is_relevant(item)]
    classified = _classify_reports(evidence)
    risk = _risk_score(entities, domain_results, classified["scam_report_count"], initial_fraud_score)

    # ------------------------------------------------------------------
    # Step 4 — enrich local suspicious-entity scores with external data
    # ------------------------------------------------------------------
    enriched_entities = _enrich_with_external_evidence(locally_scored, evidence)

    # Also apply RDAP domain-age boosts to entity scores
    rdap_by_domain = {r["domain"].lower(): r for r in domain_results if r.get("ok") and r.get("domain")}
    for entry in enriched_entities:
        ev = entry["entity"].lower()
        # Strip mailto / scheme from entity for domain lookup
        domain_key = ev.split("@", 1)[-1] if "@" in ev else ev.replace("https://", "").replace("http://", "").split("/")[0]
        rdap = rdap_by_domain.get(domain_key)
        if rdap:
            age = rdap.get("age_days")
            if age is not None and age < 180:
                entry["score"] = min(100, entry["score"] + WEIGHTS["domain_young_180d"])
                entry["matched_keywords"].append("domain age < 180 days")
            elif age is not None and age < 365:
                entry["score"] = min(100, entry["score"] + WEIGHTS["domain_young_365d"])
                entry["matched_keywords"].append("domain age < 1 year")
            if rdap.get("suspicious_tld"):
                entry["score"] = min(100, entry["score"] + WEIGHTS["suspicious_tld"])
                entry["matched_keywords"].append("suspicious TLD")

    # Final sort after all enrichment passes
    TYPE_PRIORITY = {"email": 0, "phone": 1, "url": 2, "domain": 3, "company": 4, "recruiter": 5}
    enriched_entities.sort(key=lambda x: (-x["score"], TYPE_PRIORITY.get(x["type"], 99)))

    # ------------------------------------------------------------------
    # Step 5 — return structured response
    # ------------------------------------------------------------------
    timed_out = any(item.get("source") == "pending_sources" for item in source_status)
    return {
        "status": "partial_timeout" if timed_out else "complete",
        "query": query,
        # Core new field: only suspicious entities, ranked
        "suspicious_entities": enriched_entities,
        # Aggregate OSINT risk
        "risk": risk,
        # Public intelligence evidence
        "evidence": evidence[:60],
        "domain_intelligence": domain_results,
        "scam_reports": classified["scam_reports"][:25],
        "neutral_mentions": classified["neutral_mentions"][:35],
        "source_status": source_status,
        "search_urls": _search_urls(query),
    }