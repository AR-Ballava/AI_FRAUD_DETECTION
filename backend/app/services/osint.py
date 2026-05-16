from __future__ import annotations

import asyncio
import html
import json
import re
from datetime import UTC, datetime
from urllib.parse import parse_qs, quote_plus, unquote, urlparse

import httpx

from app.utils.entities import FREE_EMAIL_DOMAINS, has_free_email


SCAM_WORDS = re.compile(r"\b(scam|fraud|fake|complaint|warning|phishing|blacklist|cheat|cheated|spam)\b", re.IGNORECASE)
SUSPICIOUS_TLDS = {"xyz", "top", "site", "online", "work", "shop"}
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
    r'<a[^>]+class="[^"]*result__snippet[^"]*"[^>]*>(.*?)</a>|<div[^>]+class="[^"]*result__snippet[^"]*"[^>]*>(.*?)</div>',
    re.IGNORECASE | re.DOTALL,
)
TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


def _query_from_entities(entities: dict) -> str:
    pieces = []
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
    deduped = []
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


def _parse_duckduckgo_html(markup: str, source_label: str) -> list[dict]:
    anchors = DDG_RESULT_RE.findall(markup)
    if not anchors:
        anchors = DDG_GENERIC_LINK_RE.findall(markup)
    snippets = [snippet_a or snippet_div for snippet_a, snippet_div in DDG_SNIPPET_RE.findall(markup)]
    results = []
    for index, (href, title_html) in enumerate(anchors):
        url = _ddg_url(href)
        if "duckduckgo.com" in urlparse(url).netloc:
            continue
        results.append(
            {
                "source": source_label,
                "title": _clean_html(title_html),
                "url": url,
                "snippet": _clean_html(snippets[index] if index < len(snippets) else ""),
            }
        )
    return _dedupe_results(results, limit=20)


def _clean_markdown(value: str) -> str:
    value = re.sub(r"!\[[^\]]*\]\([^\)]*\)", " ", value)
    value = re.sub(r"\[([^\]]+)\]\([^\)]*\)", r"\1", value)
    value = re.sub(r"[*_`#>\-]+", " ", value)
    return re.sub(r"\s+", " ", html.unescape(value)).strip()


def _parse_jina_duckduckgo(markdown: str, source_label: str) -> list[dict]:
    matches = list(JINA_DDG_RESULT_RE.finditer(markdown))
    results = []
    for index, match in enumerate(matches):
        title = _clean_markdown(match.group(1))
        url = _ddg_url(match.group(2))
        if not title or "duckduckgo.com" in urlparse(url).netloc:
            continue
        next_start = matches[index + 1].start() if index + 1 < len(matches) else len(markdown)
        body = markdown[match.end() : next_start]
        snippet_lines = [
            line
            for line in body.splitlines()
            if line.strip()
            and not line.strip().startswith("[![")
            and "duckduckgo.com/l/?" not in line
            and "URL Source:" not in line
        ]
        results.append(
            {
                "source": source_label,
                "title": title,
                "url": url,
                "snippet": _clean_markdown(" ".join(snippet_lines))[:700],
            }
        )
    return _dedupe_results(results, limit=20)


async def _duckduckgo_instant(client: httpx.AsyncClient, query: str) -> dict:
    try:
        response = await client.get(
            "https://api.duckduckgo.com/",
            params={"q": query, "format": "json", "no_html": "1", "skip_disambig": "1"},
            headers=DEFAULT_HEADERS,
        )
        response.raise_for_status()
        data = response.json()
        results = []
        if data.get("AbstractURL"):
            results.append(
                {
                    "source": "DuckDuckGo",
                    "title": data.get("Heading") or "DuckDuckGo abstract",
                    "url": data.get("AbstractURL"),
                    "snippet": data.get("AbstractText") or "",
                }
            )
        for topic in data.get("RelatedTopics", [])[:12]:
            if "Topics" in topic:
                nested = topic.get("Topics", [])
            else:
                nested = [topic]
            for item in nested[:3]:
                if item.get("FirstURL"):
                    results.append(
                        {
                            "source": "DuckDuckGo",
                            "title": item.get("Text", "")[:120] or "Related result",
                            "url": item.get("FirstURL"),
                            "snippet": item.get("Text", ""),
                        }
                    )
        return {"source": "duckduckgo_instant", "ok": True, "results": results[:10]}
    except Exception as exc:
        return {"source": "duckduckgo_instant", "ok": False, "error": str(exc), "results": []}


async def _duckduckgo_search(client: httpx.AsyncClient, query: str, source: str = "DuckDuckGo Web", limit: int = 12) -> dict:
    endpoints = [
        "https://html.duckduckgo.com/html/",
        "https://lite.duckduckgo.com/lite/",
    ]
    errors = []
    source_key = source.lower().replace(" ", "_")
    empty_response = None
    for endpoint in endpoints:
        try:
            response = await client.get(
                endpoint,
                params={"q": query},
                headers=DEFAULT_HEADERS,
                timeout=4.0,
            )
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

async def _duckduckgo_site_bundle(client: httpx.AsyncClient, query: str, source: str, sites: list[str], limit: int = 16) -> dict:
    site_query = f"{query} " + " OR ".join(f"site:{site}" for site in sites)
    results = [await _duckduckgo_search(client, site_query, source, limit=limit)]
    evidence = []
    errors = []
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
        posts = []
        for child in data.get("data", {}).get("children", []):
            post = child.get("data", {})
            title = post.get("title") or "Reddit discussion"
            permalink = post.get("permalink") or ""
            posts.append(
                {
                    "source": "Reddit",
                    "title": title,
                    "url": f"https://www.reddit.com{permalink}" if permalink.startswith("/") else permalink,
                    "snippet": (post.get("selftext") or title)[:500],
                    "score": post.get("score", 0),
                    "comments": post.get("num_comments", 0),
                    "subreddit": post.get("subreddit"),
                    "classified_as_scam_report": bool(SCAM_WORDS.search(title + " " + (post.get("selftext") or ""))),
                }
            )
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
    marker = "var ytInitialData = "
    start = markup.find(marker)
    if start == -1:
        marker = "ytInitialData = "
        start = markup.find(marker)
    if start == -1:
        return None
    start += len(marker)
    decoder = json.JSONDecoder()
    try:
        data, _ = decoder.raw_decode(markup[start:])
        return data
    except json.JSONDecodeError:
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
        results = []
        if data:
            for node in _walk_json(data):
                renderer = node.get("videoRenderer") if isinstance(node, dict) else None
                if not renderer or not renderer.get("videoId"):
                    continue
                title = _runs_text(renderer.get("title", {}))
                snippet = _runs_text(renderer.get("descriptionSnippet", {}))
                channel = _runs_text(renderer.get("ownerText", {}))
                results.append(
                    {
                        "source": "YouTube",
                        "title": title or "YouTube video",
                        "url": f"https://www.youtube.com/watch?v={renderer['videoId']}",
                        "snippet": snippet,
                        "channel": channel,
                    }
                )
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
        results = []
        for hit in data.get("hits", []):
            url = hit.get("url") or f"https://news.ycombinator.com/item?id={hit.get('objectID')}"
            results.append(
                {
                    "source": "Hacker News",
                    "title": hit.get("title") or hit.get("story_title") or "Hacker News discussion",
                    "url": url,
                    "snippet": hit.get("comment_text") or "",
                    "points": hit.get("points"),
                    "comments": hit.get("num_comments"),
                }
            )
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
        results = [
            {
                "source": "GDELT News",
                "title": article.get("title") or "Public news article",
                "url": article.get("url"),
                "snippet": article.get("seendate", ""),
                "domain": article.get("domain"),
                "language": article.get("language"),
            }
            for article in data.get("articles", [])
        ]
        return {"source": "gdelt_news", "ok": True, "results": _dedupe_results(results, limit=12)}
    except Exception as exc:
        return {"source": "gdelt_news", "ok": False, "error": str(exc), "results": []}


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
            "registrar": data.get("registrar", {}).get("name") if isinstance(data.get("registrar"), dict) else None,
            "suspicious_tld": tld in SUSPICIOUS_TLDS,
            "raw_status": data.get("status", []),
        }
    except Exception as exc:
        return {"source": "rdap", "ok": False, "domain": domain, "error": str(exc)}


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
        ]
        return {"source": "github", "ok": True, "results": results}
    except Exception as exc:
        return {"source": "github", "ok": False, "error": str(exc), "results": []}


async def _company_homepages(client: httpx.AsyncClient, domains: list[str]) -> dict:
    results = []
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


def _classify_reports(evidence: list[dict]) -> dict:
    scam_reports = []
    neutral_mentions = []
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


def _risk_score(entities: dict, domain_results: list[dict], scam_report_count: int, initial_fraud_score: float) -> dict:
    score = min(35, initial_fraud_score * 0.35)
    reasons = []

    if has_free_email(entities):
        score += 15
        reasons.append("Recruiting contact uses a free email provider")

    for domain in domain_results:
        if not domain.get("ok"):
            continue
        age = domain.get("age_days")
        if age is not None and age < 180:
            score += 20
            reasons.append(f"{domain.get('domain')} is less than 180 days old")
        elif age is not None and age < 365:
            score += 10
            reasons.append(f"{domain.get('domain')} is less than one year old")
        if domain.get("suspicious_tld"):
            score += 10
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


async def run_osint(entities: dict, initial_fraud_score: float, timeout: float) -> dict:
    query = _query_from_entities(entities)
    domains = [d for d in entities.get("domains", []) if d.lower() not in FREE_EMAIL_DOMAINS]
    domain_tasks = []

    async with httpx.AsyncClient(timeout=httpx.Timeout(timeout), follow_redirects=True) as client:
        task_specs = [
            _duckduckgo_instant(client, query),
            _duckduckgo_search(client, query, "DuckDuckGo Web", limit=14),
            _duckduckgo_site_bundle(
                client,
                query,
                "LinkedIn public results",
                ["linkedin.com/company", "linkedin.com/in", "linkedin.com/jobs"],
                limit=12,
            ),
            _duckduckgo_site_bundle(
                client,
                query,
                "Reviews and job forums",
                ["glassdoor.com", "ambitionbox.com", "teamblind.com", "indeed.com/cmp", "fishbowlapp.com"],
                limit=14,
            ),
            _duckduckgo_site_bundle(
                client,
                query,
                "Scam report sites",
                ["scamadviser.com", "trustpilot.com", "complaintsboard.com", "consumercomplaints.in", "mouthshut.com"],
                limit=14,
            ),
            _duckduckgo_site_bundle(
                client,
                query,
                "Public posts and blogs",
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
        scheduled = [asyncio.create_task(task) for task in [*task_specs, *domain_tasks]]
        done, pending = await asyncio.wait(scheduled, timeout=timeout + 2)
        for task in pending:
            task.cancel()
        results = []
        for task in done:
            try:
                results.append(task.result())
            except Exception as exc:
                results.append(exc)
        if pending:
            results.append({"source": "pending_sources", "ok": False, "error": f"{len(pending)} source task(s) timed out", "results": []})

    source_status = []
    evidence = []
    domain_results = []
    for result in results:
        if isinstance(result, Exception):
            source_status.append({"source": "unknown", "ok": False, "error": str(result)})
            continue
        source_status.append({k: result.get(k) for k in ("source", "ok", "error") if k in result})
        if result.get("source") == "rdap":
            domain_results.append(result)
        else:
            evidence.extend(result.get("results", []))

    evidence = _dedupe_results(evidence, limit=80)
    classified = _classify_reports(evidence)
    risk = _risk_score(entities, domain_results, classified["scam_report_count"], initial_fraud_score)

    return {
        "status": "partial_timeout" if any(item.get("source") == "pending_sources" for item in source_status) else "complete",
        "query": query,
        "risk": risk,
        "evidence": evidence[:60],
        "domain_intelligence": domain_results,
        "scam_reports": classified["scam_reports"][:25],
        "neutral_mentions": classified["neutral_mentions"][:35],
        "source_status": source_status,
        "search_urls": _search_urls(query),
    }
