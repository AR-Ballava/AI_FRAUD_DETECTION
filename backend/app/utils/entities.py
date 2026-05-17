from __future__ import annotations

import re
from urllib.parse import urlparse


# ---------------------------------------------------------------------------
# Core regex patterns
# ---------------------------------------------------------------------------

EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
PHONE_RE = re.compile(r"(?<!\d)(?:\+?\d[\s().-]?){8,17}\d(?!\d)")
URL_RE = re.compile(r"\bhttps?://[^\s<>)\"']+", re.IGNORECASE)
DOMAIN_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|org|net|co|io|in|edu|gov|info|biz|site|online|xyz|top|shop|work|career|careers)\b",
    re.IGNORECASE,
)
COMPANY_RE = re.compile(
    r"\b(?:company|employer|organization|organisation)\s*[:\-]\s*([A-Za-z0-9&.,' -]{2,80})",
    re.IGNORECASE,
)
RECRUITER_RE = re.compile(
    r"\b(?:recruiter|hr|hiring manager|talent acquisition|contact person)\s*[:\-]\s*([A-Z][A-Za-z.' -]{2,60})",
    re.IGNORECASE,
)
POSITION_RE = re.compile(
    r"\b(?:job title|position|role|opening)\s*[:\-]\s*([A-Za-z0-9&/,.+() -]{3,80})",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Fraud keyword patterns used for contextual matching
# ---------------------------------------------------------------------------

# Primary fraud signals — highest weight
FRAUD_KEYWORDS_PRIMARY = [
    "recruitment scam",
    "job scam",
    "fake offer",
    "advance fee",
    "phishing",
    "blacklist",
    "blacklisted",
]

# Secondary fraud signals — medium weight
FRAUD_KEYWORDS_SECONDARY = [
    "scam",
    "fraud",
    "fraudulent",
    "fake",
    "spam",
    "complaints",
    "complaint",
    "cheat",
    "cheated",
    "warning",
    "reported",
    "suspicious",
    "illegitimate",
    "impersonat",
]

ALL_FRAUD_KEYWORDS = FRAUD_KEYWORDS_PRIMARY + FRAUD_KEYWORDS_SECONDARY

# Pre-compiled pattern for fast contextual scanning
_FRAUD_PATTERN = re.compile(
    r"\b(" + "|".join(re.escape(kw) for kw in ALL_FRAUD_KEYWORDS) + r")\b",
    re.IGNORECASE,
)

# Suspicious TLDs that increase risk scores
SUSPICIOUS_TLDS = {"xyz", "top", "site", "online", "work", "shop"}

# Free / consumer email providers
FREE_EMAIL_DOMAINS = {
    "gmail.com",
    "yahoo.com",
    "outlook.com",
    "hotmail.com",
    "live.com",
    "proton.me",
    "protonmail.com",
    "rediffmail.com",
    "icloud.com",
    "aol.com",
    "ymail.com",
    "mail.com",
    "zoho.com",
}


# ---------------------------------------------------------------------------
# Sentence-level helpers for contextual matching
# ---------------------------------------------------------------------------

def _split_sentences(text: str) -> list[str]:
    """Split text into sentences using punctuation boundaries."""
    raw = re.split(r"(?<=[.!?])\s+", text.strip())
    # Also split on newlines which often act as sentence boundaries in job posts
    sentences: list[str] = []
    for part in raw:
        sentences.extend(line.strip() for line in part.splitlines() if line.strip())
    return sentences


def get_sentence_window(text: str, entity: str, window: int = 2) -> list[str]:
    """
    Return up to ``window`` sentences before and after the sentence containing
    ``entity``.  Returns an empty list if the entity is not found.
    """
    sentences = _split_sentences(text)
    entity_lower = entity.lower()
    for idx, sentence in enumerate(sentences):
        if entity_lower in sentence.lower():
            start = max(0, idx - window)
            end = min(len(sentences), idx + window + 1)
            return sentences[start:end]
    return []


def find_fraud_keywords_in_context(context_sentences: list[str]) -> list[str]:
    """
    Return de-duplicated fraud keywords found inside ``context_sentences``.
    Multi-word phrases are checked before single words to avoid double-counting.
    """
    combined = " ".join(context_sentences)
    found: list[str] = []
    seen: set[str] = set()

    # Multi-word primary keywords first (highest fidelity)
    for kw in FRAUD_KEYWORDS_PRIMARY:
        if kw.lower() in combined.lower() and kw.lower() not in seen:
            found.append(kw)
            seen.add(kw.lower())

    # Single-word secondary keywords
    for match in _FRAUD_PATTERN.finditer(combined):
        kw_lower = match.group(0).lower()
        if kw_lower not in seen:
            found.append(match.group(0).lower())
            seen.add(kw_lower)

    return found


# ---------------------------------------------------------------------------
# Entity extraction
# ---------------------------------------------------------------------------

def _clean_phone(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip(" .,-()")


def extract_entities(text: str) -> dict:
    """Extract raw entities from ``text`` without any fraud filtering."""
    safe_text = text or ""

    urls = sorted({url.rstrip(".,)") for url in URL_RE.findall(safe_text)})
    url_domains: list[str] = []
    for url in urls:
        parsed = urlparse(url)
        if parsed.netloc:
            url_domains.append(parsed.netloc.lower().removeprefix("www."))

    emails = sorted(set(EMAIL_RE.findall(safe_text)))
    email_domains = [email.split("@", 1)[1].lower() for email in emails]
    domains = sorted(
        {d.lower().removeprefix("www.") for d in DOMAIN_RE.findall(safe_text)}
        | set(email_domains)
        | set(url_domains)
    )

    print("\n===== EXTRACTED ENTITIES =====")
    print("Emails     :", emails)
    print("Phones     :", sorted({_clean_phone(p) for p in PHONE_RE.findall(safe_text)}))
    print("Domains    :", domains)
    print("URLs       :", urls)
    print("Companies  :", sorted({m.group(1).strip() for m in COMPANY_RE.finditer(safe_text)}))
    print("Recruiters :", sorted({m.group(1).strip() for m in RECRUITER_RE.finditer(safe_text)}))
    print("==============================\n")

    return {
        "emails": emails,
        "phones": sorted({_clean_phone(p) for p in PHONE_RE.findall(safe_text)}),
        "domains": domains,
        "urls": urls,
        "companies": sorted({m.group(1).strip() for m in COMPANY_RE.finditer(safe_text)})[:5],
        "recruiters": sorted({m.group(1).strip() for m in RECRUITER_RE.finditer(safe_text)})[:5],
        "positions": sorted({m.group(1).strip() for m in POSITION_RE.finditer(safe_text)})[:5],
    }


def extract_suspicious_entities(text: str) -> list[dict]:
    """
    Extract entities AND apply contextual fraud matching.

    Returns only entities whose surrounding context (±2 sentences) contains at
    least one fraud-related keyword.  Each result is a dict with:
        entity          – the raw entity value
        type            – email | phone | url | domain | company | recruiter
        matched_keywords – list of fraud keywords found in context
        context         – the context sentences joined as a string
        _context_sentences – list of raw context sentences (for scoring)
    """
    if not text:
        return []

    all_entities = extract_entities(text)
    suspicious: list[dict] = []

    def _process(values: list[str], entity_type: str) -> None:
        for value in values:
            window = get_sentence_window(text, value, window=2)
            if not window:
                # Entity not found in sentence split → fall back to global scan
                # Use the whole text as a single context block
                window = _split_sentences(text)
            keywords = find_fraud_keywords_in_context(window)

            print("\n==============================")
            print(f"ENTITY TYPE : {entity_type}")
            print(f"ENTITY      : {value}")
            print(f"KEYWORDS    : {keywords}")
            print("CONTEXT:")
            print(" | ".join(window))
            print("==============================\n")

            if keywords:
                suspicious.append(
                    {
                        "entity": value,
                        "type": entity_type,
                        "matched_keywords": keywords,
                        "context": " ".join(window),
                        "_context_sentences": window,
                    }
                )

    _process(all_entities["emails"], "email")
    _process(all_entities["phones"], "phone")
    _process(all_entities["urls"], "url")

    # For domains, skip those that are just email host parts already covered
    email_domains = {e.split("@", 1)[1].lower() for e in all_entities["emails"]}
    standalone_domains = [d for d in all_entities["domains"] if d not in email_domains]
    _process(standalone_domains, "domain")

    _process(all_entities["companies"], "company")
    _process(all_entities["recruiters"], "recruiter")

    return suspicious


def merge_entities(*entity_sets: dict) -> dict:
    """Merge multiple entity dicts, de-duplicating values."""
    keys = ["emails", "phones", "domains", "urls", "companies", "recruiters", "positions", "social_links"]
    merged = {key: [] for key in keys}
    for entities in entity_sets:
        for key in keys:
            values = entities.get(key, []) if entities else []
            if isinstance(values, str):
                values = [values]
            merged[key].extend(values)
    return {
        key: sorted({str(v).strip() for v in values if str(v).strip()})
        for key, values in merged.items()
    }


def has_free_email(entities: dict) -> bool:
    """Return True if any email in ``entities`` uses a free provider domain."""
    for email in entities.get("emails", []):
        domain = email.split("@", 1)[-1].lower()
        if domain in FREE_EMAIL_DOMAINS:
            return True
    return False