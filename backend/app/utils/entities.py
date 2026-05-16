from __future__ import annotations

import re
from urllib.parse import urlparse


EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
PHONE_RE = re.compile(r"(?<!\d)(?:\+?\d[\s().-]?){8,17}\d(?!\d)")
URL_RE = re.compile(r"\bhttps?://[^\s<>)\"']+", re.IGNORECASE)
DOMAIN_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|org|net|co|io|in|edu|gov|info|biz|site|online|xyz|top|shop|work|career|careers)\b",
    re.IGNORECASE,
)
COMPANY_RE = re.compile(r"\b(?:company|employer|organization|organisation)\s*[:\-]\s*([A-Za-z0-9&.,' -]{2,80})", re.IGNORECASE)
RECRUITER_RE = re.compile(r"\b(?:recruiter|hr|hiring manager|talent acquisition|contact person)\s*[:\-]\s*([A-Z][A-Za-z.' -]{2,60})", re.IGNORECASE)
POSITION_RE = re.compile(r"\b(?:job title|position|role|opening)\s*[:\-]\s*([A-Za-z0-9&/,.+() -]{3,80})", re.IGNORECASE)


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
}


def _clean_phone(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip(" .,-()")


def extract_entities(text: str) -> dict:
    urls = sorted({url.rstrip(".,)") for url in URL_RE.findall(text or "")})
    url_domains = []
    for url in urls:
        parsed = urlparse(url)
        if parsed.netloc:
            url_domains.append(parsed.netloc.lower().removeprefix("www."))

    emails = sorted(set(EMAIL_RE.findall(text or "")))
    email_domains = [email.split("@", 1)[1].lower() for email in emails]
    domains = sorted({d.lower().removeprefix("www.") for d in DOMAIN_RE.findall(text or "")} | set(email_domains) | set(url_domains))

    return {
        "emails": emails,
        "phones": sorted({_clean_phone(phone) for phone in PHONE_RE.findall(text or "")}),
        "domains": domains,
        "urls": urls,
        "companies": sorted({m.group(1).strip() for m in COMPANY_RE.finditer(text or "")})[:5],
        "recruiters": sorted({m.group(1).strip() for m in RECRUITER_RE.finditer(text or "")})[:5],
        "positions": sorted({m.group(1).strip() for m in POSITION_RE.finditer(text or "")})[:5],
    }


def merge_entities(*entity_sets: dict) -> dict:
    keys = ["emails", "phones", "domains", "urls", "companies", "recruiters", "positions", "social_links"]
    merged = {key: [] for key in keys}
    for entities in entity_sets:
        for key in keys:
            values = entities.get(key, []) if entities else []
            if isinstance(values, str):
                values = [values]
            merged[key].extend(values)
    return {key: sorted({str(value).strip() for value in values if str(value).strip()}) for key, values in merged.items()}


def has_free_email(entities: dict) -> bool:
    for email in entities.get("emails", []):
        domain = email.split("@", 1)[-1].lower()
        if domain in FREE_EMAIL_DOMAINS:
            return True
    return False

