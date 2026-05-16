import re
from urllib.parse import urlparse


EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
PHONE_RE = re.compile(r"(?<!\d)(?:\+?\d[\s().-]?){8,17}\d(?!\d)")
URL_RE = re.compile(r"\bhttps?://[^\s<>)\"']+", re.IGNORECASE)
DOMAIN_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|org|net|co|io|in|edu|gov|info|biz|site|online|xyz|top|shop|work|career|careers)\b",
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


def _clean_phone(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip(" .,-()")


def extract_entities(text: str) -> dict:
    urls = sorted({u.rstrip(".,)") for u in URL_RE.findall(text or "")})
    email_domains = [email.split("@", 1)[1].lower() for email in EMAIL_RE.findall(text or "")]
    url_domains = []
    for url in urls:
        parsed = urlparse(url)
        if parsed.netloc:
            url_domains.append(parsed.netloc.lower().removeprefix("www."))

    domains = sorted({d.lower().removeprefix("www.") for d in DOMAIN_RE.findall(text or "")})
    domains = sorted(set(domains + email_domains + url_domains))

    recruiters = sorted({m.group(1).strip() for m in RECRUITER_RE.finditer(text or "")})
    positions = sorted({m.group(1).strip() for m in POSITION_RE.finditer(text or "")})

    return {
        "emails": sorted(set(EMAIL_RE.findall(text or ""))),
        "phones": sorted({_clean_phone(p) for p in PHONE_RE.findall(text or "")}),
        "domains": domains,
        "urls": urls,
        "recruiters": recruiters[:5],
        "positions": positions[:5],
    }

