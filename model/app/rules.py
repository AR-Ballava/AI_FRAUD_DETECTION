from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True)
class PatternRule:
    label: str
    pattern: re.Pattern[str]
    weight: float
    reason: str


FRAUD_RULES: tuple[PatternRule, ...] = (
    PatternRule("fake_job_posting", re.compile(r"\b(no interview|no experience required|direct joining|guaranteed job)\b", re.I), 12, "claims unusually low hiring friction"),
    PatternRule("fraudulent_offer_letter", re.compile(r"\b(offer letter|appointment letter).{0,80}\b(pay|deposit|fee|refundable)\b", re.I | re.S), 16, "connects an offer letter with payment requests"),
    PatternRule("scam_recruitment_email", re.compile(r"\b(urgent|immediate|within\s+24\s+hours|limited slots|act now)\b", re.I), 9, "uses urgency or pressure language"),
    PatternRule("suspicious_terms_conditions", re.compile(r"\b(non[-\s]?refundable|processing fee|training fee|security deposit|background verification fee|registration fee)\b", re.I), 20, "requests fees that are common in recruitment scams"),
    PatternRule("company_fraud_signals", re.compile(r"\b(whatsapp|telegram|crypto|gift card|bitcoin|upi|wire transfer)\b", re.I), 14, "moves the conversation or payment into high-risk channels"),
    PatternRule("phishing_language", re.compile(r"\b(bank account|aadhaar|passport|ssn|social security|otp|one time password|login credentials)\b", re.I), 13, "asks for sensitive identity or account data"),
    PatternRule("domain_warning", re.compile(r"\b(gmail\.com|yahoo\.com|outlook\.com|hotmail\.com|proton\.me|rediffmail\.com)\b", re.I), 8, "uses a free email provider for recruiting communication"),
    PatternRule("salary_warning", re.compile(r"(?:₹|rs\.?|\$|usd|inr)?\s?(?:[8-9]\d{4,}|\d{1,2}\s?lpa).{0,80}\b(part[-\s]?time|no experience|freshers?)\b", re.I), 12, "advertises unusually attractive compensation for low requirements"),
    PatternRule("link_warning", re.compile(r"\b(click here|verify now|complete the form|shortlisted|download attachment)\b", re.I), 7, "contains common phishing call-to-action phrasing"),
)

LEGITIMATE_RULES: tuple[PatternRule, ...] = (
    PatternRule("structured_process", re.compile(r"\b(interview panel|technical interview|assessment|background check after offer|recruitment process)\b", re.I), 8, "describes a structured hiring process"),
    PatternRule("official_policy", re.compile(r"\b(equal opportunity|privacy policy|code of conduct|terms of employment|employee handbook)\b", re.I), 5, "includes formal employment policy language"),
    PatternRule("company_details", re.compile(r"\b(CIN|registered office|GSTIN|tax identification|company registration)\b", re.I), 6, "mentions verifiable company registration details"),
    PatternRule("no_fee", re.compile(r"\b(no fee|does not charge|never ask(?:s)? for money|free recruitment)\b", re.I), 10, "explicitly states recruitment is free"),
)


def _matches(text: str, rules: Iterable[PatternRule]) -> list[dict]:
    hits = []
    for rule in rules:
        for match in rule.pattern.finditer(text):
            snippet = text[max(0, match.start() - 80) : match.end() + 80].strip()
            hits.append(
                {
                    "label": rule.label,
                    "term": match.group(0),
                    "weight": rule.weight,
                    "reason": rule.reason,
                    "snippet": re.sub(r"\s+", " ", snippet),
                }
            )
    return hits


def _risk_category(score: float) -> str:
    if score >= 75:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 25:
        return "medium"
    if score >= 10:
        return "low"
    return "minimal"


def score_with_rules(text: str) -> dict:
    normalized = re.sub(r"\s+", " ", text or "").strip()
    suspicious = _matches(normalized, FRAUD_RULES)
    legitimate = _matches(normalized, LEGITIMATE_RULES)

    suspicious_score = sum(item["weight"] for item in suspicious)
    legitimate_score = sum(item["weight"] for item in legitimate)
    length_factor = min(1.15, 0.7 + math.log10(max(len(normalized), 100)) / 8)
    score = max(0, min(100, (suspicious_score * length_factor) - (legitimate_score * 0.55)))

    labels = {}
    for hit in suspicious:
        labels[hit["label"]] = labels.get(hit["label"], 0) + hit["weight"]
    ranked_labels = [
        {"label": label, "score": round(min(100, value * 4), 2)}
        for label, value in sorted(labels.items(), key=lambda item: item[1], reverse=True)
    ]

    if not ranked_labels and score < 10:
        ranked_labels = [{"label": "no_strong_fraud_signal", "score": round(100 - score, 2)}]

    suspicious_terms = []
    seen = set()
    for hit in suspicious:
        key = hit["term"].lower()
        if key not in seen:
            suspicious_terms.append(hit)
            seen.add(key)

    legitimate_indicators = []
    seen_legit = set()
    for hit in legitimate:
        key = hit["term"].lower()
        if key not in seen_legit:
            legitimate_indicators.append(hit)
            seen_legit.add(key)

    return {
        "rule_score": round(score, 2),
        "risk_level": _risk_category(score),
        "labels": ranked_labels,
        "suspicious_terms": suspicious_terms[:25],
        "legitimate_indicators": legitimate_indicators[:15],
    }

