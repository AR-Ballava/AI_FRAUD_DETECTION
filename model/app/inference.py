from __future__ import annotations

import hashlib
import os
import re
import time
from dataclasses import dataclass

import torch

from app.entities import extract_entities
from app.rules import score_with_rules


class FraudLinearModel(torch.nn.Module):
    def __init__(self, input_size: int = 16, output_size: int = 5):
        super().__init__()
        self.classifier = torch.nn.Sequential(
            torch.nn.Linear(input_size, 32),
            torch.nn.ReLU(),
            torch.nn.Linear(32, output_size),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.classifier(x)


@dataclass
class LoadedModel:
    model: FraudLinearModel | None
    labels: list[str]
    path: str
    loaded: bool


LABELS = [
    "fake_job_posting",
    "fraudulent_offer_letter",
    "scam_recruitment_email",
    "suspicious_terms_conditions",
    "company_fraud_signals",
]


def load_model(path: str) -> LoadedModel:
    if not os.path.exists(path):
        return LoadedModel(model=None, labels=LABELS, path=path, loaded=False)

    checkpoint = torch.load(path, map_location="cpu")
    labels = checkpoint.get("labels", LABELS) if isinstance(checkpoint, dict) else LABELS
    model = FraudLinearModel(output_size=len(labels))
    state_dict = checkpoint.get("state_dict", checkpoint) if isinstance(checkpoint, dict) else checkpoint
    model.load_state_dict(state_dict, strict=False)
    model.eval()
    return LoadedModel(model=model, labels=labels, path=path, loaded=True)


def _feature_vector(text: str) -> torch.Tensor:
    text_lower = text.lower()
    features = [
        len(text) / 10000,
        len(re.findall(r"\bfee|deposit|payment|refundable|processing\b", text_lower)),
        len(re.findall(r"\burgent|immediate|act now|24 hours\b", text_lower)),
        len(re.findall(r"\bwhatsapp|telegram|crypto|gift card|upi\b", text_lower)),
        len(re.findall(r"\bpassport|bank|otp|aadhaar|ssn\b", text_lower)),
        len(re.findall(r"\bgmail\.com|yahoo\.com|outlook\.com|hotmail\.com\b", text_lower)),
        len(re.findall(r"https?://", text_lower)),
        len(re.findall(r"[$₹]\s?\d+", text_lower)),
        len(re.findall(r"\binterview|assessment|panel\b", text_lower)),
        len(re.findall(r"\bno fee|never ask|does not charge\b", text_lower)),
        len(re.findall(r"\bprivacy policy|equal opportunity\b", text_lower)),
        len(re.findall(r"\bremote|part[-\s]?time|work from home\b", text_lower)),
        len(re.findall(r"\boffer letter|appointment letter\b", text_lower)),
        len(re.findall(r"\btraining|certification|kit\b", text_lower)),
        len(re.findall(r"\bclick here|verify now|complete the form\b", text_lower)),
        len(set(re.findall(r"\b[A-Za-z]{5,}\b", text_lower))) / 1000,
    ]
    return torch.tensor([features], dtype=torch.float32)


def _ml_score(loaded: LoadedModel, text: str) -> tuple[float, list[dict]]:
    if loaded.model is None:
        digest = hashlib.sha256(text.encode("utf-8", errors="ignore")).digest()
        tiny_adjustment = (digest[0] / 255) * 4 - 2
        return max(0, tiny_adjustment), []

    with torch.no_grad():
        logits = loaded.model(_feature_vector(text))
        probabilities = torch.softmax(logits, dim=-1)[0]
    score = float(probabilities.max().item() * 100)
    labels = [
        {"label": label, "score": round(float(probabilities[idx].item() * 100), 2)}
        for idx, label in enumerate(loaded.labels)
    ]
    return round(score, 2), sorted(labels, key=lambda item: item["score"], reverse=True)


def explain(fraud_score: float, suspicious_terms: list[dict], legitimate_indicators: list[dict]) -> str:
    if fraud_score >= 75:
        opening = "The document contains multiple high-severity recruitment fraud signals."
    elif fraud_score >= 50:
        opening = "The document shows strong suspicious indicators and should be independently verified."
    elif fraud_score >= 25:
        opening = "The document has moderate risk signals that warrant public-source verification."
    elif fraud_score >= 10:
        opening = "The document has light but non-zero suspicion and should be treated cautiously."
    else:
        opening = "No strong fraud pattern was detected from the submitted text."

    if suspicious_terms:
        top_terms = ", ".join(item["term"] for item in suspicious_terms[:5])
        opening += f" Primary triggers include: {top_terms}."
    if legitimate_indicators:
        opening += " Some legitimate indicators were also present, reducing the final score."
    return opening


def predict_text(loaded: LoadedModel, text: str) -> dict:
    started = time.perf_counter()
    rules = score_with_rules(text)
    ml_score, ml_labels = _ml_score(loaded, text)

    if loaded.loaded:
        fraud_score = round(min(100, (rules["rule_score"] * 0.55) + (ml_score * 0.45)), 2)
    else:
        fraud_score = round(min(100, max(0, rules["rule_score"] + ml_score)), 2)

    legitimacy_score = round(max(0, 100 - fraud_score), 2)
    confidence = round(min(99, 50 + abs(fraud_score - 50) * 0.75 + min(len(text), 5000) / 250), 2)
    labels = ml_labels[:5] if loaded.loaded and ml_labels else rules["labels"]

    response = {
        "fraud_score": fraud_score,
        "legitimacy_score": legitimacy_score,
        "risk_level": rules["risk_level"] if fraud_score < 50 else ("critical" if fraud_score >= 75 else "high"),
        "labels": labels,
        "explanation": explain(fraud_score, rules["suspicious_terms"], rules["legitimate_indicators"]),
        "ai_reasoning_summary": {
            "model_loaded": loaded.loaded,
            "decision_basis": "hybrid_ml_rules" if loaded.loaded else "rules_fallback_until_pt_model_is_available",
            "top_label": labels[0]["label"] if labels else "unknown",
            "osint_recommended": fraud_score >= 10,
        },
        "suspicious_terms": rules["suspicious_terms"],
        "legitimate_indicators": rules["legitimate_indicators"],
        "ml_score": round(ml_score, 2),
        "rule_score": rules["rule_score"],
        "confidence": confidence,
        "entities": extract_entities(text),
        "processing_time_ms": round((time.perf_counter() - started) * 1000, 2),
    }
    return response

