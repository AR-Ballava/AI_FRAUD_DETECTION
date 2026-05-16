from pydantic import BaseModel, Field, model_validator


class PredictRequest(BaseModel):
    text: str | None = Field(None, max_length=120_000)
    base64_pdf: str | None = None
    source_type: str = "text"

    @model_validator(mode="after")
    def require_payload(self) -> "PredictRequest":
        if not self.text and not self.base64_pdf:
            raise ValueError("Either text or base64_pdf is required")
        return self


class PredictResponse(BaseModel):
    fraud_score: float
    legitimacy_score: float
    risk_level: str
    labels: list[dict]
    explanation: str
    ai_reasoning_summary: dict
    suspicious_terms: list[dict]
    legitimate_indicators: list[dict]
    ml_score: float
    rule_score: float
    confidence: float
    entities: dict
    processing_time_ms: float

