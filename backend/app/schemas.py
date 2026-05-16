from pydantic import BaseModel, Field


class AnalyzeRequest(BaseModel):
    text: str = Field(..., min_length=1)
    source_type: str = "text"


class OsintRequest(BaseModel):
    entities: dict = Field(default_factory=dict)
    text: str | None = None
    fraud_score: float = 0


class AnalysisResponse(BaseModel):
    fraud_score: float
    legitimacy_score: float
    risk_level: str
    explanation: str
    ai_reasoning_summary: dict
    suspicious_terms: list[dict]
    legitimate_indicators: list[dict]
    ml_score: float
    rule_score: float
    confidence: float
    processing_time_ms: float
    entities: dict
    osint_triggered: bool
    osint: dict
    graph: dict
