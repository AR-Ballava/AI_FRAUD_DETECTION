from __future__ import annotations

import base64
import time

from fastapi import APIRouter, File, Form, HTTPException, Request, UploadFile

from app.config import get_settings
from app.schemas import AnalysisResponse, AnalyzeRequest, OsintRequest
from app.services.graph import build_graph
from app.services.model_client import ModelServiceUnavailable
from app.services.osint import run_osint, score_suspicious_entities
from app.utils.entities import extract_entities, merge_entities
from app.utils.sanitize import sanitize_text
from app.utils.validation import ValidationError, decode_text_file, validate_file_upload

router = APIRouter()


async def _analyze_payload(
    request: Request,
    text: str | None,
    source_type: str,
    base64_pdf: str | None = None,
) -> AnalysisResponse:
    settings = get_settings()
    started = time.perf_counter()

    clean_text = text or ""
    text_entities = extract_entities(clean_text)

    model_payload: dict = {"source_type": source_type}
    if base64_pdf:
        model_payload["base64_pdf"] = base64_pdf
    else:
        model_payload["text"] = sanitize_text(clean_text, settings.max_text_chars)

    try:
        model_result = await request.app.state.model_client.predict(model_payload)
    except ModelServiceUnavailable as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    entities = merge_entities(text_entities, model_result.get("entities", {}))
    fraud_score = model_result.get("fraud_score", 0.0)
    risk_level = model_result.get("risk_level", "low")

    osint_result = await run_osint(
        entities=entities,
        timeout=settings.scrape_timeout,
        source_text=clean_text,
    )
    
    osint_score = score_suspicious_entities(osint_result)
    final_score = min(100.0, max(0.0, (fraud_score * 0.7) + (osint_score * 0.3)))
    
    if final_score >= 75.0:
        final_risk = "high"
    elif final_score >= 40.0:
        final_risk = "medium"
    else:
        final_risk = "low"

    if hasattr(request.app.state, "analytics") and request.app.state.analytics:
        await request.app.state.analytics.record_detection(
            fraud_score=final_score,
            risk_level=final_risk,
            source_type=source_type,
            entities=entities,
        )

    graph = build_graph(entities, {"fraud_score": final_score}, osint_result)
    request.app.state.latest_graph = graph

    return {
        "fraud_score": final_score,
        "risk_level": final_risk,
        "source_type": source_type,
        "analysis_duration": time.perf_counter() - started,
        "entities": entities,
        "osint": osint_result,
        "graph": graph,
    }


@router.post("/analyze", response_model=AnalysisResponse)
async def analyze(request: Request, payload: AnalyzeRequest) -> AnalysisResponse:
    return await _analyze_payload(
        request=request,
        text=payload.text,
        source_type=payload.source_type,
    )


@router.post("/analyze/file", response_model=AnalysisResponse)
async def analyze_file(
    request: Request,
    file: UploadFile = File(...),
    source_type: str = Form("paste"),
) -> AnalysisResponse:
    try:
        validate_file_upload(file)
        content = await file.read()
    except ValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    if file.filename and file.filename.lower().endswith(".pdf"):
        base64_pdf = base64.b64encode(content).decode("utf-8")
        return await _analyze_payload(
            request=request,
            text=None,
            source_type=source_type,
            base64_pdf=base64_pdf,
        )

    raw_text = decode_text_file(content)
    return await _analyze_payload(
        request=request,
        text=raw_text,
        source_type=source_type,
    )


@router.post("/osint")
async def osint(request: Request, payload: OsintRequest) -> dict:
    settings = get_settings()
    raw_text = payload.source_text or ""
    entities = {
        "domains": payload.domains or [],
        "emails": payload.emails or [],
        "phones": payload.phones or [],
        "companies": payload.companies or [],
    }
    fraud_score = payload.fraud_score or 0.0
    
    osint_result = await run_osint(
        entities=entities,
        timeout=settings.scrape_timeout,
        source_text=raw_text,
    )
    graph = build_graph(entities, {"fraud_score": fraud_score}, osint_result)
    request.app.state.latest_graph = graph
    return {
        **osint_result,
        "manual": True,
        "entities": entities,
        "graph": graph,
    }


@router.get("/analytics")
async def analytics(request: Request) -> dict:
    # Pure data output path - Increments are handled explicitly by main.py middleware filtering
    return await request.app.state.analytics.snapshot()


@router.get("/stats")
async def stats(request: Request) -> dict:
    # Pure data output path - Increments are handled explicitly by main.py middleware filtering
    data = await request.app.state.analytics.snapshot()
    return {
        "lifetime_visitors": data.get("lifetime_visitors", 0),
        "lifetime_fraud_detections": data.get("lifetime_fraud_detections", 0),
        "fraud_detections": data.get("fraud_detections", 0),
        "safe_detections": data.get("safe_detections", 0),
        "daily": data.get("daily", {}),
        "monthly": data.get("monthly", {}),
        "yearly": data.get("yearly", {}),
        "recent_detections": data.get("recent_detections", [])[:10],
    }


@router.get("/graph-data")
async def graph_data(request: Request) -> dict:
    return getattr(request.app.state, "latest_graph", {"nodes": [], "edges": []})


@router.get("/health")
async def health(request: Request) -> dict:
    return {"status": "healthy", "timestamp": time.time()}