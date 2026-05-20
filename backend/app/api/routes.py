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
    fraud_score = float(model_result.get("fraud_score", 0))
    osint_triggered = fraud_score >= settings.fraud_osint_threshold

    # ── Default OSINT payload (returned even when not triggered) ──
    osint: dict = {
        "status": "not_triggered",
        "risk": {"score": 0, "level": "minimal", "reasons": []},
        # Always run local contextual entity scoring — no network required
        "suspicious_entities": score_suspicious_entities(clean_text),
        "evidence": [],
        "domain_intelligence": [],
        "scam_reports": [],
        "source_status": [],
    }

    if osint_triggered:
        # Full async OSINT fetch — passes source_text for local scoring pass
        osint = await run_osint(
            entities,
            initial_fraud_score=fraud_score,
            timeout=settings.scrape_timeout,
            source_text=clean_text,
        )

    graph = build_graph(entities, model_result, osint)
    request.app.state.latest_graph = graph

    await request.app.state.analytics.record_detection(
        fraud_score=fraud_score,
        risk_level=model_result.get("risk_level", "unknown"),
        source_type=source_type,
        entities=entities,
    )

    total_processing = round((time.perf_counter() - started) * 1000, 2)
    response = {
        **model_result,
        "processing_time_ms": model_result.get("processing_time_ms", 0) + total_processing,
        "entities": entities,
        "osint_triggered": osint_triggered,
        "osint": osint,
        "graph": graph,
    }
    return AnalysisResponse(**response)


@router.post("/analyze", response_model=AnalysisResponse)
async def analyze(payload: AnalyzeRequest, request: Request) -> AnalysisResponse:
    try:
        clean_text = sanitize_text(payload.text, get_settings().max_text_chars)
    except ValueError as exc:
        raise HTTPException(status_code=413, detail=str(exc)) from exc
    return await _analyze_payload(request, clean_text, payload.source_type)


@router.post("/upload", response_model=AnalysisResponse)
async def upload(
    request: Request,
    file: UploadFile = File(...),
    source_type: str = Form("upload"),
) -> AnalysisResponse:
    settings = get_settings()
    data = await file.read()
    try:
        file_kind = validate_file_upload(
            file.filename or "upload",
            file.content_type,
            data,
            settings.max_file_size,
        )
        if file_kind == "pdf":
            # For PDFs we can't easily do sentence-level contextual scoring
            # without extracting text first; pass empty source_text and let
            # the model-extracted entities drive OSINT.
            return await _analyze_payload(
                request,
                text="",
                source_type=source_type,
                base64_pdf=base64.b64encode(data).decode("ascii"),
            )
        raw_text = decode_text_file(data)
        clean_text = sanitize_text(raw_text, settings.max_text_chars)
        return await _analyze_payload(request, clean_text, source_type)
    except ValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=413, detail=str(exc)) from exc
    finally:
        await file.close()


@router.post("/osint")
async def osint(payload: OsintRequest, request: Request) -> dict:
    settings = get_settings()
    raw_text = ""
    text_entities: dict = {}

    if payload.text:
        try:
            raw_text = sanitize_text(payload.text, settings.max_text_chars)
        except ValueError as exc:
            raise HTTPException(status_code=413, detail=str(exc)) from exc
        text_entities = extract_entities(raw_text)

    entities = merge_entities(payload.entities, text_entities)
    if not any(
        entities.get(key)
        for key in ("emails", "phones", "domains", "urls", "companies", "recruiters", "positions")
    ):
        raise HTTPException(
            status_code=422,
            detail="Manual OSINT requires at least one company, email, domain, phone, recruiter, or job role",
        )

    fraud_score = payload.fraud_score or settings.fraud_osint_threshold
    osint_result = await run_osint(
        entities,
        fraud_score,
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
    return await request.app.state.analytics.snapshot()


@router.get("/stats")
async def stats(request: Request) -> dict:
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
    model_health = await request.app.state.model_client.health()
    return {
        "status": "ok",
        "model_service": model_health,
        "analytics": "ok",
        "rate_limit": get_settings().rate_limit,
    }