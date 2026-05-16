from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from app.config import get_settings
from app.inference import LoadedModel, load_model, predict_text
from app.pdf_utils import PdfExtractionError, extract_text_from_base64_pdf
from app.schemas import PredictRequest, PredictResponse


state: dict[str, LoadedModel] = {}


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    state["model"] = load_model(settings.model_path)
    yield
    state.clear()


app = FastAPI(
    title="AI Job Fraud Model Service",
    version="1.0.0",
    description="NLP fraud classifier and explainability API for job, offer-letter, and recruitment-email content.",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["POST", "GET"],
    allow_headers=["*"],
)


@app.get("/health")
async def health() -> dict:
    loaded = state.get("model")
    return {
        "status": "ok",
        "model_loaded": bool(loaded and loaded.loaded),
        "model_path": loaded.path if loaded else get_settings().model_path,
    }


@app.post("/predict", response_model=PredictResponse)
async def predict(payload: PredictRequest) -> PredictResponse:
    settings = get_settings()
    text = payload.text or ""

    if payload.base64_pdf:
        try:
            text = extract_text_from_base64_pdf(payload.base64_pdf, max_bytes=settings.max_file_size)
        except PdfExtractionError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    if len(text) > settings.max_text_chars:
        raise HTTPException(status_code=413, detail="Text exceeds configured inference size")

    loaded = state.get("model")
    if not loaded:
        raise HTTPException(status_code=503, detail="Model is not initialized")

    return PredictResponse(**predict_text(loaded, text))

