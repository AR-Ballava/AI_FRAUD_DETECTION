from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import router
from app.config import get_settings
from app.middleware.rate_limit import RateLimitMiddleware
from app.middleware.security import SecurityHeadersMiddleware
from app.middleware.visitor import VisitorTrackingMiddleware
from app.services.analytics import AnalyticsStore
from app.services.model_client import ModelClient


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    app.state.analytics = AnalyticsStore(settings.analytics_path)
    await app.state.analytics.load()
    app.state.model_client = ModelClient(str(settings.model_service_url), timeout=20.0)
    app.state.latest_graph = {"nodes": [], "edges": []}
    yield
    await app.state.model_client.close()


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="AI Job Fraud Intelligence Backend",
        version="1.0.0",
        description="Async REST API for fraud analysis, OSINT enrichment, analytics, and graph intelligence.",
        lifespan=lifespan,
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.origins,
        allow_credentials=False,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["*"],
    )
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(VisitorTrackingMiddleware)
    app.add_middleware(RateLimitMiddleware, rate_limit=settings.rate_limit)
    app.include_router(router)
    return app


app = create_app()

