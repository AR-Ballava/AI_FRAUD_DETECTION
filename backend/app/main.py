import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from upstash_redis.asyncio import Redis

from app.api.routes import router
from app.config import get_settings
from app.middleware.rate_limit import RateLimitMiddleware
from app.middleware.security import SecurityHeadersMiddleware
from app.services.analytics import AnalyticsStore
from app.services.model_client import ModelClient


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()

    # --- Upstash Redis (persistent analytics across container restarts) ---
    redis_url = os.getenv("UPSTASH_REDIS_REST_URL")
    redis_token = os.getenv("UPSTASH_REDIS_REST_TOKEN")
    if redis_url and redis_token:
        app.state.redis = Redis(url=redis_url, token=redis_token)
    else:
        app.state.redis = None  # falls back to file-based storage if not set

    app.state.analytics = AnalyticsStore(settings.analytics_path, redis=app.state.redis)
    await app.state.analytics.load()
    app.state.model_client = ModelClient(str(settings.model_service_url), timeout=20.0)
    app.state.latest_graph = {"nodes": [], "edges": []}
    yield
    await app.state.model_client.close()
    if app.state.redis:
        await app.state.redis.close()


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="AI Job Fraud Intelligence Backend",
        version="1.0.0",
        description="Async REST API for fraud analysis, OSINT enrichment, analytics, and graph intelligence.",
        lifespan=lifespan,
    )
    
    # 1. CORS Configuration
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.origins,
        allow_credentials=False,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["*"],
    )

    # 2. Strict Visitor Tracking Middleware
    # Intercepts exactly ONE data endpoint (/stats) to guarantee exactly +1 visitor count on layout mount/refresh
    @app.middleware("http")
    async def track_only_primary_stats_load(request, call_next):
        if request.url.path == "/stats":
            if hasattr(app.state, "analytics") and app.state.analytics:
                await app.state.analytics.record_visitor()
                
        response = await call_next(request)
        return response

    # 3. Security and Rate Limiting Middlewares (VisitorTrackingMiddleware removed to fix duplicate increments)
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(RateLimitMiddleware, rate_limit=settings.rate_limit)

    app.include_router(router)

    return app


app = create_app()