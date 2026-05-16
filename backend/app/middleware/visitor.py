from starlette.middleware.base import BaseHTTPMiddleware


class VisitorTrackingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        if request.method in {"POST", "OPTIONS"} and request.url.path in {"/analyze", "/upload"}:
            analytics = getattr(request.app.state, "analytics", None)
            if analytics and request.method == "POST":
                await analytics.record_visitor()
        return await call_next(request)

