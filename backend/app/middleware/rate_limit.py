from __future__ import annotations

import time
from collections import defaultdict, deque

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse


def _parse_rate_limit(value: str) -> tuple[int, int]:
    count_text, _, period = value.partition("/")
    count = int(count_text.strip() or 60)
    seconds = {"second": 1, "minute": 60, "hour": 3600}.get(period.strip().lower(), 60)
    return count, seconds


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, rate_limit: str) -> None:
        super().__init__(app)
        self.max_requests, self.window_seconds = _parse_rate_limit(rate_limit)
        self.requests: dict[str, deque[float]] = defaultdict(deque)

    async def dispatch(self, request: Request, call_next):
        if request.url.path == "/health":
            return await call_next(request)

        client_ip = request.client.host if request.client else "unknown"
        now = time.monotonic()
        bucket = self.requests[client_ip]
        while bucket and now - bucket[0] > self.window_seconds:
            bucket.popleft()
        if len(bucket) >= self.max_requests:
            return JSONResponse(
                {"detail": "Rate limit exceeded"},
                status_code=429,
                headers={"Retry-After": str(self.window_seconds)},
            )
        bucket.append(now)
        return await call_next(request)

