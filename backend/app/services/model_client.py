from __future__ import annotations

import asyncio

import httpx

from app.services.circuit_breaker import CircuitBreaker


class ModelServiceUnavailable(RuntimeError):
    pass


class ModelClient:
    def __init__(self, base_url: str, timeout: float = 20.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.client = httpx.AsyncClient(timeout=httpx.Timeout(timeout))
        self.breaker = CircuitBreaker()

    async def close(self) -> None:
        await self.client.aclose()

    async def health(self) -> dict:
        if not self.breaker.allow_request():
            return {"status": "unavailable", "circuit": self.breaker.state}
        try:
            response = await self.client.get(f"{self.base_url}/health")
            response.raise_for_status()
            self.breaker.record_success()
            payload = response.json()
            payload["circuit"] = self.breaker.state
            return payload
        except Exception:
            self.breaker.record_failure()
            return {"status": "unavailable", "circuit": self.breaker.state}

    async def predict(self, payload: dict) -> dict:
        if not self.breaker.allow_request():
            raise ModelServiceUnavailable("Model service circuit breaker is open")

        last_error: Exception | None = None
        for attempt in range(3):
            try:
                response = await self.client.post(f"{self.base_url}/predict", json=payload)
                response.raise_for_status()
                self.breaker.record_success()
                return response.json()
            except Exception as exc:
                last_error = exc
                self.breaker.record_failure()
                await asyncio.sleep(0.25 * (2**attempt))

        raise ModelServiceUnavailable(f"Model service failed after retries: {last_error}")

