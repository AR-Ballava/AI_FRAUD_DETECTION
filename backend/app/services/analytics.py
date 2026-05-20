from __future__ import annotations

import asyncio
import json
from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path

REDIS_KEY = "fraudlens:analytics"


def _empty_bucket() -> dict:
    return {"visitors": 0, "detections": 0, "fraud": 0, "safe": 0}


class AnalyticsStore:
    def __init__(self, path: Path, redis=None):
        self.path = Path(path)  # Ensures path is always a Path object, preventing string attribute crashes
        self.redis = redis
        self.lock = asyncio.Lock()
        self.data: dict = self._default_data()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _default_data(self) -> dict:
        return {
            "lifetime_visitors": 0,
            "lifetime_fraud_detections": 0,
            "fraud_detections": 0,
            "safe_detections": 0,
            "daily": {},
            "monthly": {},
            "yearly": {},
            "recent_detections": [],
            "updated_at": datetime.now(UTC).isoformat(),
        }

    def _keys(self, now: datetime) -> tuple[str, str, str]:
        return now.strftime("%Y-%m-%d"), now.strftime("%Y-%m"), now.strftime("%Y")

    # ------------------------------------------------------------------
    # Persistence  (Redis first, file fallback)
    # ------------------------------------------------------------------

    async def load(self) -> None:
        """Load data primarily from Redis. Only falls back to file if Redis is unreachable."""
        if self.redis:
            try:
                raw = await self.redis.get(REDIS_KEY)
                if raw:
                    # Redis has data -> Use it immediately
                    self.data = json.loads(raw)
                    return
                else:
                    # Redis is connected but completely empty -> Initialize fresh structure in Redis
                    self.data = self._default_data()
                    await self._persist()
                    return
            except Exception:
                # Redis is down/unreachable -> fall through to local file backup
                pass

        # Emergency Fallback: File-only path (Runs only if Redis is not configured or down)
        if not self.path.exists():
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.data = self._default_data()
            await self._persist()
            return
            
        try:
            self.data = json.loads(self.path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            self.data = self._default_data()
            await self._persist()

    async def _persist(self) -> None:
        """Write data to Redis (primary) AND file (backup)."""
        payload = json.dumps(self.data, indent=2, sort_keys=True)

        if self.redis:
            try:
                await self.redis.set(REDIS_KEY, payload)
            except Exception:
                pass  # Do not crash the app engine if writes to Redis drop out

        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            # Offloads filesystem I/O safely to an asynchronous worker thread
            await asyncio.to_thread(self.path.write_text, payload, "utf-8")
        except OSError:
            pass  # Handles ephemeral container runtimes gracefully (e.g. Render deployments)

    # ------------------------------------------------------------------
    # Public write methods
    # ------------------------------------------------------------------

    async def record_visitor(self) -> None:
        async with self.lock:
            now = datetime.now(UTC)
            day, month, year = self._keys(now)
            
            self.data["lifetime_visitors"] = self.data.get("lifetime_visitors", 0) + 1
            
            for bucket_name, key in (("daily", day), ("monthly", month), ("yearly", year)):
                bucket = self.data.setdefault(bucket_name, {}).setdefault(key, _empty_bucket())
                bucket["visitors"] = bucket.get("visitors", 0) + 1
                
            self.data["updated_at"] = now.isoformat()
            await self._persist()

    async def record_detection(
        self,
        fraud_score: float,
        risk_level: str,
        source_type: str,
        entities: dict,
    ) -> None:
        async with self.lock:
            now = datetime.now(UTC)
            day, month, year = self._keys(now)
            is_fraud = fraud_score >= 50
            classification = "fraud" if is_fraud else "safe"

            self.data["lifetime_fraud_detections"] = (
                self.data.get("lifetime_fraud_detections", 0) + (1 if is_fraud else 0)
            )
            self.data["fraud_detections"] = self.data.get("fraud_detections", 0) + (1 if is_fraud else 0)
            self.data["safe_detections"] = self.data.get("safe_detections", 0) + (0 if is_fraud else 1)

            for bucket_name, key in (("daily", day), ("monthly", month), ("yearly", year)):
                bucket = self.data.setdefault(bucket_name, {}).setdefault(key, _empty_bucket())
                bucket["detections"] = bucket.get("detections", 0) + 1
                bucket[classification] = bucket.get(classification, 0) + 1

            recent = self.data.setdefault("recent_detections", [])
            if not isinstance(recent, list):
                recent = []
                
            recent.insert(
                0,
                {
                    "timestamp": now.isoformat(),
                    "fraud_score": round(fraud_score, 2),
                    "risk_level": risk_level,
                    "classification": classification,
                    "source_type": source_type,
                    "domain_count": len(entities.get("domains", []) if entities else []),
                    "email_count": len(entities.get("emails", []) if entities else []),
                },
            )
            self.data["recent_detections"] = recent[:50]
            self.data["updated_at"] = now.isoformat()
            await self._persist()

    # ------------------------------------------------------------------
    # Public read method
    # ------------------------------------------------------------------

    async def snapshot(self) -> dict:
        async with self.lock:
            return deepcopy(self.data)