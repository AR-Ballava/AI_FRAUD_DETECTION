from __future__ import annotations

import asyncio
import json
from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path


def _empty_bucket() -> dict:
    return {"visitors": 0, "detections": 0, "fraud": 0, "safe": 0}


class AnalyticsStore:
    def __init__(self, path: str) -> None:
        self.path = Path(path)
        self.lock = asyncio.Lock()
        self.data = self._default_data()

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

    async def load(self) -> None:
        if not self.path.exists():
            self.path.parent.mkdir(parents=True, exist_ok=True)
            await self._persist()
            return
        try:
            self.data = json.loads(self.path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            self.data = self._default_data()
            await self._persist()

    async def _persist(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(self.data, indent=2, sort_keys=True)
        await asyncio.to_thread(self.path.write_text, payload, "utf-8")

    def _keys(self, now: datetime) -> tuple[str, str, str]:
        return now.strftime("%Y-%m-%d"), now.strftime("%Y-%m"), now.strftime("%Y")

    async def record_visitor(self) -> None:
        async with self.lock:
            now = datetime.now(UTC)
            day, month, year = self._keys(now)
            self.data["lifetime_visitors"] = self.data.get("lifetime_visitors", 0) + 1
            for bucket_name, key in (("daily", day), ("monthly", month), ("yearly", year)):
                bucket = self.data.setdefault(bucket_name, {}).setdefault(key, _empty_bucket())
                bucket["visitors"] += 1
            self.data["updated_at"] = now.isoformat()
            await self._persist()

    async def record_detection(self, fraud_score: float, risk_level: str, source_type: str, entities: dict) -> None:
        async with self.lock:
            now = datetime.now(UTC)
            day, month, year = self._keys(now)
            is_fraud = fraud_score >= 50
            classification = "fraud" if is_fraud else "safe"

            self.data["lifetime_fraud_detections"] = self.data.get("lifetime_fraud_detections", 0) + (1 if is_fraud else 0)
            self.data["fraud_detections"] = self.data.get("fraud_detections", 0) + (1 if is_fraud else 0)
            self.data["safe_detections"] = self.data.get("safe_detections", 0) + (0 if is_fraud else 1)

            for bucket_name, key in (("daily", day), ("monthly", month), ("yearly", year)):
                bucket = self.data.setdefault(bucket_name, {}).setdefault(key, _empty_bucket())
                bucket["detections"] += 1
                bucket[classification] += 1

            recent = self.data.setdefault("recent_detections", [])
            recent.insert(
                0,
                {
                    "timestamp": now.isoformat(),
                    "fraud_score": round(fraud_score, 2),
                    "risk_level": risk_level,
                    "classification": classification,
                    "source_type": source_type,
                    "domain_count": len(entities.get("domains", [])),
                    "email_count": len(entities.get("emails", [])),
                },
            )
            self.data["recent_detections"] = recent[:50]
            self.data["updated_at"] = now.isoformat()
            await self._persist()

    async def snapshot(self) -> dict:
        async with self.lock:
            return deepcopy(self.data)

