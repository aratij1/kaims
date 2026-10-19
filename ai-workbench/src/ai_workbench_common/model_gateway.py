from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
import json
from typing import Any

import httpx

from common.models import AlertSeverity


@dataclass(slots=True)
class GenerationRequest:
    severity: AlertSeverity
    task: str
    prompt: str
    payload: dict[str, Any]


class ModelGateway(ABC):
    @abstractmethod
    async def generate(self, request: GenerationRequest) -> dict[str, Any]:
        raise NotImplementedError


class MockProvider(ModelGateway):
    async def generate(self, request: GenerationRequest) -> dict[str, Any]:
        return {
            "model": "mock",
            "content": f"mock:{request.task}:{request.prompt}",
            "usage": {
                "provider": "mock",
                "model": "mock",
                "task": request.task,
                "input_tokens": 0,
                "output_tokens": 0,
                "total_tokens": 0,
                "total_cost_usd": 0.0,
                "estimated": False,
            },
        }


class RouterModelGateway(ModelGateway):
    def __init__(self, router: Any) -> None:
        self._router = router

    async def generate(self, request: GenerationRequest) -> dict[str, Any]:
        task_enum = request.task
        model_task = getattr(task_enum, "value", task_enum)
        model_task_obj = None
        if hasattr(self._router, "route"):
            try:
                from model_router import ModelTask

                model_task_obj = ModelTask(model_task)
            except Exception:
                model_task_obj = model_task
            return await self._router.route(
                severity=request.severity,
                task=model_task_obj,
                prompt=request.prompt,
                payload=request.payload,
            )
        raise RuntimeError("Configured model gateway router does not implement route()")


class HttpModelGateway(ModelGateway):
    """Calls the model-router service's POST /route API instead of importing it in-process."""

    def __init__(self, base_url: str, *, timeout_seconds: float = 30.0, max_payload_bytes: int = 48_000) -> None:
        self._base_url = base_url.rstrip("/")
        self._timeout_seconds = timeout_seconds
        self._max_payload_bytes = max(8_000, int(max_payload_bytes))

    @staticmethod
    def _compact_value(value: Any, *, depth: int = 0) -> Any:
        """Bound noisy evidence while retaining the fields needed for grounded reasoning."""
        if depth >= 6:
            return "<nested value omitted>"
        if isinstance(value, str):
            return value if len(value) <= 4_000 else f"{value[:4_000]}\n<trimmed {len(value) - 4_000} chars>"
        if isinstance(value, list):
            items = value[:20]
            compacted = [HttpModelGateway._compact_value(item, depth=depth + 1) for item in items]
            if len(value) > len(items):
                compacted.append({"omitted_items": len(value) - len(items)})
            return compacted
        if isinstance(value, dict):
            return {
                str(key): HttpModelGateway._compact_value(item, depth=depth + 1)
                for key, item in value.items()
                if str(key) not in {"raw", "raw_payload", "projection_payload", "model_calls"}
            }
        return value

    def _compact_payload(self, payload: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
        # Use the same JSON-compatible values for budget accounting and HTTP
        # transport (context includes datetime and UUID objects).
        payload = json.loads(json.dumps(payload, default=str))
        def size(value):
            return len(json.dumps(value, default=str).encode("utf-8"))

        protected_lists = {"evidence_ids", "evidence_used", "supporting_evidence_ids", "contradicting_evidence_ids", "diagnostic_signals"}

        def bounded(value, strings, items, depth=0, key=""):
            if depth > 10:
                return "<nested value omitted>"
            if isinstance(value, str):
                if key in {"evidence_id", "source", "source_type", "category", "connector", "service", "observed_at", "uri", "source_uri"}:
                    return value
                return value if len(value) <= strings else value[:strings] + "<trimmed>"
            if isinstance(value, list):
                values = value if key in protected_lists else value[:items]
                return [bounded(v, strings, items, depth + 1, key) for v in values]
            if isinstance(value, dict):
                return {k: bounded(v, strings, items, depth + 1, k) for k, v in value.items()
                        if k not in {"raw", "raw_payload", "projection_payload", "model_calls"}}
            return value

        original_bytes = size(payload)
        planes = {key: value for key, value in payload.items()
                  if key in {"discovery_evidence", "evidence"} and isinstance(value, list)}
        context = {key: value for key, value in payload.items() if key not in planes}
        evidence_count = sum(len(rows) for rows in planes.values())
        compacted = bounded(context, 4000, 20)
        # Evidence has its own budget. Large hypothesis trees must not truncate
        # every evidence plane to its first 1/3/5 rows before the model sees it.
        for key, rows in planes.items():
            compacted[key] = [bounded(row, 4000, 20) for row in rows]
        if size(compacted) > self._max_payload_bytes:
            context_budget = int(self._max_payload_bytes * (0.35 if evidence_count else 1.0))
            for strings, items in ((2000, 10), (1000, 5), (500, 3), (200, 1), (80, 1)):
                compacted = bounded(context, strings, items)
                if size(compacted) <= context_budget:
                    break
            evidence_base = dict(compacted)
            for strings in (1000, 600, 300, 150, 60):
                compacted = dict(evidence_base)
                for key, rows in planes.items():
                    compacted[key] = [bounded(row, strings, 6) for row in rows]
                if size(compacted) <= self._max_payload_bytes:
                    break
            # If the original set cannot fit even as short attributable facts,
            # retain source diversity, and report the omitted count explicitly.
            if size(compacted) > self._max_payload_bytes and evidence_count:
                buckets = {}
                aliases = {"prometheus": "metric", "telemetry": "metric", "metrics": "metric", "logs": "log", "source_code": "code", "changes": "change"}
                for key in planes:
                    for row in compacted[key]:
                        source = str(row.get("source") or row.get("source_type") or row.get("category") or "unknown") if isinstance(row, dict) else "unknown"
                        buckets.setdefault(aliases.get(source, source), []).append((key, row))
                compacted = dict(evidence_base)
                compacted.update({key: [] for key in planes})
                for index in range(max(map(len, buckets.values()), default=0)):
                    for rows in buckets.values():
                        if index >= len(rows):
                            continue
                        key, row = rows[index]
                        compacted[key].append(row)
                        if size(compacted) > self._max_payload_bytes:
                            compacted[key].pop()
        compacted_bytes = size(compacted)
        if compacted_bytes > self._max_payload_bytes:
            raise ValueError("Model payload exceeds the configured budget after compaction; narrow the investigation scope.")
        sent_count = sum(len(compacted.get(key, [])) for key in planes)
        return compacted, {
            "original_bytes": original_bytes, "sent_bytes": compacted_bytes,
            "trimmed": compacted_bytes < original_bytes, "budget_bytes": self._max_payload_bytes,
            "evidence_available": evidence_count, "evidence_sent": sent_count,
            "evidence_omitted": evidence_count - sent_count,
        }

    async def generate(self, request: GenerationRequest) -> dict[str, Any]:
        severity_value = getattr(request.severity, "value", request.severity)
        task_value = getattr(request.task, "value", request.task)
        payload, payload_budget = self._compact_payload(request.payload)
        async with httpx.AsyncClient(timeout=self._timeout_seconds) as client:
            response = await client.post(
                f"{self._base_url}/route",
                json={
                    "severity": severity_value,
                    "task": task_value,
                    "prompt": request.prompt,
                    "payload": payload,
                },
            )
            response.raise_for_status()
            result = response.json()
            if isinstance(result, dict):
                usage = result.setdefault("usage", {})
                if isinstance(usage, dict):
                    usage["request_payload"] = payload_budget
            return result


class OpenAIProvider(MockProvider):
    pass


class AzureOpenAIProvider(MockProvider):
    pass


class OllamaProvider(MockProvider):
    pass


class ClaudeProvider(MockProvider):
    pass
