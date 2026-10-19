"""Bounded, host-bound filesystem observations. Writes are not allocation proof."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime
from pathlib import Path


def digest(value: dict) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()


def seal(value: dict) -> dict:
    return {**value, "sha256": digest(value)}


def timestamp(value: str) -> datetime:
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if result.tzinfo is None:
        raise ValueError("timezone required")
    return result


def search_disk_observations(root: Path, arguments: dict, limit: int = 8) -> dict:
    """Only exact registered host/volume/tenant bindings and actual event times count.

    The producer directory is a trusted, read-only host mount. This is a bounded
    metadata search, never a filesystem walk or a remote command endpoint.
    """
    target = arguments.get("target_labels") or {}
    tenant = str(arguments.get("tenant_id") or "")
    required = ("instance", "device", "mountpoint")
    if not tenant or not all(target.get(key) for key in required):
        return {"evidence": [], "provider_status": "target_binding_required"}
    try:
        start, end = timestamp(arguments["start_time"]), timestamp(arguments["end_time"])
        if end <= start:
            raise ValueError("reversed window")
    except (KeyError, ValueError, TypeError):
        return {"evidence": [], "provider_status": "observation_window_required"}
    evidence, rejected, coverage = [], 0, []
    # Producer retention is capped at 120 snapshots; bound reads independently.
    paths = sorted(root.glob("disk-*.json"), reverse=True)[:120]
    for path in paths:
        try:
            if path.is_symlink() or path.stat().st_size > 512_000:
                continue
            payload = json.loads(path.read_text(encoding="utf-8-sig"))
            checksum = payload.pop("sha256", None)
            if checksum != digest(payload) or payload.get("schema") != "kaiops.disk-attribution.v1":
                rejected += 1
                continue
            scope = payload["scope"]
            if scope.get("tenant_id") != tenant or scope.get("environment") != arguments.get("environment"):
                continue
            if any(str(scope.get(key)) != str(target[key]) for key in required):
                continue
            begin, finish = timestamp(payload["window_start"]), timestamp(payload["window_end"])
            # Never relabel present-day observations as historical incident evidence.
            if begin < start or finish > end or finish < begin:
                continue
            coverage.append(payload.get("coverage", {}))
            for index, record in enumerate(payload.get("records", [])[:100]):
                observed = timestamp(record["observed_at"])
                if not begin <= observed <= finish:
                    continue
                reference = f"host-disk://{scope['host_id']}/{path.name}#record={index}&sha256={checksum}"
                evidence.append({**record, "source": "host_disk", "source_type": "log", "source_reference": reference,
                    "uri": reference, "service": str(arguments.get("service") or ""),
                    "resource": scope["host_id"], "scope": scope,
                    "observation_window_start": payload["window_start"],
                    "observation_window_end": payload["window_end"],
                    "coverage": payload.get("coverage", {}), "source_checksum": checksum,
                    "causal_claim": "not_established",
                    "message": "Filesystem observation; causal mechanism not established. " + json.dumps(
                        {"observation": record, "coverage": payload.get("coverage", {})}, ensure_ascii=False)[:7900]})
                if len(evidence) >= min(max(limit, 1), 20):
                    return {"evidence": evidence, "provider_status": "completed", "rejected": rejected,
                            "coverage": coverage}
        except (ValueError, KeyError, TypeError, OSError):
            rejected += 1
    return {"evidence": evidence, "provider_status": "completed" if evidence else "no_matching_history",
            "rejected": rejected, "coverage": coverage}
