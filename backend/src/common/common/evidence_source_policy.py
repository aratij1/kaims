"""Keep alert transport artifacts distinct from operational source evidence."""
from __future__ import annotations

import json
import re
from datetime import datetime
from urllib.parse import unquote


def is_alert_artifact_reference(value: object) -> bool:
    path = unquote(str(value or "")).replace("\\", "/").lower().split("#", 1)[0]
    parts = [part for part in path.split("/") if part]
    return "ingested_alerts" in parts or "landing" in parts


def is_alert_artifact(row: dict) -> bool:
    return any(is_alert_artifact_reference(row.get(key)) for key in (
        "source_uri", "source_reference", "citation", "uri", "path", "url",
    ))


def is_derived_observation(row: dict) -> bool:
    content = row.get("content") if isinstance(row.get("content"), dict) else {}
    for item in (row, content):
        if item.get("derived_observation") is True or item.get("signal_type") == "log_diagnosis":
            return True
        if any(str(item.get(key) or "").lower().startswith("log://diagnosis/")
               for key in ("source_uri", "source_reference", "uri", "citation")):
            return True
    return False


def log_observed_at(line: str) -> str | None:
    """Read an event timestamp; filesystem modification/collection is not one."""
    value = None
    try:
        payload = json.loads(line)
        if isinstance(payload, dict):
            value = next((payload.get(key) for key in ("@timestamp", "timestamp", "time", "observed_at")
                          if isinstance(payload.get(key), str)), None)
    except (ValueError, TypeError):
        pass
    if not value:
        match = re.match(r"^\s*(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2}))", line)
        value = match.group(1) if match else None
    if value:
        try:
            observed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if observed.tzinfo is not None:
                return observed.isoformat()
        except ValueError:
            pass
    return None
