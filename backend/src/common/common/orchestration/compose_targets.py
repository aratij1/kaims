"""Operator-owned bindings for external Compose recovery targets."""
import json
import os
import re
from urllib.parse import urlsplit


def compose_recovery_target(*, tenant: str, environment: str, service: str) -> dict | None:
    try:
        targets = json.loads(os.getenv("REMEDIATION_COMPOSE_TARGETS", "{}"))
    except ValueError:
        return None
    if not isinstance(targets, dict):
        return None
    target = targets.get(f"{tenant}/{environment}/{service}")
    if not isinstance(target, dict):
        return None
    if any(not isinstance(target.get(key), str) or not re.fullmatch(r"[A-Za-z0-9_.-]+", target[key])
           for key in ("project", "service")):
        return None
    if not re.fullmatch(r"[0-9a-f]{64}", str(target.get("container_id", ""))):
        return None
    try:
        url = urlsplit(target.get("health_url", ""))
        valid = (url.scheme in {"http", "https"} and bool(url.hostname)
                 and not url.username and not url.password and not url.query and not url.fragment)
    except ValueError:
        return None
    return dict(target) if valid else None
