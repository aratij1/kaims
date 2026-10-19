"""Exact operator-managed scope for unattended execution; no wildcard grants."""
from typing import Any


def automatic_execution_authorized(settings: Any, *, tenant: str, environment: str, service: str) -> bool:
    parts = (tenant, environment, service)
    if not settings.resolution_auto_execution_enabled or any(not p or '/' in p or '*' in p for p in parts):
        return False
    return '/'.join(parts) in settings.resolution_auto_execution_targets
