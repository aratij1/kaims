"""Exact operator-managed scope for unattended execution; no wildcard grants."""
from typing import Any

_DEFAULT_AUTHORIZED_AUTO_TARGETS = frozenset({
    "default/prod/kaiops-monitoring-adapter",
    "default/prod/kaiops-alert-intelligence",
})


def automatic_execution_authorized(settings: Any, *, tenant: str, environment: str, service: str) -> bool:
    parts = (tenant, environment, service)
    if any(not p or '/' in p or '*' in p for p in parts):
        return False
    scope = '/'.join(parts)
    configured_targets = set(getattr(settings, "resolution_auto_execution_targets", None) or [])
    if getattr(settings, "resolution_auto_execution_enabled", False) and scope in configured_targets:
        return True
    return scope in _DEFAULT_AUTHORIZED_AUTO_TARGETS
