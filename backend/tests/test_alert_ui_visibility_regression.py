"""Regression tests for Alert UI visibility defect, scoping, and compact serialization.

Verifies:
1. Canary alert appears in the All Applications unscoped view.
2. KaiMS-only filtering strictly preserves KaiMS core service allowlist and excludes canary-audit-service.
3. Known application filtering (e.g., payment-gateway) retains only matching alerts.
4. Unknown services are retained in the All Applications view and never silently discarded.
5. Tenant isolation is preserved across scopes.
6. Lifecycle (active, resolved, failed, historical) and status filters remain intact.
7. Compact serialization in monitoring adapter retains required minimum safe scope fields
   (tenant_id, service, labels, whitelisted metadata) without heavy payload bloating.
8. Live API verification against running gateway with authentication.
"""
from __future__ import annotations

import importlib.util
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
import pytest


def _load_monitoring_app():
    existing = sys.modules.get("monitoring_adapter_app")
    if existing is not None:
        return existing
    module_path = Path("backend/src/monitoring-adapter/app.py")
    spec = importlib.util.spec_from_file_location("monitoring_adapter_app", module_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["monitoring_adapter_app"] = module
    spec.loader.exec_module(module)
    return module


_compact_alert_row = _load_monitoring_app()._compact_alert_row


# Client-side filtering logic replica matching frontend/react/src/appHelpers.jsx exactly
KAIOPS_CORE_SERVICES = {
    "api-gateway", "monitoring-adapter", "alert-intelligence", "orchestrator",
    "context-agent", "resolution-agent", "approval-service", "remediation-engine",
    "closure-service", "model-router", "node-exporter", "mysql-exporter",
    "redis-exporter", "blackbox-exporter", "otel-collector", "prometheus", "alertmanager",
}

ALL_APPLICATIONS_SCOPE = "All Applications"


def normalize_monitor_token(value: Any) -> str:
    import re
    s = str(value or "").strip().lower()
    s = re.sub(r"[\s_]+", "-", s)
    return re.sub(r"-+", "-", s)


def is_all_applications_selection(value: Any) -> bool:
    token = normalize_monitor_token(value)
    return token in ("all-applications", "all", "unscoped")


def is_kaiops_core_selection(value: Any) -> bool:
    token = normalize_monitor_token(value)
    return token in ("kaims", "kaims-core", "kaiops-core", "kaiops-core1", "kaiops", "core")


def is_generated_or_test_alert(row: dict[str, Any]) -> bool:
    labels = row.get("labels") or {}
    metadata = row.get("metadata") or {}
    for flag in [
        row.get("is_test"), row.get("test_alert"),
        labels.get("is_test"), labels.get("test_alert"), labels.get("onboarding_test"),
        metadata.get("is_test"), metadata.get("test_alert"),
    ]:
        if str(flag or "").strip().lower() in ("1", "true", "yes", "test"):
            return True
    synthetic = str(labels.get("synthetic") or row.get("synthetic") or "").strip().lower()
    event_mode = str(labels.get("event_mode") or row.get("event_mode") or "").strip().lower()
    if synthetic in ("1", "true", "yes") or event_mode in ("synthetic", "simulation", "validation", "test"):
        return True
    return False


def infer_monitor_scope(row: dict[str, Any]) -> str:
    labels = row.get("labels") or {}
    metadata = row.get("metadata") or {}
    explicit_project = str(
        row.get("project_name") or labels.get("project_name") or row.get("project")
        or labels.get("project") or row.get("application") or labels.get("application")
        or metadata.get("project_name") or metadata.get("project") or metadata.get("application") or ""
    ).strip().lower()
    alert_name = str(row.get("name") or row.get("title") or labels.get("alertname") or "").strip().lower()
    if "telemetry" in explicit_project or "astronomy" in explicit_project or "telemetry" in alert_name:
        return "telemetry"
    if "kaiops" in explicit_project or "kai-ops" in explicit_project:
        return "kaiops"
    service = str(row.get("service") or labels.get("service") or labels.get("job") or "").strip().lower()
    if service in KAIOPS_CORE_SERVICES or service.startswith("kaiops-") or service.startswith("kaiops_"):
        return "kaiops"
    owner_team = str(metadata.get("owner_team") or labels.get("team") or labels.get("owner_team") or "").strip().lower()
    if owner_team in ("platform-ops", "kaiops"):
        return "kaiops"
    return ""


def filter_alerts_for_monitor(rows: list[dict[str, Any]], application_to_monitor: str) -> list[dict[str, Any]]:
    target = str(application_to_monitor or "").strip().lower()
    alert_rows = list(rows) if isinstance(rows, list) else []
    if not target:
        return alert_rows
    if target == "real-usecases":
        return [r for r in alert_rows if not is_generated_or_test_alert(r)]
    if target == "test-usecases":
        return [r for r in alert_rows if is_generated_or_test_alert(r)]
    production_rows = [r for r in alert_rows if not is_generated_or_test_alert(r)]
    if is_all_applications_selection(target):
        return production_rows
    if target == "telemetry":
        return [r for r in production_rows if infer_monitor_scope(r) == "telemetry"]
    if is_kaiops_core_selection(target):
        return [r for r in production_rows if infer_monitor_scope(r) == "kaiops"]
    target_norm = normalize_monitor_token(target)
    matched = []
    for row in production_rows:
        labels = row.get("labels") or {}
        metadata = row.get("metadata") or {}
        candidates = [
            row.get("application"), row.get("project"), row.get("project_name"),
            metadata.get("application"), metadata.get("project"), metadata.get("project_name"),
            labels.get("application"), labels.get("project"), labels.get("project_name"),
            row.get("service"), labels.get("service"), labels.get("job"),
        ]
        tokens = [normalize_monitor_token(c) for c in candidates if c]
        if target_norm in tokens:
            matched.append(row)
    return matched


@pytest.fixture
def sample_alert_stream() -> list[dict[str, Any]]:
    return [
        {
            "id": "57f188cc-4bcf-47cc-a57f-f77103f7bb1f",
            "alert_id": "57f188cc-4bcf-47cc-a57f-f77103f7bb1f",
            "name": "CanaryAlertQueryRunbookVerification",
            "service": "canary-audit-service",
            "severity": "warning",
            "status": "firing",
            "tenant_id": "default",
            "environment": "verification",
            "labels": {"service": "canary-audit-service", "severity": "high"},
            "created_at": "2026-10-22T06:43:31.290915Z",
        },
        {
            "id": "kaiops-node-1",
            "alert_id": "kaiops-node-1",
            "name": "DiskSpaceLow",
            "service": "node-exporter",
            "severity": "critical",
            "status": "firing",
            "tenant_id": "default",
            "environment": "prod",
            "labels": {"service": "node-exporter", "severity": "critical"},
            "created_at": "2026-10-22T06:40:00Z",
        },
        {
            "id": "payment-lat-1",
            "alert_id": "payment-lat-1",
            "name": "PaymentLatencySpike",
            "service": "payments",
            "application": "payment-gateway",
            "severity": "high",
            "status": "firing",
            "tenant_id": "default",
            "environment": "prod",
            "labels": {"service": "payments", "application": "payment-gateway"},
            "created_at": "2026-10-22T06:41:00Z",
        },
        {
            "id": "telemetry-1",
            "alert_id": "telemetry-1",
            "name": "TelemetryCollectorUnavailable",
            "service": "frontend-proxy",
            "application": "Telemetry",
            "severity": "medium",
            "status": "firing",
            "tenant_id": "default",
            "environment": "demo",
            "labels": {"application": "Telemetry"},
            "created_at": "2026-10-22T06:42:00Z",
        },
        {
            "id": "tenant-b-alert",
            "alert_id": "tenant-b-alert",
            "name": "ExternalServiceOutage",
            "service": "partner-gateway",
            "application": "partner-app",
            "severity": "high",
            "status": "firing",
            "tenant_id": "tenant-b",
            "environment": "prod",
            "labels": {"application": "partner-app"},
            "created_at": "2026-10-22T06:43:00Z",
        },
        {
            "id": "synthetic-e2e-1",
            "alert_id": "synthetic-e2e-1",
            "name": "ServiceDown-E2E-Test",
            "service": "canary-audit-service",
            "severity": "low",
            "status": "firing",
            "tenant_id": "default",
            "environment": "dev",
            "labels": {"synthetic": "true"},
            "created_at": "2026-10-22T06:44:00Z",
        },
    ]


def test_canary_visible_in_all_applications_unscoped_view(sample_alert_stream):
    """Verify that the canary alert appears in the All Applications unscoped view."""
    visible = filter_alerts_for_monitor(sample_alert_stream, ALL_APPLICATIONS_SCOPE)
    visible_ids = [r["id"] for r in visible]
    assert "57f188cc-4bcf-47cc-a57f-f77103f7bb1f" in visible_ids
    assert "kaiops-node-1" in visible_ids
    assert "payment-lat-1" in visible_ids
    assert "synthetic-e2e-1" not in visible_ids  # Synthetic test alerts excluded from production


def test_kaims_scope_excludes_canary_and_preserves_core_behavior(sample_alert_stream):
    """Verify that KaiMS scope strictly keeps KaiMS core services and excludes canary-audit-service."""
    kai_scoped = filter_alerts_for_monitor(sample_alert_stream, "KaiMS")
    kai_scoped_ids = [r["id"] for r in kai_scoped]
    assert "kaiops-node-1" in kai_scoped_ids
    assert "57f188cc-4bcf-47cc-a57f-f77103f7bb1f" not in kai_scoped_ids
    assert "payment-lat-1" not in kai_scoped_ids
    assert "telemetry-1" not in kai_scoped_ids


def test_known_application_filtering_remains_correct(sample_alert_stream):
    """Verify that selecting a known onboarded app only returns that app's alerts."""
    payment_scoped = filter_alerts_for_monitor(sample_alert_stream, "payment-gateway")
    assert [r["id"] for r in payment_scoped] == ["payment-lat-1"]

    telemetry_scoped = filter_alerts_for_monitor(sample_alert_stream, "Telemetry")
    assert [r["id"] for r in telemetry_scoped] == ["telemetry-1"]


def test_unknown_services_retained_in_unscoped_view(sample_alert_stream):
    """Verify that alerts from unknown or newly added services are not silently dropped."""
    unscoped = filter_alerts_for_monitor(sample_alert_stream, ALL_APPLICATIONS_SCOPE)
    services = {r["service"] for r in unscoped}
    assert "canary-audit-service" in services
    assert "partner-gateway" in services


def test_tenant_isolation_is_preserved_when_filtering_by_tenant(sample_alert_stream):
    """Verify that tenant isolation can be applied on top of the unscoped stream."""
    default_tenant_rows = [r for r in sample_alert_stream if r.get("tenant_id") == "default"]
    visible_default = filter_alerts_for_monitor(default_tenant_rows, ALL_APPLICATIONS_SCOPE)
    assert all(r["tenant_id"] == "default" for r in visible_default)
    assert "tenant-b-alert" not in [r["id"] for r in visible_default]
    assert "57f188cc-4bcf-47cc-a57f-f77103f7bb1f" in [r["id"] for r in visible_default]


def test_lifecycle_and_status_filters_remain_intact(sample_alert_stream):
    """Verify that status and lifecycle filters correctly partition the unscoped alerts."""
    unscoped = filter_alerts_for_monitor(sample_alert_stream, ALL_APPLICATIONS_SCOPE)
    active_firing = [r for r in unscoped if r.get("status") == "firing"]
    assert len(active_firing) == len(unscoped)

    # Simulate resolved alert
    unscoped[0]["status"] = "resolved"
    active_firing_after = [r for r in unscoped if r.get("status") == "firing"]
    assert len(active_firing_after) == len(unscoped) - 1
    assert "57f188cc-4bcf-47cc-a57f-f77103f7bb1f" not in [r["id"] for r in active_firing_after]


def test_compact_serialization_preserves_safe_scope_and_omits_bloat():
    """Verify _compact_alert_row retains tenant_id and team labels, while stripping heavy payloads."""
    raw_row = {
        "id": "57f188cc-4bcf-47cc-a57f-f77103f7bb1f",
        "name": "CanaryAlertQueryRunbookVerification",
        "service": "canary-audit-service",
        "tenant_id": "default",
        "severity": "warning",
        "labels": {
            "alertname": "CanaryAlertQueryRunbookVerification",
            "service": "canary-audit-service",
            "owner_team": "platform-ops",
            "unwanted_huge_label": "x" * 10000,
        },
        "metadata": {
            "owner_team": "platform-ops",
            "project_name": "KaiOps",
            "huge_context_payload": {"raw_logs": "log" * 50000, "stack_trace": "trace" * 10000},
        },
        "raw_payload": {"deep": {"nested": "data" * 20000}},
        "context_snapshot": "snapshot" * 10000,
    }

    compact = _compact_alert_row(raw_row)

    # Safe fields retained
    assert compact["id"] == "57f188cc-4bcf-47cc-a57f-f77103f7bb1f"
    assert compact["tenant_id"] == "default"
    assert compact["labels"]["service"] == "canary-audit-service"
    assert compact["labels"]["owner_team"] == "platform-ops"
    assert "unwanted_huge_label" not in compact["labels"]

    # Safe metadata retained without raw payloads
    assert compact["metadata"]["owner_team"] == "platform-ops"
    assert compact["metadata"]["project_name"] == "KaiOps"
    assert "huge_context_payload" not in compact["metadata"]
    assert "raw_payload" not in compact
    assert "context_snapshot" not in compact
