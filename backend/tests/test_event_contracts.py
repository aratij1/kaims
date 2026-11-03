from __future__ import annotations

import importlib.util
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest
from common.event_publishers import build_event_envelope
from common.models import (
    Alert,
    AlertSeverity,
    Approval,
    ApprovalDecision,
    Incident,
    Recommendation,
    RemediationAction,
    ResolutionReport,
)
from orchestrator.message_bus import publish_orchestration_event
from context_agent import ContextIntelligenceAgent

_CONTEXT_APP_PATH = Path(__file__).resolve().parents[2] / "ai-workbench" / "src" / "context-agent" / "app.py"
_CONTEXT_SPEC = importlib.util.spec_from_file_location("context_agent_app", _CONTEXT_APP_PATH)
assert _CONTEXT_SPEC is not None and _CONTEXT_SPEC.loader is not None
context_agent_app = importlib.util.module_from_spec(_CONTEXT_SPEC)
_CONTEXT_SPEC.loader.exec_module(context_agent_app)

_RESOLUTION_APP_PATH = Path(__file__).resolve().parents[2] / "ai-workbench" / "src" / "resolution-agent" / "app.py"
_RESOLUTION_SPEC = importlib.util.spec_from_file_location("resolution_agent_app", _RESOLUTION_APP_PATH)
assert _RESOLUTION_SPEC is not None and _RESOLUTION_SPEC.loader is not None
resolution_agent_app = importlib.util.module_from_spec(_RESOLUTION_SPEC)
_RESOLUTION_SPEC.loader.exec_module(resolution_agent_app)


def test_resolution_snapshot_expiry_normalizes_naive_database_datetime() -> None:
    normalized = resolution_agent_app._utc_aware(datetime(2026, 8, 27, 12, 0, 0))
    assert normalized.tzinfo is UTC
    assert normalized == datetime(2026, 8, 27, 12, 0, 0, tzinfo=UTC)


@pytest.mark.asyncio
async def test_inconclusive_investigation_preserves_diagnostic_evidence_handoff(monkeypatch) -> None:
    alert = Alert(
        tenant_id="tenant-a",
        source="prometheus",
        name="ApiLatencyHigh",
        service="api-gateway",
        severity=AlertSeverity.CRITICAL,
        description="p99 latency is above threshold",
    )
    incident = Incident(
        tenant_id="tenant-a",
        service=alert.service,
        severity=alert.severity,
        title=alert.name,
    )
    context = await ContextIntelligenceAgent().collect(alert, incident)
    context = context.model_copy(update={
        "metadata": {
            **context.metadata,
            "analysis_request_id": "11111111-1111-4111-8111-111111111111",
            "force_full_analysis": True,
        },
    })
    report = {
        "investigation_id": "investigation-1",
        "status": "budget_exhausted",
        "stop_reason": "evidence_budget_exhausted",
        "conclusive": False,
        "missing_sources": [],
        "next_evidence": [],
        "conclusion": {
            "hypothesis_id": "hypothesis-1",
            "confidence": 0.58,
            "evidence_ids": ["EV-1", "UNKNOWN"],
        },
        "hypotheses": [{"hypothesis_id": "hypothesis-1", "claim": "A latency mechanism is under test."}],
        "evidence": [{"evidence_id": "EV-1", "source_type": "telemetry"}],
    }

    async def fake_investigate(_context, *, persist=None):
        return report

    async def fake_resolve(_context):
        return Recommendation(
            tenant_id=_context.tenant_id,
            incident_id=_context.incident_id,
            root_cause="Ungrounded model result",
            confidence=0.12,
            impact="Latency observed",
            recommended_action="Collect missing application sources",
            severity=_context.alert.severity,
            rationale="No citations",
            commands=[],
            risk="high",
            metadata={"rca_analysis": {"evidence_used": [], "confidence_score": 0.12}},
        )

    monkeypatch.setattr(resolution_agent_app.investigator, "investigate", fake_investigate)
    monkeypatch.setattr(resolution_agent_app.agent, "resolve_with_runtime", fake_resolve)

    recommendation = await resolution_agent_app._resolve_context(context)
    analysis = recommendation.metadata["rca_analysis"]

    assert recommendation.confidence == analysis["confidence_score"] == 0.58
    assert analysis["evidence_used"] == ["EV-1"]
    assert analysis["supporting_signals"] == [
        "The diagnostic candidate references telemetry evidence EV-1."
    ]
    assert recommendation.metadata["confidence_kind"] == "leading_hypothesis"
    assert recommendation.metadata["confidence_actionable"] is False
    assert recommendation.recommended_action == "Inspect system telemetry and logs to validate hypothesis."

_APPROVAL_APP_PATH = Path(__file__).resolve().parents[1] / "src" / "approval-service" / "app.py"
_APPROVAL_SPEC = importlib.util.spec_from_file_location("approval_service_app", _APPROVAL_APP_PATH)
assert _APPROVAL_SPEC is not None and _APPROVAL_SPEC.loader is not None
approval_service_app = importlib.util.module_from_spec(_APPROVAL_SPEC)
_APPROVAL_SPEC.loader.exec_module(approval_service_app)

_REMEDIATION_APP_PATH = Path(__file__).resolve().parents[1] / "src" / "remediation-engine" / "app.py"
_REMEDIATION_SPEC = importlib.util.spec_from_file_location("remediation_engine_app", _REMEDIATION_APP_PATH)
assert _REMEDIATION_SPEC is not None and _REMEDIATION_SPEC.loader is not None
remediation_engine_app = importlib.util.module_from_spec(_REMEDIATION_SPEC)
_REMEDIATION_SPEC.loader.exec_module(remediation_engine_app)

_CLOSURE_APP_PATH = Path(__file__).resolve().parents[1] / "src" / "closure-service" / "app.py"
_CLOSURE_SPEC = importlib.util.spec_from_file_location("closure_service_app", _CLOSURE_APP_PATH)
assert _CLOSURE_SPEC is not None and _CLOSURE_SPEC.loader is not None
closure_service_app = importlib.util.module_from_spec(_CLOSURE_SPEC)
_CLOSURE_SPEC.loader.exec_module(closure_service_app)

_MONITORING_APP_PATH = Path(__file__).resolve().parents[1] / "src" / "monitoring-adapter" / "app.py"
_MONITORING_SPEC = importlib.util.spec_from_file_location("monitoring_adapter_app", _MONITORING_APP_PATH)
assert _MONITORING_SPEC is not None and _MONITORING_SPEC.loader is not None
monitoring_adapter_app = importlib.util.module_from_spec(_MONITORING_SPEC)
_MONITORING_SPEC.loader.exec_module(monitoring_adapter_app)


def test_telemetry_project_resolution_never_defaults_to_transport_or_kaiops() -> None:
    assert monitoring_adapter_app._resolve_telemetry_project({"labels": {}}) == "unassigned"
    assert monitoring_adapter_app._resolve_telemetry_project({
        "labels": {"project": "telemetry-project", "application": "wrong-fallback"},
    }) == "telemetry-project"


def test_inconclusive_diagnostic_recommendation_cannot_await_approval() -> None:
    metadata = {
        "iterative_investigation": {"conclusive": False},
        "rca_analysis": {"evidence_used": []},
        "rca_status": "insufficient_evidence",
        "execution_plan": {"execution_ready": False, "mutating": False},
        "resolution_lifecycle": {"state": "awaiting_approval"},
    }
    assert resolution_agent_app._resolution_projection_status(metadata, requires_approval=True) == "investigating"


def test_only_grounded_executable_recommendation_can_await_approval() -> None:
    metadata = {
        "iterative_investigation": {"conclusive": True},
        "rca_analysis": {"evidence_used": ["metric:checkout:5xx"]},
        "rca_status": "grounded",
        "execution_plan": {"execution_ready": True, "mutating": True},
        "resolution_lifecycle": {"state": "awaiting_approval"},
    }
    assert resolution_agent_app._resolution_projection_status(metadata, requires_approval=True) == "awaiting_approval"


def test_grounded_conclusive_recommendation_with_no_ready_plan_is_rca_ready() -> None:
    """Real, live-reproduced gap: incident_projections.status (what the main
    incident board, detail view, and inbox feed all actually read via
    monitoring-adapter's list_incident_projections/list_unified_inbox) fell
    all the way through to "investigating" for a genuinely grounded,
    conclusive RCA whenever no ready-to-execute mutating plan existed yet --
    making a completed RCA indistinguishable from one that was never looked
    at. Confirmed live on 5 real incidents whose SEPARATE incidents.status
    field had already correctly advanced to "rca_ready"
    (_advance_incident_status_on_grounded_rca), while
    incident_projections.status stayed stuck at "investigating"."""
    metadata = {
        "iterative_investigation": {"conclusive": True},
        "rca_analysis": {"evidence_used": ["trace:api-gateway:latency"]},
        "rca_status": "grounded",
        "execution_plan": {"execution_ready": False, "mutating": False},
        "resolution_lifecycle": {"state": "awaiting_approval"},
    }
    assert resolution_agent_app._resolution_projection_status(metadata, requires_approval=True) == "rca_ready"


def test_conclusive_but_not_grounded_recommendation_stays_investigating() -> None:
    """iterative_investigation.conclusive alone is not sufficient -- see the
    "investigation_report vs iterative_investigation" field-name bug fixed
    earlier: the RCA must also be genuinely grounded in accepted evidence."""
    metadata = {
        "iterative_investigation": {"conclusive": True},
        "rca_analysis": {"evidence_used": ["trace:api-gateway:latency"]},
        "rca_status": "insufficient_evidence",
        "execution_plan": {"execution_ready": False, "mutating": False},
        "resolution_lifecycle": {"state": "awaiting_approval"},
    }
    assert resolution_agent_app._resolution_projection_status(metadata, requires_approval=True) == "investigating"


def test_grounded_conclusive_recommendation_ready_to_execute_stays_approved() -> None:
    """The new "rca_ready" branch must not shadow the existing, more
    advanced "approved" outcome once a plan really is ready to execute."""
    metadata = {
        "iterative_investigation": {"conclusive": True},
        "rca_analysis": {"evidence_used": ["trace:api-gateway:latency"]},
        "rca_status": "grounded",
        "execution_plan": {"execution_ready": True, "mutating": True},
        "resolution_lifecycle": {"state": "ready_to_execute"},
    }
    assert resolution_agent_app._resolution_projection_status(metadata, requires_approval=False) == "approved"

_API_GATEWAY_APP_PATH = Path(__file__).resolve().parents[1] / "src" / "api-gateway" / "app.py"
_API_GATEWAY_SPEC = importlib.util.spec_from_file_location("api_gateway_app", _API_GATEWAY_APP_PATH)
assert _API_GATEWAY_SPEC is not None and _API_GATEWAY_SPEC.loader is not None
api_gateway_app = importlib.util.module_from_spec(_API_GATEWAY_SPEC)
sys.modules[_API_GATEWAY_SPEC.name] = api_gateway_app
_API_GATEWAY_SPEC.loader.exec_module(api_gateway_app)


def test_build_event_envelope_exposes_contract_friendly_fields() -> None:
    envelope = build_event_envelope(
        event_type="incident.workflow.selected",
        identity={"incident_id": "inc-1", "trace_id": "tr-1"},
        scope={"tenant_id": "tenant-a", "flow_id": "flow-1", "agent": "orchestrator"},
        state={"status": "investigating"},
        policy={"risk_tier": "high"},
        transport={"provider": "rabbitmq"},
        payload={"workflow": "critical-auto-remediation"},
        ai={"confidence": 0.87},
    )

    assert envelope["incident_id"] == "inc-1"
    assert envelope["trace_id"] == "tr-1"
    assert envelope["flow_id"] == "flow-1"
    assert envelope["agent"] == "orchestrator"
    assert envelope["confidence"] == 0.87


class FakePublisher:
    def __init__(self) -> None:
        self.calls: list[dict] = []

    async def publish(self, topic: str, payload: dict, key: str | None = None) -> None:
        self.calls.append({"topic": topic, "payload": payload, "key": key})


def test_incident_contract_accepts_persisted_jira_enrichment() -> None:
    incident = Incident.model_validate(
        {
            "service": "checkout",
            "title": "Checkout unavailable",
            "jira_key": "KAN-1576",
            "jira_url": "https://example.atlassian.net/browse/KAN-1576",
            "jira_link": "https://example.atlassian.net/browse/KAN-1576",
            "jira_status": "In Progress",
        }
    )

    assert incident.jira_key == "KAN-1576"
    assert incident.jira_status == "In Progress"


def test_context_agent_hydrates_incident_from_enriched_projection() -> None:
    incident = context_agent_app._incident_from_workflow_payload(
        {
            "service": "checkout",
            "title": "Checkout unavailable",
            "status": "failed",
            "state": "failed",
            "approval_status": "failed",
            "approval": {"id": "approval-1", "authorization_scope": "execution"},
        }
    )

    assert incident.service == "checkout"
    assert incident.status.value == "failed"
    assert not hasattr(incident, "approval_status")


@pytest.mark.asyncio
async def test_publish_orchestration_event_emits_event_contract() -> None:
    alert = Alert(
        tenant_id="tenant-a",
        source="prometheus",
        name="PaymentsLatencyHigh",
        service="payments",
        severity=AlertSeverity.CRITICAL,
        description="latency increased",
    )
    incident = Incident(tenant_id="tenant-a", service="payments", severity=AlertSeverity.CRITICAL, title="payments latency")
    decision = {
        "workflow": "critical-auto-remediation",
        "next_action": "collect-context",
        "policy_version": "policy-v1",
        "policy_reason": "critical severity",
        "message_bus_provider": "rabbitmq",
        "execution_mode": "human-approval",
        "risk_tier": "high",
        "planner_reason": "deterministic",
    }

    publisher = FakePublisher()
    provider_used = await publish_orchestration_event(
        producer=publisher,
        publishers={"rabbitmq": publisher},
        topic="orchestration-events",
        alert=alert,
        incident=incident,
        decision=decision,
    )

    assert provider_used == "rabbitmq"
    assert len(publisher.calls) == 1
    payload = publisher.calls[0]["payload"]
    assert "event_envelope" in payload
    assert "event_contract" in payload
    assert payload["event_contract"]["version"] == "v1"
    assert payload["event_contract"]["agent"] == "orchestrator"
    assert payload["event_contract"]["incident_id"] == str(incident.id)


@pytest.mark.asyncio
async def test_context_event_payload_includes_event_contract() -> None:
    alert = Alert(
        tenant_id="tenant-a",
        source="prometheus",
        name="PaymentsLatencyHigh",
        service="payments",
        severity=AlertSeverity.CRITICAL,
        description="latency increased",
    )
    incident = Incident(tenant_id="tenant-a", service="payments", severity=AlertSeverity.CRITICAL, title="payments latency")
    context = await ContextIntelligenceAgent().collect(alert, incident)

    payload = context_agent_app._build_context_event_payload(
        alert=alert,
        incident=incident,
        context=context,
        decision={"workflow": "critical-auto-remediation", "requires_approval": True},
        provider_used="rabbitmq",
    )

    assert "event_contract" in payload
    assert payload["event_contract"]["agent"] == "context-agent"
    assert payload["event_contract"]["incident_id"] == str(incident.id)


@pytest.mark.asyncio
async def test_analysis_request_identity_flows_from_context_to_recommendation() -> None:
    alert = Alert(
        tenant_id="tenant-a",
        source="prometheus",
        name="PaymentsLatencyHigh",
        service="payments",
        severity=AlertSeverity.CRITICAL,
        description="latency increased",
    )
    incident = Incident(
        tenant_id="tenant-a",
        service="payments",
        severity=AlertSeverity.CRITICAL,
        title="payments latency",
    )
    context = await ContextIntelligenceAgent().collect(alert, incident)
    first_request_id = "11111111-1111-4111-8111-111111111111"
    second_request_id = "22222222-2222-4222-8222-222222222222"
    first = context_agent_app._attach_analysis_request_metadata(
        context,
        decision={"analysis_request_id": first_request_id, "analysis_mode": "fresh", "force_full_analysis": True},
    )
    second = context_agent_app._attach_analysis_request_metadata(
        context,
        decision={"analysis_request_id": second_request_id, "analysis_mode": "fresh", "force_full_analysis": True},
    )

    first_payload = context_agent_app._build_context_event_payload(
        alert=alert,
        incident=incident,
        context=first,
        decision={},
        provider_used="rabbitmq",
    )
    second_payload = context_agent_app._build_context_event_payload(
        alert=alert,
        incident=incident,
        context=second,
        decision={},
        provider_used="rabbitmq",
    )

    assert first.metadata["force_full_analysis"] is True
    assert first_payload["event_contract"]["event_id"].endswith(first_request_id)
    assert second_payload["event_contract"]["event_id"].endswith(second_request_id)
    assert (
        resolution_agent_app._deterministic_recommendation_id(first)
        != resolution_agent_app._deterministic_recommendation_id(second)
    )

    snapshot_id = "55555555-5555-4555-8555-555555555555"
    first = first.model_copy(update={"metadata": {**first.metadata, "context_snapshot_id": snapshot_id}})
    recommendation = Recommendation(
        id=resolution_agent_app._deterministic_recommendation_id(first),
        tenant_id=first.tenant_id, incident_id=first.incident_id,
        root_cause="Insufficient evidence", confidence=0.2, impact="Unknown",
        recommended_action="Collect evidence", severity=first.alert.severity,
        rationale="Evidence is incomplete", commands=[], risk="low",
        metadata={"rca_analysis": {"evidence_used": first.metadata.get("evidence_ids", [])[:1]}},
    )
    resolution_agent_app._attach_rca_governance_binding(recommendation, first)
    assert recommendation.metadata["analysis_request_id"] == first_request_id
    assert recommendation.metadata["context_snapshot_id"] == snapshot_id
    assert recommendation.metadata["context_fingerprint"] == first.metadata["context_fingerprint"]
    assert recommendation.metadata["rca_version"] == 1
    assert recommendation.metadata["recommendation_version"] == str(recommendation.id)
    assert recommendation.metadata["evidence_ids"] == sorted(first.metadata.get("evidence_ids", [])[:1])
    assert recommendation.metadata["evidence_set_digest"].startswith("sha256:")
    assert recommendation.metadata["model_version"] == "deterministic-fallback-v1"
    assert recommendation.metadata["prompt_version"] == "resolution-graph-v2"
    assert recommendation.metadata["generated_at"] == recommendation.created_at.isoformat()
    plan = resolution_agent_app._apply_catalog_plan(recommendation, first)
    assert plan["rca_version"] == 1


@pytest.mark.asyncio
async def test_resolution_event_payload_includes_event_contract() -> None:
    alert = Alert(
        tenant_id="tenant-a",
        source="prometheus",
        name="PaymentsLatencyHigh",
        service="payments",
        severity=AlertSeverity.CRITICAL,
        description="latency increased",
    )
    incident = Incident(tenant_id="tenant-a", service="payments", severity=AlertSeverity.CRITICAL, title="payments latency")
    context = await ContextIntelligenceAgent().collect(alert, incident)
    recommendation = Recommendation(
        tenant_id=context.tenant_id,
        incident_id=context.incident_id,
        root_cause="Deployment 2.5",
        confidence=0.91,
        impact="Payments latency",
        recommended_action="Rollback deployment",
        severity=context.alert.severity,
        rationale="Deployment correlation and runbook guidance",
        commands=["rollback:payments-api"],
        risk="high",
        metadata={
            "reasoning": "Deployment timeline overlaps alert onset",
            "citations": ["runbook://payments", "incident://history"],
            "evidence_ids": ["ev-1", "ev-2"],
        },
    )

    payload = resolution_agent_app._build_resolution_event_payload(
        context=context,
        incident=incident,
        recommendation=recommendation,
        decision_payload={"workflow": "critical-auto-remediation"},
    )

    assert "event_contract" in payload
    assert payload["event_contract"]["agent"] == "resolution-agent"
    assert payload["event_contract"]["incident_id"] == str(incident.id)


def test_approval_event_payload_includes_event_contract() -> None:
    approval = Approval(
        incident_id="11111111-1111-1111-1111-111111111111",
        recommendation_id="22222222-2222-2222-2222-222222222222",
        tenant_id="tenant-a",
        decision=ApprovalDecision.APPROVED,
        approver="alice",
        channel="web",
        comment="approved",
    )
    approval_service_app.PENDING_INCIDENTS[str(approval.incident_id)] = {
        "recommendation": {"id": str(approval.recommendation_id)},
        "decision": {"flow_id": "flow-approval-1"},
    }

    payload = approval_service_app._build_approval_event_payload(approval)

    assert "approval" in payload
    assert "event_contract" in payload
    assert payload["event_contract"]["agent"] == "approval-service"
    assert payload["event_contract"]["incident_id"] == str(approval.incident_id)


def test_remediation_payload_builder_and_approval_extractor_compatibility() -> None:
    approval_payload = {
        "approval": {
            "incident_id": "11111111-1111-1111-1111-111111111111",
            "recommendation_id": "22222222-2222-2222-2222-222222222222",
            "decision": "approved",
            "approver": "alice",
            "channel": "web",
        }
    }
    extracted = remediation_engine_app._extract_approval_payload(approval_payload)
    assert extracted["incident_id"] == "11111111-1111-1111-1111-111111111111"

    action = RemediationAction(
        tenant_id="tenant-a",
        incident_id="11111111-1111-1111-1111-111111111111",
        action_type="restart_pod",
        target="payments",
        output="ok",
    )
    payload = remediation_engine_app._build_remediation_event_payload(
        action=action,
        source_payload={"decision": {"flow_id": "flow-remediation-1"}},
        source="approval-events",
    )

    assert "remediation_action" in payload
    assert "event_contract" in payload
    assert payload["event_contract"]["agent"] == "remediation-engine"
    assert payload["event_contract"]["incident_id"] == str(action.incident_id)
    assert payload["event_contract"]["event_id"] == f"remediation:{action.id}:{action.status.value}"


def test_closure_payload_builder_and_action_extractor_compatibility() -> None:
    raw = {
        "remediation_action": {
            "tenant_id": "tenant-a",
            "incident_id": "11111111-1111-1111-1111-111111111111",
            "action_type": "restart_pod",
            "target": "payments",
            "status": "succeeded",
            "output": "ok",
        }
    }
    extracted = closure_service_app._extract_remediation_action_payload(raw)
    assert extracted["action_type"] == "restart_pod"

    action = RemediationAction.model_validate(extracted)
    report = ResolutionReport(
        tenant_id=action.tenant_id,
        incident_id=action.incident_id,
        root_cause="Deployment regression",
        impact="Payment latency",
        action_taken="restart_pod",
        health_restored=True,
        alerts_cleared=True,
        knowledge_base_entry="kb://entry",
    )
    payload = closure_service_app._build_closure_event_payload(
        action=action,
        report=report,
        source_payload={"event_contract": {"flow_id": "flow-close-1", "trace_id": "trace-close-1"}},
    )

    assert "report" in payload
    assert "event_contract" in payload
    assert payload["event_contract"]["agent"] == "closure-service"
    assert payload["event_contract"]["incident_id"] == str(action.incident_id)
    assert payload["event_contract"]["event_id"] == f"closure:{action.id}:closed"


def test_closure_service_name_prefers_incident_service_over_action_target() -> None:
    action = RemediationAction(
        tenant_id="tenant-a",
        incident_id="11111111-1111-1111-1111-111111111111",
        action_type="validate_pipeline",
        target="11111111-1111-1111-1111-111111111111",
        output="health check failed",
    )

    assert closure_service_app._resolve_closure_service_name(action, {"service": "orders-pipeline"}) == "orders-pipeline"
    assert closure_service_app._resolve_closure_service_name(action, {}) == str(action.target)


def test_closure_final_incident_payload_ignores_ui_approval_fields() -> None:
    action = RemediationAction(
        tenant_id="tenant-a",
        incident_id="11111111-1111-1111-1111-111111111111",
        action_type="script_execution",
        target="mysql",
        status="succeeded",
        output="health restored",
        parameters={"environment": "prod"},
    )
    report = ResolutionReport(
        tenant_id=action.tenant_id,
        incident_id=action.incident_id,
        remediation_action_id=action.id,
        root_cause="Alert table growth",
        impact="DB pressure",
        action_taken="script_execution",
        health_restored=True,
        alerts_cleared=True,
        knowledge_base_entry="resolved",
    )
    payload = closure_service_app._build_final_incident_payload(
        action=action,
        report=report,
        incident_payload={
            "service": "mysql",
            "environment": "prod",
            "severity": "high",
            "title": "mysql: row count high",
            "state": "remediating",
            "approval_status": "remediating",
            "approval": {"decision": "approved"},
        },
        recommendation={"trace_id": "trace-closure"},
        source_contract={},
    )

    assert payload["status"] == "closed"
    assert payload["service"] == "mysql"
    assert payload["trace_id"] == "trace-closure"
    assert "state" not in payload
    assert "approval" not in payload
    assert "approval_status" not in payload
    Incident.model_validate(payload)


def test_monitoring_raw_alert_payload_includes_event_contract() -> None:
    alert = Alert(
        source="prometheus",
        name="DatabaseReplicaLag",
        service="orders-db",
        severity=AlertSeverity.HIGH,
        description="replica lag increased",
    )

    payload = monitoring_adapter_app._build_raw_alert_event_payload(alert)

    assert "alert" in payload
    assert "event_contract" in payload
    assert payload["event_contract"]["agent"] == "monitoring-adapter"
    assert payload["event_contract"]["payload"]["topic"] == "raw-alerts"


def test_api_gateway_audit_contract_builder() -> None:
    event = api_gateway_app.GatewayAuditEvent(
        trace_id="trace-123",
        method="GET",
        path="/alerts/recent",
        target_url="http://monitoring-adapter:8000/alerts/recent",
        status_code=200,
        latency_ms=12.4,
    )

    contract = api_gateway_app._build_gateway_audit_contract(event)

    assert contract["agent"] == "api-gateway"
    assert contract["trace_id"] == "trace-123"
    assert contract["payload"]["path"] == "/alerts/recent"
