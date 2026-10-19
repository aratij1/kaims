from __future__ import annotations

import importlib.util
import asyncio
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from common.models import Alert, AlertSeverity, Incident
MODULE_PATH = Path(__file__).resolve().parents[1] / "src" / "orchestrator" / "app.py"
SPEC = importlib.util.spec_from_file_location("orchestrator_service_app", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
orchestrator_app = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(orchestrator_app)


class FakeSession:
    def __init__(self) -> None:
        self.committed = False
        self.saved_envelopes: list[dict] = []

    async def __aenter__(self) -> "FakeSession":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        return None

    async def commit(self) -> None:
        self.committed = True


class FakeRepository:
    def __init__(self, session: FakeSession) -> None:
        self.session = session

    async def save_incident_event(self, envelope: dict) -> None:
        self.session.saved_envelopes.append(envelope)


@pytest.mark.asyncio
async def test_orchestrator_persists_metadata_envelope_before_publish(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_session = FakeSession()
    app = SimpleNamespace(state=SimpleNamespace(session_factory=lambda: fake_session))

    monkeypatch.setattr(orchestrator_app, "IncidentRepository", FakeRepository)

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
        "message_bus_provider": "rabbitmq",
        "risk_tier": "high",
        "execution_mode": "human-approval",
        "requires_approval": True,
        "policy_version": "policy-v1",
        "policy_reason": "critical severity",
        "workflow": "approval-gated",
        "next_action": "notify-oncall",
    }

    envelope = orchestrator_app.build_orchestration_envelope(
        alert=alert,
        incident=incident,
        decision=decision,
        transport_provider="rabbitmq",
        channel="orchestration-events",
    )

    await orchestrator_app._persist_orchestration_event(app, envelope)

    assert fake_session.committed is True
    assert len(fake_session.saved_envelopes) == 1
    assert fake_session.saved_envelopes[0]["event_type"] == "incident.workflow.selected"
    assert fake_session.saved_envelopes[0]["identity"]["incident_id"] == str(incident.id)


@pytest.mark.asyncio
async def test_orchestrator_does_not_advance_delivery_without_persisted_decision(monkeypatch):
    captured = {}
    async def consume(_consumer, handler):
        captured["handler"] = handler
    monkeypatch.setattr(orchestrator_app, "_build_ingress_consumers", lambda: [("test", object(), consume)])
    monkeypatch.setattr(orchestrator_app.settings, "temporal_pilot_enabled", False)
    monkeypatch.setattr(orchestrator_app, "selected_event_bus_provider", lambda _settings: "rabbitmq")
    monkeypatch.setattr(orchestrator_app.agent, "decide_workflow_async_with_runtime", AsyncMock(return_value=SimpleNamespace(workflow="investigate")))
    publish = AsyncMock()
    monkeypatch.setattr(orchestrator_app, "publish_orchestration_event", publish)
    app = SimpleNamespace(state=SimpleNamespace(producer=object(), session_factory=None))
    alert = Alert(tenant_id="tenant-a", source="prometheus", service="payments", name="Down", description="down")
    incident = Incident(tenant_id="tenant-a", service="payments", title="Down")
    await orchestrator_app.startup(app)
    await asyncio.sleep(0)
    # Invoke the captured handler directly; broker retry must see this error.
    try:
        with pytest.raises(RuntimeError, match="session factory unavailable"):
            await captured["handler"]({"alert": alert.model_dump(), "incident": incident.model_dump()})
        publish.assert_not_awaited()
    finally:
        await orchestrator_app.shutdown(app)
