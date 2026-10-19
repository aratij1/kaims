from types import SimpleNamespace
from unittest.mock import AsyncMock
import pytest
from test_governed_resolution_handoff import load_resolution_module
from common.models import Alert, AlertSeverity, Incident, Recommendation
from ai_workbench_common.models import Context

@pytest.mark.parametrize("assignment", [None, {"identity": "responder@example.test", "source": "incident_assignment"}])
async def test_resolution_persists_when_human_assignment_is_unavailable(monkeypatch, assignment):
    module = load_resolution_module()
    monkeypatch.setattr(module.settings, "database_enabled", True)
    session = AsyncMock()
    session.__aenter__.return_value = session
    repo = AsyncMock()
    enrichment = AsyncMock()
    enrichment.list_context_evidence_requirements.return_value = []
    enrichment.resolve_human_evidence_responder.return_value = assignment
    monkeypatch.setattr(module, "IncidentRepository", lambda _: repo)
    monkeypatch.setattr(module, "ContextEnrichmentRepository", lambda _: enrichment)
    monkeypatch.setattr(module, "initial_causal_collection_gaps", lambda **_: [])
    alert = Alert(tenant_id="tenant-a", source="prometheus", name="ServiceDown", service="api", severity=AlertSeverity.HIGH, description="Unavailable", metadata={"owner_team": "incident-owner"})
    incident = Incident(tenant_id="tenant-a", service="api", severity=AlertSeverity.HIGH, title="Service down")
    context = Context(tenant_id="tenant-a", alert=alert, incident_id=incident.id)
    recommendation = Recommendation(tenant_id="tenant-a", incident_id=incident.id, root_cause="Unknown", confidence=0, impact="Unknown", recommended_action="Collect evidence", severity=AlertSeverity.HIGH, rationale="Missing verification", metadata={"rca_analysis": {"missing_evidence": ["Confirm recovery independently"]}})
    await module._persist_resolution_event(app=SimpleNamespace(state=SimpleNamespace(session_factory=lambda: session)), context=context, incident=incident, recommendation=recommendation, decision_payload={"requires_approval": True})
    enrichment.resolve_human_evidence_responder.assert_awaited_once_with(tenant_id="tenant-a", incident_id=incident.id)
    kwargs = enrichment.create_human_evidence_request.await_args.kwargs
    assert kwargs["expected_responder"] == (assignment["identity"] if assignment else None)
    assert kwargs["assignment_source"] == (assignment["source"] if assignment else None)
    assert kwargs["assignment_failure_reason"] == (None if assignment else "NO_AUTHORIZED_RESPONDER")
    session.commit.assert_awaited_once()
    repo.save_incident_event.assert_awaited_once()

    repo.enqueue_resolution_event.assert_awaited_once()
    delivery = repo.enqueue_resolution_event.await_args.kwargs
    assert delivery["topic"] == "resolution-events"
    assert delivery["tenant_id"] == "tenant-a"
    assert delivery["aggregate_id"] == str(incident.id)
    assert delivery["payload"]["recommendation"]["id"] == str(recommendation.id)
    rebuilt = module._build_resolution_event_payload(context=context, incident=incident, recommendation=recommendation, decision_payload={"requires_approval": True})
    assert delivery["event_id"] == rebuilt["event_contract"]["event_id"]
    import json
    json.dumps(delivery["payload"])
