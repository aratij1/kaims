from types import SimpleNamespace
from uuid import uuid4
import pytest
from sqlalchemy import select
from ai_workbench_common.models import Context
from common.models import Alert,AlertSeverity,Incident,Recommendation
from common.database import IncidentRecord,ResolutionOutboxRecord
from test_governed_resolution_handoff import load_resolution_module

@pytest.mark.asyncio
async def test_committed_rca_handoff_survives_without_a_broker_and_replay_is_idempotent(sqlite_session_factory,monkeypatch):
    module=load_resolution_module()
    monkeypatch.setattr(module.settings,"database_enabled",True)
    monkeypatch.setattr(module,"initial_causal_collection_gaps",lambda **kwargs:[])
    alert=Alert(tenant_id="tenant-a",source="prometheus",name="ServiceDown",service="api",severity=AlertSeverity.HIGH,description="Unavailable")
    incident=Incident(tenant_id="tenant-a",service="api",severity=AlertSeverity.HIGH,title="Service unavailable")
    context=Context(tenant_id="tenant-a",incident_id=incident.id,alert=alert)
    recommendation=Recommendation(tenant_id="tenant-a",incident_id=incident.id,root_cause="Unconfirmed",confidence=0,impact="Unknown",recommended_action="Collect evidence",severity=AlertSeverity.HIGH,rationale="More evidence required",metadata={"rca_analysis":{"missing_evidence":[]}})
    async with sqlite_session_factory() as session:
        session.add(IncidentRecord(id=incident.id,tenant_id="tenant-a",service="api",environment="prod",severity="high",status="investigating",title="Service unavailable",payload={}))
        await session.commit()
    # No producer exists: persistence must not require a live broker.
    app=SimpleNamespace(state=SimpleNamespace(session_factory=sqlite_session_factory))
    for _ in range(2):
        await module._persist_resolution_event(app=app,context=context,incident=incident,recommendation=recommendation,decision_payload={"requires_approval":True})
    async with sqlite_session_factory() as session:
        rows=(await session.execute(select(ResolutionOutboxRecord))).scalars().all()
        assert len(rows)==1
        assert rows[0].status=="pending"
        assert rows[0].published_at is None
        assert rows[0].payload["recommendation"]["id"]==str(recommendation.id)
        assert rows[0].payload["decision"]["requires_approval"] is True
    recommendation=recommendation.model_copy(update={"id":uuid4()})
    await module._persist_resolution_event(app=app,context=context,incident=incident,recommendation=recommendation,decision_payload={"requires_approval":True})
    async with sqlite_session_factory() as session:
        rows=(await session.execute(select(ResolutionOutboxRecord))).scalars().all()
        assert len(rows)==2
        assert len({row.event_id for row in rows})==2
