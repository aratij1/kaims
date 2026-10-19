from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from sqlalchemy import func, select
from ai_workbench_common.models import Context
from common.database import ContextSnapshotRecord, AuditLogRecord, IncidentInvestigationBindingRecord
from common.models import Alert, Recommendation
from common.repository import IncidentRepository
from test_resolution_readiness_handoff import resolution_app as module


async def seed(factory):
    alert = Alert(tenant_id='tenant-a', source='prometheus', service='checkout', name='Down', description='unreachable')
    context = Context(tenant_id='tenant-a', incident_id=uuid4(), alert=alert,
                      metadata={'analysis_request_id': str(uuid4()), 'rca_version': 1, 'project_id': 'checkout'})
    parent = ContextSnapshotRecord(snapshot_id=uuid4(), tenant_id=context.tenant_id,
        incident_id=str(context.incident_id), source_incident_id=str(context.incident_id),
        alert_signature='a'*64, subject_fingerprint='b'*64, context_fingerprint='c'*64,
        contract_version='kaiops.context.v2', quality_score=.5, reusable=True,
        source_manifest={}, snapshot_version=1, payload=context.model_dump(mode='json'),
        collected_at=datetime.now(UTC), expires_at=datetime.now(UTC)+timedelta(hours=1))
    async with factory() as session:
        session.add(parent)
        await session.commit()
    rec = Recommendation(tenant_id=context.tenant_id, incident_id=context.incident_id,
        root_cause='Not established', confidence=.1, impact='Not established',
        recommended_action='Collect evidence', severity=alert.severity, rationale='Insufficient evidence',
        risk='high', metadata={'rca_status':'insufficient_evidence'})
    return context, parent, rec


@pytest.mark.asyncio
async def test_final_snapshot_and_recommendation_commit_together(sqlite_session_factory, monkeypatch):
    context, parent, rec = await seed(sqlite_session_factory)
    monkeypatch.setattr(module.app.state, 'session_factory', sqlite_session_factory, raising=False)
    bound = await module._commit_investigation_recommendation(context, {'evidence': []}, parent.snapshot_id, rec)
    async with sqlite_session_factory() as session:
        snapshot = await session.get(ContextSnapshotRecord, UUID(rec.metadata['context_snapshot_id']))
        audit = await session.get(AuditLogRecord, rec.id)
        binding = await session.scalar(select(IncidentInvestigationBindingRecord).where(IncidentInvestigationBindingRecord.recommendation_id == rec.id))
        assert snapshot is not None and audit is not None and binding is not None
        assert str(binding.context_snapshot_id) == bound.metadata['context_snapshot_id']
        assert snapshot.parent_snapshot_id == parent.snapshot_id


@pytest.mark.asyncio
async def test_recommendation_failure_rolls_back_final_snapshot(sqlite_session_factory, monkeypatch):
    context, parent, rec = await seed(sqlite_session_factory)
    monkeypatch.setattr(module.app.state, 'session_factory', sqlite_session_factory, raising=False)
    original_save = IncidentRepository.save_recommendation_as_audit
    async def fail(*args, **kwargs):
        await original_save(*args, **kwargs)
        raise ValueError('evidence integrity failed')
    monkeypatch.setattr(IncidentRepository, 'save_recommendation_as_audit', fail)
    with pytest.raises(ValueError, match='evidence integrity'):
        await module._commit_investigation_recommendation(context, {'evidence': []}, parent.snapshot_id, rec)
    async with sqlite_session_factory() as session:
        assert await session.scalar(select(func.count()).select_from(ContextSnapshotRecord)) == 1
        assert await session.get(AuditLogRecord, rec.id) is None
        assert await session.scalar(select(func.count()).select_from(IncidentInvestigationBindingRecord)) == 0


@pytest.mark.asyncio
async def test_new_evidence_before_finalization_still_rejects_old_analysis(sqlite_session_factory, monkeypatch):
    context, parent, rec = await seed(sqlite_session_factory)
    monkeypatch.setattr(module.app.state, 'session_factory', sqlite_session_factory, raising=False)
    async with sqlite_session_factory() as session:
        await IncidentRepository(session).persist_final_investigation_snapshot(context=context, report={'evidence': []}, parent_snapshot_id=parent.snapshot_id)
        await session.commit()
    with pytest.raises(ValueError, match='superseded'):
        await module._commit_investigation_recommendation(context, {'evidence': []}, parent.snapshot_id, rec)
    async with sqlite_session_factory() as session:
        assert await session.get(AuditLogRecord, rec.id) is None
