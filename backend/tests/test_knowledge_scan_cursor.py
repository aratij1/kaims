import importlib.util
import os
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4
import pytest
from common.database import IncidentRecord, RcaReportRecord

@pytest.mark.asyncio
async def test_knowledge_cursor_advances_past_skipped_reports(sqlite_session_factory):
    path = Path(os.environ.get('KNOWLEDGE_WORKER_TEST_PATH', 'backend/src/knowledge-development-worker/app.py'))
    spec = importlib.util.spec_from_file_location('knowledge_cursor_worker', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.schedule_config['application_scope'] = 'payments'
    orphan_id, other_id = uuid4(), uuid4()
    now = datetime.now(timezone.utc)
    async with sqlite_session_factory() as session:
        session.add(IncidentRecord(id=other_id, tenant_id='dgsl-dev', service='other', environment='prod', severity='high', status='closed', title='Other service', payload={}))
        for incident_id in [orphan_id, other_id]:
            session.add(RcaReportRecord(id=uuid4(), tenant_id='dgsl-dev', incident_id=incident_id, root_cause='test', impact='test', payload={}, created_at=now))
        session.add(RcaReportRecord(id=uuid4(), tenant_id='another-tenant', incident_id=uuid4(), root_cause='private', impact='private', payload={}, created_at=now))
        await session.commit()
    app = SimpleNamespace(state=SimpleNamespace(session_factory=sqlite_session_factory))
    first = await module._analyze_locked(app, 'test', tenant_id='dgsl-dev')
    assert first['reports_scanned'] == 2
    assert first['evidence_collected'] == 0
    assert first['checkpoint_id']
    second = await module._analyze_locked(app, 'test', tenant_id='dgsl-dev')
    assert second['reports_scanned'] == 0
    assert second['checkpoint_id'] == first['checkpoint_id']

@pytest.mark.asyncio
async def test_diagnostic_draft_is_non_executable_and_idempotent(sqlite_session_factory):
    from common.continuous_learning import FailurePattern
    from common.database import LearningAuditRecord, RunbookVersionRecord
    from common.models import EvidenceReference
    from sqlalchemy import select
    path = Path(os.environ.get('KNOWLEDGE_WORKER_TEST_PATH', 'backend/src/knowledge-development-worker/app.py'))
    spec = importlib.util.spec_from_file_location('knowledge_draft_worker', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    pattern = FailurePattern(pattern_id='pattern', issue_signature='a'*64, service='payments', environment='prod', alert_type='Errors', incident_ids=['incident'], occurrence_frequency=1, confidence=.5, common_symptoms=['Timeouts'], evidence_references=[EvidenceReference(evidence_id='log', source='logs', uri='logs://1', summary='Timeout'), EvidenceReference(evidence_id='metric', source='metrics', uri='metrics://1', summary='Errors')])
    quality={'passed':False,'checks':{'independent_sources':True,'no_conflicts':True}}
    async with sqlite_session_factory() as session:
        assert await module._draft_candidate(session, pattern, quality, tenant_id='dgsl-dev')
        next(row for row in session.new if isinstance(row, LearningAuditRecord)).sequence_id=1
        await session.commit()
        assert not await module._draft_candidate(session, pattern, quality, tenant_id='dgsl-dev')
        row=(await session.execute(select(RunbookVersionRecord))).scalar_one()
        assert row.tenant_id=='dgsl-dev'
        assert row.approval_status=='draft'
        assert row.content['execution_eligible'] is False
        assert row.content['remediation_steps']==[]
        assert row.content['catalog_stage']=='diagnostic_candidate'
        conflict={**quality,'checks':{'independent_sources':True,'no_conflicts':False}}
        assert not await module._draft_candidate(session, pattern, conflict, tenant_id='dgsl-dev')
