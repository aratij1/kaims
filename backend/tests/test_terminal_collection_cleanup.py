from datetime import UTC, datetime, timedelta
from uuid import uuid4
import pytest
from sqlalchemy import select
from common.database import AuditLogRecord, ContextEnrichmentJobRecord as Job
from common.models import Incident
from common.repository import ContextEnrichmentRepository, IncidentRepository

@pytest.mark.asyncio
async def test_terminal_cleanup_is_scoped_audited_and_preserves_leases(sqlite_session_factory):
 async with sqlite_session_factory() as session:
  closed=Incident(tenant_id='tenant',service='old',severity='critical',title='Closed',status='closed')
  active=Incident(tenant_id='tenant',service='live',severity='critical',title='Active',status='investigating')
  foreign=Incident(tenant_id='other',service='private',severity='critical',title='Other',status='closed')
  for incident in [closed,active,foreign]:await IncidentRepository(session).save_incident(incident)
  now=datetime.now(UTC)
  def make(incident,status='scheduled',expires=None):
   return Job(job_id=uuid4(),tenant_id=incident.tenant_id,incident_id=incident.id,requirement_id=uuid4(),connector_id='discovery-mcp',idempotency_key=str(uuid4()),query_payload={},observation_start=now-timedelta(hours=1),observation_end=now,status=status,available_at=now,lease_owner='worker' if status=='collecting' else None,lease_expires_at=expires)
  waiting=make(closed); expired=make(closed,'collecting',now-timedelta(seconds=1)); live=make(closed,'collecting',now+timedelta(minutes=3)); running=make(active); other=make(foreign); dead=make(closed,'dead_letter')
  session.add_all([waiting,expired,live,running,other,dead]);await session.commit()
  repo=ContextEnrichmentRepository(session)
  preview=await repo.retire_closed_incident_collection_jobs(tenant_id='tenant',actor='test',dry_run=True)
  assert preview['eligible_jobs']==2 and preview['jobs_retired']==0
  assert waiting.status=='scheduled'
  result=await repo.retire_closed_incident_collection_jobs(tenant_id='tenant',actor='test')
  await session.commit()
  assert result['jobs_retired']==2
  assert waiting.status==expired.status=='cancelled'
  assert expired.lease_owner is None
  assert live.status=='collecting' and running.status=='scheduled' and other.status=='scheduled' and dead.status=='dead_letter'
  audits=(await session.execute(select(AuditLogRecord).where(AuditLogRecord.action=='context.collection.terminal_jobs_retired'))).scalars().all()
  assert len(audits)==1 and len(audits[0].payload['jobs'])==2
  assert (await repo.retire_closed_incident_collection_jobs(tenant_id='tenant',actor='test'))['jobs_retired']==0
