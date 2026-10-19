from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from sqlalchemy import select
from common.database import (AuditLogRecord, ContextEnrichmentJobRecord as Job,
    ContextEvidenceRequirementRecord as Requirement, IncidentRecord,
    IncidentInvestigationBindingRecord as Binding)
from common.queue_lifecycle import maintain_incident_jobs, maintain_context_queue
from common.repository import ContextEnrichmentRepository


def incident(key, status="investigating"):
    return IncidentRecord(id=key, tenant_id="tenant-a", service="checkout", environment="prod",
        severity="critical", status=status, title="Checkout", payload={})


def requirement(key, version=2, status="scheduled"):
    return Requirement(requirement_id=uuid4(), tenant_id="tenant-a", incident_id=key,
        rca_version=version, requirement_key=uuid4().hex, category="logs", question="Find errors",
        reason="Check cause", priority="high", collection_mode="automatic", status=status)


def job(req, **changes):
    now = datetime.now(UTC)
    return Job(job_id=uuid4(), tenant_id="tenant-a", incident_id=req.incident_id,
        requirement_id=req.requirement_id, connector_id="discovery-mcp", idempotency_key=uuid4().hex,
        query_payload={}, observation_start=now-timedelta(minutes=30), observation_end=now,
        status=changes.pop("status", "scheduled"), attempt_count=changes.pop("attempt_count", 0),
        available_at=now-timedelta(minutes=1), version=1, **changes)


@pytest.mark.asyncio
async def test_maintenance_retires_only_obsolete_work_and_recovers_expired_leases(sqlite_session_factory):
    key = uuid4(); now = datetime.now(UTC)
    async with sqlite_session_factory() as session:
        session.add(incident(key))
        session.add(Binding(tenant_id="tenant-a", project_id="checkout", incident_id=key,
            alert_id=uuid4(), analysis_request_id=uuid4(), context_snapshot_id=uuid4(),
            context_fingerprint="a"*64, recommendation_id=uuid4(), rca_version=2,
            status="insufficient_evidence", expires_at=now+timedelta(hours=1)))
        old, fulfilled, current = requirement(key,1), requirement(key,status="collected"), requirement(key)
        session.add_all([old, fulfilled, current])
        obsolete, done = job(old), job(fulfilled)
        orphan = job(requirement(key))
        exhausted = job(current, attempt_count=4)
        expired = job(current,status="collecting",attempt_count=1,lease_owner="crashed",lease_expires_at=now-timedelta(seconds=1))
        live = job(current,status="collecting",attempt_count=1,lease_owner="live",lease_expires_at=now+timedelta(minutes=2))
        healthy = job(current); healthy.created_at=now-timedelta(days=90)
        session.add_all([obsolete,done,orphan,exhausted,expired,live,healthy])
        await session.commit()
        changes = await maintain_incident_jobs(session,tenant_id="tenant-a",incident_id=key)
        await session.commit()
        assert obsolete.status == done.status == "cancelled"
        assert orphan.status == exhausted.status == "dead_letter"
        assert current.status == "blocked"
        assert expired.status == "retry" and expired.lease_owner is None
        assert live.status == "collecting" and live.lease_owner == "live"
        assert healthy.status == "scheduled"  # Old age alone is not an obsolete job.
        assert len(changes)==5
        audits=list((await session.scalars(select(AuditLogRecord))).all())
        assert len(audits)==1 and len(audits[0].payload["changes"])==5


@pytest.mark.asyncio
async def test_sweep_cursor_advances_past_healthy_work_and_preserves_other_tenants(sqlite_session_factory):
    first,second=UUID(int=1),UUID(int=2)
    async with sqlite_session_factory() as session:
        a,b=requirement(first,1),requirement(second,1)
        session.add_all([incident(first),incident(second,"closed"),a,b])
        good,bad=job(a),job(b)
        foreign=job(a);foreign.tenant_id="tenant-b"
        session.add_all([good,bad,foreign]);await session.commit()
    checkpoints=[]
    async def checkpoint(value):
        checkpoints.append(value)
    first_pass=await maintain_context_queue(sqlite_session_factory,tenant_id="tenant-a",incident_limit=1,progress=checkpoint)
    assert first_pass["jobs_changed"]==0 and first_pass["next_cursor"]==str(first)
    assert checkpoints==[str(first)]
    second_pass=await maintain_context_queue(sqlite_session_factory,tenant_id="tenant-a",incident_limit=1,cursor=first_pass["next_cursor"])
    assert second_pass["jobs_changed"]==1 and second_pass["next_cursor"]==""
    async with sqlite_session_factory() as session:
        assert (await session.get(Job,good.job_id)).status=="scheduled"
        assert (await session.get(Job,bad.job_id)).status=="cancelled"
        assert (await session.get(Job,foreign.job_id)).status=="scheduled"


@pytest.mark.asyncio
async def test_interrupted_sweep_resumes_after_the_last_committed_incident(sqlite_session_factory):
    import asyncio
    first,second=UUID(int=1),UUID(int=2)
    async with sqlite_session_factory() as session:
        a,b=requirement(first,1),requirement(second,1)
        bad1,bad2=job(a),job(b)
        session.add_all([incident(first,"closed"),incident(second,"closed"),a,b,bad1,bad2])
        await session.commit()
    checkpoints=[]
    async def interrupted(value):
        checkpoints.append(value)
        raise asyncio.CancelledError()
    with pytest.raises(asyncio.CancelledError):
        await maintain_context_queue(sqlite_session_factory,tenant_id="tenant-a",progress=interrupted)
    assert checkpoints==[str(first)]
    async with sqlite_session_factory() as session:
        assert (await session.get(Job,bad1.job_id)).status=="cancelled"
        assert (await session.get(Job,bad2.job_id)).status=="scheduled"
    result=await maintain_context_queue(sqlite_session_factory,tenant_id="tenant-a",cursor=checkpoints[-1])
    assert result["jobs_changed"]==1


@pytest.mark.asyncio
async def test_rca_revision_preserves_same_query_retry_budget_and_backoff(sqlite_session_factory):
    key=uuid4();now=datetime.now(UTC)
    async with sqlite_session_factory() as session:
        a,b=requirement(key,1),requirement(key,2)
        a.requirement_key=b.requirement_key="same-gap"
        old=job(a,status="retry",attempt_count=2)
        old.available_at=now+timedelta(minutes=2)
        session.add_all([incident(key),a,b,old]);await session.commit()
        repo=ContextEnrichmentRepository(session)
        newer=await repo.schedule_context_enrichment_job(tenant_id="tenant-a",incident_id=key,
            requirement_id=b.requirement_id,connector_id=old.connector_id,query_payload={},
            observation_start=old.observation_start,observation_end=old.observation_end)
        assert newer.attempt_count==2
        assert newer.available_at.replace(tzinfo=UTC)>=old.available_at.replace(tzinfo=UTC)
        old.attempt_count=4
        c=requirement(key,3);c.requirement_key="same-gap";session.add(c);await session.flush()
        exhausted=await repo.schedule_context_enrichment_job(tenant_id="tenant-a",incident_id=key,
            requirement_id=c.requirement_id,connector_id=old.connector_id,query_payload={},
            observation_start=old.observation_start,observation_end=old.observation_end)
        assert exhausted.status=="dead_letter" and exhausted.attempt_count==4
        assert c.status=="blocked"


@pytest.mark.asyncio
async def test_expired_priority_cannot_jump_current_priority_and_exhausted_jobs_cannot_be_claimed(sqlite_session_factory):
    now=datetime.now(UTC)
    async with sqlite_session_factory() as session:
        key=uuid4();req=requirement(key,1);session.add_all([incident(key),req])
        expired,current,exhausted=job(req),job(req),job(req,attempt_count=4)
        expired.available_at=now-timedelta(days=1)
        expired.query_payload={"operator_priority":True,"operator_priority_until":(now-timedelta(minutes=1)).isoformat()}
        current.query_payload={"operator_priority":True,"operator_priority_until":(now+timedelta(minutes=1)).isoformat()}
        session.add_all([expired,current,exhausted]);await session.commit()
        result=await ContextEnrichmentRepository(session).claim_context_enrichment_jobs(worker_id="test",limit=1,lane="priority")
        assert result[0]["job_id"]==str(current.job_id)
        result=await ContextEnrichmentRepository(session).claim_context_enrichment_jobs(worker_id="other",limit=10)
        assert str(exhausted.job_id) not in {row["job_id"] for row in result}
