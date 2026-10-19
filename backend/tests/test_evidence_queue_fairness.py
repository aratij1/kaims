from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from common.database import ContextEnrichmentJobRecord as Job
from common.repository import ContextEnrichmentRepository


def job(incident, *, status="scheduled", priority=False, age=60, attempted=0):
    now = datetime.now(UTC)
    return Job(job_id=uuid4(), tenant_id="tenant", incident_id=incident,
        requirement_id=uuid4(), connector_id="discovery-mcp", idempotency_key=str(uuid4()),
        query_payload={"operator_priority": priority, "operator_priority_until": (now + timedelta(minutes=15)).isoformat() if priority else None}, observation_start=now-timedelta(hours=1),
        observation_end=now, status=status, available_at=now-timedelta(minutes=age),
        attempt_count=attempted, updated_at=now-timedelta(minutes=5) if attempted else now)


@pytest.mark.asyncio
async def test_bulk_old_incident_cannot_starve_unserved_incident(sqlite_session_factory):
    noisy, waiting = uuid4(), uuid4()
    async with sqlite_session_factory() as session:
        session.add_all([job(noisy, age=120) for _ in range(100)])
        session.add(job(noisy, status="collected", attempted=1))
        waiting_job = job(waiting, age=10)
        session.add(waiting_job)
        await session.commit()
        repo = ContextEnrichmentRepository(session)
        claimed = await repo.claim_context_enrichment_jobs(worker_id="fair", limit=1, lane="fair")
        assert claimed[0]["job_id"] == str(waiting_job.job_id)
        await session.commit()
        # An independent worker can claim another incident while this lease runs.
        other = await repo.claim_context_enrichment_jobs(worker_id="other", limit=1, lane="fair")
        assert other[0]["incident_id"] == str(noisy)
        assert other[0]["job_id"] != claimed[0]["job_id"]


@pytest.mark.asyncio
async def test_priority_lane_and_retry_lane_keep_independent_capacity(sqlite_session_factory):
    async with sqlite_session_factory() as session:
        session.add_all([job(uuid4(), age=120) for _ in range(10)])
        priority = job(uuid4(), priority=True, age=1)
        retry = job(uuid4(), status="retry", age=1)
        session.add_all([priority, retry])
        await session.commit()
        repo = ContextEnrichmentRepository(session)
        first = await repo.claim_context_enrichment_jobs(worker_id="priority", limit=1, lane="priority")
        assert first[0]["job_id"] == str(priority.job_id)
        await session.commit()
        second = await repo.claim_context_enrichment_jobs(worker_id="retry", limit=1, lane="retry")
        assert second[0]["job_id"] == str(retry.job_id)
        await session.commit()
        assert (await repo.claim_context_enrichment_jobs(worker_id="fair", limit=1, lane="fair"))[0]["job_id"] not in {
            str(priority.job_id), str(retry.job_id)}


@pytest.mark.asyncio
async def test_invalid_lane_fails_before_claiming_work(sqlite_session_factory):
    async with sqlite_session_factory() as session:
        session.add(job(uuid4()))
        await session.commit()
        with pytest.raises(ValueError, match="Unknown"):
            await ContextEnrichmentRepository(session).claim_context_enrichment_jobs(worker_id="worker", lane="bad")


@pytest.mark.asyncio
async def test_closed_incident_backlog_does_not_consume_collection_capacity(sqlite_session_factory):
    from common.models import Incident
    from common.repository import IncidentRepository
    incident = Incident(tenant_id="tenant", service="old", severity="critical", title="Already closed", status="closed")
    async with sqlite_session_factory() as session:
        await IncidentRepository(session).save_incident(incident)
        session.add_all([job(incident.id, age=120) for _ in range(20)])
        active_job = job(uuid4(), age=1)
        session.add(active_job)
        await session.commit()
        claimed = await ContextEnrichmentRepository(session).claim_context_enrichment_jobs(worker_id="fair", limit=1, lane="fair")
        assert claimed[0]["job_id"] == str(active_job.job_id)


@pytest.mark.asyncio
async def test_prioritization_is_scoped_audited_and_preserves_existing_queries(sqlite_session_factory):
    from common.models import Incident
    from common.repository import IncidentRepository
    from common.database import AuditLogRecord
    from sqlalchemy import select
    incident = Incident(tenant_id="tenant", service="mysql-exporter", severity="critical", title="Exporter down")
    async with sqlite_session_factory() as session:
        await IncidentRepository(session).save_incident(incident)
        pending = job(incident.id)
        pending.query_payload = {"alert": {"service": "mysql-exporter"}}
        session.add(pending)
        await session.commit()
        repo = ContextEnrichmentRepository(session)
        with pytest.raises(LookupError):
            await repo.prioritize_context_collection(tenant_id="other", incident_id=str(incident.id), actor="operator", reason="Investigate stalled collection")
        result = await repo.prioritize_context_collection(tenant_id="tenant", incident_id=str(incident.id), actor="operator", reason="Investigate stalled collection")
        assert result["jobs_prioritized"] == 1
        assert pending.query_payload["alert"]["service"] == "mysql-exporter"
        assert pending.query_payload["operator_priority"] is True
        audit = await session.scalar(select(AuditLogRecord).where(AuditLogRecord.action == "context.collection.prioritized"))
        assert audit.tenant_id == "tenant" and audit.actor == "operator"
        assert audit.payload["job_ids"] == [str(pending.job_id)]
        now = datetime.now(UTC)
        followup = await repo.schedule_context_enrichment_job(tenant_id="tenant", incident_id=incident.id,
            requirement_id=uuid4(), connector_id="prometheus", query_payload={"category": "metrics"},
            observation_start=now-timedelta(minutes=10), observation_end=now)
        assert followup.query_payload["operator_priority"] is True
        audit.payload = {**audit.payload, "expires_at": (now-timedelta(seconds=1)).isoformat()}
        await session.flush()
        later = await repo.schedule_context_enrichment_job(tenant_id="tenant", incident_id=incident.id,
            requirement_id=uuid4(), connector_id="prometheus", query_payload={"category": "metrics"},
            observation_start=now-timedelta(minutes=10), observation_end=now)
        assert "operator_priority" not in later.query_payload


@pytest.mark.asyncio
async def test_priority_gateway_uses_authenticated_identity_and_rejects_viewer():
    from types import SimpleNamespace
    from unittest.mock import AsyncMock
    import httpx
    from fastapi import FastAPI
    from api_gateway.control_routes import build_control_router
    auth = SimpleNamespace(role="ADMIN", email="operator@example.test", username="operator", user_id="operator",
                           tenant_id="tenant", jwt_id="session")
    proxy = AsyncMock(return_value={"jobs_prioritized": 8})
    app = FastAPI()
    app.include_router(build_control_router(settings=SimpleNamespace(context_agent_url="http://context"),
        guarded_proxy=proxy, raw_proxy=AsyncMock(), trace_id_from_header=lambda x: "trace", analyzer=None,
        load_recent_events=AsyncMock(), build_audit_contract=lambda x: {}, load_audit_summary=AsyncMock(),
        auth_context_from_request=AsyncMock(return_value=auth)))
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        path = f"/incidents/{uuid4()}/context-collection/prioritize"
        assert (await client.post(path, json={"comment": "Resume stalled collection", "tenant_id": "other"})).status_code == 422
        response = await client.post(path, json={"comment": "Resume stalled collection"})
        assert response.status_code == 200
        assert proxy.call_args.kwargs["payload"] == {
            "tenant_id": "tenant", "actor_id": "operator@example.test", "reason": "Resume stalled collection"}
        auth.role = "VIEWER"
        assert (await client.post(path, json={"comment": "Resume stalled collection"})).status_code == 403
