"""Bounded queue maintenance; job age alone never proves work is obsolete."""
from datetime import UTC, datetime
from uuid import UUID, uuid4

from sqlalchemy import and_, func, or_, select
from sqlalchemy.orm import load_only

from common.database import (AuditLogRecord, ContextEnrichmentJobRecord as Job,
    ContextEvidenceRequirementRecord as Requirement, IncidentRecord,
    IncidentInvestigationBindingRecord as Binding)
from common.enrichment_scheduler import persist_collected_evidence
from common.tenant_identity import require_tenant_id

MAX_COLLECTION_ATTEMPTS = 4
MAINTENANCE_JOBS_PER_INCIDENT = 10


async def maintain_incident_jobs(session, *, tenant_id, incident_id, limit=MAINTENANCE_JOBS_PER_INCIDENT):
    tenant = require_tenant_id(tenant_id, source="queue maintenance")
    now = datetime.now(UTC)
    incident_status = await session.scalar(select(IncidentRecord.status).where(
        IncidentRecord.tenant_id == tenant, IncidentRecord.id == incident_id))
    binding_version = await session.scalar(select(func.max(Binding.rca_version)).where(
        Binding.tenant_id == tenant, Binding.incident_id == incident_id))
    requirement_version = await session.scalar(select(func.max(Requirement.rca_version)).where(
        Requirement.tenant_id == tenant, Requirement.incident_id == incident_id))
    cutoff = min(int(binding_version or 0), int(requirement_version or 0))
    unleased = or_(Job.status != "collecting", Job.lease_expires_at.is_(None), Job.lease_expires_at <= now)
    obsolete = True if incident_status is None or incident_status in {"closed", "resolved", "cancelled", "canceled"} else or_(
        Requirement.requirement_id.is_(None),
        Requirement.status.in_(["collected", "answered", "satisfied", "cancelled"]),
        Requirement.rca_version < cutoff, Job.attempt_count >= MAX_COLLECTION_ATTEMPTS,
        Job.status == "collecting",
    )
    statement = select(Job, Requirement).outerjoin(Requirement, and_(
        Requirement.requirement_id == Job.requirement_id, Requirement.tenant_id == Job.tenant_id,
        Requirement.incident_id == Job.incident_id,
    )).options(load_only(Job.status, Job.attempt_count, Job.available_at, Job.last_error,
        Job.lease_owner, Job.lease_expires_at, Job.version),
        load_only(Requirement.status, Requirement.rca_version, Requirement.version)).where(
        Job.tenant_id == tenant, Job.incident_id == incident_id,
        Job.status.in_(["scheduled", "retry", "collecting"]),
        unleased, obsolete,
    ).order_by(Job.job_id).limit(max(1, min(limit, MAINTENANCE_JOBS_PER_INCIDENT)))
    if session.bind.dialect.name != "sqlite":
        statement = statement.with_for_update(skip_locked=True)
    changes = []
    for job, requirement in (await session.execute(statement)).all():
        expires = job.lease_expires_at
        if expires is not None and expires.tzinfo is None:
            expires = expires.replace(tzinfo=UTC)
        if job.status == "collecting" and expires is not None and expires > now:
            continue
        reason = None
        target = "cancelled"
        if incident_status is None or requirement is None:
            reason = "ORPHANED_COLLECTION_JOB"
            target = "dead_letter"
        elif incident_status in {"closed", "resolved", "cancelled", "canceled"}:
            reason = "INCIDENT_TERMINAL_COLLECTION_RETIRED"
        elif requirement.status in {"collected", "answered", "satisfied", "cancelled"}:
            reason = "EVIDENCE_REQUIREMENT_ALREADY_TERMINAL"
        elif requirement.rca_version < cutoff:
            reason = "SUPERSEDED_EVIDENCE_REQUIREMENT"
        elif job.attempt_count >= MAX_COLLECTION_ATTEMPTS:
            reason = "COLLECTION_RETRY_EXHAUSTED"
            target = "dead_letter"
            requirement.status = "blocked"
            requirement.version += 1
        elif job.status == "collecting":
            reason = "EXPIRED_COLLECTION_LEASE_RECOVERED"
            target = "retry"
            job.available_at = now
        if reason:
            changes.append({"job_id": str(job.job_id), "from": job.status, "to": target, "reason": reason})
            job.status, job.last_error = target, reason
            job.lease_owner = job.lease_expires_at = None
            job.version += 1
    if changes:
        session.add(AuditLogRecord(id=uuid4(), tenant_id=tenant, actor="queue-maintenance",
            action="context.queue.maintenance", resource_type="incident", resource_id=str(incident_id),
            payload={"changes": changes, "current_rca_version": cutoff}))
        await session.flush()
    return changes


async def maintain_context_queue(session_factory, *, tenant_id, cursor="", incident_limit=20, progress=None):
    """Keyset pagination prevents healthy jobs at the front starving cleanup."""
    tenant = require_tenant_id(tenant_id, source="queue maintenance")
    limit = max(1, min(incident_limit, 50))
    async with session_factory() as session:
        statement = select(Job.incident_id).where(Job.tenant_id == tenant,
            Job.status.in_(["scheduled", "retry", "collecting"]))
        if cursor:
            statement = statement.where(Job.incident_id > UUID(cursor))
        ids = list((await session.scalars(statement.distinct().order_by(Job.incident_id).limit(limit+1))).all())
    changed = 0
    for incident_id in ids[:limit]:
        async def operation(session):
            return await maintain_incident_jobs(session, tenant_id=tenant, incident_id=incident_id)
        changed += len(await persist_collected_evidence(session_factory, operation))
        if progress is not None:
            # Checkpoint only committed work, so a time-budget cancellation
            # resumes after it rather than repeatedly visiting the same page.
            await progress(str(incident_id))
    return {"incidents_scanned": min(len(ids), limit), "jobs_changed": changed,
            "next_cursor": str(ids[limit-1]) if len(ids) > limit else ""}
