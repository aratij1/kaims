"""Bounded, auditable retry after the September collector/monitoring repair.
Run inside a KaiMS service runtime; dry-run by default. Never clears incidents or evidence.
"""
import asyncio, json, sys
from collections import Counter
from datetime import UTC, datetime, timedelta
from uuid import UUID
from sqlalchemy import select, func, case
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from common.config import Settings
from common.database import ContextEnrichmentJobRecord as Job, ContextEvidenceRequirementRecord as Requirement, IncidentRecord

REPAIR = "collector-monitoring-repair-20260913"

async def main():
    engine = create_async_engine(Settings().database_url)
    recovered = []
    try:
        async with async_sessionmaker(engine)() as session:
            latest = select(Requirement.incident_id, func.max(Requirement.rca_version).label("version")).where(
                Requirement.tenant_id == "default").group_by(Requirement.incident_id).subquery()
            query = select(Job.job_id).join(Requirement, Requirement.requirement_id == Job.requirement_id).join(
                latest, (latest.c.incident_id == Requirement.incident_id) & (latest.c.version == Requirement.rca_version)
            ).join(IncidentRecord, IncidentRecord.id == Job.incident_id).where(
                Job.tenant_id == "default", Job.status.in_(["retry", "dead_letter"]),
                Job.connector_id.in_(["discovery-mcp", "prometheus"]),
                Requirement.category.in_(["metrics", "deployment"]),
                IncidentRecord.severity.in_(["critical", "high"]),
                IncidentRecord.status.not_in(["closed", "resolved", "cancelled", "canceled"]),
                Job.observation_end >= datetime.now(UTC) - timedelta(days=3),
            ).order_by(case((Job.incident_id == UUID("773a3406-3cdf-49e7-a764-2edbaa5210ee"), 0), else_=1), Job.updated_at.desc()).limit(150)
            ids = list((await session.scalars(query)).all())
            seen = set(); per_incident = Counter()
            for job_id in ids:
                job = await session.scalar(select(Job).where(Job.job_id == job_id).with_for_update(skip_locked=True))
                if job is None or job.status not in {"retry", "dead_letter"}:
                    continue
                if job.requirement_id in seen or per_incident[str(job.incident_id)] >= 4:
                    continue
                if (job.query_payload or {}).get("collector_recovery") == REPAIR:
                    continue
                requirement = await session.get(Requirement, job.requirement_id)
                if requirement.status in {"collected", "answered", "satisfied", "cancelled"}:
                    continue
                recovered.append({"job_id": str(job.job_id), "incident_id": str(job.incident_id),
                    "requirement_id": str(job.requirement_id), "category": requirement.category,
                    "connector": job.connector_id, "previous_status": job.status,
                    "previous_attempts": job.attempt_count, "previous_error": str(job.last_error or "")[:180]})
                seen.add(job.requirement_id); per_incident[str(job.incident_id)] += 1
                if "--apply" in sys.argv:
                    job.query_payload = {**job.query_payload, "collector_recovery": REPAIR}
                    job.status = "retry"; job.attempt_count = 0
                    job.available_at = datetime.now(UTC) + timedelta(seconds=3 * len(recovered))
                    job.last_error = "RETRY_AFTER_COLLECTOR_AND_MONITORING_REPAIR"
                    job.lease_owner = None; job.lease_expires_at = None; job.version += 1
                    requirement.status = "scheduled"; requirement.version += 1
                if len(recovered) == 20:
                    break
            if "--apply" in sys.argv:
                await session.commit()
            else:
                await session.rollback()
        print(json.dumps({"repair": REPAIR, "applied": "--apply" in sys.argv,
            "jobs": recovered, "incident_count": len(per_incident)}, default=str))
    finally:
        await engine.dispose()

if __name__ == "__main__":
    asyncio.run(main())
