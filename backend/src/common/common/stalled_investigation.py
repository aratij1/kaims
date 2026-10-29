"""Durably recover an initial investigation without duplicating incidents."""

from datetime import UTC, datetime, timedelta

from sqlalchemy import select

from common.database import ContextSnapshotRecord, IncidentProjectionRecord
from common.topics import ORCHESTRATION_EVENTS


async def recover_stalled_investigation(repo, alert, incident, *, now=None) -> bool:
    now = now or datetime.now(UTC)
    created = incident.created_at
    if created.tzinfo is None:
        created = created.replace(tzinfo=UTC)
    if str(incident.status).lower() not in {"open", "investigating", "detected", "collecting", "rca_ready"}:
        return False
    if created > now - timedelta(minutes=5):
        return False
    onset = alert.starts_at
    if onset.tzinfo is None:
        onset = onset.replace(tzinfo=UTC)
    new_cycle = onset > created + timedelta(minutes=5)
    if str(incident.status).lower() == "rca_ready" and not new_cycle:
        return False
    recommendation = await repo.session.scalar(
        select(IncidentProjectionRecord.recommendation_id).where(
            IncidentProjectionRecord.incident_id == incident.id,
            IncidentProjectionRecord.tenant_id == incident.tenant_id,
        )
    )
    if recommendation is not None:
        if not new_cycle:
            return False
        state = await repo.session.scalar(
            select(IncidentProjectionRecord.lifecycle_state).where(
                IncidentProjectionRecord.incident_id == incident.id,
                IncidentProjectionRecord.tenant_id == incident.tenant_id,
            )
        )
        if str(state).upper() not in {"DETECTED", "COLLECTING", "WAITING_FOR_HUMAN"}:
            return False  # Never supersede a plan awaiting approval or execution.
    expires = await repo.session.scalar(
        select(ContextSnapshotRecord.expires_at)
        .where(
            ContextSnapshotRecord.tenant_id == incident.tenant_id,
            ContextSnapshotRecord.incident_id == str(incident.id),
        )
        .order_by(ContextSnapshotRecord.collected_at.desc())
        .limit(1)
    )
    if not new_cycle and expires and (expires.replace(tzinfo=UTC) if expires.tzinfo is None else expires) > now:
        return False
    # Correlation holds the canonical incident's transaction lock. One key per
    # five-minute interval bounds replay even under repeated source deliveries.
    expires_utc = (expires.replace(tzinfo=UTC) if expires.tzinfo is None else expires) if expires else None
    use_onset = new_cycle and (recommendation is not None or expires_utc is None or expires_utc > now)
    generation = int(onset.timestamp()) if use_onset else int(now.timestamp()) // 300
    event_id = f"initial-investigation-recovery:{incident.id}:{generation}"
    return await repo.enqueue_resolution_event(
        event_id=event_id,
        aggregate_id=str(incident.id),
        tenant_id=incident.tenant_id,
        topic=ORCHESTRATION_EVENTS,
        partition_key=alert.service,
        available_after_seconds=0,
        payload={
            "event_id": event_id,
            "alert": alert.model_dump(mode="json"),
            "incident": incident.model_dump(mode="json"),
            "decision": {
                "workflow": "recover-stalled-initial-investigation",
                "message_bus_provider": "rabbitmq",
                "context_strategy": "realtime",
            },
        },
    )
