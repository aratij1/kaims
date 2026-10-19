"""Bounded read-only recovery verification; never execute, close or update Jira."""
import asyncio
import time
from datetime import UTC, datetime, timedelta
from uuid import UUID
from fastapi import Header, HTTPException
from sqlalchemy import and_, or_, select
from sqlalchemy.exc import IntegrityError
from common.database import AlertRecord, AuditLogRecord, IncidentRecord, IncidentProjectionRecord
from common.recovery_observers import load_recovery_observer_registry
from common.recovery_status import observation_id, checksum, project_observation
from common.repository import IncidentRepository
from closure_service.recovery_assessments import AssessmentIdentity, authenticate, collect_assessment, digest


async def verify_current_recovery(factory, registry, tenant, incident_id, *, collector=collect_assessment, now=None):
    now = now or datetime.now(UTC)
    async with factory() as session:
        incident = await IncidentRepository(session).get_incident(str(incident_id), tenant_id=tenant)
        if not incident:
            raise HTTPException(404, "Incident not found")
        ids = [UUID(str(value)) for value in incident.get("alert_ids", [])]
        alerts = (await session.execute(select(AlertRecord).where(AlertRecord.tenant_id == tenant, AlertRecord.id.in_(ids)))).scalars().all()
        if not ids or len(alerts) != len(set(ids)):
            raise HTTPException(409, "Every linked alert must be available in the tenant")
        names = {alert.name for alert in alerts}
        matches = [p for p in registry.profiles if p.allow_automatic_observation
            and (p.tenant_id, p.environment, p.target_resource_id) == (tenant, incident["environment"], incident["service"])
            and names == {p.alert_name, *p.additional_alert_names}
            and all(a.service == incident["service"] and a.environment == incident["environment"]
                and all((a.payload or {}).get("labels", {}).get(k) == v for k, v in p.required_alert_labels.items()) for a in alerts)]
        if len(matches) != 1:
            raise HTTPException(409, "An exact read-only recovery profile is required")
        profile = matches[0]
        profile_digest = digest({"profile": profile.model_dump(mode="json"),
            "sources": [registry.source_for(c.spec).model_dump(mode="json") for c in profile.checks]})
        identity = observation_id(tenant, incident_id)
        prior = await session.get(AuditLogRecord, identity)
        if prior and project_observation(prior.payload, now=now)["status"] == "verified" and prior.payload.get("profile_digest") == profile_digest:
            return project_observation(prior.payload, now=now)
        binding = {"alert_ids": sorted(str(a.id) for a in alerts), "tenant_id": tenant,
            "service": incident["service"], "environment": incident["environment"], "profile_digest": profile_digest}
    window = max(300, *(check.spec.observation_window_seconds for check in profile.checks))
    start = now - timedelta(seconds=window + 2 * max(c.step_seconds for c in profile.checks))
    result = await collector(registry, profile, {"assessment_id": str(identity), "requested_at": now.isoformat(),
        "observation_window_start": start.isoformat(), "binding": binding}, now=now)
    payload = {"observation_id": str(identity), "observed_at": now.isoformat(),
        "valid_until": (now + timedelta(seconds=120)).isoformat(), "binding": binding,
        "profile_digest": profile_digest, "result": result, "validation_checksum": checksum(result),
        "corrective_execution_performed": False, "closes_incident": False}
    for attempt in range(2):
        try:
            async with factory() as session:
                current = await IncidentRepository(session).get_incident(str(incident_id), tenant_id=tenant)
                if not current or sorted(str(v) for v in current.get("alert_ids", [])) != binding["alert_ids"] or (current["service"], current["environment"]) != (binding["service"], binding["environment"]):
                    raise HTTPException(409, "Incident scope changed during observation")
                prior = await session.get(AuditLogRecord, identity, with_for_update=True)
                if prior and str(prior.payload.get("observed_at") or "") > payload["observed_at"]:
                    return project_observation(prior.payload, now=datetime.now(UTC))
                if prior:
                    prior.payload = payload
                else:
                    session.add(AuditLogRecord(id=identity, tenant_id=tenant, actor="closure-service",
                        action="recovery.observation.latest", resource_type="incident", resource_id=str(incident_id), payload=payload))
                await session.commit()
            return project_observation(payload, now=datetime.now(UTC))
        except IntegrityError:
            if attempt:
                raise
    raise RuntimeError("Recovery observation persistence failed")


def mount_current_recovery(app, settings):
    async def bounded_observation(registry, tenant, incident_id):
        from common.alert_processing_budget import run_handler
        async def perform(_):
            return await verify_current_recovery(app.state.session_factory, registry, tenant, incident_id)
        return await run_handler(settings, "context-events", perform, {}, timeout_seconds=25)

    @app.post("/incidents/{incident_id}/recovery-observation")
    async def observe(incident_id: UUID, request: AssessmentIdentity, x_kaiops_internal_token: str = Header(default="")):
        authenticate(settings, request, x_kaiops_internal_token)
        if not settings.recovery_observer_registry_path:
            raise HTTPException(503, "Recovery observer registry is not configured")
        if not settings.database_enabled or getattr(app.state, "session_factory", None) is None:
            raise HTTPException(503, "Recovery observation persistence is unavailable")
        registry = load_recovery_observer_registry(settings.recovery_observer_registry_path)
        return await bounded_observation(registry, request.tenant_id, incident_id)

    last_run = 0.0
    cursor = None
    lock = asyncio.Lock()
    async def reconcile():
        nonlocal last_run, cursor
        if not settings.database_enabled or getattr(app.state, "session_factory", None) is None or lock.locked() or time.monotonic() - last_run < 60 or not settings.recovery_observer_registry_path:
            return
        async with lock:
            last_run = time.monotonic()
            registry = load_recovery_observer_registry(settings.recovery_observer_registry_path)
            profiles = [p for p in registry.profiles if p.allow_automatic_observation]
            if not profiles:
                return
            async with app.state.session_factory() as session:
                scope = or_(*(and_(IncidentRecord.tenant_id == p.tenant_id, IncidentRecord.environment == p.environment, IncidentRecord.service == p.target_resource_id) for p in profiles))
                query = select(IncidentRecord.id, IncidentRecord.tenant_id).join(IncidentProjectionRecord,
                    and_(IncidentProjectionRecord.incident_id == IncidentRecord.id, IncidentProjectionRecord.tenant_id == IncidentRecord.tenant_id)).join(AlertRecord,
                    and_(AlertRecord.id == IncidentProjectionRecord.alert_id, AlertRecord.tenant_id == IncidentRecord.tenant_id)).where(scope,
                        AlertRecord.name.in_({p.alert_name for p in profiles}), IncidentRecord.status.notin_(["closed", "resolved", "cancelled", "recovered"]))
                if cursor:
                    query = query.where(IncidentRecord.id > cursor)
                rows = (await session.execute(query.order_by(IncidentRecord.id).limit(5))).all()
            if not rows:
                cursor = None
            for incident_id, tenant in rows:
                try:
                    await bounded_observation(registry, tenant, incident_id)
                except HTTPException:
                    pass  # Ineligible scope is not recovery proof.
                cursor = incident_id
    app.state.reconcile_current_recovery = reconcile
