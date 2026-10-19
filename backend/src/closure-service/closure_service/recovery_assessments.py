"""Durable, operator-authorized verification of recovery outside the executor.

These assessments never approve a remediation plan, assert causal grounding, or
credit an executor/runbook. Closure is conditional on independent post-request evidence.
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4, uuid5

import httpx
from fastapi import Header, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select

from common.authorization import OperationalRole, role_is_allowed
from common.database import ActionRecord, AlertRecord, AuditLogRecord, IncidentProjectionRecord, IncidentRecord, IncidentLifecycleTransitionRecord, RcaReportRecord, ValidationObservationRecord
from common.models import RemediationAction, RemediationStatus, ResolutionReport
from common.recovery_observers import load_recovery_observer_registry
from common.repository import IncidentRepository
from common.resolution_lifecycle import LifecycleActor, LifecycleTransitionError, ResolutionState, create_lifecycle, extract_lifecycle, transition_lifecycle
from closure_service.observations import PrometheusRecoveryObserver

REQUESTED = "recovery.assessment.requested"
TERMINAL_ACTIONS = {"succeeded", "failed", "skipped", "policy_blocked", "rejected", "cancelled", "canceled"}
logger = logging.getLogger(__name__)


def digest(value):
    return "sha256:" + hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()


class AssessmentIdentity(BaseModel):
    model_config = ConfigDict(extra="forbid")
    actor_id: str = Field(min_length=1, max_length=255)
    actor_role: str = Field(min_length=1, max_length=64)
    tenant_id: str = Field(min_length=1, max_length=128)
    auth_jti: str = Field(min_length=1, max_length=255)


class AssessmentRequest(AssessmentIdentity):
    comment: str = Field(min_length=10, max_length=4000)


def authenticate(settings, identity, token):
    if not settings.service_internal_token:
        raise HTTPException(503, "Internal service authentication is not configured")
    if not hmac.compare_digest(token, settings.service_internal_token):
        raise HTTPException(403, "Internal service authentication failed")
    if not role_is_allowed(identity.actor_role, {OperationalRole.ADMIN.value, OperationalRole.HITL_APPROVER.value}):
        raise HTTPException(403, "Recovery assessment requires ADMIN or HITL_APPROVER")


async def context(session, incident, registry):
    """Bind all linked alerts, the current recommendation and pending execution work."""
    incident_id = UUID(str(incident["id"]))
    tenant = incident["tenant_id"]
    if incident.get("status") in {"closed", "resolved"}:
        raise HTTPException(409, "Incident is already closed")
    # External ticket ownership requires its own coordinated workflow.
    if incident.get("ticket_id"):
        raise HTTPException(409, "Linked-ticket closure requires the coordinated ticket workflow")
    actions = (await session.execute(select(ActionRecord).where(
        ActionRecord.tenant_id == tenant, ActionRecord.incident_id == incident_id,
    ).with_for_update())).scalars().all()
    if any(a.status not in TERMINAL_ACTIONS for a in actions):
        raise HTTPException(409, "Incident has unfinished execution or approval work")
    alert_ids = [UUID(str(value)) for value in incident.get("alert_ids", [])]
    alerts = (await session.execute(select(AlertRecord).where(
        AlertRecord.tenant_id == tenant, AlertRecord.id.in_(alert_ids),
    ))).scalars().all()
    if not alert_ids or len(alerts) != len(set(alert_ids)):
        raise HTTPException(409, "Assessment requires every linked alert to be available in this tenant")
    if any(a.service != incident["service"] or a.environment != incident["environment"] for a in alerts):
        raise HTTPException(409, "Linked alert scope differs from incident")
    profile = registry.assessment_profile_for(tenant_id=tenant, environment=incident["environment"],
        target=incident["service"], incident_id=incident_id, alerts=[{"name": a.name, "labels": (a.payload or {}).get("labels", {})} for a in alerts])
    if profile is None or not profile.allow_operator_verified_closure:
        raise HTTPException(409, "Operator-verified closure is not registered for this alert")
    projection = (await session.execute(select(IncidentProjectionRecord).where(
        IncidentProjectionRecord.tenant_id == tenant, IncidentProjectionRecord.incident_id == incident_id,
    ).with_for_update())).scalar_one_or_none()
    lifecycle = extract_lifecycle(incident)
    # Prove this is an operator-closable state before starting a window.
    if lifecycle:
        try:
            transition_lifecycle(lifecycle, ResolutionState.CLOSED, actor=LifecycleActor.OPERATOR)
        except LifecycleTransitionError as exc:
            raise HTTPException(409, "Incident lifecycle does not allow operator recovery closure") from exc
    binding = {
        "tenant_id": tenant, "incident_id": str(incident_id), "service": incident["service"],
        "environment": incident["environment"], "alert_name": profile.alert_name,
        "alert_names": sorted({a.name for a in alerts}),
        "alert_ids": sorted(str(a.id) for a in alerts), "status": incident["status"],
        "recommendation_id": str(projection.recommendation_id) if projection and projection.recommendation_id else None,
        "lifecycle": lifecycle,
        "projection_lifecycle": {"state": projection.lifecycle_state, "version": projection.lifecycle_version, "status": projection.status} if projection else None,
        "actions": sorted((str(a.id), a.status, str(a.updated_at)) for a in actions),
        "profile_digest": digest({"profile": profile.model_dump(mode="json"),
            "sources": [registry.source_for(c.spec).model_dump(mode="json") for c in profile.checks]}),
    }
    return profile, binding


async def commit_guard(session, incident, report, assessment_id, settings):
    """Run again under the closure transaction's incident lock."""
    if assessment_id is None or str(assessment_id) != report.metadata.get("assessment_id"):
        raise HTTPException(409, "Observed recovery requires a server-created assessment")
    row = await session.get(AuditLogRecord, UUID(str(assessment_id)))
    if row is None or row.action != REQUESTED or row.tenant_id != incident.get("tenant_id") or row.resource_id != str(incident["id"]):
        raise HTTPException(409, "Recovery assessment not found")
    registry = load_recovery_observer_registry(settings.recovery_observer_registry_path)
    _, binding = await context(session, incident, registry)
    if digest(binding) != row.payload["binding_digest"]:
        raise HTTPException(409, "Incident or observer registration changed; request a new assessment")
    if datetime.now(UTC) >= datetime.fromisoformat(row.payload["expires_at"]):
        raise HTTPException(409, "Recovery assessment expired")
    row.payload = {**row.payload, "status": "closed", "report_id": str(report.id),
        "validation_checksum": report.validation_checksum, "completed_at": datetime.now(UTC).isoformat(),
        "last_result": report.metadata["assessment"]["result"]}


async def sync_closed_assessment_projection(session, assessment_id):
    """Project a proven observed-recovery closure without inventing intermediate execution states.

    Called in the closure transaction or during an idempotent status retry. A
    legacy DETECTED projection must not override a committed verified closure.
    This exception requires the persisted assessment, report and observations;
    it is not exposed as an arbitrary lifecycle transition API.
    """
    audit = await session.get(AuditLogRecord, UUID(str(assessment_id)))
    if audit is None or audit.action != REQUESTED or audit.payload.get("status") != "closed":
        raise HTTPException(409, "A completed recovery assessment is required")
    report_id = UUID(audit.payload["report_id"])
    report = await session.get(RcaReportRecord, report_id)
    incident_id = UUID(audit.resource_id)
    incident = await session.get(IncidentRecord, incident_id)
    if (report is None or report.tenant_id != audit.tenant_id or report.incident_id != incident_id
            or incident is None or incident.tenant_id != audit.tenant_id or incident.status != "closed"):
        raise HTTPException(409, "Closed assessment identity mismatch")
    proof = report.payload
    metadata = proof.get("metadata") or {}
    result = (metadata.get("assessment") or {}).get("result") or {}
    if (proof.get("closure_kind") != "observed_recovery" or proof.get("health_restored") is not True
            or proof.get("alerts_cleared") is not True or metadata.get("assessment_id") != str(assessment_id)
            or metadata.get("corrective_execution_performed") is not False
            or metadata.get("technical_recovery_verified") is not True
            or digest(result) != audit.payload.get("validation_checksum")
            or digest(result) != proof.get("validation_checksum")
            or result.get("status") != "verified" or not result.get("checks")
            or any(c.get("status") != "passed" for c in result["checks"])):
        raise HTTPException(409, "Persisted independent recovery proof is incomplete")
    observations = (await session.execute(select(ValidationObservationRecord).where(
        ValidationObservationRecord.report_id == report_id,
        ValidationObservationRecord.tenant_id == audit.tenant_id,
    ))).scalars().all()
    expected = {s["result_checksum"] for c in result["checks"] for s in c["samples"]}
    if (not expected or {o.result_checksum for o in observations} != expected
            or any(not o.passed or o.remediation_action_id is not None or o.incident_id != incident_id for o in observations)):
        raise HTTPException(409, "Persisted recovery observations are incomplete")
    projection = (await session.execute(select(IncidentProjectionRecord).where(
        IncidentProjectionRecord.incident_id == incident_id, IncidentProjectionRecord.tenant_id == audit.tenant_id,
    ).with_for_update())).scalar_one_or_none()
    if projection is None:
        raise HTTPException(409, "Incident projection is missing")
    if projection.lifecycle_state == "CLOSED":
        return
    if projection.lifecycle_state == "EXECUTING":
        raise HTTPException(409, "Executing lifecycle cannot be superseded by observed recovery")
    previous = projection.lifecycle_state
    reason = "Recovery independently verified after operator-attested repair; no corrective execution performed."
    transition = IncidentLifecycleTransitionRecord(tenant_id=audit.tenant_id, incident_id=incident_id,
        sequence_no=projection.lifecycle_version, previous_state=previous, new_state="CLOSED",
        actor=audit.actor, reason=reason, idempotency_key=f"observed-recovery:{assessment_id}")
    session.add(transition)
    await session.flush()
    projection.lifecycle_state = "CLOSED"
    projection.lifecycle_version += 1
    projection.lifecycle_failure_code = None
    projection.lifecycle_failure_reason = None
    payload = {"schema_version": "kaiops.incident-lifecycle.v1", "transition_id": str(transition.transition_id),
        "incident_id": str(incident_id), "tenant_id": audit.tenant_id, "previous_state": previous,
        "new_state": "CLOSED", "version": projection.lifecycle_version, "actor": audit.actor,
        "reason": reason, "failure_code": None, "assessment_id": str(assessment_id), "report_id": str(report_id)}
    projection.projection_payload = {**dict(projection.projection_payload or {}), "incident_lifecycle": {
        "state": "CLOSED", "version": projection.lifecycle_version, "transition_id": str(transition.transition_id),
        "actor": audit.actor, "reason": reason, "failure_code": None,
        "occurred_at": transition.occurred_at.isoformat(), "assessment_id": str(assessment_id)}}
    await IncidentRepository(session).enqueue_resolution_event(event_id=f"incident-lifecycle:{transition.transition_id}",
        aggregate_id=str(incident_id), topic="incident-lifecycle-events", partition_key=str(incident_id),
        payload=payload, tenant_id=audit.tenant_id)


async def collect_assessment(registry, profile, record, *, now=None, observer=None):
    now = now or datetime.now(UTC)
    observer = observer or PrometheusRecoveryObserver()
    boundary = datetime.fromisoformat(record.get("observation_window_start") or record["requested_at"])
    binding = {"assessment_id": record["assessment_id"], "profile_digest": record["binding"]["profile_digest"],
               "phase": "post_assessment"}
    semaphore = asyncio.Semaphore(4)

    async def check_one(check):
        async with semaphore:
            try:
                samples = await observer.observe_window(registry.source_for(check.spec), check,
                    now=now, not_before=boundary, window_seconds=max(300, check.spec.observation_window_seconds),
                    binding=binding)
                span = (datetime.fromisoformat(samples[-1]["observed_at"]) - datetime.fromisoformat(samples[0]["observed_at"])).total_seconds() if samples else 0
                complete = len(samples) >= check.spec.minimum_sample_count and span >= max(300, check.spec.observation_window_seconds)
                status = "failed" if any(not s["passed"] for s in samples) else "passed" if complete else "warming_up"
                return {"validator_id": check.spec.validator_id, "kind": check.spec.kind, "status": status, "samples": samples}
            except (httpx.HTTPError, ValueError, TypeError, KeyError, OverflowError, AttributeError):
                return {"validator_id": check.spec.validator_id, "kind": check.spec.kind, "status": "unavailable", "samples": []}
    checks = await asyncio.gather(*(check_one(check) for check in profile.checks))
    status = "verified" if all(c["status"] == "passed" for c in checks) else "blocked" if any(c["status"] in {"failed", "unavailable"} for c in checks) else "pending_stability"
    return {"status": status, "observed_at": now.isoformat(), "checks": checks}


def mount_recovery_assessment_routes(app, settings, persist, build_event):
    def registry():
        if not settings.recovery_observer_registry_path:
            raise HTTPException(503, "Recovery observer registry is not configured")
        return load_recovery_observer_registry(settings.recovery_observer_registry_path)

    async def load_incident(session, incident_id, tenant):
        await session.execute(select(IncidentRecord).where(IncidentRecord.id == incident_id,
            IncidentRecord.tenant_id == tenant).with_for_update())
        incident = await IncidentRepository(session).get_incident(str(incident_id), tenant_id=tenant)
        if not incident:
            raise HTTPException(404, "Incident not found")
        return incident

    @app.post("/incidents/{incident_id}/recovery-assessments")
    async def request_assessment(incident_id: UUID, request: AssessmentRequest, x_kaiops_internal_token: str = Header(default="")):
        authenticate(settings, request, x_kaiops_internal_token)
        registered = registry()
        async with app.state.session_factory() as session:
            incident = await load_incident(session, incident_id, request.tenant_id)
            profile, binding = await context(session, incident, registered)
            now = datetime.now(UTC)
            assessment_id = uuid4()
            record = {**request.model_dump(), "assessment_id": str(assessment_id), "requested_at": now.isoformat(),
                "expires_at": (now + timedelta(hours=1)).isoformat(), "status": "pending_stability",
                "binding": binding, "binding_digest": digest(binding),
                "minimum_wait_seconds": max(max(300, c.spec.observation_window_seconds) + 2*c.step_seconds for c in profile.checks)}
            session.add(AuditLogRecord(id=assessment_id, tenant_id=request.tenant_id, actor=request.actor_id,
                action=REQUESTED, resource_type="incident", resource_id=str(incident_id), payload=record))
            await session.commit()
        return {key: record[key] for key in ("assessment_id", "status", "requested_at", "expires_at", "minimum_wait_seconds")}

    async def evaluate(incident_id, assessment_id, tenant):
        async with app.state.session_factory() as session:
            row = await session.get(AuditLogRecord, assessment_id)
            if row is None or row.tenant_id != tenant or row.resource_id != str(incident_id) or row.action != REQUESTED:
                raise HTTPException(404, "Recovery assessment not found")
            record = dict(row.payload)
            if record["status"] in {"closed", "expired", "superseded"}:
                if record["status"] == "closed":
                    await load_incident(session, incident_id, tenant)
                    await sync_closed_assessment_projection(session, assessment_id)
                    await session.commit()
                return {"assessment_id": str(assessment_id), "status": record["status"], "report_id": record.get("report_id")}
            if datetime.now(UTC) >= datetime.fromisoformat(record["expires_at"]):
                row.payload = {**record, "status": "expired"}
                await session.commit()
                return {"status": "expired", "assessment_id": str(assessment_id)}
            incident = await load_incident(session, incident_id, tenant)
            registered = registry()
            profile, binding = await context(session, incident, registered)
            if digest(binding) != record["binding_digest"]:
                row.payload = {**record, "status": "superseded"}
                await session.commit()
                return {"status": "superseded", "assessment_id": str(assessment_id)}
        # No database lock held during network collection.
        result = await collect_assessment(registered, profile, record)
        if result["status"] != "verified":
            async with app.state.session_factory() as session:
                row = (await session.execute(select(AuditLogRecord).where(AuditLogRecord.id == assessment_id).with_for_update())).scalar_one()
                if row.payload["status"] not in {"closed", "expired", "superseded"}:
                    row.payload = {**row.payload, "last_result": result}
                    await session.commit()
            return {"assessment_id": str(assessment_id), **result}
        lifecycle = binding["lifecycle"] or create_lifecycle(tenant_id=tenant, incident_id=incident_id,
            recommendation_id=binding["recommendation_id"] or assessment_id, plan={}, state=ResolutionState.DIAGNOSTIC_ONLY,
            reason_code="operator_recovery_assessment")
        metadata = {"closure_kind": "observed_recovery", "assessment_id": str(assessment_id),
            "corrective_execution_performed": False, "technical_recovery_verified": True,
            "actor_id": record["actor_id"], "actor_role": record["actor_role"], "auth_jti": record["auth_jti"],
            "operator_comment": record["comment"], "resolution_lifecycle": lifecycle,
            "independent_validation_observations": [s for c in result["checks"] for s in c["samples"]],
            "assessment": {"requested_at": record["requested_at"], "binding": binding, "result": result}}
        action = RemediationAction(id=assessment_id, tenant_id=tenant, incident_id=incident_id,
            action_type="recovery_verification", target=incident["service"], status=RemediationStatus.SKIPPED,
            parameters={"corrective_execution_performed": False}, output="Read-only recovery assessment; no corrective execution.")
        report = ResolutionReport(id=uuid5(assessment_id, "observed-recovery-report"), tenant_id=tenant,
            incident_id=incident_id, recommendation_id=binding["recommendation_id"], closure_kind="observed_recovery", closure_status="closed",
            root_cause="Causal analysis remains inconclusive; operator-attested repair is recorded separately.",
            impact=incident.get("summary") or f"Recovery assessed for {incident['service']}.",
            action_taken="Recovery independently verified after operator-attested repair; no corrective action executed by KaiMS.",
            validation={c["validator_id"]: True for c in result["checks"]}, health_restored=True, alerts_cleared=True,
            validation_checksum=digest(result), metadata=metadata)
        event = build_event(action=action, report=report, source_payload={"source": "operator-recovery-assessment"})
        persisted = await persist(app=app, action=action, report=report, source_payload={"source": "operator-recovery-assessment"},
            event_payload=event, sync_jira=False, observed_assessment_id=assessment_id)
        if persisted.get("status") == "stale_suppressed":
            raise HTTPException(409, persisted.get("reason"))
        return {"assessment_id": str(assessment_id), "status": "closed", "report_id": str(report.id),
            "corrective_execution_performed": False, "technical_recovery_verified": True, "checks": result["checks"]}

    @app.post("/incidents/{incident_id}/recovery-assessments/{assessment_id}/evaluate")
    async def evaluate_assessment(incident_id: UUID, assessment_id: UUID, request: AssessmentIdentity,
                                  x_kaiops_internal_token: str = Header(default="")):
        authenticate(settings, request, x_kaiops_internal_token)
        return await evaluate(incident_id, assessment_id, request.tenant_id)

    async def reconcile():
        if not settings.database_enabled or not getattr(app.state, "session_factory", None) or not settings.recovery_observer_registry_path:
            return
        async with app.state.session_factory() as session:
            rows = (await session.execute(select(AuditLogRecord).where(AuditLogRecord.action == REQUESTED,
                AuditLogRecord.payload["status"].as_string() == "pending_stability").order_by(AuditLogRecord.updated_at).limit(10))).scalars().all()
            candidates = [(UUID(r.resource_id), r.id, r.tenant_id) for r in rows]
        for incident_id, assessment_id, tenant in candidates:
            try:
                await evaluate(incident_id, assessment_id, tenant)
            except HTTPException as exc:
                async with app.state.session_factory() as session:
                    row = (await session.execute(select(AuditLogRecord).where(AuditLogRecord.id == assessment_id).with_for_update())).scalar_one()
                    if row.payload["status"] == "pending_stability":
                        row.payload = {**row.payload, "status": "superseded" if exc.status_code in {404, 409} else "pending_stability",
                                       "last_error": str(exc.detail), "last_attempt_at": datetime.now(UTC).isoformat()}
                        await session.commit()
            except Exception:
                logger.exception("Recovery assessment evaluation failed", extra={"assessment_id": str(assessment_id)})
    app.state.reconcile_recovery_assessments = reconcile
