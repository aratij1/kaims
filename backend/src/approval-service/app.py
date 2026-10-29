from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import os
from collections.abc import Awaitable, Callable, Coroutine
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import NAMESPACE_URL, UUID, uuid4, uuid5
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import httpx
from common.config import get_settings
from common.database import ApprovalAssignmentRecord, ApprovalCapacityRecord
from common.event_publishers import build_agent_event_contract, build_event_envelope
from common.kafka import KafkaConsumer
from common.kafka import consume_forever as consume_kafka_forever
from common.models import Approval, ApprovalDecision
from common.orchestration.execution_plan_contract import verify_plan_fingerprint
from common.rabbitmq import RabbitMQConsumer
from common.rabbitmq import consume_forever as consume_rabbitmq_forever
from common.repository import IncidentRepository
from common.service import create_app
from common.tenant_identity import require_tenant_id
from common.topics import APPROVAL_EVENTS, RESOLUTION_EVENTS
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, field_validator, model_validator
from sqlalchemy import func, select

settings = get_settings()
settings.service_name = "approval-service"
tasks: list[asyncio.Task] = []
_background_tasks: set[asyncio.Task] = set()

ConsumeRunner = Callable[[Any, Callable[[dict], Awaitable[None]]], Coroutine[Any, Any, None]]

PENDING_INCIDENTS: dict[str, dict] = {}
_HIGH_RISK_SEVERITIES = {"high", "critical"}
_NON_HUMAN_APPROVERS = {"", "system", "rca-agent", "automation-agent", "orchestrator"}
logger = logging.getLogger("kaiops.approval_service")


def _pending_key(tenant_id: str, incident_id: Any) -> str:
    return f"{require_tenant_id(tenant_id, source='approval cache identity')}:{str(incident_id)}"


def _looks_like_uuid(value: Any) -> bool:
    try:
        UUID(str(value or "").strip())
    except (TypeError, ValueError):
        return False
    return True


def _first_recommendation_id(*payloads: Any) -> str:
    recommendation_keys = {
        "recommendation_id",
        "remediation_recommendation_id",
        "recommended_action_id",
    }
    object_keys = {"recommendation", "approval", "source_payload", "data", "payload", "completed_payload"}

    def visit(value: Any, *, depth: int = 0) -> str:
        if depth > 6:
            return ""
        if isinstance(value, dict):
            for key in recommendation_keys:
                token = str(value.get(key) or "").strip()
                if _looks_like_uuid(token):
                    return token
            recommendation = value.get("recommendation")
            if isinstance(recommendation, dict):
                token = str(recommendation.get("id") or "").strip()
                if _looks_like_uuid(token):
                    return token
            for key in object_keys:
                nested = value.get(key)
                if isinstance(nested, dict):
                    found = visit(nested, depth=depth + 1)
                    if found:
                        return found
            return ""
        if isinstance(value, list):
            for item in value:
                found = visit(item, depth=depth + 1)
                if found:
                    return found
        return ""

    for payload in payloads:
        found = visit(payload)
        if found:
            return found
    return ""


def _recommendation_id_from_repository_payload(payload: Any) -> str:
    token = _first_recommendation_id(payload)
    if token:
        return token
    if isinstance(payload, dict):
        direct_id = str(payload.get("id") or "").strip()
        if _looks_like_uuid(direct_id):
            return direct_id
    return ""


def _signed_approval_readiness(context: dict[str, Any]) -> dict[str, Any]:
    recommendation = context.get("recommendation") if isinstance(context.get("recommendation"), dict) else {}
    metadata = recommendation.get("metadata") if isinstance(recommendation.get("metadata"), dict) else {}
    plan = metadata.get("execution_plan") if isinstance(metadata.get("execution_plan"), dict) else {}
    quality = metadata.get("evidence_quality") if isinstance(metadata.get("evidence_quality"), dict) else {}
    policy = plan.get("policy_decision") if isinstance(plan.get("policy_decision"), dict) else {}
    profile = metadata.get("connection_profile") if isinstance(metadata.get("connection_profile"), dict) else {}
    # `resolve_execution_plan` (common/orchestration/execution_plan.py) never
    # writes a `connection_profile` key at all - the connector it actually
    # resolved (with whatever `secret_ref`/`credential_ref` that connector
    # carries) is nested at `plan["connection"]["connector"]`. Every
    # catalog-compiled plan's real credential reference therefore lived
    # somewhere this check never looked, so `current_credentials` read
    # false for every one of them regardless of whether a real, valid
    # credential was actually resolved. Reproduced live: incident
    # ac90a378-23c8-4efa-98d8-7968448219e8's plan had a real, executable
    # docker-socket-proxy restart command with `available_connector: true`
    # (that field's own check already reads `plan.get("connector_id")`,
    # the plan's real top-level field) while `current_credentials` was
    # false for the exact same plan.
    plan_connector = (
        plan.get("connection", {}).get("connector", {})
        if isinstance(plan.get("connection"), dict) and isinstance(plan["connection"].get("connector"), dict)
        else {}
    )
    rollback = plan.get("rollback_commands") if isinstance(plan.get("rollback_commands"), list) else []
    validators = plan.get("validators") if isinstance(plan.get("validators"), list) else []
    credential_reference = str(
        profile.get("secret_ref")
        or profile.get("credential_ref")
        or plan_connector.get("secret_ref")
        or plan_connector.get("credential_ref")
        or metadata.get("secret_ref")
        or metadata.get("credential_ref")
        or ""
    ).strip()
    opaque_credential = credential_reference.startswith((
        "vault://", "secret://", "managed-identity://", "azure-keyvault://",
        "aws-secretsmanager://", "gcp-secretmanager://",
    ))
    checks = {
        "rca_version_binding": bool(plan.get("rca_version")),
        "evidence_snapshot_binding": bool(plan.get("evidence_snapshot_id")),
        "recommendation_version_binding": bool(plan.get("recommendation_version")),
        "approved_runbook": (
            str(metadata.get("runbook_status") or plan.get("runbook_status") or "").lower() == "approved"
        ),
        "valid_plan": bool(plan.get("plan_id") and plan.get("plan_fingerprint") and verify_plan_fingerprint(plan)),
        "execution_ready": (
            plan.get("execution_ready") is True
            and plan.get("diagnostic_only") is not True
            and str(plan.get("plan_kind") or "").lower() != "diagnostic"
        ),
        "governed_target": bool(plan.get("target_resource_id") or plan.get("remediation_target")),
        "available_connector": bool(
            plan.get("connector_id") or profile.get("connector_id") or profile.get("executor_type")
        ),
        "current_credentials": opaque_credential,
        "required_validators": bool(validators),
        "rollback_readiness": str(plan.get("rollback_mode") or "").lower() == "not_applicable" or bool(rollback),
        "policy_acceptance": str(policy.get("decision") or metadata.get("policy_decision") or "").lower()
        in ({"allow", "approved", "accept", "hitl", "hotl"} if settings.resolution_auto_execution_enabled
            else {"allow", "approved", "accept", "hitl"}),
        "evidence_threshold": (
            float(quality.get("evidence_coverage") or 0.0) >= 0.85
            and float(quality.get("citation_coverage") or 0.0) > 0.0
            and quality.get("evidence_fresh") is not False
            and int(quality.get("conflict_count") or quality.get("contradiction_count") or 0) == 0
        ),
    }
    signing_key = str(settings.service_internal_token or "").strip()
    if not signing_key:
        checks["readiness_signing_key"] = False
    missing = [name for name, passed in checks.items() if not passed]
    issued_at = datetime.now(UTC).isoformat()
    material = {
        "tenant_id": str(context.get("tenant_id") or recommendation.get("tenant_id") or ""),
        "incident_id": str(context.get("incident_id") or recommendation.get("incident_id") or ""),
        "recommendation_id": _first_recommendation_id(context, recommendation),
        "rca_version": str(plan.get("rca_version") or ""),
        "evidence_snapshot_id": str(plan.get("evidence_snapshot_id") or ""),
        "recommendation_version": str(plan.get("recommendation_version") or ""),
        "plan_id": str(plan.get("plan_id") or ""),
        "plan_fingerprint": str(plan.get("plan_fingerprint") or ""),
        "state": "execution_eligible" if not missing else "blocked",
        "checks": checks,
        "missing": missing,
        "issued_at": issued_at,
    }
    canonical = json.dumps(material, sort_keys=True, separators=(",", ":"))
    decision_id = hashlib.sha256(canonical.encode()).hexdigest()
    signature = hmac.new(signing_key.encode(), canonical.encode(), hashlib.sha256).hexdigest() if signing_key else ""
    return {**material, "decision_id": decision_id, "signature": f"hmac-sha256:{signature}" if signature else ""}


async def request_automatic_selection(payload: dict) -> None:
    """Prepare a bound remedy; execution remains governed by the resolution policy."""
    recommendation = payload.get("recommendation") or {}
    metadata = recommendation.get("metadata") or {}
    incident = payload.get("incident") or {}
    tenant = str(recommendation.get("tenant_id") or incident.get("tenant_id") or "")
    service = str(metadata.get("service") or incident.get("service") or "")
    environment = str(metadata.get("environment") or incident.get("environment") or "")
    control = metadata.get("resolution_control") or {}
    investigation = metadata.get("iterative_investigation") or {}
    grounded = investigation.get("conclusive") is True and metadata.get("rca_status") == "grounded"
    if control.get("disposition") == "watch_only":
        return
    if metadata.get("resolution_selection"):
        return
    if control.get("disposition") == "investigate" and not grounded:
        return
    body = {key: metadata.get(key) for key in ("analysis_request_id", "rca_version", "context_snapshot_id", "context_fingerprint")}
    body.update(tenant_id=tenant, incident_id=recommendation.get("incident_id"),
                alert_id=metadata.get("alert_id") or (payload.get("context") or {}).get("alert", {}).get("id"),
                recommendation_id=recommendation.get("id"), service=service, environment=environment,
                issue=incident.get("title") or recommendation.get("root_cause") or service,
                recommended_action=recommendation.get("recommended_action") or "")
    async with httpx.AsyncClient(timeout=60) as client:
        response = await client.post(f"{settings.resolution_agent_url.rstrip('/')}/resolution-catalog/assist",
            headers={"x-kaiops-internal-token": settings.service_internal_token}, json=body)
        if response.status_code in {409, 422}:
            logger.info("Automatic selection remains human-gated incident_id=%s", recommendation.get("incident_id"))
            return
        response.raise_for_status()


async def startup(app: FastAPI) -> None:
    workers = max(1, int(getattr(settings, "message_bus_worker_count", 1) or 1))
    consumers: list[tuple[str, Any, ConsumeRunner]] = []
    for worker in range(workers):
        consumers.append(
            (f"rabbitmq-w{worker + 1}", RabbitMQConsumer(settings, RESOLUTION_EVENTS), consume_rabbitmq_forever)
        )
    if settings.kafka_enabled:
        for worker in range(workers):
            consumers.insert(
                worker,
                (f"kafka-w{worker + 1}", KafkaConsumer(settings, RESOLUTION_EVENTS), consume_kafka_forever),
            )

    async def handle(payload: dict) -> None:
        incident_id = str(payload["recommendation"]["incident_id"])
        recommendation = payload.get("recommendation", {}) if isinstance(payload.get("recommendation"), dict) else {}
        tenant_id = require_tenant_id(
            recommendation.get("tenant_id")
            or payload.get("tenant_id")
            or (payload.get("incident") or {}).get("tenant_id"),
            source="resolution approval event",
        )
        cache_key = _pending_key(tenant_id, incident_id)
        metadata = recommendation.get("metadata", {}) if isinstance(recommendation.get("metadata"), dict) else {}
        control = metadata.get("resolution_control", {}) if isinstance(metadata.get("resolution_control"), dict) else {}
        PENDING_INCIDENTS[cache_key] = payload
        await request_automatic_selection(payload)
        if control.get("disposition") in {"watch_only", "investigate", "execution_ready"}:
            PENDING_INCIDENTS.pop(cache_key, None)
            return
        PENDING_INCIDENTS[cache_key] = payload

    for source, consumer, consume_forever in consumers:
        task = asyncio.create_task(consume_forever(consumer, handle), name=f"approval-service-{source}-consumer")
        tasks.append(task)


async def shutdown(_: FastAPI) -> None:
    for task in tasks:
        task.cancel()


app = create_app(title="KaiMS Approval Service", settings=settings, startup=startup, shutdown=shutdown)


@app.middleware("http")
async def require_internal_mutation_auth(request: Request, call_next):
    if request.method.upper() not in {"POST", "PUT", "PATCH", "DELETE"}:
        return await call_next(request)
    expected_token = settings.service_internal_token
    if not expected_token:
        return JSONResponse(status_code=503, content={"detail": "Internal service authentication is not configured"})
    supplied_token = str(request.headers.get("x-kaiops-internal-token") or "")
    if not hmac.compare_digest(supplied_token, expected_token):
        return JSONResponse(status_code=403, content={"detail": "Internal service authentication failed"})
    return await call_next(request)


# The one identity a policy-driven (no human) approval may ever be recorded
# under - fixed and distinct from any real username, so a policy-engine
# decision can never be mistaken for, or forged as, a person's approval in the
# audit trail.
AUTO_POLICY_APPROVER = "kaims-auto-policy"


class ApprovalRequest(BaseModel):
    incident_id: UUID
    recommendation_id: UUID | None = None
    tenant_id: str = Field(min_length=1, max_length=128)
    plan_id: UUID | None = None
    plan_fingerprint: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")
    approver: str
    approver_role: str = Field(default="hitl-reviewer", pattern="^(admin|hitl-reviewer|policy-engine)$")
    authorization_scope: str = Field(default="execution", pattern="^(dry_run|execution)$")
    channel: str = Field(default="web", pattern="^(slack|teams|email|web|policy-engine)$")
    comment: str | None = None

    @field_validator("tenant_id")
    @classmethod
    def tenant_must_be_explicit(cls, value: str) -> str:
        return require_tenant_id(value, source="approval request identity")

    @model_validator(mode="after")
    def policy_engine_role_is_internally_consistent(self) -> "ApprovalRequest":
        # "policy-engine" is a distinct role, not a human wearing a system hat -
        # it may only ever show up paired with the fixed system identity and its
        # own channel, and only once this deployment has explicitly opted into
        # unattended execution. Reject anything that mixes the two, rather than
        # silently coercing it - a caller sending mismatched fields is either a
        # bug or an attempt to slip a human decision through as a policy one (or
        # vice versa), and both must fail loudly.
        is_policy_engine = self.approver_role == "policy-engine" or self.channel == "policy-engine"
        if is_policy_engine:
            if self.approver_role != "policy-engine" or self.channel != "policy-engine":
                raise ValueError("policy-engine approvals require approver_role and channel to both be 'policy-engine'")
            if self.approver != AUTO_POLICY_APPROVER:
                raise ValueError(f"policy-engine approvals must be recorded under approver={AUTO_POLICY_APPROVER!r}")
            if not settings.resolution_auto_execution_enabled:
                raise ValueError("automatic execution is not enabled on this deployment")
        elif self.approver == AUTO_POLICY_APPROVER:
            raise ValueError("policy-engine identity cannot be used for human approval")
        return self


class ModifyRequest(ApprovalRequest):
    modified_action: str

    @model_validator(mode="after")
    def policy_engine_cannot_modify(self) -> "ModifyRequest":
        # Editing the proposed action is definitionally a human judgment call -
        # a policy engine may only ever accept the exact certified plan.
        if self.approver_role == "policy-engine":
            raise ValueError("policy-engine approvals cannot modify the proposed action")
        return self


class CapacityRequest(BaseModel):
    tenant_id: str = Field(min_length=1, max_length=128)
    username: str = Field(min_length=1, max_length=255)
    resource_names: list[str] = Field(min_length=1, max_length=50)
    weekly_hours: int = Field(ge=1, le=168)
    timezone: str = Field(default="UTC", max_length=64)
    working_days: list[int] = Field(default=[0, 1, 2, 3, 4], min_length=1, max_length=7)
    work_start: str = Field(default="09:00", pattern=r"^([01]\d|2[0-3]):[0-5]\d$")
    work_end: str = Field(default="17:00", pattern=r"^([01]\d|2[0-3]):[0-5]\d$")
    active: bool = True


class AssignmentTicket(BaseModel):
    incident_id: str = Field(min_length=1, max_length=128)
    service: str = Field(default="unknown", max_length=128)
    severity: str = Field(default="medium", max_length=32)
    resource_names: list[str] = Field(default_factory=list, max_length=50)
    estimated_hours: int | None = Field(default=None, ge=1, le=168)


class AutoAssignRequest(BaseModel):
    tenant_id: str = Field(min_length=1, max_length=128)
    tickets: list[AssignmentTicket] = Field(min_length=1, max_length=500)


def _capacity_payload(row: ApprovalCapacityRecord, allocated: int = 0) -> dict[str, Any]:
    return {
        "id": str(row.id), "username": row.username, "resource_names": row.resource_names or [],
        "weekly_hours": row.weekly_hours, "allocated_hours": allocated,
        "remaining_hours": max(0, row.weekly_hours - allocated), "timezone": row.timezone,
        "working_days": row.working_days or [], "work_start": row.work_start,
        "work_end": row.work_end, "active": row.active,
    }


def _is_working_now(row: ApprovalCapacityRecord) -> bool:
    try:
        local = datetime.now(ZoneInfo(row.timezone))
    except ZoneInfoNotFoundError:
        return False
    current = local.strftime("%H:%M")
    return local.weekday() in set(row.working_days or []) and row.work_start <= current < row.work_end


def _current_week_start() -> datetime:
    now = datetime.now(UTC)
    return (now - timedelta(days=now.weekday())).replace(hour=0, minute=0, second=0, microsecond=0)


@app.get("/capacity")
async def list_capacity(tenant_id: str = Query(min_length=1, max_length=128)) -> dict[str, Any]:
    tenant_id = require_tenant_id(tenant_id, source="capacity query")
    async with app.state.session_factory() as session:
        capacities = list((await session.scalars(select(ApprovalCapacityRecord).where(ApprovalCapacityRecord.tenant_id == tenant_id).order_by(ApprovalCapacityRecord.username))).all())
        allocated = dict((await session.execute(
            select(ApprovalAssignmentRecord.assignee, func.coalesce(func.sum(ApprovalAssignmentRecord.estimated_hours), 0))
            .where(
                ApprovalAssignmentRecord.status.in_(["assigned", "in_progress"]),
                ApprovalAssignmentRecord.tenant_id == tenant_id,
                ApprovalAssignmentRecord.created_at >= _current_week_start(),
            )
            .group_by(ApprovalAssignmentRecord.assignee)
        )).all())
    return {"rows": [_capacity_payload(row, int(allocated.get(row.username, 0))) for row in capacities]}


@app.put("/capacity/{username}")
async def upsert_capacity(username: str, request: CapacityRequest) -> dict[str, Any]:
    tenant_id = require_tenant_id(request.tenant_id, source="capacity request")
    if username.strip().lower() != request.username.strip().lower():
        raise HTTPException(status_code=422, detail="Path username must match payload username")
    if any(day < 0 or day > 6 for day in request.working_days) or request.work_start >= request.work_end:
        raise HTTPException(status_code=422, detail="Working days and start/end hours are invalid")
    try:
        ZoneInfo(request.timezone)
    except ZoneInfoNotFoundError as exc:
        raise HTTPException(status_code=422, detail="Unknown timezone") from exc
    resources = sorted({value.strip().lower() for value in request.resource_names if value.strip()})
    if not resources:
        raise HTTPException(status_code=422, detail="At least one resource name is required")
    async with app.state.session_factory() as session:
        row = await session.scalar(select(ApprovalCapacityRecord).where(ApprovalCapacityRecord.tenant_id == tenant_id, func.lower(ApprovalCapacityRecord.username) == request.username.strip().lower()))
        values = request.model_dump()
        values["username"] = request.username.strip()
        values["resource_names"] = resources
        values["working_days"] = sorted(set(request.working_days))
        if row is None:
            row = ApprovalCapacityRecord(**values)
            session.add(row)
        else:
            for key, value in values.items():
                setattr(row, key, value)
        await session.commit()
        await session.refresh(row)
    return _capacity_payload(row)


@app.get("/assignments")
async def list_assignments(tenant_id: str = Query(min_length=1, max_length=128)) -> dict[str, Any]:
    tenant_id = require_tenant_id(tenant_id, source="assignment query")
    async with app.state.session_factory() as session:
        rows = list((await session.scalars(select(ApprovalAssignmentRecord).where(ApprovalAssignmentRecord.tenant_id == tenant_id).order_by(ApprovalAssignmentRecord.created_at.desc()).limit(250))).all())
    return {"rows": [{"incident_id": row.incident_id, "assignee": row.assignee, "service": row.service, "estimated_hours": row.estimated_hours, "status": row.status, "assignment_reason": row.assignment_reason, "created_at": row.created_at.isoformat() if row.created_at else None} for row in rows]}


@app.post("/auto-assign")
async def auto_assign(request: AutoAssignRequest) -> dict[str, Any]:
    tenant_id = require_tenant_id(request.tenant_id, source="auto-assignment request")
    severity_hours = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    results: list[dict[str, Any]] = []
    async with app.state.session_factory() as session:
        capacities = list((await session.scalars(select(ApprovalCapacityRecord).where(ApprovalCapacityRecord.tenant_id == tenant_id, ApprovalCapacityRecord.active.is_(True)))).all())
        existing = {row.incident_id for row in (await session.scalars(select(ApprovalAssignmentRecord).where(ApprovalAssignmentRecord.tenant_id == tenant_id))).all()}
        allocated = dict((await session.execute(
            select(ApprovalAssignmentRecord.assignee, func.coalesce(func.sum(ApprovalAssignmentRecord.estimated_hours), 0))
            .where(
                ApprovalAssignmentRecord.status.in_(["assigned", "in_progress"]),
                ApprovalAssignmentRecord.tenant_id == tenant_id,
                ApprovalAssignmentRecord.created_at >= _current_week_start(),
            )
            .group_by(ApprovalAssignmentRecord.assignee)
        )).all())
        for ticket in request.tickets:
            if ticket.incident_id in existing:
                results.append({"incident_id": ticket.incident_id, "status": "already_assigned"})
                continue
            hours = ticket.estimated_hours or severity_hours.get(ticket.severity.lower(), 2)
            required = {ticket.service.strip().lower(), *(value.strip().lower() for value in ticket.resource_names)} - {"", "unknown"}
            eligible = []
            for capacity in capacities:
                skills = set(capacity.resource_names or [])
                remaining = capacity.weekly_hours - int(allocated.get(capacity.username, 0))
                matches = not required or bool(required & skills) or "all" in skills or "*" in skills
                if remaining >= hours and matches and _is_working_now(capacity):
                    eligible.append((remaining, -int(allocated.get(capacity.username, 0)), capacity.username, capacity))
            if not eligible:
                results.append({"incident_id": ticket.incident_id, "status": "unassigned", "reason": "No on-duty responder has matching resources and remaining capacity."})
                continue
            _, _, _, selected = max(eligible)
            reason = f"Matched {ticket.service} resources; {selected.weekly_hours - int(allocated.get(selected.username, 0))}h capacity available before assignment."
            session.add(ApprovalAssignmentRecord(tenant_id=tenant_id, incident_id=ticket.incident_id, assignee=selected.username, service=ticket.service, estimated_hours=hours, assignment_reason=reason))
            allocated[selected.username] = int(allocated.get(selected.username, 0)) + hours
            existing.add(ticket.incident_id)
            results.append({"incident_id": ticket.incident_id, "status": "assigned", "assignee": selected.username, "estimated_hours": hours, "reason": reason})
        await session.commit()
    return {"rows": results, "assigned": sum(1 for row in results if row["status"] == "assigned")}


@app.post("/approve", response_model=Approval)
async def approve(request: ApprovalRequest) -> Approval:
    approval = await _approval_from_request(request, ApprovalDecision.APPROVED)
    await _store_and_publish(approval)
    return approval


@app.post("/reject", response_model=Approval)
async def reject(request: ApprovalRequest) -> Approval:
    approval = await _approval_from_request(request, ApprovalDecision.REJECTED)
    await _store_and_publish(approval)
    return approval


@app.post("/request-evidence", response_model=Approval)
async def request_evidence(request: ApprovalRequest) -> Approval:
    if not str(request.comment or "").strip():
        raise HTTPException(status_code=422, detail="An evidence request reason is required.")
    approval = await _approval_from_request(request, ApprovalDecision.EVIDENCE_REQUESTED)
    await _store_and_publish(approval)
    return approval


@app.post("/modify", response_model=Approval)
async def modify(request: ModifyRequest) -> Approval:
    raise HTTPException(
        status_code=409,
        detail=(
            "Free-text approval modifications are disabled. Generate a new typed execution plan "
            "with a new plan_id and plan_fingerprint, then submit a new approval."
        ),
    )


async def _approval_from_request(
    request: ApprovalRequest,
    decision: ApprovalDecision,
    *,
    modified_action: str | None = None,
) -> Approval:
    pending = (
        await _load_approval_context(request.incident_id, tenant_id=request.tenant_id)
        if decision == ApprovalDecision.APPROVED
        else {}
    )
    recommendation_id = request.recommendation_id or await _resolve_recommendation_id(
        request.incident_id,
        tenant_id=request.tenant_id,
    )
    recommendation = pending.get("recommendation", {}) if isinstance(pending, dict) else {}
    metadata = recommendation.get("metadata", {}) if isinstance(recommendation, dict) else {}
    plan: dict[str, Any] = {}
    if decision == ApprovalDecision.MODIFIED:
        raise HTTPException(status_code=409, detail="Modified approvals cannot authorize execution.")
    if decision == ApprovalDecision.APPROVED:
        pending_recommendation_id = (
            _first_recommendation_id(pending, recommendation)
        )
        if pending_recommendation_id and str(recommendation_id) != pending_recommendation_id:
            raise HTTPException(
                status_code=409,
                detail="Approval recommendation is stale and does not match the current governed plan.",
            )
        pending_recommendation_id = pending_recommendation_id or str(recommendation_id)
        try:
            rca_version = int(metadata.get("rca_version") or 0)
        except (TypeError, ValueError):
            rca_version = 0
        if not rca_version:
            raise HTTPException(status_code=409, detail="Approval blocked: the current RCA version is unavailable.")
        try:
            async with app.state.session_factory() as session:
                plan = await IncidentRepository(session).get_current_execution_plan_for_incident(
                    tenant_id=request.tenant_id, incident_id=request.incident_id,
                    recommendation_id=recommendation_id, rca_version=rca_version,
                ) or {}
        except HTTPException:
            raise
        except Exception as exc:
            logger.exception("failed to load canonical execution plan")
            raise HTTPException(status_code=503, detail="Canonical execution plan is temporarily unavailable.") from exc
        if not plan:
            raise HTTPException(
                status_code=409,
                detail=(
                    "Approval blocked: this recommendation has no governed execution plan. "
                    "Regenerate incident analysis to compile a current plan before approval."
                ),
            )
        expected_tenant = str(plan.get("tenant_id") or "").strip()
        expected_incident = str(plan.get("incident_id") or "").strip()
        expected_plan_id = str(plan.get("plan_id") or "").strip()
        expected_fingerprint = str(plan.get("plan_fingerprint") or "").strip()
        if not expected_plan_id or not expected_fingerprint:
            raise HTTPException(
                status_code=409,
                detail=(
                    "Approval blocked: the governed execution plan is incomplete. "
                    "Regenerate incident analysis before approval."
                ),
            )
        selection = metadata.get("resolution_selection") if isinstance(metadata.get("resolution_selection"), dict) else {}
        if not str(plan.get("policy_version") or "").strip():
            plan["policy_version"] = str(
                (plan.get("policy_decision") or {}).get("version")
                or metadata.get("policy_version")
                or "resolution-policy.v1"
            ).strip()
        plan_ctx_fp = str(plan.get("context_fingerprint") or "").strip()
        meta_ctx_fp = str(metadata.get("context_fingerprint") or "").strip()
        plan_sel_id = str(plan.get("resolution_selection_id") or "").strip()
        meta_sel_id = str(selection.get("selection_id") or "").strip()
        req_plan_id = str(request.plan_id or "").strip()
        req_plan_fp = str(request.plan_fingerprint or "").strip()
        exact_bindings = {
            "tenant": str(plan.get("tenant_id") or "") == request.tenant_id,
            "incident": str(plan.get("incident_id") or "") == str(request.incident_id),
            "recommendation": str(plan.get("recommendation_id") or "") == pending_recommendation_id,
            "rca_version": int(plan.get("rca_version") or 0) == rca_version,
            "context_snapshot": str(plan.get("evidence_snapshot_id") or "") == str(metadata.get("context_snapshot_id") or ""),
            "context_fingerprint": (not plan_ctx_fp or not meta_ctx_fp or plan_ctx_fp == meta_ctx_fp),
            "selection": (not plan_sel_id or not meta_sel_id or plan_sel_id == meta_sel_id),
            "plan_id": (not req_plan_id or str(plan.get("plan_id") or "") == req_plan_id),
            "plan_fingerprint": (
                not req_plan_fp
                or str(plan.get("plan_fingerprint") or "") == req_plan_fp
                or (req_plan_id and str(plan.get("plan_id") or "") == req_plan_id)
            ),
            "policy_version": bool(str(plan.get("policy_version") or "").strip()),
        }
        mismatches = [name for name, matched in exact_bindings.items() if not matched]
        if mismatches:
            raise HTTPException(
                status_code=409,
                detail="Approval bindings do not match the canonical execution plan: " + ", ".join(mismatches),
            )
        pending = dict(pending)
        recommendation = dict(recommendation)
        metadata = dict(metadata)
        metadata["execution_plan"] = plan
        if request.approver_role == "policy-engine":
            from common.automatic_execution import automatic_execution_authorized
            incident = pending.get("incident") or {}
            if not automatic_execution_authorized(
                settings, tenant=request.tenant_id,
                environment=str(metadata.get("environment") or incident.get("environment") or ""),
                service=str(metadata.get("service") or incident.get("service") or ""),
            ) or (plan.get("policy_decision") or {}).get("decision") != "hotl" or (
                plan.get("approval_policy") or {}).get("decision") != "policy_required" or (
                str(plan.get("risk_tier") or "").lower() != "low"
                or float(recommendation.get("confidence") or 0) < 0.92
                or len(plan.get("actions") or []) != 1
            ):
                raise HTTPException(status_code=409, detail="Automatic approval is not authorized for this target and plan")
        recommendation["metadata"] = metadata
        pending["recommendation"] = recommendation
        readiness = _signed_approval_readiness(pending)
        if readiness.get("state") != "execution_eligible":
            missing = [str(item).replace("_", " ") for item in readiness.get("missing", []) if str(item).strip()]
            missing_detail = f" Missing controls: {', '.join(missing)}." if missing else ""
            raise HTTPException(
                status_code=409,
                detail=(
                    "Approval blocked: the current execution plan is not execution-eligible."
                    f"{missing_detail} Refresh evidence or regenerate analysis before approval."
                ),
            )
        if not verify_plan_fingerprint(plan):
            raise HTTPException(status_code=409, detail="Approval blocked: execution plan fingerprint is invalid.")
        if not expected_tenant or (expected_tenant.lower() == "default" and settings.auth_mode != "local"):
            raise HTTPException(status_code=409, detail="Approval blocked: execution plan has no verified tenant.")
        if request.tenant_id != expected_tenant:
            raise HTTPException(status_code=403, detail="Approval tenant does not match the execution plan tenant.")
        if str(request.incident_id) != expected_incident:
            raise HTTPException(status_code=409, detail="Approval incident does not match the execution plan incident.")
        if req_plan_id and req_plan_id != expected_plan_id:
            raise HTTPException(status_code=409, detail="Approval is not bound to the current execution plan fingerprint.")
        try:
            expiry = datetime.fromisoformat(str(plan.get("expiry") or "").replace("Z", "+00:00"))
        except ValueError:
            expiry = datetime.now(UTC) + timedelta(days=7)
        if expiry <= datetime.now(UTC):
            expiry = datetime.now(UTC) + timedelta(days=7)
    else:
        expected_plan_id = str(request.plan_id or "") or None
        expected_fingerprint = request.plan_fingerprint
        expiry = None
    return Approval(
        id=uuid5(NAMESPACE_URL, f"automatic-approval:{request.tenant_id}:{expected_fingerprint}")
        if request.approver_role == "policy-engine" else uuid4(),
        tenant_id=request.tenant_id,
        incident_id=request.incident_id,
        recommendation_id=recommendation_id,
        plan_id=expected_plan_id,
        plan_fingerprint=expected_fingerprint,
        approval_expires_at=expiry,
        approver_role=request.approver_role,
        authorization_scope=request.authorization_scope,
        decision=decision,
        approver=request.approver,
        channel=request.channel,
        comment=request.comment,
        modified_action=modified_action,
        metadata={
            "execution_confirmation_required": request.approver_role != "policy-engine",
            "impact": str(recommendation.get("impact") or "") if decision == ApprovalDecision.APPROVED else None,
            "authorization_scope": request.authorization_scope,
            "rca_version": plan.get("rca_version") if decision == ApprovalDecision.APPROVED else None,
            "evidence_snapshot_id": plan.get("evidence_snapshot_id") if decision == ApprovalDecision.APPROVED else None,
            "recommendation_version": plan.get("recommendation_version") if decision == ApprovalDecision.APPROVED else None,
            "resolution_selection_id": plan.get("resolution_selection_id") if decision == ApprovalDecision.APPROVED else None,
            "context_fingerprint": plan.get("context_fingerprint") if decision == ApprovalDecision.APPROVED else None,
            "policy_version": plan.get("policy_version") if decision == ApprovalDecision.APPROVED else None,
            "target_resource_id": (
                plan.get("target_resource_id") or plan.get("remediation_target")
                if decision == ApprovalDecision.APPROVED else None
            ),
            "connector_id": plan.get("connector_id") if decision == ApprovalDecision.APPROVED else None,
            "rollback_plan": (
                plan.get("rollback") or plan.get("rollback_commands")
                if decision == ApprovalDecision.APPROVED else None
            ),
            "service": plan.get("service") if decision == ApprovalDecision.APPROVED else None,
            "environment": (
                plan.get("environment")
                or (plan.get("connection") if isinstance(plan.get("connection"), dict) else {}).get("environment")
                or "prod"
                if decision == ApprovalDecision.APPROVED else None
            ),
            "remediation_target": (
                plan.get("remediation_target") or plan.get("target_resource_id")
                if decision == ApprovalDecision.APPROVED else None
            ),
            "recommended_action": (
                recommendation.get("recommended_action") or plan.get("title") or plan.get("summary")
                if decision == ApprovalDecision.APPROVED else None
            ),
            "recommended_commands": (
                plan.get("commands") or recommendation.get("commands") or []
                if decision == ApprovalDecision.APPROVED else []
            ),
            "credential_ref": (
                (plan.get("connection") if isinstance(plan.get("connection"), dict) else {}).get("credential_ref")
                or "vault://kaiops/prod/jenkins#api-token"
                if decision == ApprovalDecision.APPROVED else None
            ),
            "connection_profile": (
                {
                    "executor_type": (
                        (plan.get("connection") if isinstance(plan.get("connection"), dict) else {}).get("executor_type")
                        or (plan.get("connection") if isinstance(plan.get("connection"), dict) else {}).get("connection_type")
                        or os.getenv("REMEDIATION_DEFAULT_EXECUTOR", "jenkins")
                    ),
                    "connection_type": (
                        (plan.get("connection") if isinstance(plan.get("connection"), dict) else {}).get("connection_type")
                        or (plan.get("connection") if isinstance(plan.get("connection"), dict) else {}).get("executor_type")
                        or os.getenv("REMEDIATION_DEFAULT_EXECUTOR", "jenkins")
                    ),
                    "endpoint_url": (
                        (plan.get("connection") if isinstance(plan.get("connection"), dict) else {}).get("endpoint_url")
                        or (plan.get("connection") if isinstance(plan.get("connection"), dict) else {}).get("endpoint")
                        or os.getenv("REMEDIATION_JENKINS_URL", "http://jenkins:8080")
                    ),
                    "job_name": (
                        (plan.get("connection") if isinstance(plan.get("connection"), dict) else {}).get("job_name")
                        or os.getenv("REMEDIATION_JENKINS_JOB", "kaiops-auto-remediation")
                    ),
                    "credential_ref": (
                        (plan.get("connection") if isinstance(plan.get("connection"), dict) else {}).get("credential_ref")
                        or "vault://kaiops/prod/jenkins#api-token"
                    ),
                    "environment": (
                        plan.get("environment")
                        or (plan.get("connection") if isinstance(plan.get("connection"), dict) else {}).get("environment")
                        or "prod"
                    ),
                    "service": str(plan.get("service") or ""),
                    "target": str(plan.get("remediation_target") or plan.get("target_resource_id") or ""),
                    **(plan.get("connection") if isinstance(plan.get("connection"), dict) else {}),
                }
                if decision == ApprovalDecision.APPROVED else {}
            ),
            **({"execution_plan": plan} if decision == ApprovalDecision.APPROVED else {}),
            **(
                {
                    "runbook_id": str(plan.get("runbook_governance_id")),
                    "runbook_version": int(plan.get("playbook_version") or 1),
                    "runbook_status": str(plan.get("runbook_status") or "approved"),
                    "runbook_checksum": str(plan.get("runbook_checksum") or ""),
                }
                if decision == ApprovalDecision.APPROVED and plan.get("runbook_governance_id")
                else {}
            ),
        },
    )


async def _load_approval_context(incident_id: UUID, *, tenant_id: str) -> dict[str, Any]:
    normalized_incident_id = str(incident_id)
    normalized_tenant = require_tenant_id(tenant_id, source="approval request identity")
    cache_key = _pending_key(normalized_tenant, normalized_incident_id)
    memory_payload = PENDING_INCIDENTS.get(cache_key)
    if isinstance(memory_payload, dict):
        recommendation = memory_payload.get("recommendation")
        metadata = recommendation.get("metadata") if isinstance(recommendation, dict) else {}
        plan = metadata.get("execution_plan") if isinstance(metadata, dict) else {}
        if isinstance(plan, dict):
            plan_tenant = str(plan.get("tenant_id") or "").strip()
            if plan_tenant == normalized_tenant and not settings.database_enabled:
                return memory_payload
            if plan_tenant and plan_tenant != normalized_tenant:
                raise HTTPException(status_code=403, detail="Approval tenant does not match the execution plan tenant.")
    elif any(key.endswith(f":{normalized_incident_id}") for key in PENDING_INCIDENTS):
        # Deliberately indistinguishable from a missing incident for callers in
        # another tenant.
        raise HTTPException(status_code=404, detail="No tenant-scoped incident exists for this approval.")

    if not settings.database_enabled:
        return memory_payload if isinstance(memory_payload, dict) else {}

    try:
        async with app.state.session_factory() as session:
            repo = IncidentRepository(session)
            incident = await repo.get_incident(normalized_incident_id, tenant_id=normalized_tenant)
            if not isinstance(incident, dict):
                raise HTTPException(status_code=404, detail="No tenant-scoped incident exists for this approval.")
            recommendation = await repo.get_latest_recommendation_for_incident(
                normalized_incident_id,
                tenant_id=normalized_tenant,
            )
            if isinstance(recommendation, dict):
                metadata = dict(recommendation.get("metadata") or {})
                version = int(metadata.get("rca_version") or 0)
                canonical = await repo.get_current_execution_plan_for_incident(
                    tenant_id=normalized_tenant, incident_id=normalized_incident_id,
                    recommendation_id=recommendation["id"], rca_version=version,
                ) if version else None
                if canonical:
                    from common.database import GovernedResolutionPlanRecord
                    sel_id = canonical.get("resolution_selection_id")
                    selected = await session.get(GovernedResolutionPlanRecord, UUID(str(sel_id))) if sel_id else None
                    metadata["execution_plan"] = canonical
                    metadata["governed_resolution_plan"] = canonical
                    metadata["resolution_selection"] = dict(selected.payload) if selected else {}
                    metadata["dry_run_complete"] = True
                else:
                    # A proposed plan is not the canonical plan required by
                    # /approve. Never sign an eligible receipt for that draft.
                    proposed = metadata.pop("execution_plan", None)
                    if proposed:
                        metadata.setdefault("model_proposed_execution_plan", proposed)
                    metadata.pop("resolution_selection", None)
                recommendation = {**recommendation, "metadata": metadata}
            pending = await repo.get_pending_workflow(normalized_incident_id)
            bound_investigation = (
                await repo.get_bound_incident_investigation(
                    tenant_id=normalized_tenant,
                    incident_id=normalized_incident_id,
                    alert_id=incident.get("alert_id") or (recommendation.get("metadata") or {}).get("alert_id"),
                    recommendation_id=recommendation.get("id"),
                )
                if isinstance(recommendation, dict)
                else {}
            )
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception(
            "failed to restore durable approval context",
            extra={"incident_id": normalized_incident_id, "tenant_id": normalized_tenant},
        )
        raise HTTPException(status_code=503, detail="Durable approval context is temporarily unavailable.") from exc

    restored = _build_incident_context(
        {
            **incident,
            **({"recommendation": recommendation} if isinstance(recommendation, dict) else {}),
        },
        pending,
    )
    if isinstance(recommendation, dict):
        restored["recommendation"] = recommendation
    if isinstance(bound_investigation, dict) and bound_investigation:
        investigation_integrity = dict(bound_investigation.get("investigation_integrity") or {})
        durable_context_snapshot = dict(bound_investigation.get("context_snapshot") or {})
        if investigation_integrity.get("verified") is True and isinstance(recommendation, dict):
            try:
                alert_uuid = (
                    incident.get("alert_id")
                    or (recommendation.get("metadata") or {}).get("alert_id")
                    or (durable_context_snapshot.get("context") or {}).get("alert", {}).get("id")
                )
                restored["incident_investigation"] = IncidentRepository.build_incident_investigation_contract(
                    tenant_id=normalized_tenant,
                    project_id=str(incident.get("project_id") or "default"),
                    incident_id=normalized_incident_id,
                    alert_id=alert_uuid,
                    recommendation=recommendation,
                    context_snapshot=durable_context_snapshot,
                    approval={"approval_readiness": restored.get("approval_readiness")},
                )
            except Exception as exc:
                logger.warning("unable to build incident_investigation in approval context: %s", exc)
        restored["investigation_integrity"] = investigation_integrity
    PENDING_INCIDENTS[cache_key] = restored
    return restored


async def _resolve_recommendation_id(incident_id: UUID, *, tenant_id: str) -> UUID:
    normalized_incident_id = str(incident_id)
    normalized_tenant = require_tenant_id(tenant_id, source="approval recommendation identity")
    memory_payload = PENDING_INCIDENTS.get(_pending_key(normalized_tenant, normalized_incident_id))
    token = _first_recommendation_id(memory_payload)
    if token:
        return UUID(token)

    if settings.database_enabled:
        try:
            async with app.state.session_factory() as session:
                repo = IncidentRepository(session)
                recommendation = await repo.get_latest_recommendation_for_incident(
                    normalized_incident_id,
                    tenant_id=tenant_id,
                )
                pending = await repo.get_pending_workflow(normalized_incident_id)
                token = _recommendation_id_from_repository_payload(recommendation) or _first_recommendation_id(pending)
                if token:
                    return UUID(token)
        except Exception:
            logger.exception("failed to resolve approval recommendation", extra={"incident_id": normalized_incident_id})

    raise HTTPException(
        status_code=422,
        detail=(
            "Approval requires a recommendation_id, and no recommendation is linked "
            f"to incident {normalized_incident_id}."
        ),
    )


@app.get("/incident/{incident_id}")
async def get_incident(incident_id: str, tenant_id: str = Query(min_length=1, max_length=128)) -> dict:
    normalized_incident_id = str(incident_id or "").strip()
    normalized_tenant = require_tenant_id(tenant_id, source="approval incident query")
    if not normalized_incident_id:
        return {"incident_id": incident_id, "status": "unknown"}

    if settings.database_enabled:
        try:
            incident_uuid = UUID(normalized_incident_id)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail="incident_id must be a UUID") from exc
        context = await _load_approval_context(incident_uuid, tenant_id=normalized_tenant)
        return _build_incident_context(context, None)
    memory_payload = PENDING_INCIDENTS.get(_pending_key(normalized_tenant, normalized_incident_id))
    if isinstance(memory_payload, dict):
        return _build_incident_context(memory_payload, None)
    return {"incident_id": normalized_incident_id, "status": "unknown"}



def _build_incident_context(base_payload: dict[str, Any], pending_workflow: dict[str, Any] | None) -> dict[str, Any]:
    context = dict(base_payload or {})
    recommendation = context.get("recommendation") if isinstance(context.get("recommendation"), dict) else {}
    decision = context.get("decision") if isinstance(context.get("decision"), dict) else {}

    def _missing(value: Any) -> bool:
        if value is None:
            return True
        if isinstance(value, str):
            return not value.strip()
        return False

    if isinstance(pending_workflow, dict):
        pending_payload = pending_workflow.get("payload") if isinstance(pending_workflow.get("payload"), dict) else {}
        pending_recommendation = pending_payload.get("recommendation") if isinstance(pending_payload.get("recommendation"), dict) else {}
        pending_decision = pending_payload.get("decision") if isinstance(pending_payload.get("decision"), dict) else {}

        if not recommendation and pending_recommendation:
            recommendation = pending_recommendation
            context["recommendation"] = recommendation
        if not decision and pending_decision:
            decision = pending_decision
            context["decision"] = decision

        if _missing(context.get("incident_id")):
            context["incident_id"] = str(pending_workflow.get("incident_id") or "")
        if _missing(context.get("flow_id")):
            context["flow_id"] = str(pending_workflow.get("flow_id") or decision.get("flow_id") or "")
        if _missing(context.get("trace_id")):
            context["trace_id"] = str(pending_workflow.get("trace_id") or recommendation.get("trace_id") or "")
        if _missing(context.get("status")):
            context["status"] = str(pending_workflow.get("status") or "awaiting_approval")

    recommendation_id = _first_recommendation_id(context, recommendation, pending_workflow)
    if recommendation_id:
        context["recommendation_id"] = str(recommendation_id)

    if recommendation:
        if _missing(context.get("trace_id")):
            context["trace_id"] = str(recommendation.get("trace_id") or "")
        correlation_id = recommendation.get("correlation_id")
        if correlation_id and _missing(context.get("correlation_id")):
            context["correlation_id"] = str(correlation_id)

    if decision:
        if _missing(context.get("flow_id")):
            context["flow_id"] = str(decision.get("flow_id") or "")

    incident_id = str(context.get("incident_id") or "").strip()
    if incident_id:
        context["incident_id"] = incident_id

    rec_meta = recommendation.get("metadata") if isinstance(recommendation.get("metadata"), dict) else {}
    if isinstance(rec_meta.get("execution_plan"), dict) and rec_meta.get("execution_plan"):
        context["execution_plan"] = rec_meta["execution_plan"]
    if isinstance(rec_meta.get("governed_resolution_plan"), dict) and rec_meta.get("governed_resolution_plan"):
        context["governed_resolution_plan"] = rec_meta["governed_resolution_plan"]
    if isinstance(rec_meta.get("resolution_selection"), dict) and rec_meta.get("resolution_selection"):
        context["resolution_selection"] = rec_meta["resolution_selection"]

    context["approval_readiness"] = _signed_approval_readiness(context)
    readiness_obj = context["approval_readiness"] if isinstance(context.get("approval_readiness"), dict) else {}
    is_eligible = str(readiness_obj.get("state") or "").lower() in {"eligible", "execution_eligible"} and bool(readiness_obj.get("signature"))
    if not isinstance(context.get("investigation_integrity"), dict):
        context["investigation_integrity"] = {}
    if is_eligible:
        context["investigation_integrity"]["status"] = "verified"
        context["investigation_integrity"]["verified"] = True
        context["investigation_integrity"].setdefault("recommendation_id", context.get("recommendation_id"))
        context["investigation_integrity"].setdefault("context_snapshot_id", rec_meta.get("context_snapshot_id"))
    if not isinstance(context.get("incident_investigation"), dict):
        context["incident_investigation"] = {}
    if not isinstance(context["incident_investigation"].get("readiness"), dict):
        context["incident_investigation"]["readiness"] = {}
    if is_eligible:
        context["incident_investigation"]["readiness"]["approval_ready"] = True
        context["incident_investigation"]["readiness"]["blocking_reasons"] = []

    return context


async def _store_and_publish(approval: Approval) -> None:
    _attach_policy_metadata(approval)
    _enforce_high_risk_human_gate(approval)
    incident_id = str(approval.incident_id)
    cache_key = _pending_key(approval.tenant_id, incident_id)
    pending_context = PENDING_INCIDENTS.get(cache_key, {})
    if not isinstance(pending_context, dict):
        pending_context = {}
    PENDING_INCIDENTS[cache_key] = {
        **pending_context,
        "approval": approval.model_dump(mode="json"),
    }
    if settings.database_enabled:
        async with app.state.session_factory() as session:
            repo = IncidentRepository(session)
            await repo.save_approval(approval)
            pending = PENDING_INCIDENTS.get(cache_key, {})
            recommendation = pending.get("recommendation", {}) if isinstance(pending.get("recommendation"), dict) else {}
            decision = pending.get("decision", {}) if isinstance(pending.get("decision"), dict) else {}
            recommendation_id = str(approval.recommendation_id)
            status = "awaiting_approval"
            if approval.decision == ApprovalDecision.APPROVED and approval.authorization_scope != "dry_run":
                status = "approved"
            elif approval.decision == ApprovalDecision.REJECTED:
                status = "failed"
            elif approval.decision == ApprovalDecision.EVIDENCE_REQUESTED:
                status = "investigating"
            await repo.update_incident_approval_status(
                approval.incident_id,
                status=status,
                approval=approval,
            )
            await repo.save_incident_event(
                build_event_envelope(
                    event_type="incident.approval.recorded",
                    identity={
                        "incident_id": str(approval.incident_id),
                        "alert_id": None,
                        "trace_id": str(recommendation.get("trace_id") or ""),
                        "correlation_id": str(recommendation.get("correlation_id") or "") or None,
                        "causation_id": None,
                        "parent_event_id": None,
                    },
                    scope={
                        "tenant_id": approval.tenant_id,
                        "service": str(pending.get("incident", {}).get("service") if isinstance(pending.get("incident"), dict) else "unknown") or "unknown",
                        "environment": str(pending.get("incident", {}).get("environment") if isinstance(pending.get("incident"), dict) else "prod") or "prod",
                        "region": None,
                        "team": None,
                    },
                    state={
                        "severity": str(recommendation.get("severity") or "warning").lower(),
                        "status": status,
                        "owner": str(approval.approver or "") or None,
                    },
                    policy={
                        "risk_tier": str(decision.get("risk_tier") or "unknown"),
                        "execution_mode": str(decision.get("execution_mode") or "unknown"),
                        "requires_approval": decision.get("requires_approval"),
                        "policy_version": approval.metadata.get("policy_version"),
                        "policy_reason": approval.metadata.get("policy_reason"),
                    },
                    transport={
                        "provider": str(decision.get("message_bus_provider") or "unknown"),
                        "channel": APPROVAL_EVENTS,
                        "partition": None,
                        "offset": None,
                        "delivery_tag": None,
                    },
                    payload={
                        "recommendation_id": recommendation_id,
                        "plan_id": str(approval.plan_id or "") or None,
                        "plan_fingerprint": approval.plan_fingerprint,
                        "rca_version": approval.metadata.get("rca_version"),
                        "evidence_snapshot_id": approval.metadata.get("evidence_snapshot_id"),
                        "recommendation_version": approval.metadata.get("recommendation_version"),
                        "target_resource_id": approval.metadata.get("target_resource_id"),
                        "connector_id": approval.metadata.get("connector_id"),
                        "decision": approval.decision.value,
                        "approver": approval.approver,
                        "channel": approval.channel,
                        "comment": approval.comment,
                        "modified_action": approval.modified_action,
                        "authorization_scope": approval.authorization_scope,
                    },
                )
            )
            await session.commit()
    payload = _build_approval_event_payload(approval)
    if settings.temporal_pilot_enabled:
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.post(
                    f"{settings.orchestrator_url.rstrip('/')}/temporal/workflows/{approval.incident_id}/approval",
                    json=approval.model_dump(mode="json"),
                )
                response.raise_for_status()
        except Exception:
            logger.exception("temporal approval signal failed; publishing existing approval event fallback")
            await app.state.producer.publish(APPROVAL_EVENTS, payload, key=str(approval.incident_id))
    else:
        await app.state.producer.publish(APPROVAL_EVENTS, payload, key=str(approval.incident_id))
    _publish_evaluation_feedback(approval)


async def _post_evaluation_feedback(recommendation_id: str, body: dict[str, Any]) -> None:
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.post(
                f"{settings.evaluation_service_url.rstrip('/')}/evaluations/by-recommendation/{recommendation_id}/feedback",
                json=body,
            )
        response.raise_for_status()
    except Exception as exc:
        logger.warning("evaluation_service_feedback_publish_failed", extra={"error": str(exc)})


def _publish_evaluation_feedback(approval: Approval) -> None:
    """Fire-and-forget: never awaited, never allowed to affect the approval flow."""
    body = {
        "decision": approval.decision.value,
        "approver": approval.approver,
        "comment": approval.comment,
    }
    task = asyncio.create_task(_post_evaluation_feedback(str(approval.recommendation_id), body))
    _background_tasks.add(task)
    task.add_done_callback(_background_tasks.discard)


def _build_approval_event_payload(approval: Approval) -> dict[str, Any]:
    incident_id = str(approval.incident_id)
    pending = PENDING_INCIDENTS.get(_pending_key(approval.tenant_id, incident_id), {})
    recommendation = pending.get("recommendation", {}) if isinstance(pending.get("recommendation"), dict) else {}
    decision = pending.get("decision", {}) if isinstance(pending.get("decision"), dict) else {}
    incident = pending.get("incident", {}) if isinstance(pending.get("incident"), dict) else {}
    flow_id = str(decision.get("flow_id") or incident_id)
    recommendation_id = str(approval.recommendation_id)

    event_contract = build_agent_event_contract(
        flow_id=flow_id,
        incident_id=incident_id,
        trace_id=str(recommendation.get("trace_id") or ""),
        correlation_id=str(recommendation.get("correlation_id") or "") or None,
        agent="approval-service",
        payload={
            "decision": approval.decision.value,
            "approver": approval.approver,
            "channel": approval.channel,
            "authorization_scope": approval.authorization_scope,
            "plan_id": str(approval.plan_id or "") or None,
            "plan_fingerprint": approval.plan_fingerprint,
            "rca_version": approval.metadata.get("rca_version"),
            "evidence_snapshot_id": approval.metadata.get("evidence_snapshot_id"),
            "recommendation_version": approval.metadata.get("recommendation_version"),
            "target_resource_id": approval.metadata.get("target_resource_id"),
            "connector_id": approval.metadata.get("connector_id"),
            "topic": APPROVAL_EVENTS,
        },
        metadata={
            "policy_version": approval.metadata.get("policy_version"),
            "policy_reason": approval.metadata.get("policy_reason"),
            "recommendation_id": recommendation_id,
        },
        confidence=1.0,
        reasoning="approval outcome captured for gated remediation",
        citations=[f"recommendation://{recommendation_id}"],
        evidence_ids=[f"incident:{incident_id}"],
    )
    signed_envelope = build_event_envelope(
        event_type="incident.approval.decided",
        identity={
            "incident_id": incident_id,
            "alert_id": None,
            "trace_id": str(recommendation.get("trace_id") or ""),
            "correlation_id": str(recommendation.get("correlation_id") or "") or None,
            "causation_id": None,
            "parent_event_id": None,
        },
        scope={
            "tenant_id": approval.tenant_id,
            "service": str(incident.get("service") or "unknown"),
            "environment": str(incident.get("environment") or "unknown"),
        },
        state={"status": approval.decision.value},
        policy={"requires_approval": True},
        transport={"provider": "message-bus", "channel": APPROVAL_EVENTS},
        payload={
            "approval_id": str(approval.id),
            "recommendation_id": recommendation_id,
            "plan_id": str(approval.plan_id or ""),
            "plan_fingerprint": str(approval.plan_fingerprint or ""),
            "decision": approval.decision.value,
            "authorization_scope": approval.authorization_scope,
        },
    )
    if approval.approver_role == "policy-engine":
        event_contract["event_id"] = f"automatic-approval:{approval.id}:{approval.decision.value}"
    return {
        "approval": approval,
        "recommendation": recommendation,
        "decision": decision,
        "incident": incident,
        "event_contract": event_contract,
        "signed_envelope": signed_envelope,
    }


def _pending_severity_for_incident(tenant_id: str, incident_id: str) -> str:
    payload = PENDING_INCIDENTS.get(_pending_key(tenant_id, incident_id), {})
    if not isinstance(payload, dict):
        return ""

    recommendation = payload.get("recommendation", {})
    if isinstance(recommendation, dict):
        severity = str(recommendation.get("severity") or "").strip().lower()
        if severity:
            return severity

    incident = payload.get("incident", {})
    if isinstance(incident, dict):
        return str(incident.get("severity") or "").strip().lower()

    return ""


def _attach_policy_metadata(approval: Approval) -> None:
    payload = PENDING_INCIDENTS.get(_pending_key(approval.tenant_id, approval.incident_id), {})
    if not isinstance(payload, dict):
        return

    decision = payload.get("decision", {}) if isinstance(payload.get("decision"), dict) else {}
    recommendation = payload.get("recommendation", {}) if isinstance(payload.get("recommendation"), dict) else {}
    recommendation_metadata = recommendation.get("metadata", {}) if isinstance(recommendation.get("metadata"), dict) else {}

    policy_version = str(
        decision.get("policy_version") or recommendation_metadata.get("policy_version") or ""
    ).strip()
    policy_reason = str(
        decision.get("policy_reason") or recommendation_metadata.get("policy_reason") or ""
    ).strip()

    if policy_version:
        approval.metadata["policy_version"] = policy_version
    if policy_reason:
        approval.metadata["policy_reason"] = policy_reason
    if decision:
        approval.metadata["orchestration_decision"] = {
            "workflow": decision.get("workflow"),
            "requires_approval": decision.get("requires_approval"),
            "message_bus_provider": decision.get("message_bus_provider"),
            "stream_count": decision.get("stream_count"),
            "stream_threshold": decision.get("stream_threshold"),
        }


def _enforce_high_risk_human_gate(approval: Approval) -> None:
    if approval.approver_role == "policy-engine":
        return
    severity = _pending_severity_for_incident(approval.tenant_id, str(approval.incident_id))
    if severity not in _HIGH_RISK_SEVERITIES:
        return

    approver = str(approval.approver or "").strip().lower()
    if approver in _NON_HUMAN_APPROVERS or approver.endswith("-agent"):
        raise HTTPException(
            status_code=422,
            detail="High/critical incidents require a human approver identity.",
        )
