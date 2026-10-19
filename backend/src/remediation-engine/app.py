from __future__ import annotations

import asyncio
import logging
import re
import hashlib
import os
from collections.abc import Awaitable, Callable, Coroutine
from datetime import datetime
from typing import Any
from uuid import UUID

import httpx
from sqlalchemy import select, text

from ai_workbench_common.agent_runtime import PolicyViolation
from common.config import get_settings
from common.database import ActionRecord
from common.continuous_learning import validate_automatic_runbook_use
from common.event_publishers import build_agent_event_contract, build_event_envelope, normalize_payload
from common.kafka import KafkaConsumer, consume_forever as consume_kafka_forever
from common.models import Approval, ApprovalDecision, RemediationAction, RemediationStatus, utc_now
from common.orchestration.execution_plan_contract import canonical_plan_fingerprint, verify_plan_fingerprint
from common.orchestration.safe_remediation import PreflightEvidence
from common.tenant_identity import require_tenant_id, verify_event_envelope
from common.resolution_lifecycle import LifecycleActor, ResolutionState, create_lifecycle, decide_resolution_control, extract_lifecycle, transition_lifecycle
from common.rabbitmq import RabbitMQConsumer, consume_forever as consume_rabbitmq_forever
from common.repository import IncidentRepository
from common.service import create_app
from common.telemetry import EVENTS_PROCESSED
from common.topics import APPROVAL_EVENTS, REMEDIATION_EVENTS, RESOLUTION_EVENTS
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field
from remediation_engine import RemediationEngine
from remediation_engine.execution_contract import bind_execution_contract, verify_execution_contract

settings = get_settings()
settings.service_name = "remediation-engine"
engine = RemediationEngine()
tasks: list[asyncio.Task] = []
idempotency_locks: dict[str, asyncio.Lock] = {}
target_execution_locks: dict[str, asyncio.Lock] = {}
logger = logging.getLogger("remediation-engine")


class DiagnosticCompletionRequest(BaseModel):
    incident_id: UUID


class EmergencyStopRequest(BaseModel):
    tenant_id: str = Field(min_length=1, max_length=128)
    actor: str = Field(min_length=1, max_length=255)
    reason: str = Field(min_length=8, max_length=2000)

ACTIVE_EXECUTION_STATUSES = {
    RemediationStatus.PENDING.value,
    RemediationStatus.POLICY_CHECKED.value,
    RemediationStatus.APPROVED.value,
    RemediationStatus.DISPATCHING.value,
    RemediationStatus.EXECUTOR_ACCEPTED.value,
    RemediationStatus.RUNNING.value,
    RemediationStatus.VERIFYING.value,
}

TERMINAL_EXECUTION_STATUSES = frozenset({
    RemediationStatus.SUCCEEDED, RemediationStatus.FAILED, RemediationStatus.SKIPPED,
    RemediationStatus.EXECUTION_FAILED, RemediationStatus.VALIDATION_FAILED,
    RemediationStatus.DISPATCH_FAILED, RemediationStatus.POLICY_BLOCKED,
    RemediationStatus.ROLLED_BACK, RemediationStatus.ROLLBACK_FAILED,
    RemediationStatus.CANCELLED, RemediationStatus.TIMED_OUT,
    RemediationStatus.MANUAL_INTERVENTION_REQUIRED,
})

ConsumeRunner = Callable[[Any, Callable[[dict], Awaitable[None]]], Coroutine[Any, Any, None]]


async def _reconcile_stale_remediating(app: FastAPI) -> int:
    """Return stale projections to an operator-actionable approved state.

    A recent non-terminal action always wins. An action beyond the bounded
    execution deadline is first marked timed_out, preserving its audit trail,
    and only incidents with a persisted human approval are returned to
    approved for an explicit retry.
    """
    session_factory = getattr(app.state, "session_factory", None)
    if session_factory is None:
        return 0
    timeout_minutes = max(5, int(os.getenv("REMEDIATION_STALE_TIMEOUT_MINUTES", "20")))
    active = "'pending','policy_checked','approved','dispatching','running'"
    from common.advisory_lock import advisory_session
    async with advisory_session(session_factory, "kaiops_remediation_watchdog") as session:
        if session is None:
            return 0
        blocked_waiting = await session.execute(
            text(
                "UPDATE incident_projections p SET p.status='awaiting_approval', p.updated_at=UTC_TIMESTAMP(), "
                "p.projection_payload=JSON_SET(COALESCE(p.projection_payload, JSON_OBJECT()), "
                "'$.status', 'awaiting_approval', '$.state', 'awaiting_approval') "
                "WHERE p.status='remediating' "
                "AND EXISTS (SELECT 1 FROM actions a WHERE a.incident_id=p.incident_id "
                "AND a.status IN ('awaiting_approval','policy_blocked'))"
            )
        )
        false_remediating = await session.execute(
            text(
                "UPDATE incident_projections p SET "
                "p.status=CASE WHEN COALESCE(p.requires_approval, 0)=1 THEN 'awaiting_approval' ELSE 'approved' END, "
                "p.updated_at=UTC_TIMESTAMP(), "
                "p.projection_payload=JSON_SET(COALESCE(p.projection_payload, JSON_OBJECT()), "
                "'$.status', CASE WHEN COALESCE(p.requires_approval, 0)=1 THEN 'awaiting_approval' ELSE 'approved' END, "
                "'$.state', CASE WHEN COALESCE(p.requires_approval, 0)=1 THEN 'awaiting_approval' ELSE 'approved' END) "
                "WHERE p.status='remediating' "
                "AND NOT EXISTS (SELECT 1 FROM actions a WHERE a.incident_id=p.incident_id "
                "AND a.status NOT IN ('failed','execution_failed','dispatch_failed','validation_failed','timed_out','cancelled','skipped','policy_blocked','rolled_back','rollback_failed'))"
            )
        )
        await session.execute(
            text(
                f"UPDATE actions SET status='timed_out', updated_at=UTC_TIMESTAMP() "
                f"WHERE status IN ({active}) "
                "AND updated_at < TIMESTAMPADD(MINUTE, -:timeout_minutes, UTC_TIMESTAMP())"
            ),
            {"timeout_minutes": timeout_minutes},
        )
        result = await session.execute(
            text(
                f"UPDATE incident_projections p SET "
                "p.status='approved', p.latest_event_type='incident.remediation.stale_reconciled', "
                "p.latest_event_at=UTC_TIMESTAMP(), p.updated_at=UTC_TIMESTAMP(), "
                "p.projection_payload=JSON_SET(COALESCE(p.projection_payload, JSON_OBJECT()), "
                "'$.status', 'approved', '$.state', 'approved', "
                "'$.remediation_status', 'stale_reconciled') "
                "WHERE p.status='remediating' "
                "AND p.updated_at < TIMESTAMPADD(MINUTE, -:timeout_minutes, UTC_TIMESTAMP()) "
                "AND EXISTS (SELECT 1 FROM approvals ap WHERE ap.incident_id=p.incident_id "
                "AND ap.decision='approved') "
                f"AND NOT EXISTS (SELECT 1 FROM actions a WHERE a.incident_id=p.incident_id AND a.status IN ({active}))"
            ),
            {"timeout_minutes": timeout_minutes},
        )
        await session.commit()
        reconciled = (
            int(result.rowcount or 0)
            + int(false_remediating.rowcount or 0)
            + int(blocked_waiting.rowcount or 0)
        )
        if reconciled:
            logger.warning("reconciled %s stale remediating incident(s) to approved", reconciled)
        return reconciled



async def _remediation_watchdog(app: FastAPI) -> None:
    interval_seconds = max(30, int(os.getenv("REMEDIATION_WATCHDOG_INTERVAL_SECONDS", "60")))
    while True:
        try:
            await _reconcile_stale_remediating(app)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("remediation lifecycle watchdog failed")
        await asyncio.sleep(interval_seconds)


def _first_non_empty(*values: Any) -> str | None:
    for value in values:
        token = str(value or "").strip()
        if token:
            return token
    return None


def _looks_like_uuid(token: str | None) -> bool:
    if not token:
        return False
    try:
        UUID(str(token))
    except (TypeError, ValueError):
        return False
    return True


def _remediation_workflow_id(approval: Approval, workflow_key: str) -> str:
    # The action key remains stable for idempotent persistence, while each
    # separately persisted approval is a new authorized retry attempt. Temporal
    # reports workflows that return a failed action as COMPLETED, so reusing
    # only workflow_key silently attaches retries to the old completed run.
    approval_attempt = str(approval.id).replace("-", "")
    return f"kaiops-remediation-{workflow_key}-{approval_attempt}"


def _execution_plan_fingerprint(action: RemediationAction) -> str:
    plan = action.parameters.get("execution_plan")
    plan = plan if isinstance(plan, dict) else {}
    normalized = {
        key: [str(item).strip() for item in plan.get(key, []) if str(item).strip()]
        for key in ("commands", "scripts", "queries")
        if isinstance(plan.get(key, []), list)
    }
    return hashlib.sha256(repr(normalized).encode("utf-8")).hexdigest()


def _advance_action_lifecycle(action: RemediationAction) -> None:
    lifecycle = extract_lifecycle(action.parameters, action.metadata)
    if not lifecycle:
        return
    if action.status == RemediationStatus.SUCCEEDED:
        receipt = action.parameters.get("execution_result") or {}
        if (lifecycle.get("state") == ResolutionState.READY_TO_EXECUTE.value
                and receipt.get("executed") is True and receipt.get("recovery_validated") is True):
            lifecycle = transition_lifecycle(
                lifecycle, ResolutionState.EXECUTING, actor=LifecycleActor.REMEDIATION,
                execution={"action_id": str(action.id), "status": action.status.value,
                           "reconciled_from_executor_receipt": True},
            )
        state, reason = ResolutionState.VALIDATING, None
    elif action.status in {RemediationStatus.ROLLED_BACK}:
        state, reason = ResolutionState.ROLLED_BACK, "rollback_completed"
    elif action.status in {RemediationStatus.POLICY_BLOCKED, RemediationStatus.AWAITING_APPROVAL}:
        state, reason = ResolutionState.BLOCKED_RETRYABLE, "policy_precondition_failed"
    elif action.status in {RemediationStatus.TIMED_OUT, RemediationStatus.DISPATCH_FAILED, RemediationStatus.EXECUTION_FAILED, RemediationStatus.FAILED}:
        if (lifecycle.get("state") == ResolutionState.READY_TO_EXECUTE.value
                and not (action.parameters.get("execution_result") or {}).get("accepted")):
            state, reason = ResolutionState.BLOCKED_RETRYABLE, "dispatch_not_accepted"
        else:
            state, reason = ResolutionState.FAILED_RETRYABLE, "execution_failed"
    elif action.status == RemediationStatus.SKIPPED and action.action_type == "diagnostic_completion":
        # The diagnostic branch remains non-mutating. Closure owns the final
        # transition after it has durably recorded the diagnostic evidence.
        state, reason = ResolutionState.DIAGNOSTIC_ONLY, "diagnostic_completed_pending_closure"
        if str(lifecycle.get("state") or "").strip().lower() != ResolutionState.DIAGNOSTIC_ONLY.value:
            # A finalized catalog plan can legitimately replace an earlier
            # executable proposal with a diagnostic-only plan. Rebase the
            # lifecycle onto that authoritative plan instead of attempting the
            # illegal READY_TO_EXECUTE -> DIAGNOSTIC_ONLY transition observed
            # when a stale approval/control envelope reaches reconciliation.
            plan = action.parameters.get("execution_plan")
            plan = plan if isinstance(plan, dict) else {}
            prior_identity = f"{lifecycle.get('recommendation_id')}:{lifecycle.get('state_version', 0)}"
            lifecycle = create_lifecycle(
                tenant_id=action.tenant_id or str(lifecycle.get("tenant_id") or "default"),
                incident_id=action.incident_id,
                recommendation_id=(
                    action.parameters.get("recommendation_id")
                    or lifecycle.get("recommendation_id")
                    or action.approval_id
                    or "diagnostic-reconciliation"
                ),
                plan=plan,
                state=ResolutionState.DIAGNOSTIC_ONLY,
                reason_code="finalized_plan_diagnostic",
                supersedes=prior_identity,
                control=decide_resolution_control(
                    plan,
                    requires_approval=False,
                    sources=({"watch_only": bool(action.parameters.get("watch_only_closure"))},),
                ),
            )
    elif action.status == RemediationStatus.SKIPPED:
        state, reason = ResolutionState.FAILED_TERMINAL, "execution_skipped"
    else:
        state, reason = ResolutionState.EXECUTING, None
    action.parameters["resolution_lifecycle"] = transition_lifecycle(
        lifecycle, state, reason_code=reason, actor=LifecycleActor.REMEDIATION,
        execution={"action_id": str(action.id), "status": action.status.value, "error": action.error},
    )


def _extract_resolution_context(source_payload: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    recommendation = source_payload.get("recommendation", {}) if isinstance(source_payload.get("recommendation"), dict) else {}
    decision = source_payload.get("decision", {}) if isinstance(source_payload.get("decision"), dict) else {}
    incident = source_payload.get("incident", {}) if isinstance(source_payload.get("incident"), dict) else {}
    metadata = recommendation.get("metadata", {}) if isinstance(recommendation.get("metadata"), dict) else {}
    orchestration = metadata.get("orchestration_decision", {}) if isinstance(metadata.get("orchestration_decision"), dict) else {}
    return recommendation, decision, incident, orchestration


def _is_auto_close_diagnostic_resolution(source_payload: dict[str, Any]) -> bool:
    """Close a completed non-mutating diagnostic branch without approval."""
    recommendation, decision, incident, orchestration = _extract_resolution_context(source_payload)
    metadata = recommendation.get("metadata", {}) if isinstance(recommendation.get("metadata"), dict) else {}
    persisted = metadata.get("resolution_control", {}) if isinstance(metadata.get("resolution_control"), dict) else {}
    if persisted.get("schema_version") == "kaims.resolution-control.v1":
        if persisted.get("conflicts"):
            return False
        plan = metadata.get("execution_plan", {}) if isinstance(metadata.get("execution_plan"), dict) else {}
        executable = [*(plan.get("commands") or []), *(plan.get("scripts") or [])]
        finalized_diagnostic = (
            plan.get("diagnostic_only") is True
            or plan.get("execution_ready") is False
            or str(plan.get("plan_kind") or "").strip().lower() == "diagnostic"
            or not any(str(item).strip() for item in executable)
        )
        return (
            persisted.get("disposition") == "watch_only"
            and persisted.get("auto_close") is True
            and persisted.get("watch_only_authorized") is True
            and finalized_diagnostic
        )
    plan = metadata.get("execution_plan", {}) if isinstance(metadata.get("execution_plan"), dict) else {}
    control = decide_resolution_control(
        plan,
        requires_approval=bool(decision.get("requires_approval", True)),
        sources=(recommendation, metadata, decision, orchestration, incident),
    )
    return control["disposition"] == "watch_only" and control["auto_close"] is True


def _derive_remediation_target(source_payload: dict[str, Any], action: RemediationAction) -> str | None:
    recommendation, _, incident, _ = _extract_resolution_context(source_payload)
    metadata = recommendation.get("metadata", {}) if isinstance(recommendation.get("metadata"), dict) else {}

    candidate_target = _first_non_empty(
        action.target,
        metadata.get("remediation_target"),
        recommendation.get("target"),
        recommendation.get("resource"),
        incident.get("deployment"),
        incident.get("service"),
    )
    if candidate_target and _looks_like_uuid(candidate_target):
        return _first_non_empty(incident.get("service"), metadata.get("service"), candidate_target)
    return candidate_target


def _enrich_action_from_source_payload(action: RemediationAction, source_payload: dict[str, Any]) -> RemediationAction:
    recommendation, _, incident, _ = _extract_resolution_context(source_payload)
    metadata = recommendation.get("metadata", {}) if isinstance(recommendation.get("metadata"), dict) else {}

    target = _derive_remediation_target(source_payload, action)
    if target:
        action.target = target

    service = _first_non_empty(incident.get("service"), metadata.get("service"))
    if service and not str(action.parameters.get("service") or "").strip():
        action.parameters["service"] = service

    environment = _first_non_empty(incident.get("environment"), metadata.get("environment"))
    if environment and not str(action.parameters.get("environment") or "").strip():
        action.parameters["environment"] = environment

    recommended_action = _first_non_empty(recommendation.get("recommended_action"), recommendation.get("action"))
    if recommended_action and not str(action.parameters.get("recommended_action") or "").strip():
        action.parameters["recommended_action"] = recommended_action

    root_cause = _first_non_empty(recommendation.get("root_cause"), recommendation.get("rationale"))
    if root_cause and not str(action.parameters.get("root_cause") or "").strip():
        action.parameters["root_cause"] = root_cause

    impact = _first_non_empty(recommendation.get("impact"))
    if impact and not str(action.parameters.get("impact") or "").strip():
        action.parameters["impact"] = impact

    return action


def _extract_approval_payload(payload: dict[str, Any]) -> dict[str, Any]:
    approval = payload.get("approval") if isinstance(payload, dict) else None
    if isinstance(approval, dict):
        return approval
    return payload


def _build_remediation_event_payload(
    *,
    action: RemediationAction,
    source_payload: dict[str, Any],
    source: str,
) -> dict[str, Any]:
    incident_id = str(action.incident_id)
    recommendation = source_payload.get("recommendation", {}) if isinstance(source_payload.get("recommendation"), dict) else {}
    decision = source_payload.get("decision", {}) if isinstance(source_payload.get("decision"), dict) else {}
    flow_id = str(decision.get("flow_id") or incident_id)
    trace_id = str(recommendation.get("trace_id") or "")
    correlation_id = str(recommendation.get("correlation_id") or "") or None

    event_contract = build_agent_event_contract(
        flow_id=flow_id,
        incident_id=incident_id,
        trace_id=trace_id,
        correlation_id=correlation_id,
        agent="remediation-engine",
        payload={
            "action_type": action.action_type,
            "status": action.status.value,
            "topic": REMEDIATION_EVENTS,
            "source": source,
        },
        metadata={
            "policy_version": action.parameters.get("policy_version"),
            "policy_reason": action.parameters.get("policy_reason") or action.metadata.get("policy_reason"),
        },
        confidence=1.0 if action.status.value == "succeeded" else 0.6,
        reasoning="remediation execution result captured for closure validation",
        citations=[f"action://{action.id}"],
        evidence_ids=[f"incident:{incident_id}"],
    )
    # Stable across API retries, broker retries, and process restarts. A new
    # terminal status is a new event; replaying the same status is not.
    event_contract["event_id"] = f"remediation:{action.id}:{action.status.value}"
    return {
        "remediation_action": action,
        "resolution_lifecycle": extract_lifecycle(action.parameters, action.metadata),
        "source_payload": source_payload,
        "event_contract": event_contract,
    }


def _remediation_outbox_event_id(payload: dict[str, Any], action: RemediationAction) -> str:
    contract = payload.get("event_contract") if isinstance(payload.get("event_contract"), dict) else {}
    return str(contract.get("event_id") or f"remediation:{action.id}")


async def _mark_remediation_outbox_result(
    app: FastAPI,
    event_id: str,
    *,
    error: Exception | None = None,
) -> bool:
    if not settings.database_enabled or getattr(app.state, "session_factory", None) is None:
        return True
    async with app.state.session_factory() as session:
        repo = IncidentRepository(session)
        if error is None:
            await repo.mark_resolution_event_published(event_id)
        else:
            await repo.mark_resolution_event_retry(event_id, str(error))
        await session.commit()


async def _publish_remediation_event(app: FastAPI, payload: dict[str, Any], *, key: str) -> None:
    event_id = str((payload.get("event_contract") or {}).get("event_id") or "")
    try:
        await app.state.producer.publish(REMEDIATION_EVENTS, payload, key=key)
    except Exception as exc:
        if event_id:
            await _mark_remediation_outbox_result(app, event_id, error=exc)
        raise
    if event_id:
        await _mark_remediation_outbox_result(app, event_id)


async def _flush_remediation_outbox(app: FastAPI) -> int:
    from common.outbox_dispatch import flush_resolution_outbox
    return await flush_resolution_outbox(app, settings)


async def _remediation_outbox_dispatch_loop(app: FastAPI) -> None:
    interval = max(1.0, float(getattr(settings, "resolution_outbox_poll_seconds", 5.0) or 5.0))
    while True:
        try:
            await _flush_remediation_outbox(app)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("remediation outbox dispatch failed")
        await asyncio.sleep(interval)


async def _persist_remediation_event(
    *,
    app: FastAPI,
    action: RemediationAction,
    source_payload: dict[str, Any],
    source: str,
    event_payload: dict[str, Any] | None = None,
) -> None:
    if not settings.database_enabled or getattr(app.state, "session_factory", None) is None:
        return
    recommendation, decision, incident, orchestration = _extract_resolution_context(source_payload)
    recommendation_metadata = recommendation.get("metadata", {}) if isinstance(recommendation.get("metadata"), dict) else {}
    source_event_contract = source_payload.get("event_contract", {}) if isinstance(source_payload.get("event_contract"), dict) else {}
    source_transport = source_event_contract.get("transport", {}) if isinstance(source_event_contract.get("transport"), dict) else {}

    service_name = _first_non_empty(
        action.parameters.get("service"),
        incident.get("service"),
        recommendation_metadata.get("service"),
        action.target,
        "unknown",
    ) or "unknown"
    if _looks_like_uuid(service_name):
        service_name = _first_non_empty(incident.get("service"), recommendation_metadata.get("service"), "unknown") or "unknown"

    severity_value = _first_non_empty(recommendation.get("severity"), incident.get("severity"), "warning") or "warning"
    risk_tier_value = _first_non_empty(decision.get("risk_tier"), orchestration.get("risk_tier"), recommendation.get("risk"), "medium") or "medium"
    execution_mode_value = _first_non_empty(decision.get("execution_mode"), orchestration.get("execution_mode"), "automated") or "automated"
    transport_provider_value = _first_non_empty(
        decision.get("message_bus_provider"),
        orchestration.get("message_bus_provider"),
        source_transport.get("provider"),
        "rabbitmq",
    ) or "rabbitmq"
    source_channel_value = _first_non_empty(source_transport.get("channel"), source)

    action_status = str(action.status.value or "pending").lower()
    diagnostic_completion = action_status == "skipped" and action.action_type == "diagnostic_completion"
    state_status = "remediating"
    if diagnostic_completion:
        # Remediation records completion evidence; closure owns the terminal
        # projection after that evidence is durably validated.
        state_status = "validating"
    elif action_status in {"awaiting_approval", "policy_blocked"}:
        state_status = "awaiting_approval"
    elif action_status == "succeeded":
        state_status = "validating"
    elif action_status in {
        "failed", "rejected", "skipped", "execution_failed", "dispatch_failed",
        "validation_failed", "timed_out", "cancelled", "rollback_failed",
        "manual_intervention_required",
    }:
        state_status = "failed"

    async with app.state.session_factory() as session:
        repo = IncidentRepository(session)
        await repo.save_incident_event(
            build_event_envelope(
                event_type="incident.remediation.executed",
                identity={
                    "incident_id": str(action.incident_id),
                    "alert_id": None,
                    "trace_id": str(recommendation.get("trace_id") or ""),
                    "correlation_id": str(recommendation.get("correlation_id") or "") or None,
                    "causation_id": None,
                    "parent_event_id": None,
                },
                scope={
                    "tenant_id": action.tenant_id,
                    "service": str(service_name),
                    "environment": str(_first_non_empty(incident.get("environment"), recommendation_metadata.get("environment"), "prod") or "prod"),
                    "region": None,
                    "team": None,
                },
                state={
                    "severity": str(severity_value).lower(),
                    "status": state_status,
                    "owner": None,
                },
                policy={
                    "risk_tier": str(risk_tier_value).lower(),
                    "execution_mode": str(execution_mode_value).lower(),
                    "requires_approval": decision.get("requires_approval") if "requires_approval" in decision else orchestration.get("requires_approval"),
                    "policy_version": action.parameters.get("policy_version") or decision.get("policy_version") or orchestration.get("policy_version") or recommendation_metadata.get("policy_version"),
                    "policy_reason": action.parameters.get("policy_reason") or decision.get("policy_reason") or orchestration.get("policy_reason") or recommendation_metadata.get("policy_reason"),
                },
                transport={
                    "provider": str(transport_provider_value).lower(),
                    "channel": REMEDIATION_EVENTS,
                    "partition": None,
                    "offset": None,
                    "delivery_tag": None,
                },
                payload={
                    "source": source,
                    "source_channel": source_channel_value,
                    "source_event_contract": source_event_contract,
                    "source_payload": source_payload,
                    "approval_id": str(action.approval_id) if action.approval_id else None,
                    "action_id": str(action.id),
                    "action_type": action.action_type,
                    "status": action.status.value,
                    "output": action.output,
                    "error": action.error,
                },
            )
        )
        durable_event_payload = normalize_payload(
            event_payload or _build_remediation_event_payload(
                action=action,
                source_payload=source_payload,
                source=source,
            )
        )
        # Re-save the action and enqueue its broker handoff in this transaction.
        # The earlier execution save remains useful for live polling; this
        # atomic pair is the durable terminal handoff used by reconciliation.
        await repo.save_action(action)
        enqueued = await repo.enqueue_resolution_event(
            event_id=_remediation_outbox_event_id(durable_event_payload, action),
            aggregate_id=str(action.incident_id),
            topic=REMEDIATION_EVENTS,
            partition_key=str(action.incident_id),
            payload=durable_event_payload,
            tenant_id=action.tenant_id,
            available_after_seconds=float(getattr(settings, "resolution_outbox_initial_delay_seconds", 60.0) or 60.0),
        )
        await session.commit()
        return enqueued


async def startup(app: FastAPI) -> None:
    app.state.temporal_client = None
    if settings.remediation_temporal_enabled:
        from temporalio.client import Client

        app.state.temporal_client = await Client.connect(
            settings.temporal_address,
            namespace=settings.temporal_namespace,
        )
    workers = max(1, int(getattr(settings, "message_bus_worker_count", 1) or 1))
    approval_consumers: list[tuple[str, Any, ConsumeRunner]] = []
    resolution_consumers: list[tuple[str, Any, ConsumeRunner]] = []
    for worker in range(workers):
        approval_consumers.append(
            (f"rabbitmq-w{worker + 1}", RabbitMQConsumer(settings, APPROVAL_EVENTS), consume_rabbitmq_forever)
        )
        resolution_consumers.append(
            (f"rabbitmq-w{worker + 1}", RabbitMQConsumer(settings, RESOLUTION_EVENTS), consume_rabbitmq_forever)
        )
    if settings.kafka_enabled:
        for worker in range(workers):
            approval_consumers.insert(
                worker,
                (f"kafka-w{worker + 1}", KafkaConsumer(settings, APPROVAL_EVENTS), consume_kafka_forever),
            )
            resolution_consumers.insert(
                worker,
                (f"kafka-w{worker + 1}", KafkaConsumer(settings, RESOLUTION_EVENTS), consume_kafka_forever),
            )

    async def handle_approval(payload: dict) -> None:
        approval_payload = _extract_approval_payload(payload)
        approval = Approval.model_validate(approval_payload)
        if approval.decision == ApprovalDecision.EVIDENCE_REQUESTED:
            EVENTS_PROCESSED.labels(settings.service_name, APPROVAL_EVENTS, "evidence-requested").inc()
            return
        if approval.authorization_scope != "execution":
            EVENTS_PROCESSED.labels(settings.service_name, APPROVAL_EVENTS, "dry-run-authorized").inc()
            return
        if settings.event_envelope_signing_required:
            envelope = payload.get("signed_envelope") if isinstance(payload.get("signed_envelope"), dict) else {}
            try:
                signed_tenant = verify_event_envelope(
                    envelope,
                    key=settings.event_envelope_signing_key,
                    expected_issuer="approval-service",
                )
            except ValueError as exc:
                raise PolicyViolation(f"approval event rejected: {exc}") from exc
            signed_payload = envelope.get("payload") if isinstance(envelope.get("payload"), dict) else {}
            if (
                signed_tenant != approval.tenant_id
                or str(envelope.get("incident_id") or "") != str(approval.incident_id)
                or str(signed_payload.get("plan_id") or "") != str(approval.plan_id or "")
                or str(signed_payload.get("plan_fingerprint") or "") != str(approval.plan_fingerprint or "")
            ):
                raise PolicyViolation("approval event rejected: signed identity does not match approval")
        approval = _enrich_approval_from_payload(approval, payload)
        # The cockpit has a distinct confirmation gate after approval. Its
        # approval event records authorization only; execution is initiated by
        # the subsequent POST /execute request.
        if approval.metadata.get("execution_confirmation_required"):
            EVENTS_PROCESSED.labels(settings.service_name, APPROVAL_EVENTS, "awaiting-confirmation").inc()
            return
        if settings.remediation_temporal_enabled:
            # The message bus must not bypass the durable control plane. Direct
            # execution is lost if this service is restarted while Jenkins is
            # running, leaving a permanently non-terminal action behind.
            await execute_approval(approval)
            EVENTS_PROCESSED.labels(settings.service_name, APPROVAL_EVENTS, "workflow-accepted").inc()
            return
        action = await _execute_approval(approval)
        await _request_failure_reconsideration(action=action, source_payload=payload)
        payload_out = _build_remediation_event_payload(action=action, source_payload=payload, source=APPROVAL_EVENTS)
        publish_required = await _persist_remediation_event(
            app=app,
            action=action,
            source_payload=payload,
            source=APPROVAL_EVENTS,
            event_payload=payload_out,
        )
        if publish_required:
            await _publish_remediation_event(app, payload_out, key=str(action.incident_id))
        EVENTS_PROCESSED.labels(settings.service_name, APPROVAL_EVENTS, "ok").inc()

    async def handle_resolution(payload: dict) -> None:
        recommendation, _decision, _incident, _orchestration = _extract_resolution_context(payload)
        recommendation_metadata = recommendation.get("metadata") if isinstance(recommendation.get("metadata"), dict) else {}
        analysis = recommendation_metadata.get("remediation_analysis") if isinstance(recommendation_metadata.get("remediation_analysis"), dict) else {}
        execution_plan = recommendation_metadata.get("execution_plan") if isinstance(recommendation_metadata.get("execution_plan"), dict) else {}
        approval = _build_auto_approval(payload)
        if approval is not None:
            approval = _enrich_approval_from_payload(approval, payload)
        diagnostic_only = (
            str(analysis.get("plan_kind") or "").strip().lower() == "diagnostic"
            or analysis.get("execution_ready") is False
            or str(execution_plan.get("plan_kind") or "").strip().lower() == "diagnostic"
            or execution_plan.get("diagnostic_only") is True
            or execution_plan.get("execution_ready") is False
            or (approval is not None and _plan_is_validation_only(approval))
        )
        if diagnostic_only and _is_auto_close_diagnostic_resolution(payload):
            # Diagnostic completion is a valid terminal branch. It must not be
            # forced through approval/execution gates intended for mutations.
            if approval is None:
                return
            idempotency_key = _build_action_idempotency_key(approval, "diagnostic_completion")
            existing = await _find_existing_action(app, idempotency_key)
            if existing is not None:
                EVENTS_PROCESSED.labels(settings.service_name, RESOLUTION_EVENTS, "diagnostic-already-complete").inc()
                return
            action = engine.build_action(approval)
            action.action_type = "diagnostic_completion"
            action.idempotency_key = idempotency_key
            action.status = RemediationStatus.SKIPPED
            action.completed_at = utc_now()
            action.output = "Diagnostic analysis completed; no corrective operation was required or executed."
            action.parameters.update({
                "root_cause": recommendation.get("root_cause") or "Diagnostic analysis completed",
                "impact": recommendation.get("impact") or "No confirmed recoverable service impact",
                "execution_plan": analysis,
                "diagnostic_closure": True,
                "watch_only_closure": True,
                "diagnostic_details": {
                    "recommended_action": recommendation.get("recommended_action"),
                    "rationale": recommendation.get("rationale"),
                    "commands": recommendation.get("commands") or analysis.get("commands") or [],
                    "validation_queries": analysis.get("validation_queries") or [],
                    "readiness_blocks": analysis.get("readiness_blocks") or [],
                },
            })
            lifecycle = extract_lifecycle(approval.metadata, recommendation_metadata, recommendation)
            if lifecycle:
                action.parameters["resolution_lifecycle"] = lifecycle
            _advance_action_lifecycle(action)
            await _persist_action(app, action)
            payload_out = _build_remediation_event_payload(action=action, source_payload=payload, source=RESOLUTION_EVENTS)
            publish_required = await _persist_remediation_event(
                app=app,
                action=action,
                source_payload=payload,
                source=RESOLUTION_EVENTS,
                event_payload=payload_out,
            )
            if publish_required:
                await _publish_remediation_event(app, payload_out, key=str(action.incident_id))
            EVENTS_PROCESSED.labels(settings.service_name, RESOLUTION_EVENTS, "diagnostic-complete").inc()
            return
        if _resolution_requires_approval(payload):
            return
        try:
            _validate_auto_execution_policy(payload)
        except PolicyViolation as exc:
            blocked = _build_policy_blocked_action(payload, str(exc))
            if blocked is None:
                return
            await _persist_action(app, blocked)
            payload_out = _build_remediation_event_payload(
                action=blocked,
                source_payload=payload,
                source=RESOLUTION_EVENTS,
            )
            publish_required = await _persist_remediation_event(
                app=app,
                action=blocked,
                source_payload=payload,
                source=RESOLUTION_EVENTS,
                event_payload=payload_out,
            )
            if publish_required:
                await _publish_remediation_event(app, payload_out, key=str(blocked.incident_id))
            EVENTS_PROCESSED.labels(settings.service_name, RESOLUTION_EVENTS, "awaiting-approval").inc()
            return
        approval = _build_auto_approval(payload)
        if approval is None:
            return
        approval = _enrich_approval_from_payload(approval, payload)
        try:
            await _require_persisted_approved_runbook(approval)
        except PolicyViolation as exc:
            blocked = _build_policy_blocked_action(payload, str(exc))
            if blocked is None:
                return
            await _persist_action(app, blocked)
            payload_out = _build_remediation_event_payload(action=blocked, source_payload=payload, source=RESOLUTION_EVENTS)
            publish_required = await _persist_remediation_event(
                app=app,
                action=blocked,
                source_payload=payload,
                source=RESOLUTION_EVENTS,
                event_payload=payload_out,
            )
            if publish_required:
                await _publish_remediation_event(app, payload_out, key=str(blocked.incident_id))
            EVENTS_PROCESSED.labels(settings.service_name, RESOLUTION_EVENTS, "awaiting-approval").inc()
            return
        if settings.remediation_temporal_enabled:
            await execute_approval(approval)
            EVENTS_PROCESSED.labels(settings.service_name, RESOLUTION_EVENTS, "workflow-accepted").inc()
            return
        action = await _execute_approval(approval)
        await _request_failure_reconsideration(action=action, source_payload=payload)
        payload_out = _build_remediation_event_payload(action=action, source_payload=payload, source=RESOLUTION_EVENTS)
        publish_required = await _persist_remediation_event(
            app=app,
            action=action,
            source_payload=payload,
            source=RESOLUTION_EVENTS,
            event_payload=payload_out,
        )
        if publish_required:
            await _publish_remediation_event(app, payload_out, key=str(action.incident_id))
        EVENTS_PROCESSED.labels(settings.service_name, RESOLUTION_EVENTS, "ok").inc()

    for source, approval_consumer, consume_forever in approval_consumers:
        task = asyncio.create_task(consume_forever(approval_consumer, handle_approval), name=f"remediation-engine-{source}-consumer")
        tasks.append(task)

    for source, resolution_consumer, consume_forever in resolution_consumers:
        task = asyncio.create_task(
            consume_forever(resolution_consumer, handle_resolution),
            name=f"remediation-engine-{source}-resolution-consumer",
        )
        tasks.append(task)

    watchdog = asyncio.create_task(_remediation_watchdog(app), name="remediation-engine-lifecycle-watchdog")
    tasks.append(watchdog)
    tasks.append(asyncio.create_task(_remediation_outbox_dispatch_loop(app), name="remediation-engine-resolution-outbox"))


async def shutdown(_: FastAPI) -> None:
    for task in tasks:
        task.cancel()


app = create_app(title="KaiMS Remediation Engine", settings=settings, startup=startup, shutdown=shutdown)


@app.post("/diagnostic/complete", response_model=RemediationAction)
async def complete_persisted_diagnostic(request: DiagnosticCompletionRequest) -> RemediationAction:
    """Idempotently finish a persisted non-executable diagnostic branch."""
    if not settings.database_enabled or getattr(app.state, "session_factory", None) is None:
        raise HTTPException(status_code=503, detail="Diagnostic completion requires the incident store")
    async with app.state.session_factory() as session:
        repo = IncidentRepository(session)
        incident = await repo.get_incident(str(request.incident_id))
        stored = await repo.get_latest_recommendation_for_incident(str(request.incident_id))
    if not incident or not stored:
        raise HTTPException(status_code=404, detail="Incident or recommendation not found")
    recommendation = stored.get("recommendation") if isinstance(stored.get("recommendation"), dict) else stored
    recommendation = dict(recommendation) if isinstance(recommendation, dict) else {}
    recommendation.setdefault("incident_id", str(request.incident_id))
    metadata = recommendation.get("metadata") if isinstance(recommendation.get("metadata"), dict) else {}
    plan = metadata.get("execution_plan") if isinstance(metadata.get("execution_plan"), dict) else {}
    explicitly_diagnostic = (
        str(plan.get("plan_kind") or "").strip().lower() == "diagnostic"
        or plan.get("diagnostic_only") is True
        or plan.get("execution_ready") is False
    )
    if not explicitly_diagnostic:
        raise HTTPException(status_code=409, detail="The persisted execution plan is not diagnostic-only")
    if not recommendation.get("id"):
        raise HTTPException(status_code=409, detail="The persisted recommendation has no identity")
    payload = {"recommendation": recommendation, "incident": incident, "decision": {"requires_approval": False}}
    if not _is_auto_close_diagnostic_resolution(payload):
        raise HTTPException(status_code=409, detail="Diagnostic completion is blocked by a control conflict")
    approval = _build_auto_approval(payload)
    if approval is None:
        raise HTTPException(status_code=409, detail="Unable to derive diagnostic completion identity")
    approval = _enrich_approval_from_payload(approval, payload)
    idempotency_key = _build_action_idempotency_key(approval, "diagnostic_completion")
    existing = await _find_existing_action(app, idempotency_key)
    if existing is not None:
        return existing
    action = engine.build_action(approval)
    action.action_type = "diagnostic_completion"
    action.idempotency_key = idempotency_key
    action.status = RemediationStatus.SKIPPED
    action.completed_at = utc_now()
    action.output = "Diagnostic analysis completed; no corrective operation was required or executed."
    action.parameters.update(
        {
            "root_cause": recommendation.get("root_cause") or "Diagnostic analysis completed",
            "impact": recommendation.get("impact") or "No confirmed recoverable service impact",
            "execution_plan": plan,
            "diagnostic_closure": True,
            "watch_only_closure": True,
            "diagnostic_details": {
                "recommended_action": recommendation.get("recommended_action"),
                "rationale": recommendation.get("rationale"),
                "commands": plan.get("commands") or [],
                "validation_queries": plan.get("validation_queries") or plan.get("validation_commands") or [],
                "readiness_blocks": plan.get("readiness_blocks") or [],
            },
        }
    )
    lifecycle = extract_lifecycle(approval.metadata, metadata, recommendation)
    if lifecycle:
        action.parameters["resolution_lifecycle"] = lifecycle
    _advance_action_lifecycle(action)
    payload_out = _build_remediation_event_payload(
        action=action,
        source_payload=payload,
        source="diagnostic-reconcile",
    )
    publish_required = await _persist_remediation_event(
        app=app,
        action=action,
        source_payload=payload,
        source="diagnostic-reconcile",
        event_payload=payload_out,
    )
    if publish_required:
        await _publish_remediation_event(app, payload_out, key=str(action.incident_id))
    return action


async def _execute_approval(approval: Approval) -> RemediationAction:
    if approval.authorization_scope != "execution":
        raise HTTPException(status_code=403, detail="Dry-run authorization cannot execute a live remediation.")
    if approval.decision == ApprovalDecision.REJECTED:
        action = RemediationAction(
            tenant_id=approval.tenant_id,
            incident_id=approval.incident_id,
            approval_id=approval.id,
            recommendation_id=approval.recommendation_id,
            resolution_plan_id=approval.plan_id,
            plan_fingerprint=approval.plan_fingerprint,
            action_type="rejected",
            target=str(approval.incident_id),
            status=RemediationStatus.SKIPPED,
            output="human rejected remediation",
        )
    else:
        unsafe_reasons = _unsafe_plan_reasons(approval)
        if unsafe_reasons:
            raise HTTPException(status_code=409, detail=unsafe_reasons[0])
        if _plan_is_validation_only(approval):
            raise HTTPException(
                status_code=409,
                detail="Execution blocked: this plan contains diagnostics but no corrective capability. Select a cataloged, target-specific remediation with executable recovery checks.",
            )
        # Body/event metadata is evidence only. P0 production execution always
        # requires the exact durable HITL receipt, even if a caller forges the
        # legacy auto_approved flag.
        await _require_persisted_human_approval(approval)
        try:
            await _require_persisted_approved_runbook(approval)
        except PolicyViolation as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        action = engine.build_action(approval)
        lifecycle = extract_lifecycle(approval.metadata) or create_lifecycle(
            tenant_id=approval.tenant_id, incident_id=approval.incident_id,
            recommendation_id=approval.recommendation_id,
            plan=approval.metadata.get("execution_plan") if isinstance(approval.metadata.get("execution_plan"), dict) else {},
            state=ResolutionState.READY_TO_EXECUTE,
        )
        if lifecycle.get("state") == ResolutionState.AWAITING_APPROVAL.value:
            lifecycle = transition_lifecycle(
                lifecycle,
                ResolutionState.READY_TO_EXECUTE,
                actor=LifecycleActor.APPROVAL,
                approval={"approval_id": str(approval.id), "decision": approval.decision.value},
            )
        attempt = int((lifecycle.get("execution") if isinstance(lifecycle.get("execution"), dict) else {}).get("attempt") or 0) + 1
        action.parameters["resolution_lifecycle"] = transition_lifecycle(
            lifecycle, ResolutionState.EXECUTING,
            actor=LifecycleActor.REMEDIATION,
            approval={"approval_id": str(approval.id), "decision": approval.decision.value},
            execution={"attempt": attempt, "action_id": str(action.id)},
        )
        _require_production_credential_reference(approval, action.action_type)
        _require_live_executor_configuration(action)
        if not engine.is_action_allowed(action.action_type):
            action.status = RemediationStatus.SKIPPED
            action.error = f"Action type '{action.action_type}' is not allowlisted"
            action.output = "remediation blocked by allowlist policy"
        else:
            action.idempotency_key = _build_action_idempotency_key(approval, action.action_type)
            bind_execution_contract(action, approval)
            verify_execution_contract(action)
            action.parameters["lifecycle"] = {
                "state": RemediationStatus.DISPATCHING.value,
                "history": [
                    RemediationStatus.POLICY_CHECKED.value,
                    RemediationStatus.APPROVED.value,
                    RemediationStatus.DISPATCHING.value,
                ],
            }
            lock = idempotency_locks.setdefault(action.idempotency_key, asyncio.Lock())
            async with lock:
                existing = await _find_existing_action(app, action.idempotency_key)
                if existing is not None:
                    execution_result = existing.parameters.get("execution_result")
                    execution_result = execution_result if isinstance(execution_result, dict) else {}
                    retryable_connector_skip = (
                        existing.status == RemediationStatus.SKIPPED
                        and not bool(execution_result.get("executed"))
                        and "executor is configured" in str(existing.error or "").lower()
                    )
                    existing_execution = existing.parameters.get("execution_result")
                    existing_execution = existing_execution if isinstance(existing_execution, dict) else {}
                    retryable_legacy_queue_ack = (
                        existing.status == RemediationStatus.SUCCEEDED
                        and str(existing_execution.get("executor") or "").lower() == "jenkins"
                        and not existing_execution.get("build_result")
                    )
                    corrected_failed_plan = (
                        existing.status == RemediationStatus.FAILED
                        and _execution_plan_fingerprint(existing) != _execution_plan_fingerprint(action)
                    )
                    retryable_indeterminate_jenkins = (
                        existing.status == RemediationStatus.FAILED
                        and str(existing_execution.get("executor") or "").lower() == "jenkins"
                        and str(existing_execution.get("build_result") or "").upper() in {"", "UNKNOWN"}
                    )
                    orchestration = existing.parameters.get("orchestration")
                    orchestration = orchestration if isinstance(orchestration, dict) else {}
                    claimable_temporal_intent = (
                        existing.status in {RemediationStatus.PENDING, RemediationStatus.RUNNING}
                        and str(orchestration.get("provider") or "").lower() == "temporal"
                        and str(orchestration.get("status") or "").lower() in {"submitting", "accepted", "workflow_accepted"}
                        and not existing_execution
                    )
                    if (
                        retryable_connector_skip
                        or retryable_legacy_queue_ack
                        or corrected_failed_plan
                        or retryable_indeterminate_jenkins
                        or claimable_temporal_intent
                    ):
                        # Preserve the durable row/idempotency identity while
                        # replacing the historical configuration skip with the
                        # newly configured Jenkins attempt.
                        action.id = existing.id
                        bind_execution_contract(action, approval)
                        verify_execution_contract(action)
                        action.parameters["orchestration"] = {
                            **orchestration,
                            "status": "executing",
                        }
                        action.status = RemediationStatus.DISPATCHING
                        await _reserve_target_execution(app, action)
                        action = await engine.execute(action)
                        _advance_action_lifecycle(action)
                        await _persist_action(app, action)
                        return action
                    # A redelivered or concurrent approval/API request reaches
                    # this branch with the same deterministic key. Return the
                    # durable result instead of invoking Jenkins twice.
                    return existing
                action.status = RemediationStatus.DISPATCHING
                await _reserve_target_execution(app, action)
                action = await engine.execute(action)
                _advance_action_lifecycle(action)
                await _persist_action(app, action)
                return action

    _advance_action_lifecycle(action)
    await _persist_action(app, action)
    return action


async def _finalize_api_execution(approval: Approval, action: RemediationAction) -> RemediationAction:
    # The action row is the UI's authoritative execution state. Persist the
    # observed terminal result before publishing its event; otherwise an API
    # caller sees the terminal response while subsequent reads remain stuck on
    # the last non-terminal value.
    _advance_action_lifecycle(action)
    await _persist_action(app, action)
    source_payload = {"approval": approval.model_dump(mode="json")}
    await _request_failure_reconsideration(action=action, source_payload=source_payload)
    payload_out = _build_remediation_event_payload(
        action=action,
        source_payload=source_payload,
        source="api-execute",
    )
    publish_required = await _persist_remediation_event(
        app=app,
        action=action,
        source_payload=source_payload,
        source="api-execute",
        event_payload=payload_out,
    )
    if publish_required:
        await _publish_remediation_event(app, payload_out, key=str(action.incident_id))
    EVENTS_PROCESSED.labels(settings.service_name, "api-execute", "ok").inc()
    return action


@app.post("/execute-direct", response_model=RemediationAction, include_in_schema=False)
async def execute_approval_direct(approval: Approval, x_kaiops_internal_token: str = Header(default="")) -> RemediationAction:
    """Temporal activity target. Idempotency makes activity retries safe."""
    expected = settings.remediation_internal_token
    if not expected or x_kaiops_internal_token != expected:
        raise HTTPException(status_code=403, detail="Internal remediation activity authentication failed.")
    return await _finalize_api_execution(approval, await _execute_approval(approval))


@app.post("/dispatch-direct", response_model=RemediationAction, include_in_schema=False)
async def dispatch_approval_direct(approval: Approval, x_kaiops_internal_token: str = Header(default="")) -> RemediationAction:
    """Temporal-only, idempotent handoff to an asynchronous executor."""
    expected = settings.remediation_internal_token
    if not expected or x_kaiops_internal_token != expected:
        raise HTTPException(status_code=403, detail="Internal remediation activity authentication failed.")
    unsafe_reasons = _unsafe_plan_reasons(approval)
    if unsafe_reasons:
        raise HTTPException(status_code=409, detail=unsafe_reasons[0])
    if _plan_is_validation_only(approval):
        raise HTTPException(status_code=409, detail="Execution blocked: the approved plan is validation-only.")
    await _require_persisted_human_approval(approval)
    try:
        await _require_persisted_approved_runbook(approval)
    except PolicyViolation as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    action = engine.build_action(approval)
    _require_production_credential_reference(approval, action.action_type)
    _require_live_executor_configuration(action)
    action.idempotency_key = _build_action_idempotency_key(approval, action.action_type)
    existing = await _find_existing_action(app, action.idempotency_key)
    if existing is not None:
        existing_result = existing.parameters.get("execution_result")
        if (isinstance(existing_result, dict) and existing_result.get("accepted")
                and (existing.approval_id == approval.id
                     or existing.status.value in ACTIVE_EXECUTION_STATUSES)):
            return existing
        action.id = existing.id
    bind_execution_contract(action, approval)
    verify_execution_contract(action)
    action.status = RemediationStatus.DISPATCHING
    _advance_action_lifecycle(action)
    action.parameters["lifecycle"] = {
        "state": RemediationStatus.DISPATCHING.value,
        "history": [RemediationStatus.POLICY_CHECKED.value, RemediationStatus.APPROVED.value, RemediationStatus.DISPATCHING.value],
    }
    await _reserve_target_execution(app, action)
    action = await engine.dispatch(action)
    lifecycle = action.parameters.get("lifecycle") if isinstance(action.parameters.get("lifecycle"), dict) else {"history": []}
    lifecycle["state"] = action.status.value
    lifecycle["history"] = [*lifecycle.get("history", []), action.status.value]
    action.parameters["lifecycle"] = lifecycle
    await _persist_action(app, action)
    return action


def _require_matching_execution_attempt(approval: Approval, action: RemediationAction) -> None:
    # The plan's stable idempotency key can be reused by a separately approved
    # retry. Late callbacks from the former workflow must not mutate that retry.
    if (action.approval_id != approval.id or action.incident_id != approval.incident_id
            or action.tenant_id != approval.tenant_id):
        raise HTTPException(status_code=409, detail="Execution callback belongs to a superseded approval attempt.")


@app.post("/reconcile-direct", response_model=RemediationAction, include_in_schema=False)
async def reconcile_execution_direct(payload: dict[str, Any], x_kaiops_internal_token: str = Header(default="")) -> RemediationAction:
    """Perform one executor observation and persist only observed truth."""
    expected = settings.remediation_internal_token
    if not expected or x_kaiops_internal_token != expected:
        raise HTTPException(status_code=403, detail="Internal remediation activity authentication failed.")
    approval = Approval.model_validate(payload.get("approval") or {})
    preview = engine.build_action(approval)
    action = await _find_existing_action(app, _build_action_idempotency_key(approval, preview.action_type))
    if action is None:
        raise HTTPException(status_code=404, detail="No dispatched remediation action exists for this incident.")
    _require_matching_execution_attempt(approval, action)
    verify_execution_contract(action)
    if action.status in TERMINAL_EXECUTION_STATUSES:
        return await _finalize_api_execution(approval, action)
    previous = action.status.value
    action = await engine.observe(action)
    lifecycle = action.parameters.get("lifecycle") if isinstance(action.parameters.get("lifecycle"), dict) else {"history": []}
    lifecycle["state"] = action.status.value
    if previous != action.status.value:
        lifecycle["history"] = [*lifecycle.get("history", []), action.status.value]
    action.parameters["lifecycle"] = lifecycle
    if action.status in TERMINAL_EXECUTION_STATUSES:
        return await _finalize_api_execution(approval, action)
    await _persist_action(app, action)
    return action


@app.post("/timeout-direct", response_model=RemediationAction, include_in_schema=False)
async def timeout_execution_direct(payload: dict[str, Any], x_kaiops_internal_token: str = Header(default="")) -> RemediationAction:
    expected = settings.remediation_internal_token
    if not expected or x_kaiops_internal_token != expected:
        raise HTTPException(status_code=403, detail="Internal remediation activity authentication failed.")
    approval = Approval.model_validate(payload.get("approval") or {})
    preview = engine.build_action(approval)
    action = await _find_existing_action(app, _build_action_idempotency_key(approval, preview.action_type))
    if action is None:
        raise HTTPException(status_code=404, detail="No remediation action exists for this incident.")
    _require_matching_execution_attempt(approval, action)
    verify_execution_contract(action)
    if action.status in TERMINAL_EXECUTION_STATUSES:
        return await _finalize_api_execution(approval, action)
    # A deadline is not evidence of executor failure. A build may have finished
    # since the last poll; observe it once before recording a timeout. If the
    # observation fails, retain the last durable state and let Temporal retry.
    action = await engine.observe(action)
    if action.status in TERMINAL_EXECUTION_STATUSES:
        return await _finalize_api_execution(approval, action)
    action.status = RemediationStatus.TIMED_OUT
    action.error = str(payload.get("error") or "Executor did not reach a terminal state before the remediation deadline.")
    action.completed_at = utc_now()
    lifecycle = action.parameters.get("lifecycle") if isinstance(action.parameters.get("lifecycle"), dict) else {"history": []}
    lifecycle["state"] = RemediationStatus.TIMED_OUT.value
    lifecycle["history"] = [*lifecycle.get("history", []), RemediationStatus.TIMED_OUT.value]
    action.parameters["lifecycle"] = lifecycle
    return await _finalize_api_execution(approval, action)


@app.post("/rollback-direct", response_model=RemediationAction, include_in_schema=False)
async def rollback_execution_direct(payload: dict[str, Any], x_kaiops_internal_token: str = Header(default="")) -> RemediationAction:
    """Execute the rollback already authorized as part of an immutable plan.

    This endpoint never derives rollback commands from prose or a model.  A
    missing rollback is an escalation condition, not permission to improvise.
    """
    expected = settings.remediation_internal_token
    if not expected or x_kaiops_internal_token != expected:
        raise HTTPException(status_code=403, detail="Internal remediation activity authentication failed.")
    approval = Approval.model_validate(payload.get("approval") or {})
    await _require_persisted_human_approval(approval)
    plan = approval.metadata.get("execution_plan") if isinstance(approval.metadata.get("execution_plan"), dict) else {}
    rollback_commands = [
        str(item).strip() for item in plan.get("rollback_commands", [])
        if str(item).strip()
    ] if isinstance(plan.get("rollback_commands"), list) else []
    if str(plan.get("rollback_mode") or "").strip().lower() != "automatic":
        raise HTTPException(
            status_code=409,
            detail="Rollback blocked: the approved plan does not authorize automatic rollback.",
        )
    preview = engine.build_action(approval)
    original = await _find_existing_action(app, _build_action_idempotency_key(approval, preview.action_type))

    if original is None:
        raise HTTPException(status_code=409, detail="Rollback blocked: no governed original execution exists.")
    try:
        verify_execution_contract(original)
    except (PolicyViolation, ValueError) as exc:
        raise HTTPException(status_code=409, detail="Rollback blocked: original execution integrity failed.") from exc
    original_contract = (
        original.parameters.get("execution_contract")
        if isinstance(original.parameters.get("execution_contract"), dict)
        else {}
    )
    if (
        str(original_contract.get("approval_id") or "") != str(approval.id)
        or str(original_contract.get("incident_id") or "") != str(approval.incident_id)
        or str(original_contract.get("plan_fingerprint") or "") != str(approval.plan_fingerprint or "")
    ):
        raise HTTPException(
            status_code=409,
            detail="Rollback blocked: original execution is bound to another approval.",
        )

    if not rollback_commands:
        action = original or preview
        action.status = RemediationStatus.MANUAL_INTERVENTION_REQUIRED
        action.error = "Automatic rollback is unavailable: the approved plan contains no rollback commands."
        action.completed_at = utc_now()
        action.parameters["escalation"] = {
            "required": True,
            "reason": "approved_rollback_unavailable",
            "source_action_id": str(original.id) if original else "",
        }
        return await _finalize_api_execution(approval, action)

    rollback_plan = {
        **plan,
        "commands": rollback_commands,
        "scripts": [],
        "queries": [],
        "rollback_commands": [],
        "rollback_mode": "not_applicable",
        "validation_commands": plan.get("validation_commands", []),
    }
    rollback_plan["plan_fingerprint"] = canonical_plan_fingerprint(rollback_plan)
    rollback_plan["idempotency_key"] = rollback_plan["plan_fingerprint"]
    rollback_metadata = {
        **approval.metadata,
        "execution_plan": rollback_plan,
        "recommended_action": "Execute the pre-approved rollback for the failed remediation validation.",
        "recommended_commands": rollback_commands,
        "rollback_of_action_id": str(original.id) if original else "",
    }
    rollback_approval = approval.model_copy(update={
        "plan_fingerprint": rollback_plan["plan_fingerprint"],
        "metadata": rollback_metadata,
    })
    action = engine.build_action(rollback_approval)
    action.action_type = preview.action_type
    action.idempotency_key = _rollback_idempotency_key(approval, preview.action_type)
    existing = await _find_existing_action(app, action.idempotency_key)
    if existing is not None and existing.status in {
        RemediationStatus.ROLLED_BACK, RemediationStatus.ROLLBACK_FAILED,
        RemediationStatus.MANUAL_INTERVENTION_REQUIRED,
    }:
        return existing
    if existing is not None:
        action.id = existing.id
    action.parameters["rollback_of_action_id"] = str(original.id) if original else ""
    action.parameters["original_approved_plan_fingerprint"] = str(approval.plan_fingerprint or "")
    action.parameters["execution_plan"] = rollback_plan
    bind_execution_contract(action, rollback_approval)
    verify_execution_contract(action)
    action.status = RemediationStatus.DISPATCHING
    await _reserve_target_execution(app, action)
    result = await engine.dispatch(action)
    if result.status == RemediationStatus.SUCCEEDED:
        result.status = RemediationStatus.ROLLED_BACK
        result.error = None
        result.completed_at = utc_now()
        return await _finalize_api_execution(rollback_approval, result)
    if result.status in {RemediationStatus.FAILED, RemediationStatus.DISPATCH_FAILED, RemediationStatus.EXECUTION_FAILED}:
        return await _finalize_failed_rollback(rollback_approval, result, original)
    await _persist_action(app, result)
    return result


@app.post("/rollback-reconcile-direct", response_model=RemediationAction, include_in_schema=False)
async def reconcile_rollback_direct(payload: dict[str, Any], x_kaiops_internal_token: str = Header(default="")) -> RemediationAction:
    expected = settings.remediation_internal_token
    if not expected or x_kaiops_internal_token != expected:
        raise HTTPException(status_code=403, detail="Internal remediation activity authentication failed.")
    approval = Approval.model_validate(payload.get("approval") or {})
    preview = engine.build_action(approval)
    action = await _find_existing_action(app, _rollback_idempotency_key(approval, preview.action_type))
    if action is None:
        raise HTTPException(status_code=404, detail="No automatic rollback action exists for this incident.")
    _require_matching_execution_attempt(approval, action)
    verify_execution_contract(action)
    original = await _find_existing_action(app, _build_action_idempotency_key(approval, preview.action_type))
    if action.status in {RemediationStatus.ROLLED_BACK, RemediationStatus.ROLLBACK_FAILED, RemediationStatus.MANUAL_INTERVENTION_REQUIRED}:
        return action
    action = await engine.observe(action)
    if action.status == RemediationStatus.SUCCEEDED:
        action.status = RemediationStatus.ROLLED_BACK
        action.error = None
        action.completed_at = utc_now()
        return await _finalize_api_execution(approval, action)
    if action.status in {
        RemediationStatus.FAILED, RemediationStatus.DISPATCH_FAILED, RemediationStatus.EXECUTION_FAILED,
        RemediationStatus.VALIDATION_FAILED, RemediationStatus.CANCELLED, RemediationStatus.TIMED_OUT,
    }:
        return await _finalize_failed_rollback(approval, action, original)
    await _persist_action(app, action)
    return action


@app.post("/rollback-timeout-direct", response_model=RemediationAction, include_in_schema=False)
async def timeout_rollback_direct(payload: dict[str, Any], x_kaiops_internal_token: str = Header(default="")) -> RemediationAction:
    expected = settings.remediation_internal_token
    if not expected or x_kaiops_internal_token != expected:
        raise HTTPException(status_code=403, detail="Internal remediation activity authentication failed.")
    approval = Approval.model_validate(payload.get("approval") or {})
    preview = engine.build_action(approval)
    action = await _find_existing_action(app, _rollback_idempotency_key(approval, preview.action_type))
    if action is None:
        raise HTTPException(status_code=404, detail="No automatic rollback action exists for this incident.")
    _require_matching_execution_attempt(approval, action)
    action = await reconcile_rollback_direct(payload, x_kaiops_internal_token)
    if action.status in TERMINAL_EXECUTION_STATUSES:
        return action
    action.status = RemediationStatus.MANUAL_INTERVENTION_REQUIRED
    action.error = "Automatic rollback did not reach a verified terminal state before its deadline."
    action.completed_at = utc_now()
    action.parameters["escalation"] = {
        "required": True,
        "reason": "automatic_rollback_timed_out",
        "source_action_id": str(action.parameters.get("rollback_of_action_id") or ""),
    }
    return await _finalize_api_execution(approval, action)


@app.post("/execution-failed", response_model=RemediationAction, include_in_schema=False)
async def record_execution_failure(payload: dict[str, Any], x_kaiops_internal_token: str = Header(default="")) -> RemediationAction:
    """Persist a truthful terminal result when the durable executor rejects an activity."""
    expected = settings.remediation_internal_token
    if not expected or x_kaiops_internal_token != expected:
        raise HTTPException(status_code=403, detail="Internal remediation activity authentication failed.")
    approval = Approval.model_validate(payload.get("approval") or {})
    preview = engine.build_action(approval)
    existing = await _find_existing_action(app, _build_action_idempotency_key(approval, preview.action_type))
    if existing is None:
        preview.idempotency_key = _build_action_idempotency_key(approval, preview.action_type)
        existing = await _find_existing_action(app, preview.idempotency_key)
        action = existing or preview
    else:
        action = existing
    if existing is not None:
        _require_matching_execution_attempt(approval, action)
        if action.status in TERMINAL_EXECUTION_STATUSES:
            return await _finalize_api_execution(approval, action)
        receipt = action.parameters.get("execution_result")
        if isinstance(receipt, dict) and receipt.get("accepted") is True:
            # An HTTP error after executor acceptance is not proof that the
            # external action failed. Observe the existing execution instead.
            return await reconcile_execution_direct({"approval": approval.model_dump(mode="json")}, x_kaiops_internal_token)
    policy_blocked = bool(payload.get("policy_blocked")) or int(payload.get("http_status") or 0) == 409
    action.status = RemediationStatus.POLICY_BLOCKED if policy_blocked else RemediationStatus.FAILED
    action.error = str(payload.get("error") or "Durable remediation execution failed.").strip()
    action.completed_at = utc_now()
    orchestration = action.parameters.get("orchestration")
    orchestration = orchestration if isinstance(orchestration, dict) else {}
    action.parameters["orchestration"] = {
        **orchestration,
        "status": "policy_blocked" if policy_blocked else "failed",
        "http_status": payload.get("http_status"),
        "phase": payload.get("phase") or "execution",
    }
    return await _finalize_api_execution(approval, action)


@app.post("/execute", response_model=RemediationAction, status_code=202)
async def execute_approval(approval: Approval) -> RemediationAction:
    # Reject contract/policy failures synchronously. Starting a durable workflow
    # for a plan that can never dispatch makes a policy decision look like an
    # executor outage and creates a misleading FAILED remediation action.
    unsafe_reasons = _unsafe_plan_reasons(approval)
    if unsafe_reasons:
        raise HTTPException(status_code=409, detail=unsafe_reasons[0])
    if _plan_is_validation_only(approval):
        raise HTTPException(status_code=409, detail="Execution unavailable: this is a diagnostic-only plan. Select a reviewed corrective capability before approval.")
    if not settings.remediation_temporal_enabled:
        return await _finalize_api_execution(approval, await _execute_approval(approval))

    client = getattr(app.state, "temporal_client", None)
    if client is None:
        raise HTTPException(status_code=503, detail="Durable remediation orchestration is unavailable.")
    action_preview = engine.build_action(approval)
    # Reject invalid/self-destructive targets before creating a durable
    # workflow or submitting anything to the external executor.
    _require_live_executor_configuration(action_preview)
    readiness = await _execution_plane_readiness(action_preview)
    if not readiness["ready"]:
        raise HTTPException(status_code=503, detail=readiness["reason"])
    workflow_key = _build_action_idempotency_key(approval, action_preview.action_type)
    workflow_id = _remediation_workflow_id(approval, workflow_key)
    existing = await _find_existing_action(app, workflow_key)
    if existing is not None and existing.status in {
        RemediationStatus.SUCCEEDED,
        RemediationStatus.SKIPPED,
    }:
        return existing
    if existing is not None and existing.approval_id == approval.id and existing.status in {
        RemediationStatus.FAILED, RemediationStatus.POLICY_BLOCKED,
        RemediationStatus.EXECUTION_FAILED, RemediationStatus.DISPATCH_FAILED,
        RemediationStatus.VALIDATION_FAILED, RemediationStatus.TIMED_OUT,
    }:
        # Temporal completes a workflow which returns a failed action. Reusing
        # that approval cannot create a new run; retain the terminal receipt.
        # A separately persisted approval authorizes a distinct retry attempt.
        return existing
    if existing is not None and existing.approval_id == approval.id and existing.status in {
        RemediationStatus.PENDING,
        RemediationStatus.DISPATCHING,
        RemediationStatus.EXECUTOR_ACCEPTED,
        RemediationStatus.RUNNING,
        RemediationStatus.VERIFYING,
    }:
        return existing
    if existing is not None:
        action_preview.id = existing.id
    action_preview.idempotency_key = workflow_key
    action_preview.status = RemediationStatus.PENDING
    bind_execution_contract(action_preview, approval)
    verify_execution_contract(action_preview)
    action_preview.parameters["lifecycle"] = {
        "state": RemediationStatus.DISPATCHING.value,
        "history": [
            RemediationStatus.POLICY_CHECKED.value,
            RemediationStatus.APPROVED.value,
            RemediationStatus.DISPATCHING.value,
        ],
    }
    action_preview.parameters["orchestration"] = {
        "provider": "temporal",
        "workflow_id": workflow_id,
        "status": "submitting",
        "executor_readiness": readiness,
    }
    # Persist intent before contacting Temporal. If the process exits between
    # submission and acknowledgement, the deterministic workflow/idempotency
    # IDs make reconciliation safe instead of losing the operator action.
    await _reserve_target_execution(app, action_preview)
    # Workflow execution failures live in temporalio.exceptions. Importing this
    # from temporalio.client works in neither the pinned SDK nor current SDKs
    # and caused every durable execution request to fail before workflow start.
    from temporalio.exceptions import WorkflowAlreadyStartedError
    from temporalio.common import WorkflowIDReusePolicy

    try:
        await client.start_workflow(
            "KaiOpsRemediationWorkflow",
            approval.model_dump(mode="json"),
            id=workflow_id,
            task_queue=settings.remediation_temporal_task_queue,
            id_reuse_policy=WorkflowIDReusePolicy.ALLOW_DUPLICATE_FAILED_ONLY,
        )
    except WorkflowAlreadyStartedError:
        client.get_workflow_handle(workflow_id)
    except Exception as exc:
        action_preview.error = f"Temporal workflow submission failed: {type(exc).__name__}"
        action_preview.parameters["orchestration"]["status"] = "submission_failed"
        await _persist_action(app, action_preview)
        raise HTTPException(status_code=503, detail=action_preview.error) from exc
    # The target may be the API gateway carrying this request. A durable
    # workflow must therefore be acknowledged before remediation can restart
    # that gateway; completion is delivered through the persisted action/event
    # stream consumed by the UI.
    # Temporal acceptance proves durable orchestration only. It does not prove
    # that Jenkins (or another adapter) accepted or started the mutation.
    action_preview.status = RemediationStatus.DISPATCHING
    action_preview.started_at = utc_now()
    action_preview.parameters["orchestration"] = {
        "provider": "temporal",
        "workflow_id": workflow_id,
        "status": "workflow_accepted",
        "executor_readiness": readiness,
    }
    await _persist_action(app, action_preview)
    return action_preview


@app.get("/actions/by-incident/{incident_id}/latest", response_model=RemediationAction)
async def latest_action_for_incident(incident_id: UUID) -> RemediationAction:
    session_factory = getattr(app.state, "session_factory", None)
    if session_factory is None:
        raise HTTPException(status_code=503, detail="Remediation persistence is unavailable.")
    async with session_factory() as session:
        action = await IncidentRepository(session).find_latest_action_by_incident(incident_id)
    if action is None:
        raise HTTPException(status_code=404, detail="No remediation action exists for this incident.")
    return action


async def _stop_jenkins_execution(action: RemediationAction) -> dict[str, Any]:
    result = action.parameters.get("execution_result")
    result = result if isinstance(result, dict) else {}
    endpoint = str(result.get("connector_endpoint") or "").rstrip("/")
    queue_url = str(result.get("queue_url") or "").strip()
    build_url = str(result.get("build_url") or "").strip()
    username = os.getenv("JENKINS_USERNAME", "").strip()
    token = os.getenv("JENKINS_API_TOKEN", "").strip()
    if not endpoint or not username or not token:
        raise HTTPException(status_code=409, detail="Emergency stop is unavailable because Jenkins control metadata or runtime credentials are missing.")
    target_url = ""
    params: dict[str, str] = {}
    if build_url:
        target_url = f"{build_url.rstrip('/')}/stop"
    else:
        match = re.search(r"/queue/item/(\d+)", queue_url)
        if not match:
            raise HTTPException(status_code=409, detail="Emergency stop cannot identify the queued Jenkins item.")
        target_url = f"{endpoint}/queue/cancelItem"
        params = {"id": match.group(1)}
    async with httpx.AsyncClient(auth=(username, token), timeout=httpx.Timeout(15.0, connect=5.0), follow_redirects=True) as client:
        headers: dict[str, str] = {}
        crumb_response = await client.get(f"{endpoint}/crumbIssuer/api/json")
        if crumb_response.status_code == 200:
            crumb = crumb_response.json()
            headers[str(crumb.get("crumbRequestField") or "Jenkins-Crumb")] = str(crumb.get("crumb") or "")
        response = await client.post(target_url, params=params, headers=headers)
        response.raise_for_status()
    return {"executor": "jenkins", "target_url": target_url, "queue_cancelled": not bool(build_url), "build_stopped": bool(build_url)}


@app.post("/actions/{action_id}/emergency-stop", response_model=RemediationAction)
async def emergency_stop_action(action_id: UUID, request: EmergencyStopRequest) -> RemediationAction:
    session_factory = getattr(app.state, "session_factory", None)
    if session_factory is None:
        raise HTTPException(status_code=503, detail="Remediation persistence is unavailable.")
    async with session_factory() as session:
        action = await IncidentRepository(session).find_action_by_id(action_id, tenant_id=request.tenant_id)
    if action is None:
        raise HTTPException(status_code=404, detail="Active remediation action not found in this tenant.")
    if action.status.value not in ACTIVE_EXECUTION_STATUSES:
        raise HTTPException(status_code=409, detail=f"Emergency stop is unavailable for terminal action status '{action.status.value}'.")
    result = action.parameters.get("execution_result")
    result = result if isinstance(result, dict) else {}
    executor = str(result.get("executor") or "").strip().lower()
    if executor != "jenkins":
        raise HTTPException(status_code=409, detail=f"Emergency stop is not implemented for executor '{executor or 'unknown'}'.")
    try:
        stop_result = await _stop_jenkins_execution(action)
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail=f"Jenkins rejected the emergency-stop request ({type(exc).__name__}).") from exc
    orchestration = action.parameters.get("orchestration")
    orchestration = orchestration if isinstance(orchestration, dict) else {}
    workflow_id = str(orchestration.get("workflow_id") or "").strip()
    if workflow_id and getattr(app.state, "temporal_client", None) is not None:
        try:
            await app.state.temporal_client.get_workflow_handle(workflow_id).cancel()
            stop_result["workflow_cancelled"] = True
        except Exception as exc:
            stop_result["workflow_cancelled"] = False
            stop_result["workflow_cancel_error"] = type(exc).__name__
    action.status = RemediationStatus.CANCELLED
    action.completed_at = utc_now()
    action.error = "Execution cancelled by authenticated operator emergency stop."
    action.parameters["emergency_stop"] = {
        **stop_result,
        "actor": request.actor,
        "reason": request.reason,
        "stopped_at": action.completed_at.isoformat(),
    }
    await _persist_action(app, action, actor=request.actor)
    return action


async def _execution_plane_readiness(action: RemediationAction) -> dict[str, Any]:
    profile = action.parameters.get("connection_profile")
    profile = profile if isinstance(profile, dict) else {}
    executor = str(profile.get("executor_type") or profile.get("connection_type") or action.action_type).strip().lower()
    if executor != "jenkins":
        return {"ready": True, "executor": executor or "native", "reason": "executor configuration accepted"}
    endpoint = str(profile.get("endpoint_url") or "").rstrip("/")
    if not endpoint:
        return {"ready": False, "executor": "jenkins", "reason": "Jenkins endpoint is not configured."}
    username = os.getenv("JENKINS_USERNAME", "").strip()
    token = os.getenv("JENKINS_API_TOKEN", "").strip()
    if not username or not token:
        return {"ready": False, "executor": "jenkins", "reason": "Jenkins runtime credentials are not available."}
    try:
        async with httpx.AsyncClient(auth=(username, token), timeout=httpx.Timeout(6.0, connect=3.0)) as client:
            response = await client.get(f"{endpoint}/api/json")
            response.raise_for_status()
    except Exception as exc:
        return {
            "ready": False,
            "executor": "jenkins",
            "endpoint": endpoint,
            "reason": f"Jenkins execution plane is unavailable ({type(exc).__name__}).",
        }
    return {"ready": True, "executor": "jenkins", "endpoint": endpoint, "reason": "Jenkins API is reachable"}


@app.get("/executors/readiness")
async def execution_plane_readiness() -> dict[str, Any]:
    profile = {
        "executor_type": os.getenv("REMEDIATION_DEFAULT_EXECUTOR", "jenkins"),
        "endpoint_url": os.getenv("REMEDIATION_JENKINS_URL", "http://jenkins:8080"),
    }
    probe = RemediationAction(
        tenant_id="readiness-probe",
        incident_id=UUID("00000000-0000-4000-8000-000000000001"),
        action_type=str(profile["executor_type"]),
        target="readiness-probe",
        parameters={"connection_profile": profile},
    )
    result = await _execution_plane_readiness(probe)
    result["temporal_connected"] = getattr(app.state, "temporal_client", None) is not None
    result["ready"] = bool(result["ready"] and result["temporal_connected"])
    if not result["ready"]:
        raise HTTPException(status_code=503, detail=result)
    return result


@app.get("/executions/{incident_id}/workflow")
async def remediation_workflow_status(
    incident_id: str,
    recommendation_id: str,
    tenant_id: str,
    action_type: str = "rollback_deployment",
) -> dict[str, Any]:
    client = getattr(app.state, "temporal_client", None)
    if not settings.remediation_temporal_enabled or client is None:
        raise HTTPException(status_code=503, detail="Durable remediation orchestration is unavailable.")
    approval = Approval(
        tenant_id=tenant_id,
        incident_id=UUID(incident_id),
        recommendation_id=UUID(recommendation_id),
    )
    workflow_key = _build_action_idempotency_key(approval, action_type)
    return await client.get_workflow_handle(f"kaiops-remediation-{workflow_key}").query("status")


@app.post("/workflow-preflight")
async def remediation_workflow_preflight(approval: Approval) -> dict[str, Any]:
    client = getattr(app.state, "temporal_client", None)
    if not settings.remediation_temporal_enabled or client is None:
        raise HTTPException(status_code=503, detail="Durable remediation orchestration is unavailable.")
    workflow_key = _build_action_idempotency_key(approval, engine.build_action(approval).action_type)
    return await client.execute_workflow(
        "KaiOpsRemediationPreflightWorkflow",
        approval.model_dump(mode="json"),
        id=f"kaiops-remediation-preflight-{workflow_key}-{int(asyncio.get_running_loop().time() * 1000)}",
        task_queue=settings.remediation_temporal_task_queue,
    )


async def _require_persisted_human_approval(approval: Approval) -> None:
    """Prevent callers from turning an unpersisted request body into approval."""
    session_factory = getattr(app.state, "session_factory", None)
    if not settings.database_enabled or session_factory is None:
        raise HTTPException(status_code=503, detail="Durable approval verification is unavailable.")
    plan = approval.metadata.get("execution_plan") if isinstance(approval.metadata.get("execution_plan"), dict) else {}
    if (
        not verify_plan_fingerprint(plan)
        or str(plan.get("plan_id") or "") != str(approval.plan_id or "")
        or str(plan.get("tenant_id") or "") != approval.tenant_id
        or str(plan.get("incident_id") or "") != str(approval.incident_id)
        or str(plan.get("plan_fingerprint") or "") != str(approval.plan_fingerprint or "")
    ):
        raise HTTPException(status_code=409, detail="Execution blocked: approval does not match the immutable execution plan.")
    async with session_factory() as session:
        accepted = await IncidentRepository(session).has_accepted_approval_id(
            approval.id,
            approval.incident_id,
            approval.recommendation_id,
            tenant_id=approval.tenant_id,
            plan_id=approval.plan_id,
            plan_fingerprint=str(approval.plan_fingerprint or ""),
        )
    if not accepted:
        raise HTTPException(
            status_code=409,
            detail="Execution blocked: the exact approval ID is not a persisted accepted decision for this recommendation.",
        )


async def _require_persisted_approved_runbook(approval: Approval) -> None:
    if not settings.database_enabled:
        raise PolicyViolation("automatic execution requires durable runbook governance")
    plan = approval.metadata.get("execution_plan") if isinstance(approval.metadata.get("execution_plan"), dict) else {}
    runbook_id = str(approval.metadata.get("runbook_id") or plan.get("runbook_governance_id") or "").strip()
    if not runbook_id:
        raise PolicyViolation("automatic execution blocked: governed runbook identity is missing")
    version = int(approval.metadata.get("runbook_version") or plan.get("playbook_version") or 1)
    async with app.state.session_factory() as session:
        governance = await IncidentRepository(session).get_runbook_governance(
            runbook_id, version, tenant_id=approval.tenant_id
        )
    if not governance or governance.get("status") != "approved":
        raise PolicyViolation("automatic execution blocked: runbook version is not durably approved or is suspended")
    payload = governance.get("payload") if isinstance(governance.get("payload"), dict) else {}
    approved_checksum = str(payload.get("checksum_sha256") or "").strip()
    plan_checksum = str(approval.metadata.get("runbook_checksum") or plan.get("runbook_checksum") or "").strip()
    if not approved_checksum or approved_checksum != plan_checksum:
        raise PolicyViolation("automatic execution blocked: runbook checksum does not match durable approval")
    expires_at = str(payload.get("approval_expires_at") or "").strip()
    if not expires_at:
        raise PolicyViolation("automatic execution blocked: runbook approval expiry is missing")
    try:
        expiry = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise PolicyViolation("automatic execution blocked: runbook approval expiry is invalid") from exc
    if expiry <= utc_now():
        raise PolicyViolation("automatic execution blocked: runbook approval has expired")


@app.post("/dry-run")
async def dry_run_approval(approval: Approval) -> dict[str, Any]:
    """Build and policy-check an action without invoking its execution plugin."""
    action = engine.build_action(approval)
    _require_production_credential_reference(approval, action.action_type)
    allowed = engine.is_action_allowed(action.action_type)
    unsafe_reasons = _unsafe_plan_reasons(approval)
    connector_check = await _preflight_live_connector(action)
    passed = allowed and not unsafe_reasons and connector_check["passed"]
    plan = approval.metadata.get("execution_plan") if isinstance(approval.metadata.get("execution_plan"), dict) else {}
    plan_actions = plan.get("actions") if isinstance(plan.get("actions"), list) else []
    first_action = plan_actions[0] if plan_actions and isinstance(plan_actions[0], dict) else {}
    binding = first_action.get("safety_binding") if isinstance(first_action.get("safety_binding"), dict) else {}
    planned = binding.get("preflight") if isinstance(binding.get("preflight"), dict) else {}
    evidence_id = "preflight:" + hashlib.sha256(
        f"{approval.tenant_id}:{approval.incident_id}:{approval.plan_fingerprint}:{action.action_type}:{connector_check}".encode()
    ).hexdigest()
    profile = action.parameters.get("connection_profile")
    profile = profile if isinstance(profile, dict) else {}
    preflight_evidence = PreflightEvidence(
        status="PASSED" if passed else "FAILED",
        capability_id=str(planned.get("capability_id") or action.action_type),
        target_resource_id=str(planned.get("target_resource_id") or action.target),
        check_references=list(planned.get("check_references") or []),
        evidence_ids=[evidence_id] if passed else [],
        dry_run_required=True,
        dry_run_evidence_id=evidence_id if passed else None,
        credential_reference=str(
            planned.get("credential_reference")
            or profile.get("credential_ref")
            or approval.metadata.get("credential_ref")
            or "unavailable"
        ),
    ).model_dump(mode="json")
    action.parameters["preflight_evidence"] = preflight_evidence
    action.parameters["dry_run"] = True
    action.output = "Dry run passed; no command was executed." if passed else "Dry run blocked."
    result = {
        "status": "passed" if passed else "blocked",
        "dry_run": True,
        "executed": False,
        "incident_id": str(approval.incident_id),
        "recommendation_id": str(approval.recommendation_id),
        "action_type": action.action_type,
        "target": action.target,
        "checks": {
            "action_allowlisted": allowed,
            "plan_safe": not unsafe_reasons,
            "unsafe_reasons": unsafe_reasons,
            "approval_decision": str(approval.decision.value),
            "idempotency_key": _build_action_idempotency_key(approval, action.action_type),
            "connector": connector_check,
        },
        "message": "Dry run passed; no command was executed." if passed else (
            unsafe_reasons[0] if unsafe_reasons else connector_check.get("message") or f"Action type '{action.action_type}' is not allowlisted."
        ),
    }


async def _preflight_live_connector(action: RemediationAction) -> dict[str, Any]:
    profile = action.parameters.get("connection_profile")
    profile = profile if isinstance(profile, dict) else {}
    executor = str(profile.get("executor_type") or profile.get("connection_type") or "").strip().lower()
    if executor == "azure_container_apps_job":
        required = {
            "subscription_id": profile.get("subscription_id") or os.getenv("AZURE_SUBSCRIPTION_ID"),
            "resource_group": profile.get("resource_group") or os.getenv("AZURE_RESOURCE_GROUP"),
            "job_name": profile.get("job_name") or os.getenv("REMEDIATION_ACA_JOB_NAME"),
            "managed_identity": os.getenv("IDENTITY_ENDPOINT") and os.getenv("IDENTITY_HEADER"),
        }
        missing = [name for name, value in required.items() if not str(value or "").strip()]
        return {
            "passed": not missing,
            "executor": executor,
            "job_name": str(required["job_name"] or ""),
            "message": "Azure Container Apps Job configuration is ready." if not missing else f"Azure job preflight failed: configure {', '.join(missing)}.",
        }
    if executor != "jenkins":
        return {"passed": True, "executor": executor or "local", "message": "No Jenkins connector selected."}

    endpoint = str(profile.get("endpoint_url") or profile.get("endpoint") or "").strip().rstrip("/")
    job_name = str(profile.get("job_name") or "").strip("/")
    username = os.getenv("JENKINS_USERNAME", "").strip()
    token = os.getenv("JENKINS_API_TOKEN", "").strip()
    if not endpoint or not job_name or not username or not token:
        return {
            "passed": False,
            "executor": "jenkins",
            "message": "Jenkins preflight failed: endpoint, job, or runtime credentials are unavailable.",
        }
    job_path = "/job/" + "/job/".join(part for part in job_name.split("/") if part)
    try:
        # Jenkins can take longer than eight seconds to answer its first API
        # request after plugin activity or JVM pressure. Keep connection
        # failure detection tight, but allow a bounded read window so a healthy
        # and authenticated controller is not reported as a failed dry run.
        async with httpx.AsyncClient(auth=(username, token), timeout=httpx.Timeout(25.0, connect=5.0)) as client:
            response = await client.get(f"{endpoint}{job_path}/api/json?tree=name,buildable,inQueue")
            response.raise_for_status()
            payload = response.json()
        buildable = bool(payload.get("buildable", True))
        return {
            "passed": buildable,
            "executor": "jenkins",
            "job_name": job_name,
            "buildable": buildable,
            "in_queue": bool(payload.get("inQueue")),
            "message": "Jenkins job is reachable and buildable." if buildable else "Jenkins preflight failed: the configured job is disabled.",
        }
    except (httpx.HTTPError, ValueError) as exc:
        return {
            "passed": False,
            "executor": "jenkins",
            "job_name": job_name,
            "message": f"Jenkins preflight failed: {type(exc).__name__}.",
        }


def _unsafe_plan_reasons(approval: Approval) -> list[str]:
    """Fail closed when an edited plan contains destructive shell/database actions."""
    plan = approval.metadata.get("execution_plan") if isinstance(approval.metadata.get("execution_plan"), dict) else {}
    values = [approval.modified_action or ""]
    for key in ("commands", "scripts", "queries"):
        item = plan.get(key, [])
        values.extend(str(value) for value in (item if isinstance(item, list) else [item]))
    text = "\n".join(values).lower()
    markers = {
        "recursive filesystem deletion": ("rm -rf", "remove-item -recurse", "rmdir /s"),
        "database destruction": ("drop database", "drop table", "truncate table"),
        "infrastructure destruction": ("terraform destroy", "kubectl delete namespace"),
    }
    reasons = [f"Execution blocked: {label} requires a separately reviewed, policy-authorized plan." for label, tokens in markers.items() if any(token in text for token in tokens)]
    if str(plan.get("schema_version") or "").startswith("kaims.execution-plan."):
        expected_bindings = {
            "rca_version": approval.metadata.get("rca_version"),
            "evidence_snapshot_id": approval.metadata.get("evidence_snapshot_id"),
            "recommendation_version": str(approval.recommendation_id),
        }
        for name, expected in expected_bindings.items():
            actual = str(plan.get(name) or "").strip()
            if not actual or (expected is not None and actual != str(expected)):
                reasons.append(
                    f"Execution blocked: immutable {name.replace('_', ' ')} binding is missing or mismatched."
                )
        expected_target = str(approval.metadata.get("target_resource_id") or "").strip()
        plan_target = str(plan.get("target_resource_id") or plan.get("remediation_target") or "").strip()
        if not expected_target or expected_target != plan_target:
            reasons.append("Execution blocked: approved target resource binding is missing or mismatched.")
        expected_connector = str(approval.metadata.get("connector_id") or "").strip()
        if not expected_connector or expected_connector != str(plan.get("connector_id") or "").strip():
            reasons.append("Execution blocked: approved connector binding is missing or mismatched.")
        approved_rollback = approval.metadata.get("rollback_plan")
        plan_rollback = plan.get("rollback") or plan.get("rollback_commands")
        if approved_rollback != plan_rollback:
            reasons.append("Execution blocked: approved rollback binding is missing or mismatched.")
        if plan.get("execution_ready") is not True:
            blocks = plan.get("readiness_blocks") if isinstance(plan.get("readiness_blocks"), list) else []
            detail = "; ".join(str(value) for value in blocks[:3] if str(value).strip())
            reasons.append(
                "Execution blocked: the catalog plan is not execution-ready"
                + (f" ({detail})." if detail else ".")
            )
        if not verify_plan_fingerprint(plan):
            reasons.append("Execution blocked: the catalog plan fingerprint is missing or invalid.")
        if not plan.get("commands"):
            reasons.append("Execution blocked: the catalog plan contains no approved corrective command.")
        if not plan.get("validation_commands"):
            reasons.append("Execution blocked: the catalog plan contains no recovery validation.")
    if re.search(r"\$\{[^}]+\}|<[^>]+>|\b(?:todo|tbd)\b", text, flags=re.IGNORECASE):
        reasons.append("Execution blocked: the plan contains unresolved parameters or placeholders.")
    return reasons


def _plan_is_validation_only(approval: Approval) -> bool:
    """Return true when the plan contains diagnostics but no corrective capability."""
    plan = approval.metadata.get("execution_plan") if isinstance(approval.metadata.get("execution_plan"), dict) else {}
    executable: list[str] = []
    for key in ("commands", "scripts"):
        item = plan.get(key, [])
        executable.extend(str(value).strip() for value in (item if isinstance(item, list) else [item]) if str(value).strip())
    if not executable:
        return False
    def diagnostic_only(value: str) -> bool:
        normalized = value.lower()
        # This collector is intentionally read-only for every flag value.
        # Changing its legacy --dry-run argument must never manufacture a
        # remediation capability that the script does not implement.
        if "kaiops_alert_health_triage.sh" in normalized:
            return True
        return bool(re.search(r"--dry-run(?:=|\s+)(?:true|1)\b", value, flags=re.IGNORECASE))

    return all(diagnostic_only(value) for value in executable)


def _require_production_credential_reference(approval: Approval, action_type: str) -> None:
    profile = approval.metadata.get("connection_profile") if isinstance(approval.metadata.get("connection_profile"), dict) else {}
    environment = str(profile.get("environment") or approval.metadata.get("environment") or "").strip().lower()
    if environment not in {"prod", "production"}:
        return
    if str(action_type or "").strip().lower() in {"status", "query", "inspect", "noop"}:
        return
    executor_type = str(profile.get("executor_type") or profile.get("connection_type") or "").strip().lower()
    if executor_type == "azure_container_apps_job" and str(profile.get("identity_type") or "managed_identity").lower() == "managed_identity":
        return
    credential_ref = str(profile.get("credential_ref") or "").strip()
    valid_prefix = credential_ref.startswith(("vault://", "arn:aws:secretsmanager:", "gcp-secret://", "k8s-secret://")) or (
        credential_ref.startswith("https://") and ".vault.azure.net/secrets/" in credential_ref
    )
    if not valid_prefix:
        raise HTTPException(
            status_code=422,
            detail="Production remediation requires a valid enterprise secret-manager reference; secret values are not accepted.",
        )


def _require_live_executor_configuration(action: RemediationAction) -> None:
    """Reject non-executable approvals before they emit a failed closure event."""
    profile = action.parameters.get("connection_profile")
    profile = profile if isinstance(profile, dict) else {}
    executor_type = str(profile.get("executor_type") or profile.get("connection_type") or "").strip().lower()
    normalized_target = str(action.target or "").strip().lower().removeprefix("kaiops-")
    if (
        normalized_target == "remediation-engine"
        and executor_type == "jenkins"
        and not settings.remediation_temporal_enabled
    ):
        raise HTTPException(
            status_code=409,
            detail=(
                "Execution blocked: remediation-engine cannot synchronously restart itself through Jenkins. "
                "Use an external remediation control-plane worker with durable Jenkins reconciliation."
            ),
        )
    try:
        UUID(str(action.target))
    except (TypeError, ValueError, AttributeError):
        target_is_incident_uuid = False
    else:
        target_is_incident_uuid = True
    if target_is_incident_uuid and executor_type in {"jenkins", "azure_container_apps_job"}:
        raise HTTPException(
            status_code=409,
            detail=(
                "Execution blocked: the live remediation target is an incident UUID. "
                "Attach the approved service/resource target and execution plan before executing."
            ),
        )
    if action.action_type == "script_execution" and executor_type not in {"jenkins", "azure_container_apps_job"}:
        return
    if executor_type == "azure_container_apps_job":
        required = {
            "subscription_id": profile.get("subscription_id") or os.getenv("AZURE_SUBSCRIPTION_ID"),
            "resource_group": profile.get("resource_group") or os.getenv("AZURE_RESOURCE_GROUP"),
            "job_name": profile.get("job_name") or os.getenv("REMEDIATION_ACA_JOB_NAME"),
        }
        missing = [name for name, value in required.items() if not str(value or "").strip()]
        if not missing:
            return
        raise HTTPException(status_code=409, detail=f"Execution blocked: Azure Container Apps Job connector requires {', '.join(missing)}.")
    if executor_type == "jenkins" or action.action_type == "rollback_deployment":
        required = {
            "endpoint_url": profile.get("endpoint_url") or profile.get("endpoint"),
            "job_name": profile.get("job_name"),
            "credential_ref": profile.get("credential_ref") or profile.get("secret_ref"),
        }
        missing = [name for name, value in required.items() if not str(value or "").strip()]
        if not missing:
            return
        raise HTTPException(
            status_code=409,
            detail=(
                "Execution blocked: the Jenkins connector is incomplete. "
                f"Configure {', '.join(missing)} before approving live remediation."
            ),
        )

    raise HTTPException(
        status_code=409,
        detail=(
            f"Execution blocked: no live executor is implemented for action type '{action.action_type}'. "
            "Select a governed Jenkins connector or an approved local script execution plan."
        ),
    )


def _build_action_idempotency_key(approval: Approval, action_type: str) -> str:
    raw = f"{approval.incident_id}:{approval.recommendation_id}:{action_type}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _rollback_idempotency_key(approval: Approval, action_type: str) -> str:
    raw = f"{approval.incident_id}:{approval.recommendation_id}:{action_type}:rollback"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


async def _finalize_failed_rollback(
    approval: Approval,
    action: RemediationAction,
    original: RemediationAction | None,
) -> RemediationAction:
    action.status = RemediationStatus.ROLLBACK_FAILED
    action.error = action.error or "The approved automatic rollback did not complete successfully."
    action.completed_at = utc_now()
    action.parameters["escalation"] = {
        "required": True,
        "reason": "automatic_rollback_failed",
        "source_action_id": str(original.id) if original else str(action.parameters.get("rollback_of_action_id") or ""),
    }
    return await _finalize_api_execution(approval, action)


async def _find_existing_action(app: FastAPI, idempotency_key: str | None) -> RemediationAction | None:
    if not settings.database_enabled or not idempotency_key:
        return None
    async with app.state.session_factory() as session:
        repo = IncidentRepository(session)
        return await repo.find_action_by_idempotency_key(idempotency_key)


async def _persist_action(app: FastAPI, action: RemediationAction, *, actor: str = "remediation-engine") -> None:
    if not settings.database_enabled:
        return
    async with app.state.session_factory() as session:
        repo = IncidentRepository(session)
        await repo.save_action(action)
        await repo.save_action_audit(action, actor=actor)
        await session.commit()


def _target_execution_scope(action: RemediationAction) -> str:
    parameters = action.parameters if isinstance(action.parameters, dict) else {}
    profile = parameters.get("connection_profile") if isinstance(parameters.get("connection_profile"), dict) else {}
    # Scope by the real execution plane, not an incident's environment label.
    # Two incidents can label the same compose/container target differently;
    # allowing both was the exact race this lease is intended to prevent.
    executor = str(profile.get("endpoint_url") or profile.get("executor_type") or "default").strip().lower()
    tenant = str(action.tenant_id or "default").strip().lower()
    target = re.sub(r"\s+", "-", str(action.target or "").strip().lower())
    return f"{tenant}:{executor}:{target}"


async def _reserve_target_execution(app: FastAPI, action: RemediationAction) -> None:
    """Atomically reserve a mutation scope across incidents and replicas.

    The short database lock only protects the check-and-persist operation. The
    persisted non-terminal action is the durable lease, so a process restart
    cannot allow a second incident to mutate the same target. Terminal actions
    release the scope naturally; the existing watchdog expires abandoned work.
    """
    if not settings.database_enabled:
        return
    scope = _target_execution_scope(action)
    action.parameters["target_execution"] = {
        "scope": scope,
        "mode": "exclusive",
        "owner_action_id": str(action.id),
    }
    process_lock = target_execution_locks.setdefault(scope, asyncio.Lock())
    async with process_lock:
        from common.advisory_lock import advisory_session
        db_lock_name = f"kaiops_target_{hashlib.sha256(scope.encode('utf-8')).hexdigest()[:40]}"
        async with advisory_session(app.state.session_factory, db_lock_name, wait_seconds=5) as session:
            if session is None:
                raise HTTPException(status_code=409, detail=f"Target execution is busy; retry after the active remediation completes. scope={scope}")
            rows = (
                await session.execute(
                    select(ActionRecord).where(
                        ActionRecord.tenant_id == (action.tenant_id or "default"),
                        ActionRecord.target == action.target,
                        ActionRecord.status.in_(ACTIVE_EXECUTION_STATUSES),
                    )
                )
            ).scalars().all()
            for row in rows:
                if row.id == action.id or (action.idempotency_key and row.idempotency_key == action.idempotency_key):
                    continue
                payload = row.payload if isinstance(row.payload, dict) else {}
                try:
                    active = RemediationAction.model_validate(payload)
                    active_scope = _target_execution_scope(active)
                except Exception:
                    # Legacy active rows without a complete payload are
                    # conservatively target-wide until the watchdog expires them.
                    active_scope = scope
                if active_scope == scope:
                    raise HTTPException(
                        status_code=409,
                        detail={
                            "code": "target_execution_busy",
                            "message": "Another remediation is already mutating this target.",
                            "scope": scope,
                            "active_action_id": str(row.id),
                            "active_incident_id": str(row.incident_id),
                            "retryable": True,
                        },
                    )
            repo = IncidentRepository(session)
            await repo.save_action(action)
            await repo.save_action_audit(action)
            await session.commit()



def _rca_and_resolution_confidence(payload: dict[str, Any]) -> tuple[float | None, float | None]:
    recommendation = payload.get("recommendation", {}) if isinstance(payload.get("recommendation"), dict) else {}
    metadata = recommendation.get("metadata", {}) if isinstance(recommendation.get("metadata"), dict) else {}
    rca_analysis = metadata.get("rca_analysis", {}) if isinstance(metadata.get("rca_analysis"), dict) else {}
    context = payload.get("context", {}) if isinstance(payload.get("context"), dict) else {}
    context_metadata = context.get("metadata", {}) if isinstance(context.get("metadata"), dict) else {}
    try:
        rca_confidence = float(
            rca_analysis.get("confidence_score")
            or context.get("confidence")
            or context.get("confidence_score")
            or context_metadata.get("confidence")
            or context_metadata.get("confidence_score")
        )
    except (TypeError, ValueError):
        rca_confidence = None
    try:
        resolution_confidence = float(recommendation.get("confidence"))
    except (TypeError, ValueError):
        resolution_confidence = None
    execution_plan = metadata.get("execution_plan") if isinstance(metadata.get("execution_plan"), dict) else {}
    catalog_plan_complete = (
        execution_plan.get("schema_version") == "kaims.execution-plan.v2"
        and execution_plan.get("execution_ready") is True
        and str(execution_plan.get("plan_fingerprint") or "").startswith("sha256:")
        and bool(execution_plan.get("commands"))
        and bool(execution_plan.get("validation_commands"))
        and (
            bool(execution_plan.get("rollback_commands"))
            or execution_plan.get("rollback_mode") == "not_applicable"
        )
        and bool(str(execution_plan.get("remediation_target") or "").strip())
    )
    if catalog_plan_complete:
        # A fully bound, immutable catalog plan supplies deterministic plan
        # assurance. It does not replace the independent RCA/evidence gate.
        resolution_confidence = max(resolution_confidence or 0.0, 0.90)
    return rca_confidence, resolution_confidence


def _resolution_requires_approval(payload: dict[str, Any]) -> bool:
    recommendation = payload.get("recommendation", {}) if isinstance(payload.get("recommendation"), dict) else {}
    metadata = recommendation.get("metadata", {}) if isinstance(recommendation.get("metadata"), dict) else {}
    execution_plan = metadata.get("execution_plan") if isinstance(metadata.get("execution_plan"), dict) else {}
    policy = execution_plan.get("policy_decision") if isinstance(execution_plan.get("policy_decision"), dict) else {}
    policy_decision = str(policy.get("decision") or "").lower()
    if policy_decision == "hitl":
        return True
    if policy_decision in {"block", "investigate"}:
        return True
    if policy_decision == "hotl":
        # Autonomous mutation is not a supported decision in the P0 release.
        # Fail closed even if an older producer or a forged payload sends it.
        return True

    # Confidence is evidence for a reviewer, never execution authorization.
    # The former environment-controlled legacy bypass is intentionally gone.

    decision = payload.get("decision", {}) if isinstance(payload.get("decision"), dict) else {}
    if "requires_approval" in decision:
        return True

    orchestration = metadata.get("orchestration_decision", {}) if isinstance(metadata.get("orchestration_decision"), dict) else {}
    if "requires_approval" in orchestration:
        return True

    return True


def _build_auto_approval(payload: dict[str, Any]) -> Approval | None:
    recommendation = payload.get("recommendation", {}) if isinstance(payload.get("recommendation"), dict) else {}
    incident_id = recommendation.get("incident_id")
    recommendation_id = recommendation.get("id")
    if incident_id is None or recommendation_id is None:
        return None

    decision = payload.get("decision", {}) if isinstance(payload.get("decision"), dict) else {}
    incident = payload.get("incident", {}) if isinstance(payload.get("incident"), dict) else {}
    recommendation_metadata = recommendation.get("metadata", {}) if isinstance(recommendation.get("metadata"), dict) else {}

    policy_version = str(
        decision.get("policy_version") or recommendation_metadata.get("policy_version") or ""
    ).strip()
    policy_reason = str(
        decision.get("policy_reason") or recommendation_metadata.get("policy_reason") or ""
    ).strip()

    context_confidence, resolution_confidence = _rca_and_resolution_confidence(payload)
    metadata: dict[str, Any] = {
        "auto_approved": True,
        "approval_source": "resolution-events",
        "confidence_gate_passed": True,
        "context_confidence": context_confidence,
        "resolution_confidence": resolution_confidence,
        "auto_execute_threshold": settings.rca_resolution_auto_complete_threshold,
    }
    if policy_version:
        metadata["policy_version"] = policy_version
    if policy_reason:
        metadata["policy_reason"] = policy_reason
    service = _first_non_empty(incident.get("service"), recommendation_metadata.get("service"))
    environment = _first_non_empty(incident.get("environment"), recommendation_metadata.get("environment"))
    remediation_target = _first_non_empty(
        recommendation_metadata.get("remediation_target"),
        recommendation.get("target"),
        recommendation.get("resource"),
        incident.get("deployment"),
        service,
    )
    if service:
        metadata["service"] = service
        metadata["incident_service"] = service
    if environment:
        metadata["environment"] = environment
    supplied_profile = recommendation_metadata.get("connection_profile")
    supplied_profile = supplied_profile if isinstance(supplied_profile, dict) else {}
    default_profile = {
        "application": str(incident.get("application") or recommendation_metadata.get("application") or service or "unknown"),
        "service": str(service or "unknown"),
        "environment": str(environment or "local"),
        "namespace": str(environment or "default"),
        "endpoint_url": "http://jenkins:8080",
        "connection_type": "jenkins",
        "executor_type": "jenkins",
        "job_name": "kaiops-auto-remediation",
        "timeout_seconds": 1200,
        "credential_ref": f"vault://kaiops/{str(environment or 'local').lower()}/jenkins#api-token",
    }
    metadata["connection_profile"] = {
        **default_profile,
        **{key: value for key, value in supplied_profile.items() if value is not None and str(value).strip()},
    }
    if remediation_target:
        metadata["remediation_target"] = remediation_target
        metadata["target"] = remediation_target
    recommended_action = _first_non_empty(recommendation.get("recommended_action"), recommendation.get("action"))
    recommended_commands = recommendation.get("commands") if isinstance(recommendation.get("commands"), list) else []
    execution_plan = recommendation_metadata.get("execution_plan") if isinstance(recommendation_metadata.get("execution_plan"), dict) else {}
    if recommended_action:
        metadata["recommended_action"] = recommended_action
    if recommended_commands:
        metadata["recommended_commands"] = [str(item).strip() for item in recommended_commands if str(item).strip()]
    if execution_plan:
        # Preserve the exact reviewed catalog contract through auto approval;
        # rebuilding it from prose loses fingerprint, rollback, and validation.
        metadata["execution_plan"] = execution_plan
    for key in ("runbook_id", "runbook_slug", "runbook_version", "runbook_status", "runbook_checksum", "runbook_match_score"):
        if recommendation_metadata.get(key) is not None:
            metadata[key] = recommendation_metadata[key]

    return Approval(
        tenant_id=str(
            execution_plan.get("tenant_id")
            or recommendation.get("tenant_id")
            or incident.get("tenant_id")
            or ""
        ),
        incident_id=incident_id,
        recommendation_id=recommendation_id,
        plan_id=execution_plan.get("plan_id"),
        plan_fingerprint=execution_plan.get("plan_fingerprint"),
        approval_expires_at=execution_plan.get("expiry"),
        decision=ApprovalDecision.APPROVED,
        approver="system-auto-approval",
        channel="web",
        comment=str(recommendation.get("recommended_action") or "auto-approved remediation"),
        metadata=metadata,
    )


async def _request_failure_reconsideration(
    *, action: RemediationAction, source_payload: dict[str, Any]
) -> None:
    """Ask resolution intelligence for a fresh, approval-gated plan after execution failure."""
    if action.status != RemediationStatus.FAILED:
        return
    previous = source_payload.get("recommendation", {}) if isinstance(source_payload.get("recommendation"), dict) else {}
    if not previous and isinstance(source_payload.get("approval"), dict):
        approval_metadata = source_payload["approval"].get("metadata", {})
        approval_metadata = approval_metadata if isinstance(approval_metadata, dict) else {}
        previous = {
            "id": source_payload["approval"].get("recommendation_id"),
            "recommended_action": approval_metadata.get("recommended_action"),
            "commands": approval_metadata.get("recommended_commands", []),
            "severity": approval_metadata.get("severity", "warning"),
            "metadata": approval_metadata,
        }
    previous_metadata = previous.get("metadata", {}) if isinstance(previous.get("metadata"), dict) else {}
    attempt = int(previous_metadata.get("execution_reconsideration_attempt") or 0) + 1
    maximum = max(0, int(os.getenv("REMEDIATION_FAILURE_RECONSIDERATION_LIMIT", "2")))
    if attempt > maximum:
        action.metadata["failure_reconsideration"] = {"status": "limit_reached", "attempt": attempt - 1, "limit": maximum}
        await _persist_action(app, action)
        return
    request = {
        "incident_id": str(action.incident_id),
        "action_id": str(action.id),
        "action_type": action.action_type,
        "target": action.target,
        "preflight_evidence": action.parameters.get("preflight_evidence", {}),
        "service": str(action.parameters.get("service") or action.target),
        "environment": str(action.parameters.get("environment") or "prod"),
        "error": str(action.error or action.output or "execution failed"),
        "execution_result": action.parameters.get("execution_result", {}),
        "previous_recommendation": previous,
        "attempt": attempt,
    }
    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            response = await client.post(f"{settings.resolution_agent_url.rstrip('/')}/reconsider-execution", json=request)
            response.raise_for_status()
            revised_payload = response.json()
        await app.state.producer.publish(RESOLUTION_EVENTS, revised_payload, key=str(action.incident_id))
        action.metadata["failure_reconsideration"] = {"status": "awaiting_approval", "attempt": attempt, "limit": maximum}
    except Exception as exc:
        action.metadata["failure_reconsideration"] = {"status": "request_failed", "attempt": attempt, "error": str(exc)}
    await _persist_action(app, action)


def _enrich_approval_from_payload(approval: Approval, payload: dict[str, Any]) -> Approval:
    recommendation, _, incident, _ = _extract_resolution_context(payload)
    recommendation_metadata = recommendation.get("metadata", {}) if isinstance(recommendation.get("metadata"), dict) else {}

    service = _first_non_empty(approval.metadata.get("service"), incident.get("service"), recommendation_metadata.get("service"))
    environment = _first_non_empty(
        approval.metadata.get("environment"),
        incident.get("environment"),
        recommendation_metadata.get("environment"),
    )
    remediation_target = _first_non_empty(
        approval.metadata.get("remediation_target"),
        approval.metadata.get("target"),
        recommendation_metadata.get("remediation_target"),
        recommendation.get("target"),
        recommendation.get("resource"),
        incident.get("deployment"),
        service,
    )
    recommended_action = _first_non_empty(
        approval.metadata.get("recommended_action"),
        recommendation.get("recommended_action"),
        recommendation.get("action"),
    )
    recommended_commands = recommendation.get("commands") if isinstance(recommendation.get("commands"), list) else []

    if service:
        approval.metadata["service"] = service
        approval.metadata["incident_service"] = service
    if environment:
        approval.metadata["environment"] = environment
    if remediation_target:
        approval.metadata["remediation_target"] = remediation_target
        approval.metadata["target"] = remediation_target
    if recommended_action:
        approval.metadata["recommended_action"] = recommended_action
    if recommended_commands and not isinstance(approval.metadata.get("recommended_commands"), list):
        approval.metadata["recommended_commands"] = [str(item).strip() for item in recommended_commands if str(item).strip()]
    lifecycle = extract_lifecycle(recommendation_metadata, recommendation)
    if lifecycle:
        approval.metadata["resolution_lifecycle"] = lifecycle
    for key in ("runbook_id", "runbook_slug", "runbook_version", "runbook_status", "runbook_checksum", "runbook_match_score"):
        if approval.metadata.get(key) is None and recommendation_metadata.get(key) is not None:
            approval.metadata[key] = recommendation_metadata[key]

    return approval


def _validate_auto_execution_policy(payload: dict[str, Any]) -> None:
    recommendation = payload.get("recommendation", {}) if isinstance(payload.get("recommendation"), dict) else {}
    metadata = recommendation.get("metadata", {}) if isinstance(recommendation.get("metadata"), dict) else {}
    context_confidence, resolution_confidence = _rca_and_resolution_confidence(payload)
    threshold = float(settings.rca_resolution_auto_complete_threshold)
    if context_confidence is None or resolution_confidence is None:
        raise PolicyViolation("auto execution blocked: context and resolution confidence are both required")
    if context_confidence < threshold or resolution_confidence < threshold:
        raise PolicyViolation(
            f"auto execution blocked: context={context_confidence:.2f}, resolution={resolution_confidence:.2f}, threshold={threshold:.2f}"
        )

    rca_analysis = metadata.get("rca_analysis") if isinstance(metadata.get("rca_analysis"), dict) else {}
    evidence_ids = metadata.get("evidence_ids") or rca_analysis.get("evidence_used")
    if not isinstance(evidence_ids, list) or not evidence_ids:
        raise PolicyViolation("auto execution blocked: missing evidence_ids")

    reasoning = str(
        metadata.get("reasoning")
        or rca_analysis.get("causal_chain")
        or rca_analysis.get("root_cause")
        or recommendation.get("root_cause")
        or ""
    ).strip()
    if not reasoning:
        raise PolicyViolation("auto execution blocked: missing reasoning")

    commands = recommendation.get("commands") if isinstance(recommendation.get("commands"), list) else []
    runbook_id = str(metadata.get("runbook_id") or "").strip()
    if runbook_id:
        try:
            validate_automatic_runbook_use(
                runbook_id=runbook_id,
                runbook_status=str(metadata.get("runbook_status") or ""),
                evidence_match_score=float(metadata.get("runbook_match_score") or 0.0),
                minimum_match_score=threshold,
            )
        except (TypeError, ValueError) as exc:
            raise PolicyViolation(f"auto execution blocked: {exc}") from exc
    elif not any(str(item).strip() for item in commands):
        raise PolicyViolation("auto execution blocked: no approved runbook or concrete resolution command plan")


def _build_policy_blocked_action(payload: dict[str, Any], reason: str) -> RemediationAction | None:
    recommendation = payload.get("recommendation", {}) if isinstance(payload.get("recommendation"), dict) else {}
    incident_id = recommendation.get("incident_id")
    recommendation_id = recommendation.get("id")
    metadata = recommendation.get("metadata", {}) if isinstance(recommendation.get("metadata"), dict) else {}
    incident = payload.get("incident", {}) if isinstance(payload.get("incident"), dict) else {}
    target = _first_non_empty(
        metadata.get("remediation_target"),
        recommendation.get("target"),
        recommendation.get("resource"),
        incident.get("deployment"),
        incident.get("service"),
        metadata.get("service"),
        incident_id,
    )
    if incident_id is None:
        return None
    lifecycle = extract_lifecycle(recommendation)
    tenant_id = require_tenant_id(
        recommendation.get("tenant_id")
        or incident.get("tenant_id")
        or (lifecycle or {}).get("tenant_id"),
        source="policy-blocked remediation event",
    )
    if lifecycle:
        lifecycle = transition_lifecycle(
            lifecycle,
            ResolutionState.BLOCKED_RETRYABLE,
            reason_code="policy_precondition_failed",
            actor=LifecycleActor.REMEDIATION,
        )
    return RemediationAction(
        tenant_id=tenant_id,
        incident_id=incident_id,
        approval_id=None,
        action_type="policy-blocked",
        target=str(target),
        status=RemediationStatus.AWAITING_APPROVAL,
        output="automatic execution deferred; operator approval required",
        error=reason,
        metadata={
            "policy_blocked": True,
            "policy_reason": reason,
            "recommendation_id": recommendation_id,
            "source": "resolution-events",
            "resolution_lifecycle": lifecycle,
        },
    )
