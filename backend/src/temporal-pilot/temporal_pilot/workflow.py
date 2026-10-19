from __future__ import annotations

import asyncio
from datetime import timedelta
import math
from typing import Any

from temporalio import workflow
from temporalio.common import RetryPolicy


ACTIVITY_RETRY = RetryPolicy(
    initial_interval=timedelta(seconds=2),
    backoff_coefficient=2.0,
    maximum_interval=timedelta(minutes=1),
    maximum_attempts=5,
)


@workflow.defn(name="KaiOpsIncidentPilotWorkflow")
class KaiOpsIncidentPilotWorkflow:
    def __init__(self) -> None:
        self._approval: dict[str, Any] | None = None
        self._cancel_requested = False
        self._state: dict[str, Any] = {"stage": "created", "history": ["created"]}

    def _stage(self, value: str, **fields: Any) -> None:
        self._state = {**self._state, **fields, "stage": value, "history": [*self._state["history"], value]}

    @workflow.signal
    def approval(self, payload: dict[str, Any]) -> None:
        self._approval = payload

    @workflow.signal
    def cancel(self, reason: str = "operator requested cancellation") -> None:
        self._cancel_requested = True
        self._state = {**self._state, "cancellation_reason": reason}

    @workflow.query
    def status(self) -> dict[str, Any]:
        return dict(self._state)

    @workflow.run
    async def run(self, payload: dict[str, Any]) -> dict[str, Any]:
        incident_id = str(payload["incident"]["id"])
        audit = {"incident_id": incident_id, "trace_id": payload.get("trace_id"), "workflow_id": workflow.info().workflow_id}
        self._stage("collecting_context", audit=audit)
        context = await workflow.execute_activity(
            "collect_context", payload, start_to_close_timeout=timedelta(minutes=5), retry_policy=ACTIVITY_RETRY,
        )
        self._stage("resolving", context_collected=True)
        recommendation = await workflow.execute_activity(
            "resolve_recommendation", context, start_to_close_timeout=timedelta(minutes=5), retry_policy=ACTIVITY_RETRY,
        )
        self._stage("awaiting_approval", recommendation_id=recommendation.get("id"))
        try:
            await workflow.wait_condition(
                lambda: self._approval is not None or self._cancel_requested,
                timeout=timedelta(hours=max(1, int(payload.get("approval_timeout_hours", 24)))),
            )
        except asyncio.TimeoutError:
            self._stage("approval_timed_out")
            return dict(self._state)

        if self._cancel_requested:
            self._stage("compensating")
            compensation = await workflow.execute_activity(
                "request_compensation", {**audit, "reason": self._state.get("cancellation_reason")},
                start_to_close_timeout=timedelta(minutes=2), retry_policy=ACTIVITY_RETRY,
            )
            self._stage("cancelled", compensation=compensation)
            return dict(self._state)

        approval = dict(self._approval or {})
        if str(approval.get("decision", "")).lower() in {"rejected", "reject"}:
            self._stage("rejected", approval=approval)
            return dict(self._state)

        # Approval authorizes the proposed plan, but it is not the separate
        # operator confirmation to execute it.  The cockpit's POST /execute
        # starts KaiOpsRemediationWorkflow with the fully enriched, approved
        # execution contract.  Executing this sparse signal here loses the
        # service/plan and can turn the incident UUID into a live target.
        self._stage("approved_awaiting_execution", approval=approval)
        return dict(self._state)


@workflow.defn(name="KaiOpsRemediationWorkflow")
class KaiOpsRemediationWorkflow:
    """Durable owner of one approved remediation execution."""

    def __init__(self) -> None:
        self._state: dict[str, Any] = {"stage": "created", "history": ["created"]}

    def _stage(self, value: str, **fields: Any) -> None:
        self._state = {**self._state, **fields, "stage": value, "history": [*self._state["history"], value]}

    @workflow.query
    def status(self) -> dict[str, Any]:
        return dict(self._state)

    async def _finish_or_rollback(self, approval: dict[str, Any], action: dict[str, Any]) -> dict[str, Any]:
        status = str(action.get("status") or "execution_failed").lower()
        if status != "validation_failed":
            self._stage(status, action=action)
            return action
        metadata = approval.get("metadata") if isinstance(approval.get("metadata"), dict) else {}
        plan = metadata.get("execution_plan") if isinstance(metadata.get("execution_plan"), dict) else {}
        rollback_commands = plan.get("rollback_commands") if isinstance(plan.get("rollback_commands"), list) else []
        rollback_authorized = bool(
            str(approval.get("decision") or "").lower() == "approved"
            and str(plan.get("rollback_mode") or "").lower() == "automatic"
            and any(str(command).strip() for command in rollback_commands)
            and str(approval.get("plan_fingerprint") or "") == str(plan.get("plan_fingerprint") or "")
        )
        if not rollback_authorized:
            escalation = {
                **action,
                "status": "manual_intervention_required",
                "error": "Validation failed, but automatic rollback is not authorized by the approved plan.",
                "rollback_decision": {
                    "disposition": "BLOCKED",
                    "reason_codes": ["approved_automatic_rollback_binding_missing"],
                },
            }
            self._stage("manual_intervention_required", action=escalation, failed_action=action)
            return escalation
        self._stage("rolling_back", failed_action=action)
        rollback = await workflow.execute_activity(
            "rollback_remediation_action",
            approval,
            start_to_close_timeout=timedelta(minutes=15),
            heartbeat_timeout=timedelta(seconds=30),
            retry_policy=RetryPolicy(
                initial_interval=timedelta(seconds=5), maximum_interval=timedelta(seconds=30), maximum_attempts=3,
            ),
        )
        rollback_status = str(rollback.get("status") or "rollback_failed").lower()
        self._stage(rollback_status, action=rollback, failed_action=action)
        return rollback

    @workflow.run
    async def run(self, approval: dict[str, Any]) -> dict[str, Any]:
        self._stage(
            "dispatching",
            incident_id=str(approval.get("incident_id") or ""),
            recommendation_id=str(approval.get("recommendation_id") or ""),
        )
        action = await workflow.execute_activity(
            "dispatch_remediation_action",
            approval,
            start_to_close_timeout=timedelta(minutes=1),
            heartbeat_timeout=timedelta(seconds=30),
            retry_policy=RetryPolicy(
                initial_interval=timedelta(seconds=5),
                backoff_coefficient=2.0,
                maximum_interval=timedelta(seconds=30),
                maximum_attempts=3,
            ),
        )
        status = str(action.get("status") or "dispatch_failed").lower()
        terminal = {
            "succeeded", "failed", "skipped", "policy_blocked", "dispatch_failed",
            "execution_failed", "validation_failed", "rolled_back", "rollback_failed",
            "timed_out", "cancelled", "manual_intervention_required",
        }
        if status in terminal:
            return await self._finish_or_rollback(approval, action)
        self._stage("executor_accepted", action_id=str(action.get("id") or ""))
        # Temporal owns the wait. Each activity performs one bounded read-only
        # observation, so worker/API restarts never lose the external build.
        profile = approval.get("metadata", {}).get("connection_profile", {})
        timeout_seconds = int(profile.get("timeout_seconds") or 1200) if isinstance(profile, dict) else 1200
        timeout_seconds = max(60, min(timeout_seconds, 3600))
        poll_seconds = 10
        deadline = (
            workflow.now() + timedelta(seconds=timeout_seconds)
            if workflow.patched("executor-wait-wall-clock-deadline-v1") else None
        )
        for attempt in range(math.ceil(timeout_seconds / poll_seconds)):
            if deadline is not None and workflow.now() >= deadline:
                break
            await workflow.sleep(timedelta(seconds=poll_seconds))
            if deadline is not None and workflow.now() >= deadline:
                break
            action = await workflow.execute_activity(
                "reconcile_remediation_action",
                approval,
                start_to_close_timeout=timedelta(seconds=45),
                heartbeat_timeout=timedelta(seconds=30),
                retry_policy=RetryPolicy(maximum_attempts=3),
            )
            status = str(action.get("status") or "execution_failed").lower()
            self._stage(status, reconciliation_attempt=attempt + 1, action=action)
            if status in terminal:
                return await self._finish_or_rollback(approval, action)
        action = await workflow.execute_activity(
            "timeout_remediation_action",
            approval,
            start_to_close_timeout=timedelta(seconds=45),
            retry_policy=RetryPolicy(maximum_attempts=3),
        )
        if workflow.patched("timeout-preserves-observed-terminal-result-v1"):
            return await self._finish_or_rollback(approval, action)
        self._stage("timed_out", timeout_seconds=timeout_seconds, action=action)
        return action


@workflow.defn(name="KaiOpsRemediationPreflightWorkflow")
class KaiOpsRemediationPreflightWorkflow:
    @workflow.run
    async def run(self, approval: dict[str, Any]) -> dict[str, Any]:
        return await workflow.execute_activity(
            "preflight_remediation_action",
            approval,
            start_to_close_timeout=timedelta(seconds=30),
            retry_policy=RetryPolicy(maximum_attempts=2),
        )
