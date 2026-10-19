from __future__ import annotations

import asyncio
from typing import Any
from time import perf_counter

import httpx
from common.config import get_settings
from temporalio import activity
from common.telemetry import WORKFLOW_FAILURES, WORKFLOW_LATENCY
from opentelemetry import trace

settings = get_settings()


async def _post(base: str, path: str, payload: dict[str, Any], params: dict[str, Any] | None = None, extra_headers: dict[str, str] | None = None) -> dict[str, Any]:
    info = activity.info()
    # Activity IDs are only unique inside a workflow. Include the workflow ID
    # so retries are idempotent without colliding with unrelated executions.
    headers = {"Idempotency-Key": f"{info.workflow_id}:{info.activity_id}"}
    if settings.ai_layer_auth_token:
        headers["Authorization"] = f"Bearer {settings.ai_layer_auth_token}"
    headers.update(extra_headers or {})
    started = perf_counter()
    stage = path.strip("/") or "activity"
    try:
        with trace.get_tracer("kaiops.temporal").start_as_current_span(f"temporal.activity.{stage}") as span:
            span.set_attribute("temporal.workflow.id", info.workflow_id)
            span.set_attribute("temporal.activity.id", info.activity_id)
            async with httpx.AsyncClient(timeout=settings.ai_layer_request_timeout_seconds, headers=headers) as client:
                response = await client.post(f"{base.rstrip('/')}/{path.lstrip('/')}", json=payload, params=params)
                response.raise_for_status()
                data = response.json()
        WORKFLOW_LATENCY.labels("temporal-incident-pilot", stage, "ok").observe(perf_counter() - started)
        return data if isinstance(data, dict) else {"data": data}
    except Exception:
        WORKFLOW_LATENCY.labels("temporal-incident-pilot", stage, "error").observe(perf_counter() - started)
        WORKFLOW_FAILURES.labels("temporal-incident-pilot", stage).inc()
        raise


@activity.defn(name="collect_context")
async def collect_context(payload: dict[str, Any]) -> dict[str, Any]:
    return await _post(settings.context_agent_url, "/collect", payload, {"publish_events": "false"})


@activity.defn(name="resolve_recommendation")
async def resolve_recommendation(context: dict[str, Any]) -> dict[str, Any]:
    return await _post(settings.resolution_agent_url, "/resolve", context, {"publish_events": "false"})


@activity.defn(name="execute_remediation_decision")
async def execute_remediation_decision(approval: dict[str, Any]) -> dict[str, Any]:
    return await _post(settings.remediation_engine_url, "/execute", approval)


@activity.defn(name="execute_remediation_action")
async def execute_remediation_action(approval: dict[str, Any]) -> dict[str, Any]:
    activity.heartbeat({"stage": "dispatching", "incident_id": approval.get("incident_id")})
    execution = asyncio.create_task(_post(
        settings.remediation_engine_url, "/execute-direct", approval,
        extra_headers={"X-KaiOps-Internal-Token": settings.remediation_internal_token},
    ))
    try:
        while not execution.done():
            done, _ = await asyncio.wait({execution}, timeout=30.0)
            if not done:
                activity.heartbeat({"stage": "executor_running", "incident_id": approval.get("incident_id")})
    finally:
        # Temporal cancellation must not leave a detached HTTP request running
        # alongside a retried activity. This cancels the local request only;
        # an already accepted external action still requires reconciliation.
        if not execution.done():
            execution.cancel()
            await asyncio.gather(execution, return_exceptions=True)
    try:
        result = await execution
    except httpx.HTTPStatusError as exc:
        detail = ""
        try:
            body = exc.response.json()
            detail = str(body.get("detail") or body)
        except (ValueError, AttributeError):
            detail = str(exc.response.text or "").strip()
        error = detail or f"Remediation executor rejected the request with HTTP {exc.response.status_code}."
        result = await _post(
            settings.remediation_engine_url,
            "/execution-failed",
            {"approval": approval, "error": error, "http_status": exc.response.status_code, "policy_blocked": exc.response.status_code == 409},
            extra_headers={"X-KaiOps-Internal-Token": settings.remediation_internal_token},
        )
    activity.heartbeat({"stage": "terminal", "status": result.get("status")})
    return result


@activity.defn(name="dispatch_remediation_action")
async def dispatch_remediation_action(approval: dict[str, Any]) -> dict[str, Any]:
    activity.heartbeat({"stage": "dispatching", "incident_id": approval.get("incident_id")})
    try:
        return await _post(
            settings.remediation_engine_url,
            "/dispatch-direct",
            approval,
            extra_headers={"X-KaiOps-Internal-Token": settings.remediation_internal_token},
        )
    except httpx.HTTPStatusError as exc:
        # 4xx responses are deterministic policy/contract decisions. Retrying
        # them cannot succeed and previously left the UI apparently hanging.
        if 400 <= exc.response.status_code < 500 or activity.info().attempt >= 3:
            try:
                body = exc.response.json()
                detail = str(body.get("detail") or body)
            except (ValueError, AttributeError):
                detail = str(exc.response.text or "").strip()
            return await _post(
                settings.remediation_engine_url,
                "/execution-failed",
                {
                    "approval": approval,
                    "error": detail or f"Dispatch rejected with HTTP {exc.response.status_code}.",
                    "http_status": exc.response.status_code,
                    "phase": "dispatch",
                    "policy_blocked": exc.response.status_code == 409,
                },
                extra_headers={"X-KaiOps-Internal-Token": settings.remediation_internal_token},
            )
        raise


@activity.defn(name="reconcile_remediation_action")
async def reconcile_remediation_action(approval: dict[str, Any]) -> dict[str, Any]:
    activity.heartbeat({"stage": "reconciling", "incident_id": approval.get("incident_id")})
    return await _post(
        settings.remediation_engine_url,
        "/reconcile-direct",
        {"approval": approval},
        extra_headers={"X-KaiOps-Internal-Token": settings.remediation_internal_token},
    )


@activity.defn(name="timeout_remediation_action")
async def timeout_remediation_action(approval: dict[str, Any]) -> dict[str, Any]:
    profile = approval.get("metadata", {}).get("connection_profile", {})
    timeout_seconds = int(profile.get("timeout_seconds") or 1200) if isinstance(profile, dict) else 1200
    timeout_seconds = max(60, min(timeout_seconds, 3600))
    return await _post(
        settings.remediation_engine_url,
        "/timeout-direct",
        {"approval": approval, "error": f"Executor did not reach a terminal state within {timeout_seconds} seconds."},
        extra_headers={"X-KaiOps-Internal-Token": settings.remediation_internal_token},
    )


@activity.defn(name="rollback_remediation_action")
async def rollback_remediation_action(approval: dict[str, Any]) -> dict[str, Any]:
    activity.heartbeat({"stage": "rolling_back", "incident_id": approval.get("incident_id")})
    action = await _post(
        settings.remediation_engine_url,
        "/rollback-direct",
        {"approval": approval},
        extra_headers={"X-KaiOps-Internal-Token": settings.remediation_internal_token},
    )
    terminal = {"rolled_back", "rollback_failed", "manual_intervention_required"}
    if str(action.get("status") or "").lower() in terminal:
        return action
    for attempt in range(60):
        await asyncio.sleep(10)
        activity.heartbeat({"stage": "rollback_reconciling", "incident_id": approval.get("incident_id"), "attempt": attempt + 1})
        action = await _post(
            settings.remediation_engine_url,
            "/rollback-reconcile-direct",
            {"approval": approval},
            extra_headers={"X-KaiOps-Internal-Token": settings.remediation_internal_token},
        )
        if str(action.get("status") or "").lower() in terminal:
            return action
    return await _post(
        settings.remediation_engine_url,
        "/rollback-timeout-direct",
        {"approval": approval},
        extra_headers={"X-KaiOps-Internal-Token": settings.remediation_internal_token},
    )


@activity.defn(name="preflight_remediation_action")
async def preflight_remediation_action(approval: dict[str, Any]) -> dict[str, Any]:
    return await _post(settings.remediation_engine_url, "/dry-run", approval)


@activity.defn(name="request_compensation")
async def request_compensation(payload: dict[str, Any]) -> dict[str, Any]:
    # There is no truthful rollback endpoint yet. This durable hook records that
    # compensation is required without claiming that rollback ran.
    activity.logger.warning("temporal_compensation_required", extra=payload)
    return {"status": "rollback_required", **payload}
