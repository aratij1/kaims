"""Failure-path contracts for asynchronous recovery ownership."""
import asyncio
import importlib.util
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import AsyncMock, Mock
from uuid import uuid4

import pytest
from common.models import Approval, ApprovalDecision, RemediationAction, RemediationStatus
from test_remediation_auto_resolution_path import load_remediation_app_module


def load_temporal(name):
    spec = importlib.util.spec_from_file_location(
        f"deadline_test_{name}", Path(f"backend/src/temporal-pilot/temporal_pilot/{name}.py")
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def setup_execution(monkeypatch, status):
    module = load_remediation_app_module()
    approval = Approval(tenant_id="tenant-a", incident_id=uuid4(), recommendation_id=uuid4(),
                        decision=ApprovalDecision.APPROVED, approver="reviewer")
    action = RemediationAction(tenant_id="tenant-a", incident_id=approval.incident_id, approval_id=approval.id,
                              action_type="restart_service", target="frontend-proxy", status=status)
    monkeypatch.setattr(module.settings, "remediation_internal_token", "test-internal")
    monkeypatch.setattr(module.engine, "build_action", Mock(return_value=action))
    monkeypatch.setattr(module, "_find_existing_action", AsyncMock(return_value=action))
    monkeypatch.setattr(module, "verify_execution_contract", Mock())
    monkeypatch.setattr(module, "_finalize_api_execution", AsyncMock(side_effect=lambda _, action: action))
    monkeypatch.setattr(module.engine, "observe", AsyncMock(return_value=action))
    return module, approval, action


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [RemediationStatus.SUCCEEDED, RemediationStatus.VALIDATION_FAILED,
                                    RemediationStatus.CANCELLED, RemediationStatus.TIMED_OUT])
@pytest.mark.parametrize("endpoint", ["timeout_execution_direct", "reconcile_execution_direct"])
async def test_delayed_activity_preserves_persisted_terminal_result(monkeypatch, status, endpoint):
    module, approval, action = setup_execution(monkeypatch, status)
    result = await getattr(module, endpoint)({"approval": approval.model_dump(mode="json")}, "test-internal")
    assert result.status == status
    module.engine.observe.assert_not_awaited()
    module._finalize_api_execution.assert_awaited_once_with(approval, action)


@pytest.mark.asyncio
@pytest.mark.parametrize("observed", [RemediationStatus.SUCCEEDED, RemediationStatus.VALIDATION_FAILED,
                                      RemediationStatus.RUNNING])
async def test_deadline_observes_executor_before_declaring_timeout(monkeypatch, observed):
    module, approval, action = setup_execution(monkeypatch, RemediationStatus.RUNNING)
    async def observe(current):
        current.status = observed
        return current
    module.engine.observe.side_effect = observe
    result = await module.timeout_execution_direct({"approval": approval.model_dump(mode="json")}, "test-internal")
    assert result.status == (RemediationStatus.TIMED_OUT if observed == RemediationStatus.RUNNING else observed)
    module.engine.observe.assert_awaited_once_with(action)


@pytest.mark.asyncio
async def test_unavailable_executor_does_not_invent_timeout_evidence(monkeypatch):
    module, approval, action = setup_execution(monkeypatch, RemediationStatus.RUNNING)
    module.engine.observe.side_effect = RuntimeError("observer unavailable")
    with pytest.raises(RuntimeError, match="observer unavailable"):
        await module.timeout_execution_direct({"approval": approval.model_dump(mode="json")}, "test-internal")
    assert action.status == RemediationStatus.RUNNING
    module._finalize_api_execution.assert_not_awaited()


@pytest.mark.asyncio
async def test_timeout_verifies_contract_before_observation(monkeypatch):
    module, approval, _ = setup_execution(monkeypatch, RemediationStatus.RUNNING)
    module.verify_execution_contract.side_effect = ValueError("tampered")
    with pytest.raises(ValueError, match="tampered"):
        await module.timeout_execution_direct({"approval": approval.model_dump(mode="json")}, "test-internal")
    module.engine.observe.assert_not_awaited()
    module._finalize_api_execution.assert_not_awaited()


@pytest.mark.asyncio
async def test_temporal_cancellation_drains_local_executor_request(monkeypatch):
    module = load_temporal("activities")
    started, drained = asyncio.Event(), asyncio.Event()
    async def blocked_request(*args, **kwargs):
        started.set()
        try:
            await asyncio.Event().wait()
        finally:
            drained.set()
    monkeypatch.setattr(module, "_post", blocked_request)
    monkeypatch.setattr(module.activity, "heartbeat", lambda *_: None)
    task = asyncio.create_task(module.execute_remediation_action({"incident_id": "incident"}))
    await asyncio.wait_for(started.wait(), timeout=2)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert drained.is_set()


@pytest.mark.asyncio
@pytest.mark.parametrize("observed", ["succeeded", "timed_out", "validation_failed"])
async def test_workflow_deadline_uses_actual_terminal_status(monkeypatch, observed):
    module = load_temporal("workflow")
    async def activity(name, *args, **kwargs):
        return {"status": observed if name == "timeout_remediation_action" else "running"}
    monkeypatch.setattr(module.workflow, "execute_activity", activity)
    monkeypatch.setattr(module.workflow, "sleep", AsyncMock())
    monkeypatch.setattr(module.workflow, "patched", lambda _: True)
    monkeypatch.setattr(module.workflow, "now", lambda: datetime(2026, 10, 18, tzinfo=UTC))
    instance = module.KaiOpsRemediationWorkflow()
    result = await instance.run({"metadata": {"connection_profile": {"timeout_seconds": 60}}})
    expected = "manual_intervention_required" if observed == "validation_failed" else observed
    assert result["status"] == expected
    assert instance.status()["stage"] == expected


@pytest.mark.asyncio
@pytest.mark.parametrize("endpoint", [
    "timeout_execution_direct", "reconcile_execution_direct", "record_execution_failure",
    "timeout_rollback_direct", "reconcile_rollback_direct",
])
async def test_superseded_approval_callback_cannot_mutate_new_retry(monkeypatch, endpoint):
    module, approval, action = setup_execution(monkeypatch, RemediationStatus.RUNNING)
    action.approval_id = uuid4()
    with pytest.raises(module.HTTPException) as error:
        await getattr(module, endpoint)({"approval": approval.model_dump(mode="json")}, "test-internal")
    assert error.value.status_code == 409
    assert action.status == RemediationStatus.RUNNING
    module.engine.observe.assert_not_awaited()
    module._finalize_api_execution.assert_not_awaited()


@pytest.mark.asyncio
async def test_failure_callback_preserves_completed_execution(monkeypatch):
    module, approval, action = setup_execution(monkeypatch, RemediationStatus.SUCCEEDED)
    result = await module.record_execution_failure(
        {"approval": approval.model_dump(mode="json"), "http_status": 500}, "test-internal")
    assert result.status == RemediationStatus.SUCCEEDED
    assert result.error is None


@pytest.mark.asyncio
async def test_failure_after_acceptance_observes_existing_execution(monkeypatch):
    module, approval, action = setup_execution(monkeypatch, RemediationStatus.RUNNING)
    action.parameters["execution_result"] = {"accepted": True}
    monkeypatch.setattr(module, "_persist_action", AsyncMock())
    result = await module.record_execution_failure(
        {"approval": approval.model_dump(mode="json"), "http_status": 500}, "test-internal")
    assert result.status == RemediationStatus.RUNNING
    module.engine.observe.assert_awaited_once_with(action)
    module._finalize_api_execution.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [RemediationStatus.ROLLED_BACK, RemediationStatus.ROLLBACK_FAILED,
                                    RemediationStatus.MANUAL_INTERVENTION_REQUIRED])
async def test_delayed_rollback_timeout_preserves_terminal_result(monkeypatch, status):
    module, approval, action = setup_execution(monkeypatch, status)
    result = await module.timeout_rollback_direct({"approval": approval.model_dump(mode="json")}, "test-internal")
    assert result.status == status
    module.engine.observe.assert_not_awaited()


@pytest.mark.asyncio
async def test_rollback_completed_at_deadline_is_not_reported_as_timeout(monkeypatch):
    module, approval, action = setup_execution(monkeypatch, RemediationStatus.ROLLING_BACK)
    async def observe(current):
        current.status = RemediationStatus.SUCCEEDED
        return current
    module.engine.observe.side_effect = observe
    result = await module.timeout_rollback_direct({"approval": approval.model_dump(mode="json")}, "test-internal")
    assert result.status == RemediationStatus.ROLLED_BACK
    assert result.error is None


@pytest.mark.asyncio
async def test_observation_retries_count_toward_workflow_deadline(monkeypatch):
    module = load_temporal("workflow")
    clock = [datetime(2026, 10, 18, tzinfo=UTC)]
    observations = []
    async def activity(name, *args, **kwargs):
        if name == "reconcile_remediation_action":
            observations.append(clock[0])
            # Model a slow observation including its activity retries.
            clock[0] += timedelta(seconds=55)
        return {"status": "timed_out" if name == "timeout_remediation_action" else "running"}
    async def sleep(duration):
        clock[0] += duration
    monkeypatch.setattr(module.workflow, "execute_activity", activity)
    monkeypatch.setattr(module.workflow, "sleep", sleep)
    monkeypatch.setattr(module.workflow, "now", lambda: clock[0])
    monkeypatch.setattr(module.workflow, "patched", lambda _: True)
    instance = module.KaiOpsRemediationWorkflow()
    result = await instance.run({"metadata": {"connection_profile": {"timeout_seconds": 60}}})
    assert result["status"] == "timed_out"
    assert len(observations) == 1


@pytest.mark.asyncio
async def test_older_temporal_histories_keep_original_timeout_branch(monkeypatch):
    module = load_temporal("workflow")
    observations = []
    async def activity(name, *args, **kwargs):
        observations.append(name)
        return {"status": "timed_out" if name == "timeout_remediation_action" else "running"}
    monkeypatch.setattr(module.workflow, "execute_activity", activity)
    monkeypatch.setattr(module.workflow, "sleep", AsyncMock())
    monkeypatch.setattr(module.workflow, "patched", lambda _: False)
    monkeypatch.setattr(
        module.workflow, "now", Mock(side_effect=AssertionError("legacy replay must not read new deadline"))
    )
    instance = module.KaiOpsRemediationWorkflow()
    result = await instance.run({"metadata": {"connection_profile": {"timeout_seconds": 60}}})
    assert result["status"] == "timed_out"
    assert observations.count("reconcile_remediation_action") == 6
    assert instance.status()["stage"] == "timed_out"
