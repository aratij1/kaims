from __future__ import annotations

import json

import httpx
import pytest
from common.models import ApprovalDecision, RemediationAction, RemediationStatus
from remediation_engine.plugins import (
    AzureContainerAppsJobPlugin,
    FakeCapabilityAdapter,
    JenkinsRollbackPlugin,
    RemediationEngine,
)
from remediation_test_helpers import governed_approval as Approval


@pytest.mark.asyncio
async def test_fake_capability_adapter_requires_onboarded_resource_and_credential() -> None:
    adapter = FakeCapabilityAdapter()
    action = RemediationAction(
        tenant_id="tenant-a",
        incident_id="11111111-1111-1111-1111-111111111111",
        action_type="fake_test",
        target="display-name-is-not-an-identity",
    )

    with pytest.raises(ValueError, match="target_resource_id"):
        await adapter.preflight(action)

    action.parameters["target_resource_id"] = "azure:/subscriptions/sub-a/resourceGroups/rg-a/apps/api"
    with pytest.raises(ValueError, match="credential reference"):
        await adapter.preflight(action)


@pytest.mark.asyncio
async def test_fake_capability_adapter_implements_full_lifecycle_contract() -> None:
    adapter = FakeCapabilityAdapter()
    action = RemediationAction(
        tenant_id="tenant-a",
        incident_id="11111111-1111-1111-1111-111111111111",
        action_type="fake_test",
        target="api",
        parameters={
            "target_resource_id": "k8s:/clusters/prod/namespaces/payments/deployments/api",
            "credential_ref": "vault://tenant-a/k8s/prod-remediator",
            "required_permissions": ["deployments.patch"],
        },
    )

    assert (await adapter.discover(action))["discovered"] is True
    assert (await adapter.diagnose(action))["diagnostic_only"] is True
    assert (await adapter.preflight(action))["required_permissions"] == ["deployments.patch"]
    completed = await adapter.execute(action)
    assert completed.status == RemediationStatus.SUCCEEDED
    assert (await adapter.validate(completed))["passed"] is True
    assert (await adapter.health())["live_execution"] is False


def _jenkins_result(submitted: dict[str, str]) -> dict:
    dry_run = submitted.get("KAI_OPS_DRY_RUN") == "true"
    plan = json.loads(submitted.get("KAI_OPS_EXECUTION_PLAN") or "{}")
    return {
        "schema_version": "kaiops.remediation.result.v2",
        "incident_id": submitted["KAI_OPS_INCIDENT_ID"],
        "approval_id": submitted["KAI_OPS_APPROVAL_ID"],
        "target": submitted["KAI_OPS_TARGET"],
        "plan_digest": submitted["KAI_OPS_PLAN_DIGEST"],
        "executed_script_count": 0 if dry_run else len(plan.get("scripts") or []),
        "dry_run": dry_run,
        "dry_run_validated": dry_run,
        "preflight_passed": not dry_run,
        "executed": not dry_run,
        "recovery_validated": not dry_run,
        "result": "SUCCESS",
    }


@pytest.mark.asyncio
async def test_remediation_engine_registers_tool_specs() -> None:
    engine = RemediationEngine()

    assert "rollback_deployment" in engine.tool_registry.tools
    assert "restart_pod" in engine.tool_registry.tools
    assert "api_execution" in engine.tool_registry.tools
    assert "jenkins" in engine.tool_registry.tools


@pytest.mark.asyncio
async def test_selected_jenkins_executor_routes_non_rollback_actions_to_jenkins() -> None:
    engine = RemediationEngine()
    approval = Approval(
        incident_id="11111111-1111-1111-1111-111111111111",
        recommendation_id="22222222-2222-2222-2222-222222222222",
        decision=ApprovalDecision.APPROVED,
        approver="sre-user",
        comment="restart pod",
        metadata={"connection_profile": {"executor_type": "jenkins"}},
    )

    result = await engine.execute(engine.build_action(approval))

    assert result.status == RemediationStatus.SKIPPED
    assert result.parameters["execution_result"]["executor"] == "jenkins"


def test_default_jenkins_profile_is_applied_to_alerts_without_connector(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("REMEDIATION_DEFAULT_EXECUTOR", "jenkins")
    monkeypatch.setenv("REMEDIATION_JENKINS_URL", "http://jenkins:8080")
    monkeypatch.setenv("REMEDIATION_JENKINS_JOB", "kaiops-auto-remediation")
    monkeypatch.setenv("REMEDIATION_JENKINS_CREDENTIAL_REF", "vault://kaiops/local/jenkins#api-token")

    action = RemediationEngine().build_action(
        Approval(
            incident_id="11111111-1111-1111-1111-111111111111",
            recommendation_id="22222222-2222-2222-2222-222222222222",
            decision=ApprovalDecision.APPROVED,
            approver="sre-user",
            comment="restart pod",
        )
    )

    assert action.parameters["connection_profile"]["executor_type"] == "jenkins"
    assert action.parameters["connection_profile"]["endpoint_url"] == "http://jenkins:8080"
    assert action.parameters["connection_profile"]["job_name"] == "kaiops-auto-remediation"
    assert action.parameters["connection_profile"]["credential_ref"].startswith("vault://")


def test_jenkins_preserves_the_exact_approved_script_without_substitution(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("REMEDIATION_DEFAULT_EXECUTOR", "jenkins")
    monkeypatch.setenv("REMEDIATION_EXECUTION_PLATFORM", "docker-compose")
    action = RemediationEngine().build_action(
        Approval(
            incident_id="11111111-1111-1111-1111-111111111111",
            recommendation_id="22222222-2222-2222-2222-222222222222",
            decision=ApprovalDecision.APPROVED,
            approver="sre-user",
            comment="run the approved health remediation script",
            metadata={
                "service": "api-gateway",
                "environment": "prod",
                "execution_plan": {
                    "commands": [],
                    "scripts": [
                        "bash scripts/remediation/kaiops_alert_health_triage.sh "
                        "--service api-gateway --environment prod --dry-run false"
                    ],
                    "queries": [],
                },
            },
        )
    )

    plan = action.parameters["execution_plan"]
    assert plan["commands"] == []
    assert plan["scripts"] == [
        "bash scripts/remediation/kaiops_alert_health_triage.sh "
        "--service api-gateway --environment prod --dry-run false"
    ]
    assert plan["queries"] == []


@pytest.mark.asyncio
async def test_remediation_engine_executes_via_tool_registry() -> None:
    engine = RemediationEngine()
    approval = Approval(
        incident_id="11111111-1111-1111-1111-111111111111",
        recommendation_id="22222222-2222-2222-2222-222222222222",
        decision=ApprovalDecision.APPROVED,
        approver="sre-user",
        comment="restart pod",
    )
    action = engine.build_action(approval)

    result = await engine.execute(action)

    assert result.status == RemediationStatus.SKIPPED
    assert result.parameters["execution_result"]["executed"] is False
    assert result.parameters["execution_result"]["executor"] == "kubernetes"
    assert "No real kubernetes executor is configured" in str(result.error)
    assert "simulat" not in result.output.lower()


@pytest.mark.asyncio
async def test_tool_registry_permission_is_enforced() -> None:
    engine = RemediationEngine()
    action = engine.build_action(
        Approval(
            incident_id="11111111-1111-1111-1111-111111111111",
            recommendation_id="22222222-2222-2222-2222-222222222222",
            decision=ApprovalDecision.APPROVED,
            approver="sre-user",
            comment="rollback",
        )
    )

    with pytest.raises(PermissionError):
        await engine.tool_registry.execute(
            action.action_type,
            {"action": action.model_dump(mode="json")},
            role="viewer",
        )


@pytest.mark.asyncio
async def test_jenkins_rollback_requires_a_complete_connector() -> None:
    action = RemediationEngine().build_action(
        Approval(
            incident_id="11111111-1111-1111-1111-111111111111",
            recommendation_id="22222222-2222-2222-2222-222222222222",
            decision=ApprovalDecision.APPROVED,
            approver="sre-user",
            comment="rollback deployment",
            metadata={"connection_profile": {"endpoint_url": "https://jenkins.example.com"}},
        )
    )

    result = await JenkinsRollbackPlugin().execute(action)

    assert result.status == RemediationStatus.SKIPPED
    assert result.parameters["execution_result"]["executor"] == "jenkins"
    assert "No real jenkins executor is configured" in str(result.error)


@pytest.mark.asyncio
async def test_jenkins_rollback_requires_runtime_secret_injection(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("JENKINS_USERNAME", raising=False)
    monkeypatch.delenv("JENKINS_API_TOKEN", raising=False)
    action = RemediationEngine().build_action(
        Approval(
            incident_id="11111111-1111-1111-1111-111111111111",
            recommendation_id="22222222-2222-2222-2222-222222222222",
            decision=ApprovalDecision.APPROVED,
            approver="sre-user",
            comment="rollback deployment",
            metadata={"connection_profile": {
                "endpoint_url": "https://jenkins.example.com",
                "job_name": "payments/rollback",
                "credential_ref": "vault://kaiops/prod/jenkins",
                "allowed_operations": ["rollback_deployment"],
            }},
        )
    )

    result = await JenkinsRollbackPlugin().execute(action)

    assert result.status == RemediationStatus.SKIPPED
    assert "runtime secret provider" in str(result.error)


@pytest.mark.asyncio
async def test_jenkins_does_not_infer_restart_intent_from_triage_script(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("JENKINS_USERNAME", raising=False)
    monkeypatch.delenv("JENKINS_API_TOKEN", raising=False)
    action = RemediationEngine().build_action(Approval(
        incident_id="11111111-1111-1111-1111-111111111111",
        recommendation_id="22222222-2222-2222-2222-222222222222",
        decision=ApprovalDecision.APPROVED,
        approver="sre-user",
        metadata={
            "service": "closure-service",
            "execution_plan": {
                "scripts": ["bash scripts/remediation/kaiops_alert_health_triage.sh --service closure-service --dry-run false"],
                "commands": ["curl -X POST http://docker-socket-proxy:2375/containers/kaiops_azure-closure-service-1/restart?t=30"],
                "preflight": ["curl http://docker-socket-proxy:2375/containers/kaiops_azure-closure-service-1/json"],
                "validation_commands": ["curl http://closure-service:8000/healthz"],
                "rollback_commands": ["curl http://docker-socket-proxy:2375/containers/kaiops_azure-closure-service-1/json"],
            },
            "connection_profile": {
                "executor_type": "jenkins",
                "endpoint_url": "https://jenkins.example.com",
                "job_name": "kaiops-auto-remediation",
                "credential_ref": "vault://kaiops/prod/default-token",
                "allowed_operations": ["restart_service"],
            },
        },
    ))

    assert action.action_type == "api_execution"
    assert action.parameters["execution_plan"]["preflight"] == [
        "curl http://docker-socket-proxy:2375/containers/kaiops_azure-closure-service-1/json"
    ]
    assert action.parameters["execution_plan"]["validation_commands"] == [
        "curl http://closure-service:8000/healthz"
    ]
    result = await JenkinsRollbackPlugin().execute(action)

    assert result.parameters["connector_operation"] == "api_execution"
    assert result.status == RemediationStatus.SKIPPED
    assert "does not allow operation api_execution" in str(result.error)


def test_jenkins_fills_missing_safety_envelope_from_governed_template(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("REMEDIATION_EXECUTION_PLATFORM", "docker-compose")
    monkeypatch.setenv("REMEDIATION_COMPOSE_PROJECT", "kaiops_pubsub")
    action = RemediationEngine().build_action(Approval(
        incident_id="11111111-1111-1111-1111-111111111111",
        recommendation_id="22222222-2222-2222-2222-222222222222",
        decision=ApprovalDecision.APPROVED,
        approver="sre-user",
        comment="restart service",
        metadata={
            "service": "kaiops-remediation-engine",
            "execution_plan": {"commands": ["curl http://approved-command"]},
            "connection_profile": {"executor_type": "jenkins"},
        },
    ))

    plan = action.parameters["execution_plan"]
    assert plan["commands"] == ["curl http://approved-command"]
    assert plan["preflight"] == []
    assert plan["validation_commands"] == []
    assert plan["rollback_commands"] == []
    assert plan["rollback_mode"] == "not_applicable"


def test_jenkins_adapts_catalog_ansible_plan_to_local_docker_executor(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("REMEDIATION_EXECUTION_PLATFORM", "docker-compose")
    monkeypatch.setenv("REMEDIATION_COMPOSE_PROJECT", "kaiops_azure")
    action = RemediationEngine().build_action(Approval(
        incident_id="11111111-1111-1111-1111-111111111111",
        recommendation_id="22222222-2222-2222-2222-222222222222",
        decision=ApprovalDecision.APPROVED,
        approver="sre-user",
        comment="restart service",
        metadata={
            "service": "kaiops-discovery-mcp",
            "execution_plan": {
                "commands": [
                    "ansible-playbook playbooks/restart-service.yml "
                    "-e service=kaiops-discovery-mcp -e env=e2e"
                ],
                "queries": ["promql: up{job=\"kaiops-discovery-mcp\"}"],
            },
            "connection_profile": {"executor_type": "jenkins"},
        },
    ))

    plan = action.parameters["execution_plan"]
    assert plan["commands"] == [
        "ansible-playbook playbooks/restart-service.yml -e service=kaiops-discovery-mcp -e env=e2e"
    ]
    assert plan["queries"] == ['promql: up{job="kaiops-discovery-mcp"}']
    assert plan["validation_commands"] == []


def test_jenkins_does_not_attach_invented_container_checks_to_approved_script(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("REMEDIATION_EXECUTION_PLATFORM", "docker-compose")
    monkeypatch.setenv("REMEDIATION_COMPOSE_PROJECT", "kaiops_azure")
    action = RemediationEngine().build_action(Approval(
        incident_id="11111111-1111-1111-1111-111111111111",
        recommendation_id="22222222-2222-2222-2222-222222222222",
        decision=ApprovalDecision.APPROVED,
        approver="sre-user",
        metadata={
            "service": "external-monitoring-service",
            "execution_plan": {
                "scripts": [
                    "bash scripts/remediation/kaiops_alert_health_triage.sh "
                    "--service external-monitoring-service --dry-run false"
                ],
            },
            "connection_profile": {"executor_type": "jenkins"},
        },
    ))

    plan = action.parameters["execution_plan"]
    assert plan["scripts"]
    assert plan["preflight"] == []
    assert plan["validation_commands"] == []
    assert plan["rollback_commands"] == []


@pytest.mark.asyncio
async def test_jenkins_submits_application_resolution_contract(monkeypatch: pytest.MonkeyPatch) -> None:
    submitted: dict[str, str] = {}
    build_polls = 0

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal build_polls
        if request.url.path.endswith("/crumbIssuer/api/json"):
            return httpx.Response(404)
        if request.url.path == "/queue/item/7/api/json":
            return httpx.Response(200, json={"cancelled": False, "executable": {"url": "https://jenkins.example/job/payments/7/"}})
        if request.url.path == "/job/payments/7/api/json":
            build_polls += 1
            if build_polls == 1:
                return httpx.Response(200, json={"building": False, "result": None})
            return httpx.Response(200, json={"building": False, "result": "SUCCESS"})
        if request.url.path == "/job/payments/7/artifact/kaiops-result.json":
            return httpx.Response(200, json=_jenkins_result(submitted))
        submitted.update(dict(request.url.params))
        return httpx.Response(201, headers={"location": "https://jenkins.example/queue/item/7"})

    monkeypatch.setenv("JENKINS_USERNAME", "kaiops")
    monkeypatch.setenv("JENKINS_API_TOKEN", "secret")
    async_client = httpx.AsyncClient
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kwargs: async_client(transport=httpx.MockTransport(handler), **kwargs))
    action = RemediationEngine().build_action(Approval(
        incident_id="11111111-1111-1111-1111-111111111111",
        recommendation_id="22222222-2222-2222-2222-222222222222",
        decision=ApprovalDecision.APPROVED,
        approver="sre-user",
        comment="restart pod",
        metadata={"connection_profile": {"executor_type": "jenkins", "endpoint_url": "https://jenkins.example", "job_name": "kaiops/remediation/payments", "credential_ref": "vault://jenkins"}},
    ))
    action.parameters.update({"application_id": "payments", "namespace": "prod-payments", "resolution_id": "restart-workload", "dry_run": True})

    result = await JenkinsRollbackPlugin().execute(action)

    assert result.status == RemediationStatus.SUCCEEDED
    assert submitted["KAI_OPS_APPLICATION_ID"] == "payments"
    assert submitted["KAI_OPS_NAMESPACE"] == "prod-payments"
    assert submitted["KAI_OPS_RESOLUTION_ID"] == "restart-workload"
    assert submitted["KAI_OPS_DRY_RUN"] == "true"
    assert submitted["KAI_OPS_PLAN_DIGEST"].startswith("sha256:")
    assert result.parameters["execution_result"]["approved_plan_digest"] == submitted["KAI_OPS_PLAN_DIGEST"]
    assert result.parameters["execution_result"]["executed_plan_digest"] == submitted["KAI_OPS_PLAN_DIGEST"]
    assert result.parameters["execution_result"]["build_result"] == "SUCCESS"
    assert build_polls == 2


@pytest.mark.asyncio
async def test_jenkins_does_not_finalize_stale_result_while_building(monkeypatch: pytest.MonkeyPatch) -> None:
    build_polls = 0
    submitted: dict[str, str] = {}

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal build_polls
        if request.url.path.endswith("/crumbIssuer/api/json"):
            return httpx.Response(404)
        if request.url.path == "/queue/item/8/api/json":
            return httpx.Response(200, json={"cancelled": False, "executable": {"url": "/job/payments/8/"}})
        if request.url.path == "/job/payments/8/api/json":
            build_polls += 1
            if build_polls == 1:
                return httpx.Response(200, json={"building": True, "result": "FAILURE"})
            return httpx.Response(200, json={"building": False, "result": "SUCCESS"})
        if request.url.path == "/job/payments/8/artifact/kaiops-result.json":
            return httpx.Response(200, json=_jenkins_result(submitted))
        if request.method == "POST":
            submitted.update(dict(request.url.params))
        return httpx.Response(201, headers={"location": "/queue/item/8/"})

    monkeypatch.setenv("JENKINS_USERNAME", "kaiops")
    monkeypatch.setenv("JENKINS_API_TOKEN", "secret")
    monkeypatch.setenv("REMEDIATION_JENKINS_POLL_SECONDS", "0.01")
    async_client = httpx.AsyncClient
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kwargs: async_client(transport=httpx.MockTransport(handler), **kwargs))
    action = RemediationEngine().build_action(Approval(
        incident_id="11111111-1111-1111-1111-111111111111",
        recommendation_id="22222222-2222-2222-2222-222222222222",
        decision=ApprovalDecision.APPROVED,
        approver="sre-user",
        metadata={"connection_profile": {"executor_type": "jenkins", "endpoint_url": "https://jenkins.example", "job_name": "payments", "credential_ref": "vault://jenkins"}},
    ))

    result = await JenkinsRollbackPlugin().execute(action)

    assert result.status == RemediationStatus.SUCCEEDED
    assert result.parameters["execution_result"]["queue_url"] == "https://jenkins.example/queue/item/8/"
    assert result.parameters["execution_result"]["build_url"] == "https://jenkins.example/job/payments/8/"
    assert build_polls == 2


@pytest.mark.asyncio
async def test_jenkins_waits_until_queue_exposes_executable_url(monkeypatch: pytest.MonkeyPatch) -> None:
    queue_polls = 0
    submitted: dict[str, str] = {}

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal queue_polls
        if request.url.path.endswith("/crumbIssuer/api/json"):
            return httpx.Response(404)
        if request.url.path == "/queue/item/9/api/json":
            queue_polls += 1
            executable = {} if queue_polls == 1 else {"url": "/job/payments/9/"}
            return httpx.Response(200, json={"cancelled": False, "executable": executable})
        if request.url.path == "/job/payments/9/api/json":
            return httpx.Response(200, json={"building": False, "result": "SUCCESS"})
        if request.url.path == "/job/payments/9/artifact/kaiops-result.json":
            return httpx.Response(200, json=_jenkins_result(submitted))
        if request.url.path == "/api/json":
            raise AssertionError("queue polling must not fall back to the Jenkins controller URL")
        submitted.update(dict(request.url.params))
        return httpx.Response(201, headers={"location": "/queue/item/9/"})

    monkeypatch.setenv("JENKINS_USERNAME", "kaiops")
    monkeypatch.setenv("JENKINS_API_TOKEN", "secret")
    monkeypatch.setenv("REMEDIATION_JENKINS_POLL_SECONDS", "0.01")
    async_client = httpx.AsyncClient
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kwargs: async_client(transport=httpx.MockTransport(handler), **kwargs))
    action = RemediationEngine().build_action(Approval(
        incident_id="11111111-1111-1111-1111-111111111111",
        recommendation_id="22222222-2222-2222-2222-222222222222",
        decision=ApprovalDecision.APPROVED,
        metadata={"connection_profile": {"endpoint_url": "https://jenkins.example", "job_name": "payments", "credential_ref": "vault://jenkins"}},
    ))

    result = await JenkinsRollbackPlugin().execute(action)

    assert result.status == RemediationStatus.SUCCEEDED
    assert queue_polls == 2
    assert result.parameters["execution_result"]["build_url"] == "https://jenkins.example/job/payments/9/"


def test_jenkins_registry_timeout_exceeds_connector_maximum() -> None:
    engine = RemediationEngine()
    assert engine.tool_registry.tools["jenkins"].timeout_seconds > 900


def test_jenkins_rewrites_advertised_browser_origin_to_connector_origin() -> None:
    assert JenkinsRollbackPlugin._connector_url(
        "http://jenkins:8080",
        "http://localhost:8082/job/kaiops-auto-remediation/27/",
    ) == "http://jenkins:8080/job/kaiops-auto-remediation/27/"


@pytest.mark.asyncio
async def test_azure_container_apps_job_uses_managed_identity_and_waits_for_terminal_status(monkeypatch: pytest.MonkeyPatch) -> None:
    polls = 0

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal polls
        if request.url.host == "identity.local":
            assert request.headers["X-IDENTITY-HEADER"] == "identity-secret"
            return httpx.Response(200, json={"access_token": "managed-token"})
        assert request.headers["Authorization"] == "Bearer managed-token"
        if request.method == "POST":
            return httpx.Response(200, json={"name": "execution-42"})
        polls += 1
        status = "Running" if polls == 1 else "Succeeded"
        return httpx.Response(200, json={"properties": {"status": status}})

    monkeypatch.setenv("IDENTITY_ENDPOINT", "http://identity.local/token")
    monkeypatch.setenv("IDENTITY_HEADER", "identity-secret")
    monkeypatch.setenv("REMEDIATION_ACA_POLL_SECONDS", "0.01")
    async_client = httpx.AsyncClient
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kwargs: async_client(transport=httpx.MockTransport(handler), **kwargs))
    action = RemediationEngine().build_action(Approval(
        incident_id="11111111-1111-1111-1111-111111111111",
        recommendation_id="22222222-2222-2222-2222-222222222222",
        decision=ApprovalDecision.APPROVED,
        approver="sre-user",
        metadata={
            "service": "payments",
            "connection_profile": {
                "executor_type": "azure_container_apps_job",
                "subscription_id": "sub-1",
                "resource_group": "rg-1",
                "job_name": "kaiops-remediation",
            },
        },
    ))

    result = await AzureContainerAppsJobPlugin().execute(action)

    assert result.status == RemediationStatus.SUCCEEDED
    assert result.parameters["execution_result"]["executor"] == "azure_container_apps_job"
    assert result.parameters["execution_result"]["execution_id"] == "execution-42"
    assert polls == 2
