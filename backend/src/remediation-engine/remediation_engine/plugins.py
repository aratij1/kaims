from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import shlex
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import urljoin, urlparse

import httpx

from ai_workbench_common.agentic import AgentContext, BaseAgent
from common.execution_safety import ExecutionSafetyDecision, assess_execution_safety
from common.models import Approval, ApprovalDecision, RemediationAction, RemediationStatus, utc_now
from common.orchestration.execution_plan import docker_compose_restart_plan
from common.orchestration.execution_plan_contract import verify_plan_fingerprint
from common.resolution_lifecycle import ResolutionState, create_lifecycle, extract_lifecycle
from common.resilience import CircuitBreaker, circuit_breaker
from common.tool_registry import ToolRegistry, ToolSpec
from remediation_engine.capability_executors import (
    AnsibleConnectorExecutor,
    ApiConnectorExecutor,
    CapabilityExecutionRequest,
    DatabaseDiagnosticExecutor,
    KubernetesConnectorExecutor,
    TerraformConnectorExecutor,
)


def jenkins_result_proves_outcome(candidate: dict[str, Any], *, dry_run: bool, script_count: int) -> bool:
    if candidate.get("dry_run") is not dry_run or candidate.get("result") != "SUCCESS":
        return False
    if dry_run:
        return (
            candidate.get("dry_run_validated") is True
            and candidate.get("executed") is False
            and candidate.get("recovery_validated") is False
            and candidate.get("executed_script_count") == 0
        )
    return (
        candidate.get("preflight_passed") is True
        and candidate.get("executed") is True
        and candidate.get("recovery_validated") is True
        and candidate.get("executed_script_count") == script_count
    )


class RemediationPlugin(Protocol):
    action_type: str

    async def discover(self, action: RemediationAction) -> dict[str, Any]: ...
    async def diagnose(self, action: RemediationAction) -> dict[str, Any]: ...
    async def preflight(self, action: RemediationAction) -> dict[str, Any]: ...
    async def dry_run(self, action: RemediationAction) -> RemediationAction: ...
    async def execute(self, action: RemediationAction) -> RemediationAction: ...
    async def validate(self, action: RemediationAction) -> dict[str, Any]: ...
    async def rollback(self, action: RemediationAction) -> RemediationAction: ...
    async def emergency_stop(self, action: RemediationAction) -> RemediationAction: ...
    def required_permissions(self, action: RemediationAction) -> list[str]: ...
    async def health(self) -> dict[str, Any]: ...


@dataclass
class BasePlugin:
    action_type: str
    breaker: CircuitBreaker = field(default_factory=CircuitBreaker)

    @staticmethod
    def _governed_binding(action: RemediationAction) -> tuple[str, str]:
        resource_id = str(
            action.parameters.get("target_resource_id")
            or action.parameters.get("onboarding_resource_id")
            or ""
        ).strip()
        profile = action.parameters.get("connection_profile")
        profile = profile if isinstance(profile, dict) else {}
        credential_ref = str(
            action.parameters.get("credential_ref")
            or profile.get("credential_ref")
            or profile.get("secret_ref")
            or ""
        ).strip()
        if not resource_id:
            raise ValueError("immutable onboarded target_resource_id is required")
        if not credential_ref:
            raise ValueError("onboarded credential reference is required")
        return resource_id, credential_ref

    async def discover(self, action: RemediationAction) -> dict[str, Any]:
        resource_id, _ = self._governed_binding(action)
        return {"adapter": self.action_type, "target_resource_id": resource_id, "discovered": True}

    async def diagnose(self, action: RemediationAction) -> dict[str, Any]:
        resource_id, _ = self._governed_binding(action)
        return {"adapter": self.action_type, "target_resource_id": resource_id, "diagnostic_only": True}

    async def preflight(self, action: RemediationAction) -> dict[str, Any]:
        resource_id, credential_ref = self._governed_binding(action)
        return {
            "passed": True,
            "target_resource_id": resource_id,
            "credential_ref": credential_ref,
            "required_permissions": self.required_permissions(action),
        }

    async def dry_run(self, action: RemediationAction) -> RemediationAction:
        await self.preflight(action)
        action.parameters["dry_run"] = True
        return await self.execute(action)

    async def validate(self, action: RemediationAction) -> dict[str, Any]:
        return {"passed": action.status == RemediationStatus.SUCCEEDED, "adapter": self.action_type}

    async def rollback(self, action: RemediationAction) -> RemediationAction:
        action.status = RemediationStatus.MANUAL_INTERVENTION_REQUIRED
        action.error = f"No governed rollback adapter is configured for {self.action_type}"
        return action

    async def emergency_stop(self, action: RemediationAction) -> RemediationAction:
        action.status = RemediationStatus.MANUAL_INTERVENTION_REQUIRED
        action.error = f"Emergency stop requested for {self.action_type}; operator confirmation required"
        return action

    def required_permissions(self, action: RemediationAction) -> list[str]:
        permissions = action.parameters.get("required_permissions")
        return [str(item) for item in permissions] if isinstance(permissions, list) else []

    async def health(self) -> dict[str, Any]:
        return {"adapter": self.action_type, "healthy": True, "live_execution": False}

    async def _not_configured(self, action: RemediationAction, executor_name: str) -> RemediationAction:
        await asyncio.sleep(0)
        target = str(action.target or "unknown-target").strip() or "unknown-target"
        service = str(action.parameters.get("service") or "").strip()
        environment = str(action.parameters.get("environment") or "").strip()
        execution_plan = action.parameters.get("execution_plan") if isinstance(action.parameters.get("execution_plan"), dict) else {}
        commands = execution_plan.get("commands") if isinstance(execution_plan.get("commands"), list) else []
        scripts = execution_plan.get("scripts") if isinstance(execution_plan.get("scripts"), list) else []
        queries = execution_plan.get("queries") if isinstance(execution_plan.get("queries"), list) else []

        action.status = RemediationStatus.SKIPPED
        action.error = f"No real {executor_name} executor is configured for action_type={action.action_type}"
        action.output = (
            f"Execution not performed; target={target}; service={service or '-'}; environment={environment or '-'}; "
            f"commands={len(commands)}; scripts={len(scripts)}; queries={len(queries)}. "
            "Configure a connector executor and secret_ref before enabling live remediation."
        )
        action.parameters["execution_result"] = {
            "executed": False,
            "executor": executor_name,
            "reason": action.error,
            "target": target,
            "service": service,
            "environment": environment,
            "commands": commands,
            "scripts": scripts,
            "queries": queries,
        }
        return action


class FakeCapabilityAdapter(BasePlugin):
    """Deterministic, side-effect-free adapter for lifecycle contract tests."""

    def __init__(self, action_type: str = "fake_test") -> None:
        super().__init__(action_type)

    async def execute(self, action: RemediationAction) -> RemediationAction:
        resource_id, credential_ref = self._governed_binding(action)
        action.status = RemediationStatus.SUCCEEDED
        action.started_at = action.started_at or utc_now()
        action.completed_at = utc_now()
        action.output = f"fake execution completed for {resource_id}"
        action.parameters["execution_result"] = {
            "executor": self.action_type,
            "executed": not bool(action.parameters.get("dry_run")),
            "target_resource_id": resource_id,
            "credential_ref": credential_ref,
        }
        return action

class JenkinsRollbackPlugin(BasePlugin):
    def __init__(self) -> None:
        super().__init__("rollback_deployment")

    @staticmethod
    def _execution_plan_envelope(action: RemediationAction) -> tuple[str, str, int]:
        raw_plan = action.parameters.get("execution_plan")
        plan = dict(raw_plan) if isinstance(raw_plan, dict) else {}
        fallback_cmd = "curl --fail --silent --show-error --output /dev/null http://jenkins:8080/login"

        def _is_jenkins_executable_cmd(cmd: Any) -> bool:
            val = str(cmd or "").strip()
            if not val or "\n" in val or len(val) > 2000:
                return False
            if "http://docker-socket-proxy:2375/containers/" in val:
                return True
            if val.startswith("docker compose --project-name ") and "/opt/kaiops/docker-compose.yml" in val:
                return True
            if re.match(
                r"^curl --fail --silent --show-error( --output /dev/null)?( --retry \d+)?( --retry-all-errors)?( --retry-connrefused)?( --retry-delay \d+)?( -X POST)? '?http://[A-Za-z0-9_.:-]+/[A-Za-z0-9_./?=&-]*'?$",
                val,
            ):
                return True
            return False

        def _is_jenkins_executable_script(scr: Any) -> bool:
            val = str(scr or "").strip()
            return bool(
                re.match(
                    r"^(bash|sh)\s+scripts/remediation/kaiops_alert_health_triage\.sh(?:\s+--(service|environment|api-gateway-url|prometheus-url|mysql-host|mysql-database|mysql-user|alerts-table|dry-run)\s+[A-Za-z0-9_.:/-]+)+$",
                    val,
                )
            )

        def _sanitize_cmd_list(items: Any) -> list[str]:
            raw_list = items if isinstance(items, list) else []
            valid = [str(x).strip() for x in raw_list if _is_jenkins_executable_cmd(x)]
            return valid if valid else [fallback_cmd]

        raw_scripts = plan.get("scripts") if isinstance(plan.get("scripts"), list) else []
        valid_scripts = [str(s).strip() for s in raw_scripts if _is_jenkins_executable_script(s)]
        plan["scripts"] = valid_scripts
        plan["commands"] = _sanitize_cmd_list(plan.get("commands"))
        plan["preflight"] = _sanitize_cmd_list(plan.get("preflight_commands") or plan.get("preflight"))
        plan["preflight_commands"] = list(plan["preflight"])
        plan["validation_commands"] = _sanitize_cmd_list(plan.get("validation_commands"))
        plan["rollback_commands"] = _sanitize_cmd_list(plan.get("rollback_commands"))
        if not plan.get("rollback_mode"):
            plan["rollback_mode"] = "automatic"

        serialized = json.dumps(plan, sort_keys=True, separators=(",", ":"))
        digest = f"sha256:{hashlib.sha256(serialized.encode('utf-8')).hexdigest()}"
        return serialized, digest, len(valid_scripts)

    @staticmethod
    def _connector_url(endpoint: str, advertised_url: str) -> str:
        """Keep Jenkins-advertised paths but use the configured connector origin."""
        candidate = str(advertised_url or "").strip()
        if not candidate:
            return ""
        parsed = urlparse(candidate)
        path = parsed.path if parsed.scheme and parsed.netloc else candidate
        return urljoin(f"{endpoint.rstrip('/')}/", path.lstrip("/"))

    @staticmethod
    def _connector_operation(action: RemediationAction) -> str:
        """Resolve the operation exclusively from typed, approved action data."""
        explicit = str(action.parameters.get("connector_operation") or "").strip().lower()
        if explicit:
            return explicit
        return action.action_type

    async def dispatch(self, action: RemediationAction) -> RemediationAction:
        """Submit once and return immediately with the durable external identity."""
        profile = action.parameters.get("connection_profile") if isinstance(action.parameters.get("connection_profile"), dict) else {}
        endpoint = str(profile.get("endpoint_url") or profile.get("endpoint") or "").rstrip("/")
        job_name = str(profile.get("job_name") or "").strip("/")
        secret_ref = str(profile.get("credential_ref") or profile.get("secret_ref") or "").strip()
        if not endpoint or not job_name or not secret_ref:
            return await self._not_configured(action, "jenkins")
        operation = self._connector_operation(action)
        allowed = profile.get("allowed_operations") if isinstance(profile.get("allowed_operations"), list) else []
        if allowed and operation not in {str(item).strip().lower() for item in allowed}:
            action.status = RemediationStatus.POLICY_BLOCKED
            action.error = f"Connector does not allow operation {operation}"
            return action
        username = os.getenv("JENKINS_USERNAME", "").strip()
        token = os.getenv("JENKINS_API_TOKEN", "").strip()
        if not username or not token:
            action.status = RemediationStatus.DISPATCH_FAILED
            action.error = f"Runtime credentials for {secret_ref} are unavailable"
            return action
        job_path = "/job/" + "/job/".join(part for part in job_name.split("/") if part)
        execution_plan_json, execution_plan_digest, expected_script_count = self._execution_plan_envelope(action)
        parameters = {
            "KAI_OPS_INCIDENT_ID": str(action.incident_id),
            "KAI_OPS_APPROVAL_ID": str(action.approval_id or ""),
            "KAI_OPS_APPLICATION_ID": str(action.parameters.get("application_id") or ""),
            "KAI_OPS_TARGET": str(action.target),
            "KAI_OPS_SERVICE": str(action.parameters.get("service") or ""),
            "KAI_OPS_ENVIRONMENT": str(action.parameters.get("environment") or ""),
            "KAI_OPS_NAMESPACE": str(action.parameters.get("namespace") or "default"),
            "KAI_OPS_RESOLUTION_ID": str(action.parameters.get("resolution_id") or operation),
            "KAI_OPS_DRY_RUN": str(bool(action.parameters.get("dry_run", False))).lower(),
            "KAI_OPS_EXECUTION_PLAN": execution_plan_json,
            "KAI_OPS_PLAN_DIGEST": execution_plan_digest,
        }
        async with httpx.AsyncClient(auth=(username, token), timeout=httpx.Timeout(30.0, connect=10.0)) as client:
            headers: dict[str, str] = {}
            crumb_response = await client.get(f"{endpoint}/crumbIssuer/api/json")
            if crumb_response.status_code == 200:
                crumb = crumb_response.json()
                headers[str(crumb.get("crumbRequestField") or "Jenkins-Crumb")] = str(crumb.get("crumb") or "")
            response = await client.post(f"{endpoint}{job_path}/buildWithParameters", data=parameters, headers=headers)
            response.raise_for_status()
        queue_url = urljoin(f"{endpoint}/", str(response.headers.get("location") or "").strip())
        if not queue_url:
            action.status = RemediationStatus.DISPATCH_FAILED
            action.error = "Jenkins accepted the request without returning a queue URL"
            return action
        action.status = RemediationStatus.EXECUTOR_ACCEPTED
        action.started_at = action.started_at or utc_now()
        action.parameters["connector_operation"] = operation
        action.parameters["execution_result"] = {
            "executor": "jenkins",
            "phase": "queued",
            "accepted": True,
            "executed": False,
            "connector_endpoint": endpoint,
            "job_name": job_name,
            "queue_url": queue_url,
            "build_url": "",
            "secret_ref": secret_ref,
            "approved_plan_digest": execution_plan_digest,
            "expected_script_count": expected_script_count,
        }
        return action

    async def observe(self, action: RemediationAction) -> RemediationAction:
        """Perform one read-only reconciliation pass; never wait for Jenkins."""
        result = action.parameters.get("execution_result")
        result = result if isinstance(result, dict) else {}
        endpoint = str(result.get("connector_endpoint") or "").rstrip("/")
        queue_url = str(result.get("queue_url") or "").strip()
        build_url = str(result.get("build_url") or "").strip()
        username = os.getenv("JENKINS_USERNAME", "").strip()
        token = os.getenv("JENKINS_API_TOKEN", "").strip()
        if not endpoint or not queue_url or not username or not token:
            action.status = RemediationStatus.DISPATCH_FAILED
            action.error = "Jenkins reconciliation identity or credentials are unavailable"
            return action
        async with httpx.AsyncClient(auth=(username, token), timeout=httpx.Timeout(20.0, connect=5.0)) as client:
            if not build_url:
                response = await client.get(f"{queue_url.rstrip('/')}/api/json")
                response.raise_for_status()
                payload = response.json()
                if bool(payload.get("cancelled")):
                    action.status = RemediationStatus.CANCELLED
                    action.error = "Jenkins cancelled the queued remediation build"
                    action.completed_at = utc_now()
                    return action
                executable = payload.get("executable") if isinstance(payload.get("executable"), dict) else {}
                advertised = str(executable.get("url") or "").strip()
                if not advertised:
                    action.status = RemediationStatus.EXECUTOR_ACCEPTED
                    result["phase"] = "queued"
                    action.parameters["execution_result"] = result
                    return action
                build_url = self._connector_url(endpoint, advertised)
                result["build_url"] = build_url
            response = await client.get(f"{build_url.rstrip('/')}/api/json")
            response.raise_for_status()
            payload = response.json()
            terminal = str(payload.get("result") or "").strip().upper()
            if bool(payload.get("building")) or not terminal:
                action.status = RemediationStatus.RUNNING
                result["phase"] = "executing"
                action.parameters["execution_result"] = result
                return action
            result["build_result"] = terminal
            if terminal != "SUCCESS":
                action.status = RemediationStatus.EXECUTION_FAILED
                action.error = f"Jenkins build finished with result {terminal}"
                action.completed_at = utc_now()
                action.parameters["execution_result"] = result
                return action
            artifact = await client.get(f"{build_url.rstrip('/')}/artifact/kaiops-result.json")
            artifact.raise_for_status()
            evidence = artifact.json()
        expected = {
            "incident_id": str(action.incident_id),
            "approval_id": str(action.approval_id or ""),
            "target": str(action.target),
            "plan_digest": str(result.get("approved_plan_digest") or ""),
        }
        mismatched = [key for key, value in expected.items() if str(evidence.get(key) or "") != value]
        truthful = (
            not mismatched
            and bool(evidence.get("preflight_passed"))
            and bool(evidence.get("recovery_validated"))
            and (bool(action.parameters.get("dry_run")) or bool(evidence.get("executed")))
            and int(evidence.get("executed_script_count") or 0) == int(result.get("expected_script_count") or 0)
        )
        result.update({
            "phase": "terminal",
            "recovery_evidence": evidence,
            "executed": bool(evidence.get("executed")),
            "recovery_validated": bool(evidence.get("recovery_validated")),
            "executed_plan_digest": str(evidence.get("plan_digest") or ""),
            "executed_script_count": int(evidence.get("executed_script_count") or 0),
        })
        action.parameters["execution_result"] = result
        action.completed_at = action.completed_at or utc_now()
        if truthful:
            action.status = RemediationStatus.SUCCEEDED
            action.output = f"Jenkins execution and recovery validation completed for {result.get('job_name')}"
        else:
            action.status = RemediationStatus.VALIDATION_FAILED
            action.error = "Jenkins SUCCESS did not provide matching execution and recovery evidence" + (f": {', '.join(mismatched)}" if mismatched else "")
        return action

    @circuit_breaker(CircuitBreaker())
    async def execute(self, action: RemediationAction) -> RemediationAction:
        profile = action.parameters.get("connection_profile") if isinstance(action.parameters.get("connection_profile"), dict) else {}
        endpoint = str(profile.get("endpoint_url") or profile.get("endpoint") or "").rstrip("/")
        job_name = str(profile.get("job_name") or "").strip("/")
        secret_ref = str(profile.get("credential_ref") or profile.get("secret_ref") or "").strip()
        allowed = profile.get("allowed_operations") if isinstance(profile.get("allowed_operations"), list) else []
        if not endpoint or not job_name or not secret_ref:
            return await self._not_configured(action, "jenkins")
        connector_operation = self._connector_operation(action)
        action.parameters["connector_operation"] = connector_operation
        if allowed and connector_operation not in {str(item).strip().lower() for item in allowed}:
            action.status = RemediationStatus.SKIPPED
            action.error = f"Connector does not allow operation {connector_operation}"
            return action

        parsed = urlparse(endpoint)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("Jenkins endpoint must be an absolute HTTP(S) URL")

        username = os.getenv("JENKINS_USERNAME", "").strip()
        token = os.getenv("JENKINS_API_TOKEN", "").strip()
        if not username or not token:
            action.status = RemediationStatus.SKIPPED
            action.error = f"Secret reference {secret_ref} is configured, but the runtime secret provider did not inject JENKINS_USERNAME and JENKINS_API_TOKEN"
            return action

        job_path = "/job/" + "/job/".join(part for part in job_name.split("/") if part)
        build_url = f"{endpoint}{job_path}/buildWithParameters"
        timeout_seconds = max(30.0, min(float(profile.get("timeout_seconds") or 1200), 1500.0))
        execution_plan_json, execution_plan_digest, expected_script_count = self._execution_plan_envelope(action)
        parameters = {
            "KAI_OPS_INCIDENT_ID": str(action.incident_id),
            "KAI_OPS_APPROVAL_ID": str(action.approval_id or ""),
            "KAI_OPS_APPLICATION_ID": str(action.parameters.get("application_id") or ""),
            "KAI_OPS_TARGET": str(action.target),
            "KAI_OPS_SERVICE": str(action.parameters.get("service") or ""),
            "KAI_OPS_ENVIRONMENT": str(action.parameters.get("environment") or ""),
            "KAI_OPS_NAMESPACE": str(action.parameters.get("namespace") or "default"),
            "KAI_OPS_RESOLUTION_ID": str(action.parameters.get("resolution_id") or connector_operation),
            "KAI_OPS_DRY_RUN": str(bool(action.parameters.get("dry_run", False))).lower(),
            "KAI_OPS_EXECUTION_PLAN": execution_plan_json,
            "KAI_OPS_PLAN_DIGEST": execution_plan_digest,
        }
        async with httpx.AsyncClient(auth=(username, token), timeout=httpx.Timeout(timeout_seconds, connect=10.0)) as client:
            headers: dict[str, str] = {}
            crumb_response = await client.get(f"{endpoint}/crumbIssuer/api/json")
            if crumb_response.status_code == 200:
                crumb = crumb_response.json()
                headers[str(crumb.get("crumbRequestField") or "Jenkins-Crumb")] = str(crumb.get("crumb") or "")
            response = await client.post(build_url, data=parameters, headers=headers)
            response.raise_for_status()
            queue_url = urljoin(f"{endpoint}/", str(response.headers.get("location") or "").strip())
            if not queue_url:
                action.status = RemediationStatus.FAILED
                action.error = "Jenkins accepted the request without returning a queue URL"
                return action

            poll_interval = max(0.25, min(float(os.getenv("REMEDIATION_JENKINS_POLL_SECONDS", "1")), 10.0))
            deadline = asyncio.get_running_loop().time() + timeout_seconds
            resolved_build_url = ""
            while asyncio.get_running_loop().time() < deadline:
                queue_response = await client.get(f"{queue_url.rstrip('/')}/api/json")
                queue_response.raise_for_status()
                queue_payload = queue_response.json()
                if bool(queue_payload.get("cancelled")):
                    action.status = RemediationStatus.FAILED
                    action.error = "Jenkins cancelled the queued remediation build"
                    break
                executable = queue_payload.get("executable") if isinstance(queue_payload.get("executable"), dict) else {}
                executable_url = str(executable.get("url") or "").strip()
                # urljoin(base, "") returns the base URL, which previously
                # made a queued build look resolved and caused us to poll the
                # Jenkins controller forever instead of the queue item.
                if executable_url:
                    resolved_build_url = self._connector_url(endpoint, executable_url)
                    break
                await asyncio.sleep(poll_interval)

            build_result = ""
            recovery_evidence: dict[str, Any] = {}
            while resolved_build_url and asyncio.get_running_loop().time() < deadline:
                build_response = await client.get(f"{resolved_build_url.rstrip('/')}/api/json")
                build_response.raise_for_status()
                build_payload = build_response.json()
                terminal_result = str(build_payload.get("result") or "").strip().upper()
                building = bool(build_payload.get("building"))
                # Jenkins may briefly expose a stale result while a retried or
                # resumed Pipeline still reports building=true. Require both
                # signals to agree before finalizing the durable action.
                if terminal_result and not building:
                    build_result = terminal_result
                    break
                await asyncio.sleep(poll_interval)

            if build_result == "SUCCESS":
                try:
                    artifact_response = await client.get(
                        f"{resolved_build_url.rstrip('/')}/artifact/kaiops-result.json"
                    )
                    artifact_response.raise_for_status()
                    candidate = artifact_response.json()
                    if not isinstance(candidate, dict):
                        raise ValueError("result artifact is not an object")
                    expected = {
                        "incident_id": str(action.incident_id),
                        "approval_id": str(action.approval_id or ""),
                        "target": str(action.target),
                        "plan_digest": execution_plan_digest,
                    }
                    mismatched = [key for key, value in expected.items() if str(candidate.get(key) or "") != value]
                    if mismatched:
                        raise ValueError(f"result artifact identity mismatch: {', '.join(mismatched)}")
                    dry_run = bool(action.parameters.get("dry_run", False))
                    truthful_success = jenkins_result_proves_outcome(
                        candidate, dry_run=dry_run, script_count=expected_script_count,
                    )
                    if not truthful_success:
                        raise ValueError("result artifact does not prove execution and recovery validation")
                    recovery_evidence = candidate
                except (httpx.HTTPError, ValueError, json.JSONDecodeError) as exc:
                    action.error = f"Jenkins SUCCESS lacked valid recovery evidence: {exc}"

        if not action.error and not resolved_build_url:
            action.status = RemediationStatus.FAILED
            action.error = f"Jenkins queue did not start a build within {timeout_seconds:g}s"
        elif not action.error and not build_result:
            action.status = RemediationStatus.FAILED
            action.error = f"Jenkins build did not finish within {timeout_seconds:g}s"
        elif not action.error and build_result == "SUCCESS" and recovery_evidence:
            action.status = RemediationStatus.SUCCEEDED
            action.output = (
                f"Jenkins dry run validated for {job_name}"
                if bool(action.parameters.get("dry_run", False))
                else f"Jenkins execution and recovery validation completed for {job_name}"
            )
        elif not action.error:
            action.status = RemediationStatus.FAILED
            action.error = f"Jenkins build finished with result {build_result}"
            action.output = f"Jenkins remediation failed for {job_name}"
        action.parameters["execution_result"] = {
            "executor": "jenkins",
            "connector_endpoint": endpoint,
            "job_name": job_name,
            "connector_operation": connector_operation,
            "queue_url": queue_url,
            "build_url": resolved_build_url,
            "build_result": build_result or None,
            "recovery_evidence": recovery_evidence,
            "executed": bool(recovery_evidence.get("executed")),
            "recovery_validated": bool(recovery_evidence.get("recovery_validated")),
            "approved_plan_digest": execution_plan_digest,
            "executed_plan_digest": str(recovery_evidence.get("plan_digest") or ""),
            "executed_script_count": int(recovery_evidence.get("executed_script_count") or 0),
            "secret_ref": secret_ref,
            "submitted_parameters": {key: value for key, value in parameters.items() if key != "KAI_OPS_EXECUTION_PLAN"},
            "summary": action.error or action.output,
        }
        return action


class AzureContainerAppsJobPlugin(BasePlugin):
    def __init__(self) -> None:
        super().__init__("azure_container_apps_job")

    async def execute(self, action: RemediationAction) -> RemediationAction:
        profile = action.parameters.get("connection_profile") if isinstance(action.parameters.get("connection_profile"), dict) else {}
        subscription = str(profile.get("subscription_id") or os.getenv("AZURE_SUBSCRIPTION_ID", "")).strip()
        resource_group = str(profile.get("resource_group") or os.getenv("AZURE_RESOURCE_GROUP", "")).strip()
        job_name = str(profile.get("job_name") or os.getenv("REMEDIATION_ACA_JOB_NAME", "")).strip()
        identity_endpoint = os.getenv("IDENTITY_ENDPOINT", "").strip()
        identity_header = os.getenv("IDENTITY_HEADER", "").strip()
        if not all((subscription, resource_group, job_name, identity_endpoint, identity_header)):
            return await self._not_configured(action, "azure-container-apps-job")

        timeout_seconds = max(30.0, min(float(profile.get("timeout_seconds") or 900), 1800.0))
        api_version = "2024-03-01"
        resource = (
            f"https://management.azure.com/subscriptions/{subscription}/resourceGroups/{resource_group}"
            f"/providers/Microsoft.App/jobs/{job_name}"
        )
        token_url = f"{identity_endpoint}?resource=https%3A%2F%2Fmanagement.azure.com%2F&api-version=2019-08-01"
        async with httpx.AsyncClient(timeout=httpx.Timeout(timeout_seconds, connect=10.0)) as client:
            token_response = await client.get(token_url, headers={"X-IDENTITY-HEADER": identity_header})
            token_response.raise_for_status()
            access_token = str(token_response.json().get("access_token") or "")
            if not access_token:
                raise RuntimeError("Managed identity endpoint returned no Azure access token")
            headers = {"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"}
            env = [
                {"name": "KAI_OPS_INCIDENT_ID", "value": str(action.incident_id)},
                {"name": "KAI_OPS_APPROVAL_ID", "value": str(action.approval_id or "")},
                {"name": "KAI_OPS_ACTION_TYPE", "value": action.action_type},
                {"name": "KAI_OPS_TARGET", "value": str(action.target)},
                {"name": "KAI_OPS_EXECUTION_PLAN", "value": json.dumps(action.parameters.get("execution_plan") or {}, separators=(",", ":"))},
            ]
            start_response = await client.post(
                f"{resource}/start?api-version={api_version}",
                headers=headers,
                json={"containers": [{"name": "remediation", "env": env}]},
            )
            start_response.raise_for_status()
            start_payload = start_response.json() if start_response.content else {}
            execution_name = str(start_payload.get("name") or start_payload.get("id", "").rstrip("/").split("/")[-1]).strip()
            if not execution_name:
                raise RuntimeError("Azure Container Apps Jobs accepted the request without an execution name")

            deadline = asyncio.get_running_loop().time() + timeout_seconds
            terminal_status = ""
            while asyncio.get_running_loop().time() < deadline:
                execution_response = await client.get(
                    f"{resource}/executions/{execution_name}?api-version={api_version}", headers=headers
                )
                execution_response.raise_for_status()
                properties = execution_response.json().get("properties", {})
                status = str(properties.get("status") or "").strip()
                if status.lower() in {"succeeded", "failed", "stopped", "degraded"}:
                    terminal_status = status
                    break
                await asyncio.sleep(max(1.0, min(float(os.getenv("REMEDIATION_ACA_POLL_SECONDS", "5")), 30.0)))

        succeeded = terminal_status.lower() == "succeeded"
        action.status = RemediationStatus.SUCCEEDED if succeeded else RemediationStatus.FAILED
        action.output = f"Azure Container Apps Job execution {execution_name} succeeded" if succeeded else ""
        action.error = None if succeeded else (
            f"Azure Container Apps Job execution {execution_name} finished with status {terminal_status}"
            if terminal_status else f"Azure Container Apps Job execution {execution_name} timed out after {timeout_seconds:g}s"
        )
        action.parameters["execution_result"] = {
            "executed": succeeded,
            "executor": "azure_container_apps_job",
            "job_name": job_name,
            "execution_id": execution_name,
            "execution_status": terminal_status or "TIMED_OUT",
            "resource_id": resource,
            "summary": action.error or action.output,
        }
        return action


class KubernetesRestartPlugin(BasePlugin):
    def __init__(self) -> None:
        super().__init__("restart_pod")

    @circuit_breaker(CircuitBreaker())
    async def execute(self, action: RemediationAction) -> RemediationAction:
        return await _execute_registered_capability(action, KubernetesConnectorExecutor)


class AnsibleRemediationPlugin(BasePlugin):
    def __init__(self) -> None:
        super().__init__("restart_service")

    async def execute(self, action: RemediationAction) -> RemediationAction:
        return await _execute_registered_capability(action, AnsibleConnectorExecutor)


class TerraformRollbackPlugin(BasePlugin):
    def __init__(self) -> None:
        super().__init__("terraform_rollback")

    async def execute(self, action: RemediationAction) -> RemediationAction:
        return await _execute_registered_capability(action, TerraformConnectorExecutor)


class ApiExecutionPlugin(BasePlugin):
    def __init__(self) -> None:
        super().__init__("api_execution")

    async def execute(self, action: RemediationAction) -> RemediationAction:
        return await _execute_registered_capability(action, ApiConnectorExecutor)


class DatabaseDiagnosticPlugin(BasePlugin):
    def __init__(self) -> None:
        super().__init__("database_diagnostic")

    async def execute(self, action: RemediationAction) -> RemediationAction:
        return await _execute_registered_capability(action, DatabaseDiagnosticExecutor)


async def _execute_registered_capability(
    action: RemediationAction,
    executor_type: type[KubernetesConnectorExecutor],
) -> RemediationAction:
    plan = action.parameters.get("remediation_plan")
    plan = plan if isinstance(plan, dict) else {}
    profile = action.parameters.get("connection_profile")
    profile = profile if isinstance(profile, dict) else {}
    endpoint = str(profile.get("executor_endpoint") or profile.get("endpoint") or "").strip()
    if not plan or not endpoint:
        action.status = RemediationStatus.SKIPPED
        action.error = (
            f"No real {executor_type.connector_kind} executor is configured: "
            "typed remediation_plan and onboarded connector executor_endpoint are required"
        )
        action.parameters["execution_result"] = {
            "executed": False,
            "executor": executor_type.connector_kind,
            "reason": action.error,
        }
        return action
    try:
        request = CapabilityExecutionRequest(
            tenant_id=action.tenant_id,
            incident_id=str(action.incident_id),
            capability_id=str(plan.get("recommended_capability") or ""),
            connector_id=str(plan.get("connector_id") or ""),
            target_resource_id=str(plan.get("target_resource_id") or ""),
            target_identity_verified=bool(plan.get("target_identity_verified")),
            environment=str(action.parameters.get("environment") or "unknown").lower(),
            parameters=plan.get("required_parameters") if isinstance(plan.get("required_parameters"), dict) else {},
            secret_ref=str(profile.get("secret_ref") or profile.get("credential_ref") or ""),
            idempotency_key=str(action.idempotency_key or action.id),
            timeout_seconds=float(action.parameters.get("timeout_seconds") or 30),
            max_attempts=int(action.parameters.get("max_attempts") or 1),
        )
        async with httpx.AsyncClient() as client:
            executor = executor_type(endpoint, client)
            precheck = await executor.precheck(request)
            if not precheck.succeeded:
                result = precheck
            elif bool(action.parameters.get("dry_run")):
                result = await executor.dry_run(request)
            else:
                result = await executor.execute(request)
    except (KeyError, TypeError, ValueError) as exc:
        action.status = RemediationStatus.POLICY_BLOCKED
        action.error = f"Capability execution contract rejected: {exc}"
        action.parameters["execution_result"] = {
            "executed": False,
            "executor": executor_type.connector_kind,
            "reason": action.error,
        }
        return action
    action.started_at = action.started_at or utc_now()
    action.completed_at = utc_now()
    action.status = RemediationStatus.SUCCEEDED if result.succeeded else RemediationStatus.FAILED
    action.output = result.summary if result.succeeded else ""
    action.error = None if result.succeeded else result.summary
    action.parameters["execution_result"] = result.model_dump(mode="json")
    return action


class LocalScriptExecutionPlugin(BasePlugin):
    def __init__(self) -> None:
        super().__init__("script_execution")

    @staticmethod
    def _repo_root() -> Path:
        current = Path(__file__).resolve()
        for parent in current.parents:
            if (parent / "scripts" / "remediation").is_dir():
                return parent
        return Path("/app")

    def _resolve_script_command(self, action: RemediationAction) -> list[str]:
        execution_plan = action.parameters.get("execution_plan") if isinstance(action.parameters.get("execution_plan"), dict) else {}
        scripts = execution_plan.get("scripts") if isinstance(execution_plan.get("scripts"), list) else []
        commands = action.parameters.get("commands") if isinstance(action.parameters.get("commands"), list) else []
        raw = next(
            (
                str(item).replace("script:", "", 1).strip()
                for item in [*scripts, *commands]
                if "kaiops_alert_health_triage.sh" in str(item)
            ),
            "",
        )
        if not raw:
            raise ValueError("script_execution requires kaiops_alert_health_triage.sh in execution_plan.scripts")

        parts = shlex.split(raw)
        script_index = next((index for index, part in enumerate(parts) if part.endswith("kaiops_alert_health_triage.sh")), -1)
        if script_index < 0:
            raise ValueError("approved script path was not found")

        script_token = parts[script_index]
        relative_script = Path(script_token)
        script_path = relative_script if relative_script.is_absolute() else self._repo_root() / relative_script
        allowed_dir = (self._repo_root() / "scripts" / "remediation").resolve()
        resolved_script = script_path.resolve()
        if allowed_dir not in resolved_script.parents:
            raise PermissionError(f"script path {resolved_script} is outside approved remediation directory")
        if not resolved_script.exists():
            raise FileNotFoundError(f"approved remediation script not found: {resolved_script}")

        arguments = parts[script_index + 1:]
        url_defaults = {
            "--api-gateway-url": os.environ.get("API_GATEWAY_URL", "http://api-gateway:8000"),
            "--prometheus-url": os.environ.get("PROMETHEUS_URL", "http://prometheus:9090"),
        }
        for option, default in url_defaults.items():
            if option not in arguments:
                continue
            value_index = arguments.index(option) + 1
            value = arguments[value_index] if value_index < len(arguments) else ""
            parsed = urlparse(value)
            if parsed.scheme not in {"http", "https"} or not parsed.netloc:
                arguments[value_index:value_index + 1] = [default]

        return ["sh", str(resolved_script), *arguments]

    async def execute(self, action: RemediationAction) -> RemediationAction:
        command = self._resolve_script_command(action)
        script_path = Path(command[1])
        script_input = script_path.read_bytes().replace(b"\r\n", b"\n").replace(b"\r", b"\n")
        runtime_command = ["sh", "-s", "--", *command[2:]]
        env = os.environ.copy()
        env.setdefault("MYSQL_PASSWORD", env.get("DB_PASSWORD", ""))
        timeout_seconds = float(action.parameters.get("timeout_seconds") or 45)
        process = await asyncio.create_subprocess_exec(
            *runtime_command,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
            cwd=str(self._repo_root()),
        )
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(input=script_input), timeout=timeout_seconds)
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
            action.status = RemediationStatus.FAILED
            action.error = f"script timed out after {timeout_seconds:g}s"
            action.output = ""
            return action

        output = stdout.decode("utf-8", errors="replace").strip()
        error = stderr.decode("utf-8", errors="replace").strip()
        validation_only = any(
            marker in output.lower()
            for marker in (
                "dry run complete. no remediation mutation was executed",
                "live remediation is intentionally connector-gated",
            )
        )
        action.output = output
        action.error = error if process.returncode else ""
        if process.returncode != 0:
            action.status = RemediationStatus.FAILED
        elif validation_only:
            action.status = RemediationStatus.SKIPPED
            action.error = "Validation completed, but this script did not apply a remediation change. Select a governed live executor to execute the plan."
        else:
            action.status = RemediationStatus.SUCCEEDED
        action.parameters["execution_result"] = {
            "executed": process.returncode == 0 and not validation_only,
            "validation_only": validation_only,
            "executor": "local-script",
            "command": command,
            "runtime_command": runtime_command,
            "returncode": process.returncode,
            "stdout": output,
            "stderr": error,
            "summary": action.error or "Remediation command completed and returned a successful exit status.",
        }
        return action


@dataclass
class RemediationEngine(BaseAgent):
    plugins: dict[str, RemediationPlugin] = field(
        default_factory=lambda: {
            "jenkins": JenkinsRollbackPlugin(),
            "azure_container_apps_job": AzureContainerAppsJobPlugin(),
            "rollback_deployment": JenkinsRollbackPlugin(),
            "restart_pod": KubernetesRestartPlugin(),
            "scale_deployment": KubernetesRestartPlugin(),
            "restart_service": AnsibleRemediationPlugin(),
            "clear_cache": ApiExecutionPlugin(),
            "failover_database": ApiExecutionPlugin(),
            "api_execution": ApiExecutionPlugin(),
            "database_diagnostic": DatabaseDiagnosticPlugin(),
            "script_execution": LocalScriptExecutionPlugin(),
            "terraform_rollback": TerraformRollbackPlugin(),
        }
    )
    tool_registry: ToolRegistry = field(default_factory=ToolRegistry)
    name: str = "automation-agent"

    def __post_init__(self) -> None:
        if self.tool_registry.tools:
            return

        async def _build_tool_handler(plugin: RemediationPlugin, payload: dict[str, Any]) -> dict[str, Any]:
            action_payload = payload.get("action")
            if not isinstance(action_payload, dict):
                raise ValueError("tool payload must include 'action'")
            action = RemediationAction.model_validate(action_payload)
            completed = await plugin.execute(action)
            return completed.model_dump(mode="json")

        for action_type, plugin in self.plugins.items():
            async def handler(payload: dict[str, Any], _plugin: RemediationPlugin = plugin) -> dict[str, Any]:
                return await _build_tool_handler(_plugin, payload)

            self.tool_registry.register(
                ToolSpec(
                    name=action_type,
                    handler=handler,
                    # Jenkins is a run-to-completion connector. Its own bounded
                    # queue/build deadline is authoritative; a shorter wrapper
                    # timeout would cancel polling and manufacture a failure
                    # while the external build continues running.
                    timeout_seconds=1830.0 if action_type == "azure_container_apps_job" else 930.0 if action_type in {"jenkins", "rollback_deployment"} else 60.0,
                    permissions={"automation-agent"},
                )
            )

    async def can_execute(self, context: AgentContext) -> bool:
        return "approval" in context.previous_agent_results

    def is_action_allowed(self, action_type: str) -> bool:
        normalized = str(action_type or "").strip().lower()
        if not normalized:
            return False
        return normalized in set(self.plugins.keys())

    @staticmethod
    def _looks_like_uuid(token: str) -> bool:
        return bool(re.fullmatch(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}", token.strip()))

    @staticmethod
    def _normalize_text(value: Any) -> str:
        return str(value or "").strip().lower()

    def _sanitize_recommended_commands(self, commands: list[str]) -> list[str]:
        sanitized: list[str] = []
        seen: set[str] = set()
        for raw in commands:
            token = str(raw or "").strip().strip("`")
            if not token:
                continue
            token = re.sub(r"^\s*(cmd|command|script|query)\s*:\s*", "", token, flags=re.IGNORECASE).strip()
            if not token or token.startswith("#"):
                continue
            lower = token.lower()
            if lower.startswith("preview only") or lower.startswith("recommended_action"):
                continue
            if lower in seen:
                continue
            seen.add(lower)
            sanitized.append(token)
        return sanitized

    def _infer_target_from_commands(self, commands: list[str]) -> str:
        for command in commands:
            token = str(command or "").strip()
            if not token:
                continue

            deployment_match = re.search(r"deployment/([a-z0-9][a-z0-9_.-]*)", token, flags=re.IGNORECASE)
            if deployment_match:
                return deployment_match.group(1)

            service_flag_match = re.search(r"-Service\s+([a-z0-9][a-z0-9_.-]*)", token, flags=re.IGNORECASE)
            if service_flag_match:
                return service_flag_match.group(1)

            service_arg_match = re.search(r"service=([a-z0-9][a-z0-9_.-]*)", token, flags=re.IGNORECASE)
            if service_arg_match:
                return service_arg_match.group(1)

            findstr_match = re.search(r"findstr\s+([a-z0-9][a-z0-9_.-]*)", token, flags=re.IGNORECASE)
            if findstr_match:
                return findstr_match.group(1)

        return ""

    def _action_type_from_plan(self, *, plan: dict[str, Any]) -> str:
        """Select an executor only from typed plan data, never operator prose."""
        actions = plan.get("actions") if isinstance(plan.get("actions"), list) else []
        first = actions[0] if actions and isinstance(actions[0], dict) else {}
        safety = first.get("safety_binding") if isinstance(first.get("safety_binding"), dict) else {}
        capability = safety.get("capability") if isinstance(safety.get("capability"), dict) else {}
        capability_id = str(capability.get("capability_id") or "").strip().lower()
        explicit = {
            "kubernetes.restart_workload": "restart_pod",
            "kubernetes.scale_workload": "scale_deployment",
            "kubernetes.rollback_deployment": "rollback_deployment",
            "linux.restart_service": "restart_service",
            "windows.restart_service": "restart_service",
            "cache.clear_cache": "clear_cache",
            "database.failover": "failover_database",
            "terraform.rollback": "terraform_rollback",
            "jenkins.rollback_deployment": "rollback_deployment",
            "application.invoke_recovery_endpoint": "api_execution",
            "application.restart_service": "restart_service",
        }
        if capability_id in explicit:
            return explicit[capability_id]
        raise ValueError("UNSUPPORTED_ACTION_PLAN: registered capability identity is absent or unsupported")

    def build_action(self, approval: Approval) -> RemediationAction:
        recommended_action = str(approval.metadata.get("recommended_action") or "").strip()
        recommended_commands = approval.metadata.get("recommended_commands") if isinstance(approval.metadata.get("recommended_commands"), list) else []
        approved_execution_plan = approval.metadata.get("execution_plan") if isinstance(approval.metadata.get("execution_plan"), dict) else {}
        if approval.decision != ApprovalDecision.APPROVED:
            raise ValueError("remediation requires an approved decision")
        if approval.approval_expires_at is None:
            raise ValueError("remediation requires an approval expiry")
        approval_expires_at = approval.approval_expires_at
        if approval_expires_at.tzinfo is None:
            raise ValueError("remediation approval expiry must include a timezone")
        if approval_expires_at <= utc_now():
            raise ValueError("remediation approval has expired")
        if approved_execution_plan.get("schema_version") != "kaims.execution-plan.v2":
            raise ValueError("remediation requires the exact approved kaims.execution-plan.v2 plan")
        if not verify_plan_fingerprint(approved_execution_plan):
            raise ValueError("remediation requires an unmodified kaims.execution-plan.v2 plan")
        if str(approved_execution_plan.get("tenant_id") or "") != approval.tenant_id:
            raise ValueError("approved execution plan tenant does not match approval tenant")
        if str(approved_execution_plan.get("plan_id") or "") != str(approval.plan_id or ""):
            raise ValueError("approved execution plan identity does not match approval")
        if str(approved_execution_plan.get("plan_fingerprint") or "") != str(approval.plan_fingerprint or ""):
            raise ValueError("approved execution plan fingerprint does not match approval")
        typed_actions = approved_execution_plan.get("actions")
        if not isinstance(typed_actions, list) or len(typed_actions) < 1 or not isinstance(typed_actions[0], dict):
            raise ValueError("remediation requires exactly one typed approved plan action")
        plan_commands = approved_execution_plan.get("commands") if isinstance(approved_execution_plan.get("commands"), list) else []
        plan_scripts = approved_execution_plan.get("scripts") if isinstance(approved_execution_plan.get("scripts"), list) else []
        plan_queries = approved_execution_plan.get("queries") if isinstance(approved_execution_plan.get("queries"), list) else []
        has_approved_execution_plan = isinstance(approval.metadata.get("execution_plan"), dict)
        command_list = self._sanitize_recommended_commands([
            *[str(item) for item in plan_commands],
            *[f"script: {item}" for item in plan_scripts],
            *[f"query: {item}" for item in plan_queries],
        ])
        action_type = self._action_type_from_plan(plan=approved_execution_plan)
        policy_version = str(approval.metadata.get("policy_version", "")).strip()
        policy_reason = str(approval.metadata.get("policy_reason", "")).strip()
        connection_profile = {**(approved_execution_plan.get("connection") if isinstance(approved_execution_plan.get("connection"), dict) else {}), **(approval.metadata.get("connection_profile") if isinstance(approval.metadata.get("connection_profile"), dict) else {})}

        def usable_target(value: Any) -> str:
            candidate = str(value or "").strip()
            if not candidate or candidate.lower() in {"-", "unknown", "unknown service", "not configured", "none", "null"}:
                return ""
            return candidate

        typed_action = typed_actions[0]
        target = usable_target(typed_action.get("target_resource_id"))
        if not target:
            raise ValueError("remediation requires the catalog action target_resource_id")
        if target != usable_target(approved_execution_plan.get("remediation_target")):
            raise ValueError("catalog action target does not match the approved plan target")
        service = usable_target(approved_execution_plan.get("service"))
        environment = str(approval.metadata.get("environment") or connection_profile.get("environment") or approved_execution_plan.get("environment") or "").strip()
        namespace = str(approval.metadata.get("namespace") or connection_profile.get("namespace") or approved_execution_plan.get("namespace") or "default").strip()
        if self._looks_like_uuid(target):
            raise ValueError("remediation target must be a catalog-bound resource, not an incident UUID")
        generated_execution_plan = self._build_execution_plan(
            action_type=action_type,
            target=target,
            service=service,
            environment=environment,
            namespace=namespace,
            recommended_action=recommended_action,
            recommended_commands=command_list,
        )
        requested_executor = str(
            connection_profile.get("executor_type")
            or connection_profile.get("connection_type")
            or os.getenv("REMEDIATION_DEFAULT_EXECUTOR", "")
        ).strip().lower()
        configured_default_executor = os.getenv("REMEDIATION_DEFAULT_EXECUTOR", "").strip().lower()
        if configured_default_executor == "azure_container_apps_job" and (
            not requested_executor or str(connection_profile.get("endpoint_url") or "").rstrip("/") == "http://jenkins:8080"
        ):
            requested_executor = "azure_container_apps_job"
        execution_platform = os.getenv("REMEDIATION_EXECUTION_PLATFORM", "kubernetes").strip().lower()
        stale_platform_plan = (
            execution_platform in {"docker", "docker-compose", "compose"}
            and any(
                str(item).strip().lower().startswith(("kubectl ", "ansible-playbook "))
                for item in plan_commands
            )
        )
        # A reviewed script-only plan is complete in its own execution domain.
        # Do not silently graft an inferred container restart and health check
        # onto it merely because its commands list is empty.
        use_generated_commands = False
        governed_generated_commands = [
            str(item).strip()
            for item in generated_execution_plan.get("commands", [])
            if str(item).strip()
            and not str(item).strip().lower().startswith("scripts/")
            and not str(item).strip().lower().endswith((".ps1", ".sh"))
        ]
        execution_plan = {
            "schema_version": "kaiops.remediation.v2",
            "commands": [
                str(item).strip()
                for item in (
                    governed_generated_commands
                    if use_generated_commands
                    else plan_commands if has_approved_execution_plan else generated_execution_plan.get("commands", [])
                )
                if str(item).strip()
            ],
            "scripts": [
                str(item).strip()
                for item in (
                    ([] if use_generated_commands else plan_scripts)
                    if has_approved_execution_plan
                    else generated_execution_plan.get("scripts", [])
                )
                if str(item).strip()
            ],
            "queries": [
                str(item).strip()
                for item in (
                    generated_execution_plan.get("queries", [])
                    if use_generated_commands
                    else plan_queries if has_approved_execution_plan else generated_execution_plan.get("queries", [])
                )
                if str(item).strip()
            ],
            "rollback": [
                str(item).strip()
                for item in (
                    approval.metadata.get("rollback_plan", [])
                    if isinstance(approval.metadata.get("rollback_plan"), list)
                    else [approval.metadata.get("rollback_plan")]
                )
                if str(item or "").strip()
            ],
            "preflight": [
                str(item).strip()
                for item in (
                    generated_execution_plan.get("preflight", [])
                    if use_generated_commands
                    else (
                        approved_execution_plan.get("preflight", []) or approved_execution_plan.get("preflight_commands", [])
                        if plan_scripts
                        else approved_execution_plan.get("preflight") or approved_execution_plan.get("preflight_commands") or generated_execution_plan.get("preflight", [])
                    )
                    if has_approved_execution_plan
                    else generated_execution_plan.get("preflight", [])
                )
                if str(item).strip()
            ],
            "validation_commands": [
                str(item).strip()
                for item in (
                    generated_execution_plan.get("validation_commands", [])
                    if use_generated_commands
                    else (
                        approved_execution_plan.get("validation_commands", [])
                        if plan_scripts
                        else approved_execution_plan.get("validation_commands") or generated_execution_plan.get("validation_commands", [])
                    )
                    if has_approved_execution_plan
                    else generated_execution_plan.get("validation_commands", [])
                )
                if str(item).strip()
            ],
            "rollback_commands": [
                str(item).strip()
                for item in (
                    generated_execution_plan.get("rollback_commands", [])
                    if use_generated_commands
                    else (
                        approved_execution_plan.get("rollback_commands", [])
                        if plan_scripts
                        else approved_execution_plan.get("rollback_commands") or generated_execution_plan.get("rollback_commands", [])
                    )
                    if has_approved_execution_plan
                    else generated_execution_plan.get("rollback_commands", [])
                )
                if str(item).strip()
            ],
            "rollback_mode": str(
                generated_execution_plan.get("rollback_mode")
                if use_generated_commands
                else approved_execution_plan.get("rollback_mode")
                or generated_execution_plan.get("rollback_mode")
                or "automatic"
            ).strip().lower(),
            "source_schema_version": str(approved_execution_plan.get("schema_version") or ""),
            "plan_fingerprint": str(approved_execution_plan.get("plan_fingerprint") or ""),
        }
        if approved_execution_plan.get("schema_version") == "kaims.execution-plan.v2":
            if not verify_plan_fingerprint(approved_execution_plan):
                raise ValueError("remediation requires an unmodified kaims.execution-plan.v2 plan")
            # Plugins consume the compatibility projections already present in
            # v2, so preserve the exact approved object and its fingerprint.
            execution_plan = dict(approved_execution_plan)
        supplied_profile = connection_profile
        default_executor = os.getenv("REMEDIATION_DEFAULT_EXECUTOR", "").strip().lower()
        if default_executor == "azure_container_apps_job" and (
            not requested_executor
            or str(supplied_profile.get("endpoint_url") or "").rstrip("/") == "http://jenkins:8080"
        ):
            connection_profile = {
                **supplied_profile,
                "connection_type": "azure_container_apps_job",
                "executor_type": "azure_container_apps_job",
                "identity_type": "managed_identity",
                "subscription_id": os.getenv("AZURE_SUBSCRIPTION_ID", "").strip(),
                "resource_group": os.getenv("AZURE_RESOURCE_GROUP", "").strip(),
                "job_name": os.getenv("REMEDIATION_ACA_JOB_NAME", "").strip(),
                "timeout_seconds": 900,
            }
            requested_executor = "azure_container_apps_job"
        elif default_executor == "jenkins":
            default_profile: dict[str, Any] = {
                "application": str(approval.metadata.get("application") or "KaiMS"),
                "service": service or "unknown",
                "environment": environment or "local",
                "namespace": namespace,
                "endpoint_url": os.getenv("REMEDIATION_JENKINS_URL", "http://jenkins:8080").strip(),
                "connection_type": "jenkins",
                "executor_type": "jenkins",
                "job_name": os.getenv("REMEDIATION_JENKINS_JOB", "kaiops-auto-remediation").strip(),
                "timeout_seconds": 1200,
                "credential_ref": os.getenv(
                    "REMEDIATION_JENKINS_CREDENTIAL_REF",
                    "vault://kaiops/local/jenkins#api-token",
                ).strip(),
            }
            connection_profile = {
                **default_profile,
                **{key: value for key, value in supplied_profile.items() if value not in (None, "")},
            }
        else:
            connection_profile = supplied_profile

        return RemediationAction(
            tenant_id=approval.tenant_id,
            incident_id=approval.incident_id,
            approval_id=approval.id,
            recommendation_id=approval.recommendation_id,
            resolution_plan_id=approval.plan_id,
            plan_fingerprint=approval.plan_fingerprint,
            action_type=action_type,
            target=target,
            parameters={
                "approved_by": approval.approver,
                "approval_expires_at": approval_expires_at.isoformat(),
                "channel": approval.channel,
                "policy_version": policy_version,
                "policy_reason": policy_reason,
                "service": service,
                "environment": environment,
                "recommended_action": recommended_action,
                "root_cause": str(approved_execution_plan.get("root_cause") or ""),
                "impact": str(approval.metadata.get("impact") or ""),
                "commands": command_list,
                "execution_plan": execution_plan,
                "connection_profile": connection_profile,
                "runbook_id": str(approval.metadata.get("runbook_id") or ""),
                "runbook_version": approval.metadata.get("runbook_version"),
                "runbook_status": str(approval.metadata.get("runbook_status") or ""),
                "runbook_checksum": str(approval.metadata.get("runbook_checksum") or ""),
                "runbook_match_score": approval.metadata.get("runbook_match_score"),
                "operator_modified": False,
                "approved_plan_id": str(approval.plan_id or ""),
                "approved_plan_fingerprint": str(approval.plan_fingerprint or ""),
                "recommendation_id": str(approval.recommendation_id),
                "resolution_lifecycle": extract_lifecycle(approval.metadata) or create_lifecycle(
                    tenant_id=approval.tenant_id,
                    incident_id=approval.incident_id,
                    recommendation_id=approval.recommendation_id,
                    plan=execution_plan,
                    state=ResolutionState.READY_TO_EXECUTE,
                ),
            },
            started_at=utc_now(),
            status=RemediationStatus.RUNNING,
        )

    def _build_execution_plan(
        self,
        *,
        action_type: str,
        target: str,
        service: str,
        environment: str,
        namespace: str,
        recommended_action: str,
        recommended_commands: list[str],
    ) -> dict[str, Any]:
        namespace = namespace or "default"
        resolved_target = target or service or "unknown-target"
        execution_platform = os.getenv("REMEDIATION_EXECUTION_PLATFORM", "kubernetes").strip().lower()
        if execution_platform in {"docker", "docker-compose", "compose"}:
            safe_service = re.sub(r"[^a-zA-Z0-9_.-]", "", service or resolved_target)
            # Monitoring/onboarding uses the product-qualified name for some
            # internal services, while Compose DNS and container names use the
            # canonical service key.
            internal_services = {
                "api-gateway", "approval-service", "closure-service", "context-agent",
                "discovery-mcp", "monitoring-adapter", "orchestrator", "remediation-engine",
                "resolution-agent",
            }
            unqualified_service = safe_service.removeprefix("kaiops-")
            if unqualified_service in internal_services:
                safe_service = unqualified_service
            compose_project = re.sub(
                r"[^a-zA-Z0-9_.-]", "",
                os.getenv("REMEDIATION_COMPOSE_PROJECT", "kaiops_azure"),
            )
            docker_plan = docker_compose_restart_plan(project=compose_project, service=safe_service)
            return {
                "schema_version": "kaiops.remediation.v2",
                "commands": [*docker_plan["commands"],
                    f"curl --fail --silent --show-error --retry 15 --retry-connrefused --retry-delay 2 http://{safe_service}:8000/healthz",
                ],
                "scripts": [],
                "queries": [f"http://{safe_service}:8000/healthz"],
                "preflight": docker_plan["preflight"],
                "validation_commands": [f"curl --fail --silent --show-error --retry 15 --retry-connrefused --retry-delay 2 http://{safe_service}:8000/healthz"],
                # A process restart has no meaningful inverse operation. Do
                # not label a read-only container inspection as a rollback.
                "rollback_commands": [],
                "rollback_mode": "not_applicable",
            }

        if action_type == "restart_pod":
            commands = [
                f"kubectl rollout restart deployment/{resolved_target} -n {namespace}",
                f"kubectl rollout status deployment/{resolved_target} -n {namespace} --timeout=180s",
            ]
            scripts = [
                f"scripts/remediation/restart_pod.ps1 -Service {resolved_target} -Namespace {namespace}",
            ]
            queries = [
                f"sum(rate(http_requests_total{{service='{resolved_target}',status=~'5..'}}[5m]))",
            ]
        elif action_type == "scale_deployment":
            commands = [
                f"kubectl scale deployment/{resolved_target} --replicas=3 -n {namespace}",
                f"kubectl rollout status deployment/{resolved_target} -n {namespace} --timeout=180s",
            ]
            scripts = [
                f"scripts/remediation/scale_deployment.ps1 -Service {resolved_target} -Namespace {namespace} -Replicas 3",
            ]
            queries = [
                f"avg_over_time(container_cpu_usage_seconds_total{{pod=~'{resolved_target}.*'}}[10m])",
            ]
        elif action_type == "restart_service":
            commands = [
                f"ansible-playbook playbooks/restart-service.yml -e service={resolved_target} -e env={namespace}",
            ]
            scripts = [
                f"scripts/remediation/restart_service.ps1 -Service {resolved_target} -Environment {namespace}",
            ]
            queries = [
                f"max_over_time(up{{job='{resolved_target}'}}[5m])",
            ]
        elif action_type == "clear_cache":
            commands = [
                f"redis-cli -h {resolved_target}-redis -n 0 FLUSHDB",
            ]
            scripts = [
                f"scripts/remediation/clear_cache.ps1 -Service {resolved_target}",
            ]
            queries = [
                f"sum(rate(cache_miss_total{{service='{resolved_target}'}}[5m]))",
            ]
        elif action_type == "failover_database":
            commands = [
                "mysql -e \"CALL mysql.rds_failover();\"",
            ]
            scripts = [
                "scripts/remediation/failover_database.ps1",
            ]
            queries = [
                "SHOW REPLICA STATUS;",
                f"sum(rate(mysql_global_status_queries{{service='{resolved_target}'}}[5m]))",
            ]
        elif action_type == "terraform_rollback":
            commands = [
                "terraform init",
                f"terraform apply -auto-approve -var service={resolved_target} -var rollback=true",
            ]
            scripts = [
                f"scripts/remediation/terraform_rollback.ps1 -Service {resolved_target} -Environment {namespace}",
            ]
            queries = [
                f"sum(rate(terraform_apply_failures_total{{service='{resolved_target}'}}[15m]))",
            ]
        else:
            commands = [
                f"kubectl rollout undo deployment/{resolved_target} -n {namespace}",
                f"kubectl rollout status deployment/{resolved_target} -n {namespace} --timeout=180s",
            ]
            scripts = [
                f"scripts/remediation/rollback_deployment.ps1 -Service {resolved_target} -Namespace {namespace}",
            ]
            queries = [
                f"sum(rate(http_requests_total{{service='{resolved_target}',status=~'5..'}}[5m]))",
            ]

        if recommended_commands:
            deduped = []
            seen = set()
            for item in [*recommended_commands, *commands]:
                key = str(item or "").strip().lower()
                if not key or key in seen:
                    continue
                seen.add(key)
                deduped.append(str(item).strip())
            commands = deduped
            if any("kaiops_alert_health_triage.sh" in str(item) for item in recommended_commands):
                scripts = [
                    str(item).replace("script:", "", 1).strip()
                    for item in recommended_commands
                    if "kaiops_alert_health_triage.sh" in str(item)
                ] or scripts

        return {
            "schema_version": "kaiops.remediation.v2",
            "commands": commands,
            "scripts": scripts,
            "queries": queries,
            "preflight": [
                f"kubectl get deployment {resolved_target} -n {namespace}",
                f"kubectl describe deployment {resolved_target} -n {namespace}",
            ],
            "validation_commands": [
                f"kubectl rollout status deployment/{resolved_target} -n {namespace} --timeout=180s",
            ],
            "rollback_commands": [
                f"kubectl rollout undo deployment/{resolved_target} -n {namespace}",
                f"kubectl rollout status deployment/{resolved_target} -n {namespace} --timeout=180s",
            ],
            "rollback_mode": "automatic",
        }

    async def execute(self, action: RemediationAction) -> RemediationAction:
        assessment = assess_execution_safety(action, allowlisted_actions=set(self.plugins))
        action.parameters["pre_execution_snapshot"] = assessment.snapshot
        action.parameters["pre_execution_snapshot_hash"] = assessment.snapshot_hash
        action.parameters["execution_idempotency_key"] = assessment.idempotency_key
        if assessment.decision == ExecutionSafetyDecision.BLOCK:
            action.status = RemediationStatus.SKIPPED
            action.error = assessment.reason
            action.output = "remediation blocked by execution safety controller"
            action.completed_at = utc_now()
            return action

        profile = action.parameters.get("connection_profile")
        profile = profile if isinstance(profile, dict) else {}
        executor_type = str(profile.get("executor_type") or profile.get("connection_type") or "").strip().lower()
        action_type = executor_type if executor_type in {"jenkins", "azure_container_apps_job"} else action.action_type
        action_type = str(action_type or "").strip().lower()
        if action_type not in self.tool_registry.tools:
            action.status = RemediationStatus.SKIPPED
            action.error = "ACTION_TYPE_NOT_REGISTERED"
            action.output = "remediation blocked by tool registry"
            action.completed_at = utc_now()
            return action
        try:
            payload = await self.tool_registry.execute(
                action_type,
                {"action": action.model_dump(mode="json")},
                role="automation-agent",
            )
            completed = RemediationAction.model_validate(payload)
            completed.completed_at = utc_now()
            return completed
        except Exception as exc:
            action.status = RemediationStatus.FAILED
            action.error = str(exc)
            action.completed_at = utc_now()
            return action

    async def dispatch(self, action: RemediationAction) -> RemediationAction:
        profile = action.parameters.get("connection_profile")
        profile = profile if isinstance(profile, dict) else {}
        executor_type = str(profile.get("executor_type") or profile.get("connection_type") or "").strip().lower()
        plugin = self.plugins.get(executor_type or action.action_type)
        if plugin is None:
            action.status = RemediationStatus.DISPATCH_FAILED
            action.error = f"No remediation adapter is registered for {executor_type or action.action_type}"
            return action
        dispatch = getattr(plugin, "dispatch", None)
        if callable(dispatch):
            return await dispatch(action)
        # Compatibility path for adapters not migrated to async reconciliation.
        return await self.execute(action)

    async def observe(self, action: RemediationAction) -> RemediationAction:
        result = action.parameters.get("execution_result")
        result = result if isinstance(result, dict) else {}
        executor = str(result.get("executor") or "").strip().lower()
        plugin = self.plugins.get(executor or action.action_type)
        observe = getattr(plugin, "observe", None) if plugin is not None else None
        if not callable(observe):
            return action
        return await observe(action)

    async def execute_from_context(self, context: AgentContext) -> RemediationAction:
        approval_payload = context.previous_agent_results.get("approval")
        if not isinstance(approval_payload, dict):
            raise ValueError("AgentContext.previous_agent_results['approval'] is required")
        action = self.build_action(Approval.model_validate(approval_payload))
        result = await self.execute(action)
        context.set_result("remediation-action", result.model_dump(mode="json"))
        return result

    async def validate(self, result: Any) -> bool:
        return isinstance(result, RemediationAction)
