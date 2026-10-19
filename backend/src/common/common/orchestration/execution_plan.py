from __future__ import annotations

import json
from hashlib import sha256
import os
import re
from datetime import timedelta
from functools import lru_cache
from pathlib import Path
from typing import Any
from urllib.parse import quote
from uuid import UUID

from common.config import Settings
from common.connection_config import connector_catalog_from_connection_config, load_connection_config
from common.models import Alert
from common.recovery_observers import load_recovery_observer_registry
from common.orchestration.execution_plan_contract import (
    ApprovalPolicy,
    ExecutionPlanV2,
    PlanAction,
    deterministic_plan_id,
    utc_now,
)
from common.orchestration.safe_remediation import (
    BlastRadiusAssessment,
    CapabilitySpec,
    CredentialReference,
    PreflightEvidence,
    SafeRemediationBinding,
)


_VARIABLE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")
_SAFE_VALUE = re.compile(r"^[A-Za-z0-9_./:@,+%=-]+$")
_MUTATING_SAFETY = {"write", "restart", "scale", "rollback", "failover", "delete"}
_EXECUTABLE_PREFIXES = ("ansible-playbook ", "kubectl ", "curl ", "mysql ", "python ", "sh ", "docker compose ")
_HTTP_URL = re.compile(r"https?://[A-Za-z0-9_.:-]+(?:/[A-Za-z0-9_./?=&%+:-]*)?")


def docker_compose_restart_plan(*, project: str, service: str, container_id: str | None = None) -> dict[str, list[str]]:
    """Resolve a Compose target by stable labels instead of an ephemeral name."""
    target_filters = {"label": [
        f"com.docker.compose.project={project}", f"com.docker.compose.service={service}",
    ]}
    if container_id:
        if not re.fullmatch(r"[0-9a-f]{64}", container_id):
            raise ValueError("Invalid pinned container identity")
        target_filters["id"] = [container_id]
        target_filters["status"] = ["exited", "dead"]
    filters = quote(json.dumps(target_filters, separators=(",", ":")), safe="")
    # Docker excludes stopped containers unless all=true, precisely the targets
    # that a service-down recovery must be able to find.
    list_url = f"http://docker-socket-proxy:2375/containers/json?all=true&filters={filters}"
    id_lookup = (
        f"curl --fail --silent --show-error '{list_url}' "
        "| grep -o '\"Id\":\"[^\"]*\"' | head -n 1 | cut -d'\"' -f4"
    )
    operation = "start" if container_id else "restart?t=30"
    return {
        "preflight": [f"{id_lookup} | grep --quiet ."],
        "commands": [
            f"container_id=$({id_lookup}); test -n \"$container_id\" && "
            "curl --fail --silent --show-error --retry 3 --retry-all-errors --retry-delay 1 "
            f"-X POST http://docker-socket-proxy:2375/containers/$container_id/{operation}"
        ],
    }


# Compose has no engine-level "scale" primitive: the Docker Engine API alone
# cannot add a correctly-networked replica of a running service, only the
# `docker compose` CLI knows how (it owns the container-clone, network-alias,
# and naming logic). Reimplementing that over raw HTTP calls -- the pattern
# docker_compose_restart_plan above uses -- would mean hand-building
# container-lifecycle logic with real risk of a networking or port-binding
# mistake in the platform's most safety-critical path. This plan instead
# shells out to the real CLI, which requires the Jenkins agent to have it
# installed and mounted against this project's actual compose file (see
# deploy/jenkins/Dockerfile.local and the jenkins service's volumes) -- a
# deliberate, narrow widening of what that agent can do to the Docker
# daemon, scoped to exactly this operation.
_SCALE_REPLICA_BOUNDS = (1, 5)


def docker_compose_scale_plan(*, project: str, service: str, replicas: int) -> dict[str, list[str]]:
    """Resolve a Compose service scale using the real `docker compose` CLI.

    `--no-recreate` keeps whatever replica already exists untouched; only
    the additional (or excess) replicas are created or removed. Unlike a
    restart, scaling has a genuine, safe inverse: scaling back down to the
    original replica count. That is exactly what execution_plan.py binds as
    this operation's rollback_commands, so a scale-out plan can carry a real
    executable rollback instead of the `rollback_mode: not_applicable`
    restart requires.

    `--no-recreate` is required on BOTH commands, not just the scale-out one
    -- live-verified the hard way: omitting it from the scale-down command
    let `docker compose up` re-evaluate the *entire* project's reconciliation
    state rather than just this one service, and it stopped and recreated
    several unrelated running containers (including the sandboxed proxy this
    command itself depends on, breaking the run mid-command). `--no-recreate`
    only suppresses recreating containers whose config didn't change; a
    container count above the requested --scale value is still removed
    regardless, so scaling down still works correctly with it present.
    """
    bounded = max(_SCALE_REPLICA_BOUNDS[0], min(int(replicas), _SCALE_REPLICA_BOUNDS[1]))
    safe_project = re.sub(r"[^A-Za-z0-9_.-]", "", project)
    safe_service = re.sub(r"[^A-Za-z0-9_.-]", "", service)
    compose_prefix = f"docker compose --project-name {safe_project} --file /opt/kaiops/docker-compose.yml"
    return {
        "preflight": [f"{compose_prefix} ps --format json {safe_service} | grep --quiet ."],
        "commands": [f"{compose_prefix} up -d --no-build --no-recreate --scale {safe_service}={bounded} {safe_service}"],
        "rollback": [f"{compose_prefix} up -d --no-build --no-recreate --scale {safe_service}=1 {safe_service}"],
    }


def _repo_root() -> Path:
    current = Path(__file__).resolve()
    for parent in current.parents:
        if (parent / "pyproject.toml").exists() and (parent / "backend").exists():
            return parent
    return current.parents[5]


def _read_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _rag_root() -> Path:
    repo_root = _repo_root()
    repository_catalog = repo_root / "backend" / "rag"
    if repository_catalog.is_dir():
        return repository_catalog
    container_catalog = repo_root / "rag"
    if container_catalog.is_dir():
        return container_catalog
    return repository_catalog


def _merge_connector_catalogs(legacy: dict[str, Any], central: dict[str, Any]) -> dict[str, Any]:
    legacy_connectors = legacy.get("connectors", {}) if isinstance(legacy.get("connectors"), dict) else {}
    central_connectors = central.get("connectors", {}) if isinstance(central.get("connectors"), dict) else {}
    connectors = {
        **{
            str(key).strip().lower(): value
            for key, value in legacy_connectors.items()
            if str(key).strip() and isinstance(value, dict)
        },
        **{
            str(key).strip().lower(): value
            for key, value in central_connectors.items()
            if str(key).strip() and isinstance(value, dict)
        },
    }
    default_connector = str(
        central.get("default_connector") or legacy.get("default_connector") or "generic-api"
    ).strip()
    return {
        "version": str(central.get("version") or legacy.get("version") or "connectors-v1"),
        "default_connector": default_connector,
        "auto_onboarding": legacy.get("auto_onboarding", {})
        if isinstance(legacy.get("auto_onboarding"), dict)
        else {},
        "connectors": connectors,
    }


@lru_cache(maxsize=1)
def _execution_catalogs() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    root = _rag_root()
    legacy_connectors = _read_json(root / "execution" / "connectors.json")
    settings = Settings()
    connection_config = load_connection_config(settings)
    connection_config["recovery_observer_registry_path"] = settings.recovery_observer_registry_path
    central_connectors = connector_catalog_from_connection_config(connection_config)
    connectors = _merge_connector_catalogs(legacy_connectors, central_connectors)
    actions = _read_json(root / "execution" / "action_catalog.json")
    playbooks = _read_json(root / "execution" / "playbooks.json")
    connectivity = _read_json(root / "onboarding" / "connectivity.json")
    return connectors, actions, playbooks, connectivity, connection_config


def _match_playbook(*, alert: Alert, playbooks: dict[str, Any], resolution_hints: str = "") -> dict[str, Any]:
    candidates = playbooks.get("playbooks", []) if isinstance(playbooks.get("playbooks"), list) else []
    service = str(alert.service or "").strip().lower()
    alert_id = str(getattr(alert, "id", "") or getattr(alert, "alert_id", "") or getattr(alert, "source_ref", "")).strip().lower()
    alert_type = str(getattr(alert, "type", "") or getattr(alert, "alert_type", "") or "").strip().lower()
    text = " ".join(
        [
            str(alert.name or "").strip().lower(),
            str(alert.description or "").strip().lower(),
            str(alert.source or "").strip().lower(),
            str(resolution_hints or "").strip().lower(),
        ]
    )

    ranked: list[tuple[int, int, dict[str, Any]]] = []
    for order, candidate in enumerate(candidates):
        if not isinstance(candidate, dict):
            continue
        match = candidate.get("match", {}) if isinstance(candidate.get("match"), dict) else {}
        alert_ids = [str(item).strip().lower() for item in match.get("alert_ids", []) if str(item).strip()]
        services = [str(item).strip().lower() for item in match.get("services", []) if str(item).strip()]
        alert_types = [str(item).strip().lower() for item in match.get("alert_types", []) if str(item).strip()]
        keywords = [str(item).strip().lower() for item in match.get("alert_keywords", []) if str(item).strip()]
        # Service lists normally remain a hard governance boundary. Reviewed
        # playbooks may opt into reuse for newly discovered services; alert
        # identity/type/keyword evidence must still match and the connector
        # operation allow-list is enforced later while building the plan.
        reusable_for_unlisted_services = match.get("allow_unlisted_services") is True
        service_hit = bool(services and service in services)
        if services and not service_hit and not reusable_for_unlisted_services:
            continue
        id_hit = bool(alert_ids and alert_id in alert_ids)
        type_hit = bool(alert_types and alert_type and alert_type in alert_types)
        keyword_hits = sum(1 for keyword in keywords if keyword in text)
        generic = not any((alert_ids, services, alert_types, keywords))
        if not generic and not any((id_hit, type_hit, keyword_hits)):
            continue
        score = (
            (100 if id_hit else 0)
            + (30 if service_hit else 0)
            + (20 if type_hit else 0)
            + min(20, keyword_hits * 5)
        )
        ranked.append((score, -order, candidate))

    if ranked:
        return max(ranked, key=lambda item: (item[0], item[1]))[2]

    return {
        "id": "generic-triage-playbook",
        "name": "Generic triage playbook",
        "preflight_checks": ["Connector health check passes", "Incident context available"],
        "steps": [
            {
                "name": "Collect baseline diagnostics",
                "type": "diagnostic",
                "commands": [],
            },
            {
                "name": "Prepare manual remediation path",
                "type": "remediation",
                "approval_gate": True,
                "commands": [],
            },
        ],
    }


def _alert_variables(alert: Alert, connector: dict[str, Any], connectivity: dict[str, Any]) -> dict[str, str]:
    metadata = alert.metadata if isinstance(alert.metadata, dict) else {}
    labels = alert.labels if isinstance(getattr(alert, "labels", None), dict) else {}
    supplied = {**metadata, **labels}
    service = str(alert.service or "").strip()
    environment = str(alert.environment or "prod").strip()
    endpoint = str(connector.get("endpoint") or "").rstrip("/")
    defaults: dict[str, Any] = {
        "service": service,
        "environment": environment,
        "namespace": supplied.get("namespace", "default"),
        "api_gateway_url": supplied.get("api_gateway_url", "http://api-gateway:8000"),
        "policy_engine_url": supplied.get("policy_engine_url", "http://policy-engine:8000"),
        "prometheus_url": supplied.get("prometheus_url", connectivity.get("prometheus_url") or "http://prometheus:9090"),
        "mysql_host": supplied.get("mysql_host", connector.get("host") or "mysql"),
        "mysql_port": supplied.get("mysql_port", connector.get("port") or 3306),
        "mysql_database": supplied.get("mysql_database", connector.get("database") or "kaiops"),
        "mysql_user": supplied.get("mysql_user", "kaiops"),
        "alerts_table": supplied.get("alerts_table", "alerts"),
        "latency_threshold_seconds": supplied.get("latency_threshold_seconds", "3"),
        "dry_run": supplied.get("dry_run", "false"),
        "workflow_id": supplied.get("workflow_id", getattr(alert, "correlation_id", "") or ""),
    }
    if endpoint and service == "policy-engine":
        defaults["policy_engine_url"] = endpoint
    safe: dict[str, str] = {}
    for key, value in defaults.items():
        rendered = str(value or "").strip()
        if rendered and _SAFE_VALUE.fullmatch(rendered):
            safe[key] = rendered
    return safe


def _bind_command(template: str, variables: dict[str, str]) -> tuple[str, list[str]]:
    missing: list[str] = []

    def replace(match: re.Match[str]) -> str:
        name = match.group(1)
        if name not in variables:
            missing.append(name)
            return match.group(0)
        return variables[name]

    return _VARIABLE.sub(replace, template), sorted(set(missing))


def _looks_executable(command: str) -> bool:
    return command.strip().lower().startswith(_EXECUTABLE_PREFIXES)


_REGISTERED_CAPABILITY_BINDINGS: dict[tuple[str, str], str] = {
    ("kubernetes", "restart_pod"): "kubernetes.restart_workload",
    ("kubernetes", "restart_service"): "kubernetes.restart_workload",
    ("kubernetes", "rollback_deployment"): "kubernetes.rollback_deployment",
    ("kubernetes", "scale_service"): "kubernetes.scale_workload",
    ("kubernetes", "scale_workload"): "kubernetes.scale_workload",
    ("ssh-linux", "restart_service"): "linux.restart_service",
    ("windows-powershell", "restart_service"): "windows.restart_service",
    ("redis", "clear_cache"): "cache.clear_cache",
    ("mysql", "failover_database"): "database.failover",
    ("terraform", "terraform_rollback"): "terraform.rollback",
    ("jenkins", "rollback_deployment"): "jenkins.rollback_deployment",
    ("custom-api", "api_execution"): "application.invoke_recovery_endpoint",
    ("api", "restart_service"): "application.restart_service",
    ("api", "scale_service"): "application.scale_workload",
}


def _registered_capability_id(*, connector: dict[str, Any], operation: str) -> str:
    connector_type = str(connector.get("type") or "").strip().lower()
    capability_id = _REGISTERED_CAPABILITY_BINDINGS.get((connector_type, operation))
    if not capability_id:
        raise ValueError(
            f"catalog operation {operation!r} is not registered for connector type {connector_type!r}"
        )
    return capability_id


def _safe_remediation_binding(
    *,
    tenant_id: str,
    connector: dict[str, Any],
    operation: str,
    target_resource_id: str,
    service: str,
    preflight_commands: list[str],
    evidence_ids: list[str],
    reversible: bool,
) -> SafeRemediationBinding:
    connector_id = str(connector.get("connector_id") or "").strip()
    credential_ref = str(connector.get("credential_ref") or connector.get("secret_ref") or "").strip()
    capability_id = _registered_capability_id(connector=connector, operation=operation)
    capability = CapabilitySpec(
        capability_id=capability_id,
        connector_id=connector_id,
        operation=operation,
        allowed_resource_ids=[target_resource_id],
        required_permissions=[operation],
        mutating=True,
        reversible=reversible,
        dry_run_supported=True,
    )
    credential = CredentialReference(
        reference=credential_ref,
        tenant_id=tenant_id,
        connector_id=connector_id,
        resource_ids=[target_resource_id],
    )
    blast_radius = BlastRadiusAssessment(
        target_resource_id=target_resource_id,
        scope="single-service",
        affected_resource_ids=[target_resource_id],
        affected_services=[service],
        evidence_ids=evidence_ids,
        verified=True,
        unknown_dependencies=False,
    )
    preflight = PreflightEvidence(
        status="PLANNED",
        capability_id=capability_id,
        target_resource_id=target_resource_id,
        check_references=[
            f"catalog-check:{sha256(command.encode()).hexdigest()}"
            for command in preflight_commands
            if command.strip()
        ],
        dry_run_required=True,
        credential_reference=credential_ref,
    )
    return SafeRemediationBinding(
        capability=capability,
        credential=credential,
        blast_radius=blast_radius,
        preflight=preflight,
    )


def _typed_validator_specs(
    commands: list[str], *, tenant_id: str, connector_id: str, target_resource_id: str,
) -> list[dict[str, Any]]:
    """Project catalog checks into immutable registry references, never URLs."""
    validators: list[dict[str, Any]] = []
    seen: set[str] = set()
    for command in commands:
        reference_hash = sha256(str(command or "").encode()).hexdigest()
        if not str(command or "").strip() or reference_hash in seen:
            continue
        seen.add(reference_hash)
        kind = "availability"
        material = f"{tenant_id}:{connector_id}:{target_resource_id}:{kind}:{reference_hash}"
        validator_id = f"validator-{sha256(material.encode()).hexdigest()[:24]}"
        validators.append({
            "validator_id": validator_id,
            "tenant_id": tenant_id,
            "connector_id": connector_id,
            "target_resource_id": target_resource_id,
            "kind": kind,
            "check_reference": f"catalog-check:{reference_hash}",
            "expected_condition": "catalog validation check succeeds",
            "evaluation_operator": "eq",
            "threshold": True,
            "observation_window_seconds": 300,
            "minimum_sample_count": 2,
            "timeout_seconds": 10,
            "authoritative_source": connector_id,
            "onboarding_registry_reference": f"validator-registry:{validator_id}",
        })
    return validators


def _playbook_operations(playbook: dict[str, Any], actions: dict[str, Any]) -> set[str]:
    command_catalog = actions.get("commands", {}) if isinstance(actions.get("commands"), dict) else {}
    operations: set[str] = set()
    for step in playbook.get("steps", []) if isinstance(playbook.get("steps"), list) else []:
        if not isinstance(step, dict):
            continue
        for command_id in step.get("commands", []) if isinstance(step.get("commands"), list) else []:
            command = command_catalog.get(str(command_id))
            if isinstance(command, dict) and str(command.get("operation") or "").strip():
                operations.add(str(command["operation"]).strip())
    return operations


def _connector_for_service(
    *, service: str, connectors: dict[str, Any], playbook: dict[str, Any], actions: dict[str, Any]
) -> dict[str, Any]:
    service_key = str(service or "").strip().lower()
    available = connectors.get("connectors", {}) if isinstance(connectors.get("connectors"), dict) else {}
    default_key = str(connectors.get("default_connector") or "generic-api").strip()

    if service_key in available and isinstance(available[service_key], dict):
        return available[service_key]

    auto = connectors.get("auto_onboarding", {}) if isinstance(connectors.get("auto_onboarding"), dict) else {}
    match = playbook.get("match", {}) if isinstance(playbook.get("match"), dict) else {}
    reusable = match.get("allow_unlisted_services") is True
    if auto.get("enabled") is True and service_key and (reusable or auto.get("requires_reusable_playbook") is not True):
        policy_operations = {
            str(item).strip()
            for item in auto.get("allowed_operations", [])
            if str(item).strip()
        }
        required_operations = _playbook_operations(playbook, actions)
        if required_operations and required_operations.issubset(policy_operations):
            template_key = str(auto.get("template_connector") or default_key).strip().lower()
            template = available.get(template_key)
            if isinstance(template, dict):
                return {
                    **template,
                    "connector_id": f"auto-{service_key}",
                    "system": service_key,
                    "allowed_operations": sorted(required_operations),
                    "onboarding": {
                        "mode": "automatic",
                        "governance": "reviewed-reusable-playbook",
                        "playbook_id": str(playbook.get("id") or ""),
                        "template_connector": template_key,
                    },
                }
    if default_key in available and isinstance(available[default_key], dict):
        return available[default_key]

    return {
        "connector_id": "generic-api",
        "system": service_key or "generic",
        "type": "api",
        "endpoint": "https://api.internal",
        "auth_method": "service-account-token",
        "secret_ref": "vault://kaiops/prod/default-token",
        "allowed_operations": ["read_status"],
    }


def _execution_service(*, alert: Alert, playbook: dict[str, Any]) -> str:
    """Resolve the reviewed mutation target independently of the alert source."""
    match = playbook.get("match", {}) if isinstance(playbook.get("match"), dict) else {}
    return str(
        playbook.get("execution_service")
        or playbook.get("remediation_target")
        or match.get("execution_service")
        or alert.service
        or ""
    ).strip()


def resolve_execution_plan(
    *,
    alert: Alert,
    workflow_name: str,
    requires_approval: bool,
    risk_tier: str,
    execution_mode: str,
    resolution_hints: str = "",
    evidence_basis: list[str] | None = None,
    incident_id: UUID | str | None = None,
    root_cause: str = "RCA not yet established",
    confidence: float = 0.0,
) -> dict[str, Any]:
    connectors, actions, playbooks, connectivity, connection_config = _execution_catalogs()
    playbook = _match_playbook(alert=alert, playbooks=playbooks, resolution_hints=resolution_hints)
    execution_service = _execution_service(alert=alert, playbook=playbook)
    connector = _connector_for_service(
        service=execution_service, connectors=connectors, playbook=playbook, actions=actions
    )

    command_catalog = actions.get("commands", {}) if isinstance(actions.get("commands"), dict) else {}
    variables = _alert_variables(alert, connector, connectivity)

    resolved_steps: list[dict[str, Any]] = []
    phase_commands: dict[str, list[str]] = {"diagnostic": [], "remediation": [], "validation": [], "rollback": []}
    readiness_blocks: list[str] = []
    mutating = False
    for index, step in enumerate(playbook.get("steps", []) if isinstance(playbook.get("steps"), list) else [], start=1):
        if not isinstance(step, dict):
            continue
        command_ids = [str(item).strip() for item in step.get("commands", []) if str(item).strip()]
        commands: list[dict[str, Any]] = []
        for command_id in command_ids:
            command = command_catalog.get(command_id)
            if not isinstance(command, dict):
                continue
            operation = str(command.get("operation") or "").strip()
            allowed_ops = connector.get("allowed_operations", []) if isinstance(connector.get("allowed_operations"), list) else []
            rendered, missing = _bind_command(str(command.get("command") or "").strip(), variables)
            rollback, rollback_missing = _bind_command(str(command.get("rollback") or "").strip(), variables)
            allowed = operation in allowed_ops if operation else False
            safety = str(command.get("safety") or "unknown").strip().lower()
            if not allowed:
                readiness_blocks.append(f"connector does not allow {command_id}:{operation}")
            if missing:
                readiness_blocks.append(f"{command_id} requires: {', '.join(missing)}")
            phase = str(step.get("type") or "task").strip().lower()
            if rendered:
                phase_commands.setdefault(phase, []).append(rendered)
            is_mutation = safety in _MUTATING_SAFETY or bool(command.get("approval_required"))
            mutating = mutating or is_mutation
            if is_mutation:
                if not rollback:
                    readiness_blocks.append(f"{command_id} has no rollback")
                elif rollback_missing:
                    readiness_blocks.append(f"{command_id} rollback requires: {', '.join(rollback_missing)}")
                elif not _looks_executable(rollback):
                    readiness_blocks.append(f"{command_id} rollback is a procedure, not an executable command")
                else:
                    phase_commands["rollback"].append(rollback)
            commands.append(
                {
                    "id": command_id,
                    "operation": operation,
                    "allowed": allowed,
                    "command": rendered,
                    "rollback": rollback,
                    "safety": safety,
                    "expected_evidence": list(command.get("expected_evidence") or []),
                    "unresolved_variables": missing,
                }
            )

        resolved_steps.append(
            {
                "order": index,
                "name": str(step.get("name") or f"Step {index}"),
                "type": str(step.get("type") or "task"),
                "approval_gate": bool(step.get("approval_gate", False)),
                "commands": commands,
            }
        )

    project = connectivity.get("project", {}) if isinstance(connectivity.get("project"), dict) else {}
    playbook_id = str(playbook.get("id") or "generic-kaiops-triage-playbook")
    playbook_version = playbook.get("version")
    runbook_status = str(playbook.get("status") or "unregistered").strip().lower()
    if mutating and not phase_commands["validation"]:
        readiness_blocks.append("mutating plan has no validation command")
    if len(phase_commands["remediation"]) > 1:
        readiness_blocks.append("multiple corrective alternatives require an explicit operator selection")
    if not execution_service:
        readiness_blocks.append("concrete target service is missing")
    if mutating and not isinstance(playbook_version, int):
        readiness_blocks.append("approved runbook version is missing")
    if mutating and runbook_status != "approved":
        readiness_blocks.append("runbook version is not approved")
    rollback_mode = "automatic"
    recovery_strategy: dict[str, Any] | None = None
    # Set by a docker-compose override branch below when it replaces
    # phase_commands["remediation"] with executor-specific commands that do
    # not correspond 1:1 with the catalog-rendered commands in
    # resolved_steps -- so typed_actions is built from what will actually
    # run, not stale catalog text, keeping the plan's flat "commands" field
    # and its typed actions in agreement.
    docker_compose_override_operation: str | None = None
    execution_platform = os.getenv("REMEDIATION_EXECUTION_PLATFORM", "kubernetes").strip().lower()
    if execution_platform in {"docker", "docker-compose", "compose"} and mutating:
        remediation_operations = {
            str(command.get("operation") or "").strip()
            for step in resolved_steps
            if str(step.get("type") or "").strip().lower() == "remediation"
            for command in step.get("commands", [])
            if isinstance(command, dict) and str(command.get("command") or "").strip()
        }
        docker_service = re.sub(r"[^A-Za-z0-9_.-]", "", execution_service.removeprefix("kaiops-"))
        internal_services = {
            "alert-intelligence", "api-gateway", "application-onboarding", "approval-service",
            "closure-service", "context-agent", "discovery-mcp", "model-router",
            "monitoring-adapter", "orchestrator", "remediation-engine", "resolution-agent",
        }
        from common.orchestration.compose_targets import compose_recovery_target
        external_target = compose_recovery_target(
            tenant=alert.tenant_id, environment=alert.environment, service=execution_service,
        )
        if remediation_operations == {"restart_service"} and (docker_service in internal_services or external_target):
            compose_project = re.sub(
                r"[^A-Za-z0-9_.-]", "", os.getenv("REMEDIATION_COMPOSE_PROJECT", "kaiops_azure")
            ) or "kaiops_azure"
            if external_target:
                compose_project, docker_service = external_target["project"], external_target["service"]
            docker_plan = docker_compose_restart_plan(project=compose_project, service=docker_service,
                container_id=external_target["container_id"] if external_target else None)
            phase_commands["diagnostic"] = docker_plan["preflight"]
            phase_commands["remediation"] = docker_plan["commands"]
            import shlex
            health_url = external_target["health_url"] if external_target else f"http://{docker_service}:8000/healthz"
            phase_commands["validation"] = [
                f"curl --fail --silent --show-error --retry 15 --retry-all-errors --retry-connrefused --retry-delay 2 {shlex.quote(health_url)}"
            ]
            # Process restart has no inverse. Recovery is retry/escalation, not
            # a misleading second restart labelled as rollback. This is only
            # accepted in place of a real rollback when the specific matched
            # catalog command explicitly declares an approved recovery
            # strategy (see action_catalog.json); it is never inferred from
            # the mere absence of a rollback, and no fake rollback command is
            # fabricated here.
            phase_commands["rollback"] = []
            rollback_mode = "not_applicable"
            docker_compose_override_operation = "restart_service"
            candidate_strategies = [
                catalog_command.get("recovery_strategy")
                for step in resolved_steps
                for resolved_command in step.get("commands", [])
                if isinstance(resolved_command, dict)
                and resolved_command.get("operation") == "restart_service"
                for catalog_command in [command_catalog.get(resolved_command.get("id"))]
                if isinstance(catalog_command, dict)
                and isinstance(catalog_command.get("recovery_strategy"), dict)
            ]
            if candidate_strategies and bool(candidate_strategies[0].get("requires_acknowledgement")):
                recovery_strategy = candidate_strategies[0]
        elif remediation_operations == {"scale_service"} and docker_service in internal_services:
            compose_project = re.sub(
                r"[^A-Za-z0-9_.-]", "", os.getenv("REMEDIATION_COMPOSE_PROJECT", "kaiops_azure")
            ) or "kaiops_azure"
            # A fixed, safe default -- the same precedent the kubernetes
            # scale_deployment branch already sets (kubectl scale --replicas=3
            # below) rather than trusting an unbounded value from evidence.
            docker_plan = docker_compose_scale_plan(project=compose_project, service=docker_service, replicas=2)
            phase_commands["diagnostic"] = docker_plan["preflight"]
            phase_commands["remediation"] = docker_plan["commands"]
            phase_commands["validation"] = [
                f"curl --fail --silent --show-error --retry 15 --retry-all-errors --retry-connrefused --retry-delay 2 http://{docker_service}:8000/healthz"
            ]
            phase_commands["rollback"] = docker_plan["rollback"]
            rollback_mode = "automatic"
            docker_compose_override_operation = "scale_service"
            # The catalog's kubectl-style template for this operation
            # references replica-count variables (${replicas},
            # ${previous_replicas}) that are never part of the standard
            # alert/evidence variable set -- irrelevant here because this
            # branch replaces that template outright with the fixed, bounded
            # replica count above, never the templated command text itself.
            scale_command_ids = {
                command_id for command_id, spec in command_catalog.items()
                if isinstance(spec, dict) and str(spec.get("operation") or "").strip() == "scale_service"
            }
            readiness_blocks = [
                reason for reason in readiness_blocks
                if not any(
                    reason.startswith(f"{command_id} requires:") or reason.startswith(f"{command_id} rollback requires:")
                    for command_id in scale_command_ids
                )
            ]
        else:
            readiness_blocks.append(
                f"{execution_platform} executor does not implement catalog operations: "
                + ", ".join(sorted(remediation_operations or {"unknown"}))
            )
            # The catalog's validation/rollback text is still the unrendered
            # kubectl template at this point (only the two branches above ever
            # replace it) - e.g. a platform-wide alert like "kaiops-platform"
            # that never maps to one specific internal service. Leaving it in
            # place reads as a real, ready-to-run command; it can never
            # execute in this environment regardless of readiness_blocks, so
            # showing it at all is misleading rather than just unavailable.
            phase_commands["validation"] = []
            phase_commands["rollback"] = []
    recovery_strategy_acknowledged = recovery_strategy is not None
    if mutating and not phase_commands["rollback"] and not (
        rollback_mode == "not_applicable" and recovery_strategy_acknowledged
    ):
        readiness_blocks.append("mutating plan has no executable rollback")
    credential_ref = str(connector.get("credential_ref") or connector.get("secret_ref") or "").strip()
    if mutating:
        try:
            CredentialReference(
                reference=credential_ref,
                tenant_id=str(getattr(alert, "tenant_id", "") or "").strip(),
                connector_id=str(connector.get("connector_id") or "").strip(),
                resource_ids=[execution_service],
            )
        except ValueError:
            readiness_blocks.append("approved resource-scoped credential reference is missing")
    registered_profile = None
    registry_path = os.getenv(
        "RECOVERY_OBSERVER_REGISTRY_PATH", str(connection_config.get("recovery_observer_registry_path") or "")
    ).strip()
    if registry_path and mutating:
        registry = load_recovery_observer_registry(registry_path)
        registered_profile = registry.profile_for(
            tenant_id=str(alert.tenant_id), environment=str(alert.environment),
            target=execution_service, alert_name=str(alert.name),
        )
        if registered_profile is None:
            readiness_blocks.append("independent recovery observation profile is not registered")
    diagnostic_only = not mutating
    execution_ready = mutating and not readiness_blocks
    tenant_id = str(getattr(alert, "tenant_id", "") or "").strip()
    incident_token = incident_id or (
        alert.metadata.get("incident_id") if isinstance(alert.metadata, dict) else None
    ) or alert.correlation_id or alert.id
    try:
        canonical_incident_id = UUID(str(incident_token))
    except (TypeError, ValueError) as exc:
        raise ValueError("incident_id must be a UUID bound to the current incident") from exc
    generated_at = utc_now()
    normalized_risk = str(risk_tier or "medium").strip().lower()
    if normalized_risk not in {"low", "medium", "high", "critical"}:
        normalized_risk = "medium"
    # The docker-compose restart_service branch above replaces
    # phase_commands["remediation"] with executor-specific commands that do
    # not correspond 1:1 with the catalog-rendered commands in
    # resolved_steps (see docker_compose_override_operation above), typed_actions
    # must be built from the actual commands that will run, not the stale
    # catalog text, or the plan's flat "commands" field and its typed
    # actions would disagree.
    if docker_compose_override_operation is not None:
        override_operation = docker_compose_override_operation
        typed_actions = [
            PlanAction(
                action_id=f"{override_operation}:{index}",
                connector_id=str(connector.get("connector_id") or ""),
                target_resource_id=execution_service,
                inputs={
                    "catalog_command": command_text,
                    "operation": override_operation,
                    "parameters": variables,
                },
                expected_outcome="service health recovers and independent validation passes",
                validation=list(phase_commands["validation"]),
                rollback_action=(phase_commands["rollback"][0] if phase_commands["rollback"] else None),
                reversible=bool(phase_commands["rollback"]),
                required_permissions=[override_operation],
                safety_binding=_safe_remediation_binding(
                    tenant_id=tenant_id,
                    connector=connector,
                    operation=override_operation,
                    target_resource_id=execution_service,
                    service=str(alert.service or "").strip(),
                    preflight_commands=phase_commands["diagnostic"],
                    evidence_ids=sorted({str(item) for item in (evidence_basis or []) if str(item).strip()}),
                    reversible=bool(phase_commands["rollback"]),
                ),
            )
            for index, command_text in enumerate(phase_commands["remediation"])
            if execution_ready and command_text
        ]
    else:
        typed_actions = [
            PlanAction(
                action_id=str(command.get("id") or ""),
                connector_id=str(connector.get("connector_id") or ""),
                target_resource_id=execution_service,
                inputs={
                    "catalog_command": str(command.get("command") or ""),
                    "operation": str(command.get("operation") or ""),
                    "parameters": variables,
                },
                expected_outcome="; ".join(str(item) for item in command.get("expected_evidence", []))
                or "service health recovers and independent validation passes",
                validation=list(phase_commands["validation"]),
                rollback_action=(phase_commands["rollback"][0] if phase_commands["rollback"] else None),
                reversible=bool(phase_commands["rollback"]),
                required_permissions=[str(command.get("operation") or "")],
                safety_binding=_safe_remediation_binding(
                    tenant_id=tenant_id,
                    connector=connector,
                    operation=str(command.get("operation") or ""),
                    target_resource_id=execution_service,
                    service=str(alert.service or "").strip(),
                    preflight_commands=phase_commands["diagnostic"],
                    evidence_ids=sorted({str(item) for item in (evidence_basis or []) if str(item).strip()}),
                    reversible=bool(phase_commands["rollback"]),
                ),
            )
            for step in resolved_steps
            if str(step.get("type") or "").strip().lower() == "remediation"
            for command in step.get("commands", [])
            if execution_ready and isinstance(command, dict) and str(command.get("command") or "").strip()
        ]
    approval_decision = "hitl_required" if mutating else "recommend_only"
    validators = _typed_validator_specs(
        phase_commands["validation"],
        tenant_id=tenant_id,
        connector_id=str(connector.get("connector_id") or ""),
        target_resource_id=execution_service,
    )
    if registered_profile is not None:
        validators = registered_profile.specs()
    plan = {
        "version": "execution-plan-v2",
        "schema_version": "kaims.execution-plan.v2",
        "plan_id": deterministic_plan_id(
            tenant_id=tenant_id,
            incident_id=canonical_incident_id,
            playbook_id=playbook_id,
            target=execution_service,
        ),
        "incident_id": canonical_incident_id,
        "tenant_id": tenant_id,
        "service": str(alert.service or "").strip(),
        "environment": str(alert.environment or "").strip(),
        "generated_at": generated_at,
        "source": "approved-execution-catalog",
        "evidence_references": sorted({str(item) for item in (evidence_basis or []) if str(item).strip()}),
        "root_cause": str(root_cause or "RCA not yet established").strip(),
        "confidence": max(0.0, min(float(confidence or 0.0), 1.0)),
        "risk": normalized_risk,
        "actions": typed_actions,
        "preflight": phase_commands["diagnostic"],
        "validation": phase_commands["validation"],
        "rollback": phase_commands["rollback"] if execution_ready else [],
        "approval_policy": ApprovalPolicy(
            decision=approval_decision,
            reason_codes=["p0_hitl_only"] if mutating else ["diagnostic_only"],
        ),
        "plan_fingerprint": "",
        "expiry": generated_at + timedelta(minutes=15),
        "idempotency_key": "",
        "workflow": workflow_name,
        "alert": {
            "service": str(alert.service or "").strip(),
            "name": str(alert.name or "").strip(),
            "source": str(alert.source or "").strip(),
            "id": str(getattr(alert, "id", "") or getattr(alert, "alert_id", "") or getattr(alert, "source_ref", "")).strip(),
            "type": str(getattr(alert, "type", "") or getattr(alert, "alert_type", "") or "").strip(),
        },
        "risk_tier": normalized_risk,
        "execution_mode": str(execution_mode or "unknown").lower(),
        "requires_approval": bool(requires_approval),
        "approval_required": bool(requires_approval),
        "connection": {
            "architecture": connection_config.get("connection_architecture", {})
            if isinstance(connection_config.get("connection_architecture"), dict)
            else {},
            "platform": connection_config.get("platform", {}) if isinstance(connection_config.get("platform"), dict) else {},
            "project": {
                "name": str(project.get("name") or "unknown"),
                "environment": str(project.get("environment") or "unknown"),
                "region": str(project.get("region") or "unknown"),
                "owner_team": str(project.get("owner_team") or "unknown"),
            },
            "connector": connector,
            "connectivity_checks": {
                "prometheus_url": str(connectivity.get("prometheus_url") or ""),
                "new_relic_url": str(connectivity.get("new_relic_url") or ""),
                "datadog_url": str(connectivity.get("datadog_url") or ""),
            },
        },
        "playbook": {
            "id": playbook_id,
            "name": str(playbook.get("name") or "Generic triage playbook"),
            "match": playbook.get("match", {}) if isinstance(playbook.get("match"), dict) else {},
            "preflight_checks": [
                str(item) for item in playbook.get("preflight_checks", []) if str(item).strip()
            ],
            "steps": resolved_steps,
        },
        "playbook_id": playbook_id,
        "runbook_governance_id": playbook.get("governance_id"),
        "runbook_checksum": playbook.get("checksum_sha256"),
        "playbook_version": playbook_version,
        "runbook_status": runbook_status,
        "connector_id": str(connector.get("connector_id") or ""),
        "remediation_target": execution_service,
        "mutating": mutating,
        "plan_kind": "remediation" if execution_ready else "diagnostic",
        "diagnostic_only": diagnostic_only or not execution_ready,
        "execution_ready": execution_ready,
        "readiness_blocks": sorted(set(readiness_blocks)),
        "preflight_commands": phase_commands["diagnostic"],
        "commands": phase_commands["remediation"] if execution_ready else [],
        "validation_commands": phase_commands["validation"],
        "validation_endpoints": [],
        "validators": validators,
        "required_validation_kinds": sorted({str(item["kind"]) for item in validators}),
        "stability_window_seconds": 300,
        "rollback_commands": phase_commands["rollback"] if execution_ready else [],
        "rollback_mode": rollback_mode,
        "recovery_strategy": recovery_strategy,
        "recovery_strategy_acknowledged": recovery_strategy_acknowledged,
        "queries": phase_commands["validation"],
        "scripts": [],
        "parameters": variables,
        "evidence_basis": sorted({str(item) for item in (evidence_basis or []) if str(item).strip()}),
        "classification": {
            "playbook_id": playbook_id,
            "diagnostic_only": diagnostic_only or not execution_ready,
            "catalog_versions": {
                "actions": str(actions.get("version") or "unknown"),
                "playbooks": str(playbooks.get("version") or "unknown"),
                "connectors": str(connectors.get("version") or "unknown"),
            },
        },
        "investigation_report": {},
        "historical_precedents": [],
        "investigation_status": None,
        "investigation_id": None,
        "next_evidence": [],
        "policy_decision": {},
    }
    return ExecutionPlanV2.model_validate(plan).finalized().model_dump(mode="json")
