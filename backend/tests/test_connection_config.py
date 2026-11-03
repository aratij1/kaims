from __future__ import annotations

import json

from common.config import Settings
from common.connection_config import connector_catalog_from_connection_config, load_connection_config
from common.models import Alert, AlertSeverity
from common.orchestration.execution_plan import _match_playbook, resolve_execution_plan


def test_connection_config_expands_env_and_normalizes_connectors(tmp_path, monkeypatch) -> None:
    config_path = tmp_path / "connections.json"
    config_path.write_text(
        json.dumps(
            {
                "version": "kaiops-connections-v1",
                "environment": "${ENVIRONMENT:-dev}",
                "cloud_provider": "${CLOUD_PROVIDER:-local}",
                "external_applications": {
                    "default_connector": "checkout",
                    "connectors": {
                        "checkout": {
                            "connector_id": "checkout-api",
                            "system": "checkout",
                            "type": "api",
                            "endpoint": "${CHECKOUT_ENDPOINT:-https://checkout.internal}",
                            "secret_ref": "vault://kaiops/${ENVIRONMENT:-dev}/checkout-token",
                            "allowed_operations": ["read_status", "restart_service"],
                        }
                    },
                },
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("ENVIRONMENT", "qa")
    monkeypatch.setenv("CLOUD_PROVIDER", "aws")
    monkeypatch.setenv("CHECKOUT_ENDPOINT", "https://checkout.prod.internal")

    config = load_connection_config(Settings(ENVIRONMENT="test", CONNECTION_CONFIG_PATH=str(config_path)))
    catalog = connector_catalog_from_connection_config(config)

    assert config["environment"] == "qa"
    assert config["cloud_provider"] == "aws"
    assert catalog["default_connector"] == "checkout"
    assert catalog["connectors"]["checkout"]["endpoint"] == "https://checkout.prod.internal"
    assert catalog["connectors"]["checkout"]["secret_ref"] == "vault://kaiops/qa/checkout-token"
    assert catalog["connectors"]["checkout"]["retry"]["max_attempts"] == 2


def test_execution_plan_includes_standard_connection_architecture() -> None:
    alert = Alert(
        tenant_id="tenant-a",
        source="prometheus",
        name="DatabaseReplicaLag",
        service="orders-db",
        severity=AlertSeverity.CRITICAL,
        description="orders database replica lag above threshold",
    )

    plan = resolve_execution_plan(
        alert=alert,
        workflow_name="critical-auto-remediation",
        requires_approval=True,
        risk_tier="high",
        execution_mode="human-approval",
    )

    connection = plan["connection"]
    assert connection["architecture"]["mode"] == "externalized-shared-state"
    assert connection["connector"]["connector_id"] == "orders-db-api"
    assert connection["connector"]["timeout_seconds"] == 10
    assert "read_status" in connection["connector"]["allowed_operations"]
    assert connection["platform"]["message_bus"]["provider"]


def _resolve(alert: Alert) -> dict:
    alert = alert.model_copy(update={"tenant_id": "tenant-a"})
    return resolve_execution_plan(
        alert=alert,
        workflow_name="critical-auto-remediation",
        requires_approval=True,
        risk_tier="high",
        execution_mode="human-approval",
    )


def test_catalog_plan_matches_alert_without_requiring_alert_type() -> None:
    plan = _resolve(
        Alert(
            source="prometheus",
            name="KaiOpsServiceDown",
            service="api-gateway",
            severity=AlertSeverity.CRITICAL,
            description="API endpoint is unreachable",
        )
    )

    assert plan["playbook"]["id"] == "kaiops-service-down-playbook"
    assert plan["execution_ready"] is True
    assert plan["commands"]
    assert plan["validation_commands"]
    assert plan["rollback_commands"]
    assert plan["plan_fingerprint"].startswith("sha256:")
    assert not any("${" in command for command in plan["preflight_commands"] + plan["commands"])


def test_unknown_alert_is_diagnostic_only_and_never_invents_mutation() -> None:
    plan = _resolve(
        Alert(
            source="prometheus",
            name="NovelSubsystemSignal",
            service="unknown-worker",
            severity=AlertSeverity.WARNING,
            description="unclassified symptom",
        )
    )

    assert plan["playbook"]["id"] == "generic-kaiops-triage-playbook"
    assert plan["plan_kind"] == "diagnostic"
    assert plan["execution_ready"] is False
    assert plan["commands"] == []


def test_reusable_playbook_matches_new_service_by_reviewed_alert_signature() -> None:
    playbook = _match_playbook(
        alert=Alert(
            source="prometheus",
            name="ServiceDown",
            service="newly-discovered-service",
            severity=AlertSeverity.CRITICAL,
            description="endpoint is unreachable",
        ),
        playbooks={
            "playbooks": [
                {
                    "id": "reviewed-service-down",
                    "match": {
                        "services": ["known-service"],
                        "alert_keywords": ["service down", "unreachable"],
                        "allow_unlisted_services": True,
                    },
                    "steps": [],
                }
            ]
        },
    )

    assert playbook["id"] == "reviewed-service-down"


def test_service_boundary_remains_closed_without_explicit_reuse() -> None:
    playbook = _match_playbook(
        alert=Alert(
            source="prometheus",
            name="ServiceDown",
            service="unreviewed-service",
            severity=AlertSeverity.CRITICAL,
            description="endpoint is unreachable",
        ),
        playbooks={
            "playbooks": [
                {
                    "id": "restricted-service-down",
                    "match": {
                        "services": ["known-service"],
                        "alert_keywords": ["service down", "unreachable"],
                    },
                    "steps": [],
                }
            ]
        },
    )

    assert playbook["id"] == "generic-triage-playbook"


def test_reusable_playbook_auto_onboards_only_policy_allowed_operations(monkeypatch) -> None:
    import common.orchestration.execution_plan as execution_plan_module

    catalogs = execution_plan_module._execution_catalogs()
    execution_plan_module._execution_catalogs.cache_clear()
    connectors, actions, playbooks, connectivity, connection_config = catalogs
    monkeypatch.setattr(
        execution_plan_module,
        "_execution_catalogs",
        lambda: (connectors, actions, playbooks, connectivity, connection_config),
    )
    plan = _resolve(
        Alert(
            source="prometheus",
            name="ServiceDown",
            service="new-runtime-service",
            severity=AlertSeverity.CRITICAL,
            description="endpoint is unreachable",
        )
    )

    connector = plan["connection"]["connector"]
    assert connector["connector_id"] == "auto-new-runtime-service"
    assert connector["onboarding"]["mode"] == "automatic"
    assert connector["onboarding"]["playbook_id"] == "kaiops-service-down-playbook"
    assert set(connector["allowed_operations"]) == {
        "read_status",
        "read_metrics",
        "script_execution",
        "restart_service",
        "verify_slo",
    }
    assert plan["execution_ready"] is True


def test_policy_engine_alert_uses_reviewed_target_connector_not_detector_connector(monkeypatch) -> None:
    import common.orchestration.execution_plan as execution_plan_module

    catalogs = execution_plan_module._execution_catalogs()
    execution_plan_module._execution_catalogs.cache_clear()
    connectors, actions, playbooks, connectivity, connection_config = catalogs
    monkeypatch.setattr(
        execution_plan_module,
        "_execution_catalogs",
        lambda: (connectors, actions, playbooks, connectivity, connection_config),
    )

    plan = _resolve(
        Alert(
            source="prometheus",
            name="PolicyEngineUnavailable",
            service="orchestrator",
            environment="prod",
            severity=AlertSeverity.CRITICAL,
            description="No orchestrator event-processing metric is present.",
        )
    )

    assert plan["playbook"]["id"] == "policy-engine-unavailable-playbook"
    assert plan["remediation_target"] == "policy-engine"
    assert plan["connection"]["connector"]["connector_id"] == "policy-engine-runtime"
    assert plan["commands"] == [
        "kubectl rollout restart deployment/policy-engine -n default"
    ]
    assert plan["rollback_commands"] == [
        "kubectl rollout undo deployment/policy-engine -n default"
    ]
    assert plan["validation_commands"]
    assert plan["execution_ready"] is True
    assert plan["readiness_blocks"] == []


def test_incomplete_mutations_require_operator_resolution() -> None:
    latency = _resolve(
        Alert(
            source="prometheus",
            name="KaiOpsHighLatencyP95",
            service="api-gateway",
            severity=AlertSeverity.CRITICAL,
            description="p95 latency is above the SLO",
        )
    )
    mysql = _resolve(
        Alert(
            source="prometheus",
            name="KaiOpsMysqlAlertsTableRowsHigh",
            service="mysql",
            severity=AlertSeverity.WARNING,
            description="alerts table row count is above threshold",
        )
    )

    assert latency["execution_ready"] is False
    assert any("requires: replicas" in reason for reason in latency["readiness_blocks"])
    assert any("rollback requires: previous_replicas" in reason for reason in latency["readiness_blocks"])
    assert mysql["execution_ready"] is False
    assert any("rollback is a procedure" in reason for reason in mysql["readiness_blocks"])


def test_docker_compose_restart_with_acknowledged_recovery_strategy_is_execution_ready(monkeypatch) -> None:
    # restart_service_runtime declares an approved recovery_strategy in
    # action_catalog.json specifically for platforms with no native inverse
    # (docker-compose). That acknowledged, catalog-declared exemption - never
    # inferred from the bare absence of a rollback - is what makes this plan
    # execution_ready while remaining genuinely non-reversible.
    monkeypatch.setenv("REMEDIATION_EXECUTION_PLATFORM", "docker-compose")
    monkeypatch.setenv("REMEDIATION_COMPOSE_PROJECT", "kaiops_azure")

    plan = _resolve(
        Alert(
            source="prometheus",
            name="KaiOpsServiceDown",
            service="api-gateway",
            severity=AlertSeverity.CRITICAL,
            description="API endpoint is unreachable",
        )
    )

    assert plan["execution_ready"] is True
    assert plan["remediation_target"] == "api-gateway"
    assert plan["commands"] != []
    assert "com.docker.compose.service%3Dapi-gateway" in plan["preflight_commands"][0]
    assert plan["validation_commands"] == [
        "curl --fail --silent --show-error --retry 15 --retry-all-errors --retry-connrefused "
        "--retry-delay 2 http://api-gateway:8000/healthz"
    ]
    # Genuinely no rollback command exists - no fake rollback is fabricated.
    assert plan["rollback_commands"] == []
    assert plan["rollback_mode"] == "not_applicable"
    assert plan["recovery_strategy_acknowledged"] is True
    assert plan["recovery_strategy"]["type"] == "retry_and_escalate"
    assert "mutating plan has no executable rollback" not in plan["readiness_blocks"]
    # Every PlanAction must still report reversible=False: execution-eligible
    # is not the same claim as reversible, and downstream policy must still
    # see this as non-reversible.
    assert plan["actions"], "expected at least one remediation action in the plan"
    assert all(action["reversible"] is False for action in plan["actions"])


def test_docker_compose_restart_without_acknowledged_recovery_strategy_stays_blocked(monkeypatch) -> None:
    # Negative test: an operation lacking BOTH a real rollback and a
    # catalog-declared recovery_strategy must remain blocked. This proves the
    # exemption is not a blanket "not_applicable always passes" rule - it is
    # scoped strictly to commands that explicitly opt in via the catalog.
    monkeypatch.setenv("REMEDIATION_EXECUTION_PLATFORM", "docker-compose")
    monkeypatch.setenv("REMEDIATION_COMPOSE_PROJECT", "kaiops_azure")

    from common.orchestration import execution_plan as execution_plan_module

    original_catalogs = execution_plan_module._execution_catalogs()
    connectors, actions, playbooks, connectivity, connection_config = original_catalogs
    patched_actions = json.loads(json.dumps(actions))
    patched_actions["commands"]["restart_service_runtime"].pop("recovery_strategy", None)

    monkeypatch.setattr(
        execution_plan_module,
        "_execution_catalogs",
        lambda: (connectors, patched_actions, playbooks, connectivity, connection_config),
    )

    plan = _resolve(
        Alert(
            source="prometheus",
            name="KaiOpsServiceDown",
            service="api-gateway",
            severity=AlertSeverity.CRITICAL,
            description="API endpoint is unreachable",
        )
    )

    assert plan["execution_ready"] is False
    assert plan["rollback_commands"] == []
    assert plan["rollback_mode"] == "not_applicable"
    assert plan["recovery_strategy_acknowledged"] is False
    assert "mutating plan has no executable rollback" in plan["readiness_blocks"]


def test_docker_compose_uses_the_supported_scale_executor(monkeypatch) -> None:
    monkeypatch.setenv("REMEDIATION_EXECUTION_PLATFORM", "docker-compose")

    plan = _resolve(
        Alert(
            source="prometheus",
            name="KaiOpsHighLatencyP95",
            service="api-gateway",
            severity=AlertSeverity.CRITICAL,
            description="p95 latency is above the SLO",
        )
    )

    assert plan["execution_ready"] is True
    assert len(plan["commands"]) == 1
    assert "--scale api-gateway=2 api-gateway" in plan["commands"][0]
    assert plan["rollback_commands"]
    assert "--scale api-gateway=1 api-gateway" in plan["rollback_commands"][0]


def _catalogs_with_scale_only_playbook():
    """kaiops-high-latency-playbook pairs scale_service_workers with a
    rollback alternative, so it always resolves to two ambiguous remediation
    operations (see the negative test above). Strip the rollback step to
    isolate scale_service as the sole operation this positive test needs.
    """
    from common.orchestration import execution_plan as execution_plan_module

    execution_plan_module._execution_catalogs.cache_clear()
    connectors, actions, playbooks, connectivity, connection_config = execution_plan_module._execution_catalogs()
    patched_playbooks = json.loads(json.dumps(playbooks))
    for playbook in patched_playbooks.get("playbooks", []):
        if playbook.get("id") == "kaiops-high-latency-playbook":
            playbook["steps"] = [
                step for step in playbook["steps"]
                if step.get("name") != "Rollback deployment if correlated with release"
            ]
    return connectors, actions, patched_playbooks, connectivity, connection_config


def test_docker_compose_scale_service_uses_the_real_compose_cli(monkeypatch) -> None:
    """Scaling has no engine-level primitive in Compose the way restart does
    (a raw HTTP call to the socket proxy), so this shells out to the real
    `docker compose` CLI instead of hand-building container-clone logic --
    and unlike restart, scaling back down is a genuine, executable rollback.
    """
    monkeypatch.setenv("REMEDIATION_EXECUTION_PLATFORM", "docker-compose")
    monkeypatch.setenv("REMEDIATION_COMPOSE_PROJECT", "kaims")

    from common.orchestration import execution_plan as execution_plan_module

    catalogs = _catalogs_with_scale_only_playbook()
    monkeypatch.setattr(execution_plan_module, "_execution_catalogs", lambda: catalogs)

    plan = _resolve(
        Alert(
            source="prometheus",
            name="KaiOpsHighLatencyP95",
            service="api-gateway",
            severity=AlertSeverity.CRITICAL,
            description="p95 latency is above the SLO",
        )
    )

    assert plan["execution_ready"] is True, plan["readiness_blocks"]
    assert plan["commands"] == [
        "docker compose --project-name kaims --file /opt/kaiops/docker-compose.yml "
        "up -d --no-build --no-recreate --scale api-gateway=2 api-gateway"
    ]
    assert plan["rollback_commands"] == [
        "docker compose --project-name kaims --file /opt/kaiops/docker-compose.yml "
        "up -d --no-build --no-recreate --scale api-gateway=1 api-gateway"
    ]
    assert plan["rollback_mode"] == "automatic"
    assert "mutating plan has no executable rollback" not in plan["readiness_blocks"]
    assert "does not implement catalog operations" not in " ".join(plan["readiness_blocks"])


def test_docker_compose_scale_service_stays_blocked_outside_internal_services(monkeypatch) -> None:
    """The same safety scope as restart: only the fixed internal-services
    allowlist gets a real docker-compose plan. Anything else still fails
    closed rather than guessing at an external application's compose service
    name.
    """
    monkeypatch.setenv("REMEDIATION_EXECUTION_PLATFORM", "docker-compose")

    from common.orchestration import execution_plan as execution_plan_module

    catalogs = _catalogs_with_scale_only_playbook()
    monkeypatch.setattr(execution_plan_module, "_execution_catalogs", lambda: catalogs)

    plan = _resolve(
        Alert(
            source="prometheus",
            name="KaiOpsHighLatencyP95",
            service="external-orders-api",
            severity=AlertSeverity.CRITICAL,
            description="p95 latency is above the SLO",
        )
    )

    assert plan["execution_ready"] is False
    assert plan["commands"] == []
    assert any("does not implement catalog operations" in reason for reason in plan["readiness_blocks"])
