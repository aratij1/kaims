from __future__ import annotations

import pytest
from common.models import Alert, AlertSeverity
from common.orchestration import execution_plan as execution_plan_module
from common.orchestration.execution_plan_contract import (
    ExecutionPlanV2,
    canonical_plan_fingerprint,
    verify_plan_fingerprint,
)


def _alert() -> Alert:
    return Alert(
        tenant_id="tenant-a",
        source="prometheus",
        name="KaiOpsServiceDown",
        service="api-gateway",
        severity=AlertSeverity.CRITICAL,
        description="API endpoint is unreachable",
    )


def test_execution_plan_v2_has_one_normalized_top_level_contract() -> None:
    plan = execution_plan_module.resolve_execution_plan(
        alert=_alert(),
        workflow_name="critical-auto-remediation",
        requires_approval=True,
        risk_tier="high",
        execution_mode="human-approval",
        resolution_hints="restart only if current availability evidence confirms the outage",
        evidence_basis=["metric:up:api-gateway", "log:connection-refused"],
    )

    assert plan["schema_version"] == "kaims.execution-plan.v2"
    assert plan["plan_fingerprint"].startswith("sha256:")
    assert plan["idempotency_key"] == plan["plan_fingerprint"]
    assert plan["playbook_id"] == plan["playbook"]["id"]
    assert isinstance(plan["playbook_version"], int)
    assert plan["connector_id"] == plan["connection"]["connector"]["connector_id"]
    assert plan["remediation_target"] == "api-gateway"
    assert plan["requires_approval"] is True
    assert plan["diagnostic_only"] is False
    assert plan["mutating"] is True
    assert plan["execution_ready"] is True
    assert plan["evidence_basis"] == ["log:connection-refused", "metric:up:api-gateway"]
    assert ExecutionPlanV2.model_validate(plan).model_dump(mode="json") == plan
    assert verify_plan_fingerprint(plan)
    assert plan["preflight_commands"]
    assert plan["commands"]
    assert plan["validation_commands"]
    assert plan["rollback_commands"]
    assert all(action["safety_binding"] for action in plan["actions"])
    binding = plan["actions"][0]["safety_binding"]
    assert binding["capability"]["registered"] is True
    assert binding["credential"]["reference"].startswith(("vault://", "https://"))
    assert binding["blast_radius"]["verified"] is True
    assert binding["preflight"]["status"] == "PLANNED"


def test_unapproved_runbook_cannot_create_a_mutating_plan(monkeypatch) -> None:
    connectors, actions, playbooks, connectivity, connection_config = execution_plan_module._execution_catalogs()
    unapproved = {
        **playbooks,
        "playbooks": [
            {
                **playbooks["playbooks"][0],
                "status": "draft",
            }
        ],
    }
    monkeypatch.setattr(
        execution_plan_module,
        "_execution_catalogs",
        lambda: (connectors, actions, unapproved, connectivity, connection_config),
    )

    plan = execution_plan_module.resolve_execution_plan(
        alert=_alert(),
        workflow_name="critical-auto-remediation",
        requires_approval=True,
        risk_tier="high",
        execution_mode="human-approval",
    )

    assert plan["execution_ready"] is False
    assert plan["diagnostic_only"] is True
    assert plan["commands"] == []
    assert "runbook version is not approved" in plan["readiness_blocks"]


def test_resolution_hints_are_matching_input_not_commands() -> None:
    plan = execution_plan_module.resolve_execution_plan(
        alert=_alert(),
        workflow_name="critical-auto-remediation",
        requires_approval=True,
        risk_tier="high",
        execution_mode="human-approval",
        resolution_hints="rm -rf /; invent a production command",
    )

    rendered = plan["preflight_commands"] + plan["commands"] + plan["validation_commands"] + plan["rollback_commands"]
    assert all("rm -rf" not in command for command in rendered)


def test_missing_tenant_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ENVIRONMENT", "production")
    alert = _alert().model_copy(update={"tenant_id": "default"})

    with pytest.raises(ValueError, match="verified identity"):
        execution_plan_module.resolve_execution_plan(
            alert=alert,
            workflow_name="critical-auto-remediation",
            requires_approval=True,
            risk_tier="high",
            execution_mode="human-approval",
        )


def test_fingerprint_ignores_generation_time_but_detects_plan_edits() -> None:
    plan = execution_plan_module.resolve_execution_plan(
        alert=_alert(),
        workflow_name="critical-auto-remediation",
        requires_approval=True,
        risk_tier="high",
        execution_mode="human-approval",
    )
    changed_timestamp = {**plan, "generated_at": "2099-01-01T00:00:00Z"}
    changed_target = {**plan, "remediation_target": "another-service"}

    assert canonical_plan_fingerprint(changed_timestamp) == plan["plan_fingerprint"]
    assert canonical_plan_fingerprint(changed_target) != plan["plan_fingerprint"]


def test_execution_plan_requires_timezone_aware_expiry() -> None:
    plan = execution_plan_module.resolve_execution_plan(
        alert=_alert(),
        workflow_name="critical-auto-remediation",
        requires_approval=True,
        risk_tier="high",
        execution_mode="human-approval",
    )
    plan["expiry"] = "2099-01-01T00:00:00"

    with pytest.raises(ValueError, match="timezone-aware"):
        ExecutionPlanV2.model_validate(plan)
