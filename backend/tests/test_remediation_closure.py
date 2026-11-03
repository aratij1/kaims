from datetime import UTC, datetime

import pytest
from closure_service import ClosureValidationAgent
from common.models import Approval, ApprovalDecision, RemediationStatus
from common.orchestration.execution_plan_contract import canonical_plan_fingerprint
from common.resolution_lifecycle import ResolutionState, create_lifecycle
from remediation_engine import RemediationEngine


def _approved_rollback() -> Approval:
    expiry = datetime(2099, 1, 1, tzinfo=UTC)
    plan = {
        "schema_version": "kaims.execution-plan.v2",
        "tenant_id": "tenant-a",
        "incident_id": "11111111-1111-1111-1111-111111111111",
        "plan_id": "33333333-3333-3333-3333-333333333333",
        "expiry": expiry.isoformat(),
        "actions": [{
            "action_id": "rollback_deployment",
            "connector_id": "jenkins",
            "target_resource_id": "payments-api",
            "inputs": {"operation": "rollback_deployment"},
            "safety_binding": {
                "capability": {
                    "capability_id": "jenkins.rollback_deployment",
                    "connector_id": "jenkins",
                    "operation": "rollback_deployment",
                    "allowed_resource_ids": ["payments-api"],
                },
                "credential": {
                    "reference": "vault://test/jenkins",
                    "tenant_id": "tenant-a",
                    "connector_id": "jenkins",
                    "resource_ids": ["payments-api"],
                },
                "blast_radius": {"target_resource_id": "payments-api"},
                "preflight": {"target_resource_id": "payments-api"},
            },
        }],
        "commands": [],
        "scripts": [],
        "queries": [],
        "validation_endpoints": [],
        "remediation_target": "payments-api",
    }
    plan["plan_fingerprint"] = canonical_plan_fingerprint(plan)
    return Approval(
        tenant_id="tenant-a",
        incident_id=plan["incident_id"],
        recommendation_id="22222222-2222-2222-2222-222222222222",
        plan_id=plan["plan_id"],
        plan_fingerprint=plan["plan_fingerprint"],
        approval_expires_at=expiry,
        decision=ApprovalDecision.APPROVED,
        approver="sre@example.com",
        comment="Rollback deployment",
        metadata={"execution_plan": plan},
    )


@pytest.mark.asyncio
async def test_remediation_engine_executes_rollback_strategy() -> None:
    approval = _approved_rollback()
    engine = RemediationEngine()

    action = engine.build_action(approval)
    completed = await engine.execute(action)

    assert action.recommendation_id == approval.recommendation_id
    assert action.resolution_plan_id == approval.plan_id
    assert action.plan_fingerprint == approval.plan_fingerprint
    assert action.action_type == "rollback_deployment"
    assert completed.status == RemediationStatus.SKIPPED
    assert completed.parameters["execution_result"]["executed"] is False
    assert "No real jenkins executor is configured" in str(completed.error)
    assert "Execution not performed" in completed.output


@pytest.mark.asyncio
async def test_closure_validation_generates_report() -> None:
    approval = _approved_rollback()
    action = await RemediationEngine().execute(RemediationEngine().build_action(approval))

    report = await ClosureValidationAgent().validate(action)

    assert report.recommendation_id == approval.recommendation_id
    assert report.resolution_plan_id == approval.plan_id
    assert report.plan_fingerprint == approval.plan_fingerprint
    assert report.approval_id == approval.id
    assert report.remediation_action_id == action.id
    assert report.closure_status == "validation_failed"
    assert report.health_restored is False
    assert report.alerts_cleared is False
    assert report.validation["remediation_succeeded"] is False
    assert report.validation["alerts_cleared"] is False
    assert report.validation["validation_executable"] is False
    assert report.validation["validation_supplied"] is False


@pytest.mark.asyncio
async def test_diagnostic_completion_does_not_claim_recovery() -> None:
    approval = _approved_rollback()
    action = RemediationEngine().build_action(approval)
    action.action_type = "diagnostic_completion"
    action.status = RemediationStatus.SKIPPED
    action.parameters.update({
        "diagnostic_closure": True,
        "diagnostic_details": {"checks": ["logs"]},
        "resolution_lifecycle": create_lifecycle(
            tenant_id="tenant-a",
            incident_id=action.incident_id,
            recommendation_id=approval.recommendation_id,
            plan={"plan_kind": "diagnostic", "execution_ready": False},
            state=ResolutionState.DIAGNOSTIC_ONLY,
        ),
    })

    report = await ClosureValidationAgent().validate(action)

    assert report.health_restored is False
    assert report.alerts_cleared is False
    assert report.validation["diagnostic_completed"] is True


def test_remediation_allowlist_blocks_unknown_action_type() -> None:
    engine = RemediationEngine()

    assert engine.is_action_allowed("rollback_deployment") is True
    assert engine.is_action_allowed("shell_exec") is False
