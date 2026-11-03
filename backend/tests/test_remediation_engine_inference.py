import pytest
from common.models import ApprovalDecision
from common.orchestration.execution_plan_contract import canonical_plan_fingerprint
from remediation_engine import RemediationEngine
from remediation_test_helpers import governed_approval as Approval


def test_build_action_prefers_recommended_commands_for_action_type() -> None:
    approval = Approval(
        incident_id="11111111-1111-1111-1111-111111111111",
        recommendation_id="22222222-2222-2222-2222-222222222222",
        decision=ApprovalDecision.APPROVED,
        approver="sre@example.com",
        comment="Proceed",
        metadata={
            "service": "checkout-api",
            "recommended_action": "Scale service to absorb traffic",
            "recommended_commands": [
                "kubectl scale deployment/checkout-api --replicas=4 -n prod",
            ],
        },
    )

    action = RemediationEngine().build_action(approval)

    assert action.action_type == "scale_deployment"
    assert action.target == "checkout-api"


def test_build_action_rejects_uuid_target_instead_of_guessing_service() -> None:
    approval = Approval(
        incident_id="11111111-1111-1111-1111-111111111111",
        recommendation_id="22222222-2222-2222-2222-222222222222",
        decision=ApprovalDecision.APPROVED,
        approver="sre@example.com",
        comment="Restart service",
        metadata={
            "target": "33333333-3333-4333-9333-333333333333",
            "service": "payments-api",
        },
    )

    with pytest.raises(ValueError, match="catalog-bound resource"):
        RemediationEngine().build_action(approval)


def test_build_action_does_not_infer_action_type_from_command_text() -> None:
    approval = Approval(
        incident_id="11111111-1111-1111-1111-111111111111",
        recommendation_id="22222222-2222-2222-2222-222222222222",
        decision=ApprovalDecision.APPROVED,
        approver="sre@example.com",
        comment="Proceed",
        metadata={"recommended_commands": ["kubectl rollout undo deployment/checkout-api -n prod"]},
    )
    plan = dict(approval.metadata["execution_plan"])
    plan["actions"] = [{"action_id": "descriptive-step", "inputs": {}}]
    plan["plan_fingerprint"] = canonical_plan_fingerprint(plan)
    approval.metadata["execution_plan"] = plan
    approval.plan_fingerprint = plan["plan_fingerprint"]

    with pytest.raises(ValueError, match="UNSUPPORTED_ACTION_PLAN"):
        RemediationEngine().build_action(approval)


def test_docker_socket_restart_command_stays_outside_automated_allowlist() -> None:
    approval = Approval(
        incident_id="11111111-1111-1111-1111-111111111111",
        recommendation_id="22222222-2222-2222-2222-222222222222",
        decision=ApprovalDecision.APPROVED,
        approver="sre@example.com",
        comment="execute exact reviewed plan",
        metadata={
            "service": "kaiops-discovery-mcp",
            "recommended_action": "Restart the kaiops-discovery-mcp service and validate its health.",
            "execution_plan": {
                "commands": [
                    "curl -X POST http://docker-socket-proxy:2375/containers/kaiops_pubsub-discovery-mcp-1/restart?t=30"
                ],
                "validation_commands": ["curl http://discovery-mcp:8000/healthz"],
            },
            "connection_profile": {
                "executor_type": "jenkins",
                "allowed_operations": ["restart_service"],
            },
        },
    )

    with pytest.raises(ValueError, match="outside the automated allowlist"):
        RemediationEngine().build_action(approval)
