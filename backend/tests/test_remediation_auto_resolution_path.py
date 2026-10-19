from importlib import util
from pathlib import Path

import pytest
from common.models import ApprovalDecision, RemediationAction, RemediationStatus
from remediation_test_helpers import governed_approval as Approval


def load_remediation_app_module():
    module_path = Path("backend/src/remediation-engine/app.py")
    spec = util.spec_from_file_location("remediation_engine_app", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load remediation-engine app module")
    module = util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_live_execution_rejects_incomplete_jenkins_connector() -> None:
    module = load_remediation_app_module()
    approval = Approval(
        incident_id="11111111-1111-1111-1111-111111111111",
        recommendation_id="22222222-2222-2222-2222-222222222222",
        decision=ApprovalDecision.APPROVED,
        approver="sre-user",
        comment="rollback deployment",
    )
    action = module.engine.build_action(approval)

    with pytest.raises(module.HTTPException, match="Jenkins connector is incomplete") as exc_info:
        module._require_live_executor_configuration(action)

    assert exc_info.value.status_code == 409


def test_live_execution_accepts_complete_jenkins_connector() -> None:
    module = load_remediation_app_module()
    approval = Approval(
        incident_id="11111111-1111-1111-1111-111111111111",
        recommendation_id="22222222-2222-2222-2222-222222222222",
        decision=ApprovalDecision.APPROVED,
        approver="sre-user",
        comment="rollback deployment",
        metadata={
            "service": "checkout-api",
            "connection_profile": {
                "executor_type": "jenkins",
                "endpoint_url": "http://jenkins:8080",
                "job_name": "kaiops-auto-remediation",
                "credential_ref": "vault://kaiops/local/jenkins#api-token",
            }
        },
    )
    action = module.engine.build_action(approval)

    module._require_live_executor_configuration(action)


def test_live_execution_uses_nested_approved_connection_service_as_target() -> None:
    module = load_remediation_app_module()
    approval = Approval(
        incident_id="11111111-1111-1111-1111-111111111111",
        recommendation_id="22222222-2222-2222-2222-222222222222",
        decision=ApprovalDecision.APPROVED,
        approver="sre-user",
        comment="restart service",
        metadata={
            "remediation_target": "-",
            "connection_profile": {
                "service": "checkout-api",
                "application": "storefront",
                "environment": "prod",
                "executor_type": "jenkins",
                "endpoint_url": "http://jenkins:8080",
                "job_name": "kaiops-auto-remediation",
                "credential_ref": "vault://kaiops/prod/jenkins#api-token",
            },
        },
    )

    action = module.engine.build_action(approval)

    assert action.target == "checkout-api"
    assert action.parameters["service"] == "checkout-api"
    module._require_live_executor_configuration(action)


def test_live_execution_rejects_incident_uuid_as_jenkins_target() -> None:
    module = load_remediation_app_module()
    approval = Approval(
        incident_id="11111111-1111-1111-1111-111111111111",
        recommendation_id="22222222-2222-2222-2222-222222222222",
        decision=ApprovalDecision.APPROVED,
        approver="sre-user",
        comment="rollback deployment",
        metadata={
            "connection_profile": {
                "executor_type": "jenkins",
                "endpoint_url": "http://jenkins:8080",
                "job_name": "kaiops-auto-remediation",
                "credential_ref": "vault://kaiops/local/jenkins#api-token",
            }
        },
    )
    action = module.engine.build_action(approval)

    with pytest.raises(module.HTTPException, match="incident UUID") as exc_info:
        module._require_live_executor_configuration(action)

    assert exc_info.value.status_code == 409


def test_live_execution_accepts_durable_remediation_engine_self_restart() -> None:
    module = load_remediation_app_module()
    approval = Approval(
        incident_id="11111111-1111-1111-1111-111111111111",
        recommendation_id="22222222-2222-2222-2222-222222222222",
        decision=ApprovalDecision.APPROVED,
        approver="sre-user",
        comment="restart service",
        metadata={
            "service": "kaiops-remediation-engine",
            "connection_profile": {
                "executor_type": "jenkins",
                "endpoint_url": "http://jenkins:8080",
                "job_name": "kaiops-auto-remediation",
                "credential_ref": "vault://kaiops/prod/jenkins",
            },
        },
    )
    action = module.engine.build_action(approval)

    module.settings.remediation_temporal_enabled = True
    module._require_live_executor_configuration(action)


def test_live_execution_rejects_synchronous_remediation_engine_self_restart() -> None:
    module = load_remediation_app_module()
    approval = Approval(
        incident_id="11111111-1111-1111-1111-111111111111",
        recommendation_id="22222222-2222-2222-2222-222222222222",
        decision=ApprovalDecision.APPROVED,
        approver="sre-user",
        comment="restart service",
        metadata={
            "service": "kaiops-remediation-engine",
            "connection_profile": {
                "executor_type": "jenkins",
                "endpoint_url": "http://jenkins:8080",
                "job_name": "kaiops-auto-remediation",
                "credential_ref": "vault://kaiops/prod/jenkins",
            },
        },
    )
    action = module.engine.build_action(approval)

    module.settings.remediation_temporal_enabled = False
    with pytest.raises(module.HTTPException, match="cannot synchronously restart itself") as exc_info:
        module._require_live_executor_configuration(action)

    assert exc_info.value.status_code == 409


def test_legacy_decision_cannot_disable_approval_in_p0_safety_mode() -> None:
    module = load_remediation_app_module()

    payload = {
        "decision": {"requires_approval": False},
        "recommendation": {
            "id": "22222222-2222-2222-2222-222222222222",
            "incident_id": "11111111-1111-1111-1111-111111111111",
        },
    }

    assert module._resolution_requires_approval(payload) is True


def test_legacy_metadata_cannot_disable_approval_in_p0_safety_mode() -> None:
    module = load_remediation_app_module()

    payload = {
        "recommendation": {
            "id": "22222222-2222-2222-2222-222222222222",
            "incident_id": "11111111-1111-1111-1111-111111111111",
            "metadata": {
                "orchestration_decision": {
                    "requires_approval": False,
                }
            },
        }
    }

    assert module._resolution_requires_approval(payload) is True


def test_confidence_gate_prefers_grounded_rca_over_coarse_context_score() -> None:
    module = load_remediation_app_module()
    payload = {
        "context": {"confidence_score": 0.30},
        "recommendation": {
            "confidence": 0.82,
            "metadata": {"rca_analysis": {"confidence_score": 0.86}},
        },
    }

    assert module._rca_and_resolution_confidence(payload) == (0.86, 0.82)


def test_complete_catalog_plan_supplies_resolution_assurance_not_rca_assurance() -> None:
    module = load_remediation_app_module()
    payload = {
        "context": {"confidence_score": 0.30},
        "recommendation": {
            "confidence": 0.54,
            "metadata": {
                "rca_analysis": {"confidence_score": 0.84},
                "execution_plan": {
                    "schema_version": "kaims.execution-plan.v2",
                    "execution_ready": True,
                    "plan_fingerprint": "sha256:abc",
                    "commands": ["kubectl rollout restart deployment/payments -n prod"],
                    "validation_commands": ["kubectl rollout status deployment/payments -n prod"],
                    "rollback_commands": ["kubectl rollout undo deployment/payments -n prod"],
                    "remediation_target": "payments",
                },
            },
        },
    }

    assert module._rca_and_resolution_confidence(payload) == (0.84, 0.90)


def test_confidence_alone_cannot_skip_required_approval() -> None:
    """High confidence is evidence quality, not autonomous authorization."""
    module = load_remediation_app_module()

    payload = {
        "decision": {"requires_approval": True},
        "recommendation": {
            "id": "22222222-2222-2222-2222-222222222222",
            "incident_id": "11111111-1111-1111-1111-111111111111",
            "confidence": 0.80,
            "metadata": {"rca_analysis": {"confidence_score": 0.85}},
        },
    }

    assert module._resolution_requires_approval(payload) is True


@pytest.mark.asyncio
async def test_failed_execution_requests_a_fresh_approval_gated_plan(monkeypatch) -> None:
    module = load_remediation_app_module()
    captured: dict = {}

    class Response:
        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict:
            return {"recommendation": {"id": "reconsidered-v2"}}

    class Client:
        def __init__(self, *args, **kwargs) -> None:
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        async def post(self, url, json):
            captured["url"] = url
            captured["request"] = json
            return Response()

    class Producer:
        async def publish(self, topic, payload, key=None) -> None:
            captured["published"] = (topic, payload, key)

    async def persist(_app, action) -> None:
        captured["persisted"] = action.metadata["failure_reconsideration"]

    monkeypatch.setattr(module.httpx, "AsyncClient", Client)
    monkeypatch.setattr(module, "_persist_action", persist)
    monkeypatch.setattr(module.app.state, "producer", Producer(), raising=False)
    action = RemediationAction(
        tenant_id="tenant-a",
        incident_id="11111111-1111-1111-1111-111111111111",
        approval_id="22222222-2222-2222-2222-222222222222",
        action_type="restart_service",
        target="checkout-api",
        status=RemediationStatus.FAILED,
        error="health check failed",
        parameters={"preflight_evidence": {"status": "PASSED"}},
    )

    await module._request_failure_reconsideration(
        action=action,
        source_payload={"recommendation": {"id": "recommendation-v1", "metadata": {}}},
    )

    assert captured["request"]["preflight_evidence"] == {"status": "PASSED"}
    assert captured["url"].endswith("/reconsider-execution")
    assert captured["published"][1]["recommendation"]["id"] == "reconsidered-v2"
    assert captured["persisted"]["status"] == "awaiting_approval"


def test_resolution_requires_approval_keeps_existing_flow_when_resolution_confidence_below_threshold() -> None:
    module = load_remediation_app_module()

    payload = {
        "decision": {"requires_approval": True},
        "recommendation": {
            "id": "22222222-2222-2222-2222-222222222222",
            "incident_id": "11111111-1111-1111-1111-111111111111",
            "confidence": 0.60,
            "metadata": {"rca_analysis": {"confidence_score": 0.85}},
        },
    }

    assert module._resolution_requires_approval(payload) is True


def test_resolution_requires_approval_keeps_existing_flow_when_rca_confidence_below_threshold() -> None:
    module = load_remediation_app_module()

    payload = {
        "decision": {"requires_approval": False},
        "recommendation": {
            "id": "22222222-2222-2222-2222-222222222222",
            "incident_id": "11111111-1111-1111-1111-111111111111",
            "confidence": 0.90,
            "metadata": {"rca_analysis": {"confidence_score": 0.55}},
        },
    }

    # Confidence and a legacy decision flag cannot authorize autonomous
    # mutation while P0 safety mode is active.
    assert module._resolution_requires_approval(payload) is True


def test_resolution_requires_approval_threshold_is_configurable() -> None:
    module = load_remediation_app_module()
    original_threshold = module.settings.rca_resolution_auto_complete_threshold
    try:
        module.settings.rca_resolution_auto_complete_threshold = 0.95
        payload = {
            "decision": {"requires_approval": True},
            "recommendation": {
                "id": "22222222-2222-2222-2222-222222222222",
                "incident_id": "11111111-1111-1111-1111-111111111111",
                "confidence": 0.80,
                "metadata": {"rca_analysis": {"confidence_score": 0.85}},
            },
        }
        # Same 0.80/0.85 confidences that auto-completed against the 0.70
        # default no longer clear a raised 0.95 threshold, so the existing
        # (severity-mandated) approval flow applies.
        assert module._resolution_requires_approval(payload) is True
    finally:
        module.settings.rca_resolution_auto_complete_threshold = original_threshold


def test_build_auto_approval_includes_policy_metadata() -> None:
    module = load_remediation_app_module()

    payload = {
        "decision": {
            "requires_approval": False,
            "policy_version": "policy-v2",
            "policy_reason": "confidence >= threshold",
        },
        "recommendation": {
            "tenant_id": "tenant-a",
            "id": "22222222-2222-2222-2222-222222222222",
            "incident_id": "11111111-1111-1111-1111-111111111111",
            "recommended_action": "restart pod deployment",
        },
    }

    approval = module._build_auto_approval(payload)

    assert approval is not None
    assert str(approval.incident_id) == "11111111-1111-1111-1111-111111111111"
    assert str(approval.recommendation_id) == "22222222-2222-2222-2222-222222222222"
    assert approval.approver == "system-auto-approval"
    assert approval.metadata.get("auto_approved") is True
    assert approval.metadata.get("policy_version") == "policy-v2"
    assert approval.metadata.get("policy_reason") == "confidence >= threshold"


def test_build_auto_approval_preserves_resolution_executor_profile() -> None:
    module = load_remediation_app_module()
    payload = {
        "incident": {"tenant_id": "tenant-a", "service": "checkout", "environment": "prod", "application": "storefront"},
        "decision": {"requires_approval": False},
        "recommendation": {
            "id": "22222222-2222-2222-2222-222222222222",
            "incident_id": "11111111-1111-1111-1111-111111111111",
            "recommended_action": "restart checkout",
            "metadata": {
                "connection_profile": {
                    "endpoint_url": "https://jenkins.storefront.example",
                    "job_name": "storefront-checkout-remediation",
                    "credential_ref": "vault://storefront/prod/jenkins#token",
                    "namespace": "storefront-prod",
                }
            },
        },
    }

    approval = module._build_auto_approval(payload)

    assert approval is not None
    profile = approval.metadata["connection_profile"]
    assert profile["application"] == "storefront"
    assert profile["service"] == "checkout"
    assert profile["endpoint_url"] == "https://jenkins.storefront.example"
    assert profile["job_name"] == "storefront-checkout-remediation"
    assert profile["credential_ref"] == "vault://storefront/prod/jenkins#token"
    assert profile["namespace"] == "storefront-prod"


def test_build_auto_approval_preserves_catalog_execution_contract() -> None:
    module = load_remediation_app_module()
    plan = {
        "schema_version": "kaims.execution-plan.v2",
        "execution_ready": True,
        "plan_fingerprint": "sha256:approved-plan",
        "commands": ["kubectl rollout restart deployment/checkout -n prod"],
        "validation_commands": ["kubectl rollout status deployment/checkout -n prod"],
        "rollback_commands": ["kubectl rollout undo deployment/checkout -n prod"],
        "remediation_target": "checkout",
    }
    payload = {
        "incident": {"tenant_id": "tenant-a", "service": "checkout", "environment": "prod"},
        "decision": {"requires_approval": False},
        "recommendation": {
            "tenant_id": "tenant-a",
            "id": "22222222-2222-2222-2222-222222222222",
            "incident_id": "11111111-1111-1111-1111-111111111111",
            "recommended_action": "restart checkout",
            "commands": plan["commands"],
            "metadata": {"execution_plan": plan},
        },
    }

    approval = module._build_auto_approval(payload)

    assert approval is not None
    assert approval.metadata["execution_plan"] == plan


def test_policy_blocked_action_displays_service_target_not_incident_uuid() -> None:
    module = load_remediation_app_module()
    payload = {
        "incident": {"service": "payments", "tenant_id": "tenant-a"},
        "recommendation": {
            "id": "22222222-2222-2222-2222-222222222222",
            "incident_id": "11111111-1111-1111-1111-111111111111",
            "metadata": {},
        },
    }

    action = module._build_policy_blocked_action(payload, "confidence below threshold")

    assert action is not None
    assert action.target == "payments"


def test_build_auto_approval_returns_none_when_identifiers_missing() -> None:
    module = load_remediation_app_module()

    payload = {
        "decision": {"requires_approval": False},
        "recommendation": {"recommended_action": "restart pod deployment"},
    }

    assert module._build_auto_approval(payload) is None


def test_validate_auto_execution_policy_accepts_well_formed_payload() -> None:
    module = load_remediation_app_module()

    payload = {
        "decision": {"requires_approval": False, "risk_tier": "medium"},
        "recommendation": {
            "id": "22222222-2222-2222-2222-222222222222",
            "incident_id": "11111111-1111-1111-1111-111111111111",
            "confidence": 0.93,
            "commands": ["kubectl rollout undo deployment/checkout -n prod"],
            "metadata": {
                "evidence_ids": ["ev-1"],
                "reasoning": "Rollback selected from runbook and deployment timeline.",
                "rca_analysis": {"confidence_score": 0.82},
                "runbook_id": "rb-checkout-1",
                "runbook_status": "approved",
                "runbook_match_score": 0.93,
            },
        },
    }

    module._validate_auto_execution_policy(payload)


def test_validate_auto_execution_policy_rejects_missing_evidence() -> None:
    module = load_remediation_app_module()

    payload = {
        "decision": {"requires_approval": False, "risk_tier": "medium"},
        "recommendation": {
            "id": "22222222-2222-2222-2222-222222222222",
            "incident_id": "11111111-1111-1111-1111-111111111111",
            "confidence": 0.93,
            "metadata": {
                "reasoning": "Rollback selected from runbook and deployment timeline.",
                "rca_analysis": {"confidence_score": 0.82},
            },
        },
    }

    with pytest.raises(module.PolicyViolation):
        module._validate_auto_execution_policy(payload)


def test_validate_auto_execution_policy_rejects_new_or_suspended_runbook() -> None:
    module = load_remediation_app_module()
    payload = {
        "decision": {"requires_approval": False, "risk_tier": "low"},
        "recommendation": {
            "confidence": 0.96,
            "metadata": {
                "evidence_ids": ["ev-1"], "reasoning": "matched evidence",
                "rca_analysis": {"confidence_score": 0.96},
                "runbook_id": "rb-1", "runbook_status": "suspended", "runbook_match_score": 0.96,
            },
        },
    }
    with pytest.raises(module.PolicyViolation, match="approved, active runbook"):
        module._validate_auto_execution_policy(payload)


def test_context_and_resolution_scores_at_configured_threshold_allow_auto_execution() -> None:
    module = load_remediation_app_module()
    payload = {
        "context": {"confidence_score": 0.74},
        "recommendation": {
            "confidence": 0.76,
            "commands": ["kubectl rollout restart deployment/api-gateway -n prod"],
            "metadata": {"evidence_ids": ["metric-1"], "reasoning": "Error rate followed the deployment."},
        },
    }
    module._validate_auto_execution_policy(payload)


def test_context_score_below_configured_threshold_blocks_auto_execution() -> None:
    module = load_remediation_app_module()
    payload = {
        "context": {"confidence_score": 0.69},
        "recommendation": {
            "confidence": 0.91,
            "commands": ["kubectl rollout restart deployment/api-gateway -n prod"],
            "metadata": {"evidence_ids": ["metric-1"], "reasoning": "Error rate followed the deployment."},
        },
    }
    with pytest.raises(module.PolicyViolation, match="threshold"):
        module._validate_auto_execution_policy(payload)


def test_dry_run_rejects_destructive_plan_even_after_generic_approval() -> None:
    module = load_remediation_app_module()
    approval = Approval(
        incident_id="11111111-1111-1111-1111-111111111111",
        recommendation_id="22222222-2222-2222-2222-222222222222",
        decision=ApprovalDecision.APPROVED,
        approver="reviewer",
        metadata={"execution_plan": {"commands": ["rm -rf /"]}},
    )
    reasons = module._unsafe_plan_reasons(approval)
    assert reasons and "filesystem deletion" in reasons[0]


def test_validation_only_plan_is_detected_before_live_execution() -> None:
    module = load_remediation_app_module()
    approval = Approval(
        incident_id="11111111-1111-1111-1111-111111111111",
        recommendation_id="22222222-2222-2222-2222-222222222222",
        decision=ApprovalDecision.APPROVED,
        approver="reviewer",
        metadata={"execution_plan": {"scripts": ["sh scripts/remediation/check.sh --dry-run true"]}},
    )

    assert module._plan_is_validation_only(approval) is True


def test_live_plan_is_not_misclassified_as_validation_only() -> None:
    module = load_remediation_app_module()
    approval = Approval(
        incident_id="11111111-1111-1111-1111-111111111111",
        recommendation_id="22222222-2222-2222-2222-222222222222",
        decision=ApprovalDecision.APPROVED,
        approver="reviewer",
        metadata={"execution_plan": {"scripts": ["sh scripts/remediation/restart.sh --dry-run false"]}},
    )

    assert module._plan_is_validation_only(approval) is False


def test_generic_triage_collector_cannot_be_promoted_to_live_remediation() -> None:
    module = load_remediation_app_module()
    approval = Approval(
        incident_id="11111111-1111-1111-1111-111111111111",
        recommendation_id="22222222-2222-2222-2222-222222222222",
        decision=ApprovalDecision.APPROVED,
        approver="reviewer",
        metadata={
            "execution_plan": {
                "scripts": [
                    "bash scripts/remediation/kaiops_alert_health_triage.sh "
                    "--service mysql --dry-run false"
                ]
            }
        },
    )

    assert module._plan_is_validation_only(approval) is True


def test_auto_approval_preserves_diagnostic_execution_plan_for_terminal_branch() -> None:
    module = load_remediation_app_module()
    payload = {
        "recommendation": {
            "id": "22222222-2222-2222-2222-222222222222",
            "incident_id": "11111111-1111-1111-1111-111111111111",
            "recommended_action": "Collect diagnostics only",
            "metadata": {
                "execution_plan": {
                    "plan_kind": "diagnostic",
                    "execution_ready": False,
                    "scripts": ["bash scripts/remediation/kaiops_alert_health_triage.sh --dry-run false"],
                }
            },
        },
        "incident": {"tenant_id": "tenant-a", "service": "checkout-api", "environment": "prod"},
    }

    approval = module._build_auto_approval(payload)

    assert approval is not None
    assert approval.metadata["execution_plan"]["execution_ready"] is False
    assert module._plan_is_validation_only(approval) is True


def test_diagnostic_completion_waits_for_closure_owner() -> None:
    module = load_remediation_app_module()
    approval = Approval(
        incident_id="11111111-1111-1111-1111-111111111111",
        recommendation_id="22222222-2222-2222-2222-222222222222",
        decision=ApprovalDecision.APPROVED,
        approver="system-auto-approval",
        metadata={
            "resolution_lifecycle": module.create_lifecycle(
                tenant_id="tenant-a",
                incident_id="11111111-1111-1111-1111-111111111111",
                recommendation_id="22222222-2222-2222-2222-222222222222",
                plan={"plan_kind": "diagnostic"},
                state=module.ResolutionState.DIAGNOSTIC_ONLY,
            )
        },
    )
    action = module.engine.build_action(approval)
    action.action_type = "diagnostic_completion"
    action.status = module.RemediationStatus.SKIPPED
    action.parameters["resolution_lifecycle"] = approval.metadata["resolution_lifecycle"]

    module._advance_action_lifecycle(action)

    assert action.parameters["resolution_lifecycle"]["state"] == "diagnostic_only"
    assert action.parameters["resolution_lifecycle"]["reason_code"] == "diagnostic_completed_pending_closure"


def test_diagnostic_completion_rebases_stale_executable_lifecycle() -> None:
    module = load_remediation_app_module()
    incident_id = "11111111-1111-1111-1111-111111111111"
    recommendation_id = "22222222-2222-2222-2222-222222222222"
    stale_lifecycle = module.create_lifecycle(
        tenant_id="tenant-a",
        incident_id=incident_id,
        recommendation_id=recommendation_id,
        plan={"execution_ready": True, "commands": ["kubectl rollout restart deployment/api"]},
        state=module.ResolutionState.READY_TO_EXECUTE,
    )
    approval = Approval(
        incident_id=incident_id,
        recommendation_id=recommendation_id,
        decision=ApprovalDecision.APPROVED,
        approver="system-auto-approval",
        metadata={"resolution_lifecycle": stale_lifecycle},
    )
    action = module.engine.build_action(approval)
    action.action_type = "diagnostic_completion"
    action.status = module.RemediationStatus.SKIPPED
    action.parameters.update({
        "recommendation_id": recommendation_id,
        "watch_only_closure": True,
        "execution_plan": {
            "plan_kind": "diagnostic",
            "diagnostic_only": True,
            "execution_ready": False,
            "queries": ["up{service=\"api\"}"],
        },
        "resolution_lifecycle": stale_lifecycle,
    })

    module._advance_action_lifecycle(action)

    lifecycle = action.parameters["resolution_lifecycle"]
    assert lifecycle["state"] == "diagnostic_only"
    assert lifecycle["reason_code"] == "diagnostic_completed_pending_closure"
    assert lifecycle["supersedes"].startswith(recommendation_id)
    assert lifecycle["control"]["auto_close"] is True


def test_diagnostic_completion_requires_watch_only_marker_to_auto_close() -> None:
    module = load_remediation_app_module()
    diagnostic = {"recommendation": {"metadata": {"execution_plan": {"plan_kind": "diagnostic"}}}}
    watch_only = {
        "recommendation": {
            "metadata": {
                "execution_plan": {"plan_kind": "diagnostic"},
                "resolution_mode": "watch-only",
            }
        }
    }

    assert module._is_auto_close_diagnostic_resolution(diagnostic) is False
    assert module._is_auto_close_diagnostic_resolution(watch_only) is True


def test_final_diagnostic_plan_does_not_override_stale_approval_control_for_closure() -> None:
    module = load_remediation_app_module()
    payload = {
        "recommendation": {"metadata": {
            "resolution_control": {
                "schema_version": "kaims.resolution-control.v1",
                "disposition": "approval_required",
                "approval_required": True,
                "conflicts": [],
            },
            "execution_plan": {
                "plan_kind": "diagnostic",
                "diagnostic_only": True,
                "execution_ready": False,
                "commands": ["kubectl get pods"],
            },
        }},
        "decision": {"requires_approval": True},
    }

    assert module._is_auto_close_diagnostic_resolution(payload) is False


def test_build_policy_blocked_action_returns_approval_wait_state() -> None:
    module = load_remediation_app_module()

    payload = {
        "recommendation": {
            "id": "22222222-2222-2222-2222-222222222222",
            "incident_id": "11111111-1111-1111-1111-111111111111",
            "tenant_id": "tenant-a",
        }
    }

    action = module._build_policy_blocked_action(payload, "auto execution blocked: confidence below threshold")

    assert action is not None
    assert str(action.incident_id) == "11111111-1111-1111-1111-111111111111"
    assert action.action_type == "policy-blocked"
    assert action.status.value == "awaiting_approval"
    assert action.metadata.get("policy_blocked") is True

@pytest.mark.asyncio
async def test_runbook_governance_uses_immutable_plan_identity(monkeypatch):
    from unittest.mock import AsyncMock
    from types import SimpleNamespace
    module = load_remediation_app_module()
    class Session:
        async def __aenter__(self): return self
        async def __aexit__(self, *args): return False
    governance = {'status': 'approved', 'payload': {'checksum_sha256': 'sha256:approved',
                   'approval_expires_at': '2099-01-01T00:00:00Z'}}
    repository = SimpleNamespace(get_runbook_governance=AsyncMock(return_value=governance))
    monkeypatch.setattr(module, 'IncidentRepository', lambda _: repository)
    module.app.state.session_factory = Session
    module.settings.database_enabled = True
    approval = SimpleNamespace(tenant_id='tenant-a', metadata={'execution_plan': {
        'runbook_governance_id': 'governed-id', 'playbook_version': 3,
        'runbook_checksum': 'sha256:approved'}})
    await module._require_persisted_approved_runbook(approval)
    repository.get_runbook_governance.assert_awaited_once_with('governed-id',3,tenant_id='tenant-a')
    approval.metadata['execution_plan']['runbook_checksum'] = 'sha256:tampered'
    with pytest.raises(module.PolicyViolation, match='checksum'):
        await module._require_persisted_approved_runbook(approval)
    approval.metadata['execution_plan']['runbook_checksum'] = 'sha256:approved'
    governance['status'] = 'suspended'
    with pytest.raises(module.PolicyViolation, match='suspended'):
        await module._require_persisted_approved_runbook(approval)


def test_successful_async_receipt_advances_canonical_lifecycle_without_faking_recovery():
    from types import SimpleNamespace
    from uuid import uuid4
    module = load_remediation_app_module()
    incident, recommendation = uuid4(), uuid4()
    lifecycle = module.create_lifecycle(tenant_id='tenant-a',incident_id=incident,recommendation_id=recommendation,
        plan={},state=module.ResolutionState.READY_TO_EXECUTE)
    action = SimpleNamespace(id=uuid4(),status=RemediationStatus.SUCCEEDED,error=None,
        parameters={'resolution_lifecycle':lifecycle,'execution_result':{'executed':True,'recovery_validated':True}},metadata={})
    module._advance_action_lifecycle(action)
    assert action.parameters['resolution_lifecycle']['state']=='validating'
    assert action.parameters['resolution_lifecycle']['state']!='recovered'
    action.parameters={'resolution_lifecycle':lifecycle,'execution_result':{'executed':False}}
    with pytest.raises(ValueError,match='illegal resolution lifecycle transition'):
        module._advance_action_lifecycle(action)


def test_dispatch_failure_before_executor_acceptance_remains_a_truthful_retry_block():
    from types import SimpleNamespace
    from uuid import uuid4
    module=load_remediation_app_module()
    lifecycle=module.create_lifecycle(tenant_id='tenant-a',incident_id=uuid4(),recommendation_id=uuid4(),
        plan={},state=module.ResolutionState.READY_TO_EXECUTE)
    action=SimpleNamespace(id=uuid4(),status=RemediationStatus.FAILED,error='Executor transport unavailable',
        parameters={'resolution_lifecycle':lifecycle},metadata={})
    module._advance_action_lifecycle(action)
    assert action.parameters['resolution_lifecycle']['state']=='blocked_retryable'
    assert action.parameters['resolution_lifecycle']['reason_code']=='dispatch_not_accepted'
