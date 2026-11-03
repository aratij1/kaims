from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import NAMESPACE_URL, uuid5

from common.models import Approval as ApprovalModel
from common.orchestration.execution_plan_contract import canonical_plan_fingerprint


_TEST_CAPABILITIES = {
    "restart_service": "linux.restart_service",
    "restart_pod": "kubernetes.restart_workload",
    "rollback_deployment": "jenkins.rollback_deployment",
    "scale_service": "kubernetes.scale_workload",
    "clear_cache": "cache.clear_cache",
    "failover_database": "database.failover",
    "terraform_rollback": "terraform.rollback",
    "api_execution": "application.invoke_recovery_endpoint",
    "script_execution": "application.invoke_recovery_endpoint",
}


def governed_approval(**kwargs: Any) -> ApprovalModel:
    """Build a test approval whose legacy fixture intent is an explicit v2 action."""

    tenant_id = str(kwargs.get("tenant_id") or "tenant-a")
    incident_id = str(kwargs["incident_id"])
    metadata = dict(kwargs.get("metadata") or {})
    recommendation_id = str(kwargs.get("recommendation_id") or "")
    supplied_plan = metadata.get("execution_plan")
    supplied_plan = dict(supplied_plan) if isinstance(supplied_plan, dict) else {}
    if (
        supplied_plan.get("schema_version") == "kaims.execution-plan.v2"
        and supplied_plan.get("plan_fingerprint")
    ):
        plan = supplied_plan
    else:
        commands = list(supplied_plan.get("commands") or metadata.get("recommended_commands") or [])
        scripts = list(supplied_plan.get("scripts") or [])
        queries = list(supplied_plan.get("queries") or [])
        connection = metadata.get("connection_profile") if isinstance(metadata.get("connection_profile"), dict) else {}
        intent = " ".join(
            [
                str(metadata.get("recommended_action") or ""),
                str(kwargs.get("comment") or ""),
                *[str(item) for item in commands],
                *[str(item) for item in scripts],
            ]
        ).lower()
        if "scale" in intent:
            operation = "scale_service"
        elif "rollback" in intent or "rollout undo" in intent:
            operation = "rollback_deployment"
        elif "restart pod" in intent or "rollout restart" in intent:
            operation = "restart_pod"
        elif scripts:
            operation = "script_execution"
        elif "restart" in intent:
            operation = "restart_service"
        elif "terraform" in intent:
            operation = "terraform_rollback"
        else:
            operation = "api_execution"
        target_candidates = (
            metadata.get("remediation_target"), metadata.get("target"), metadata.get("service"),
            connection.get("service"), supplied_plan.get("remediation_target"), incident_id,
        )
        target = next(
            str(value).strip() for value in target_candidates
            if str(value or "").strip().lower()
            not in {"", "-", "unknown", "unknown service", "not configured", "none", "null"}
        )
        plan_id = uuid5(NAMESPACE_URL, f"test-plan:{tenant_id}:{incident_id}:{operation}")
        connector_id = str(supplied_plan.get("connector_id") or "test-connector")
        capability_id = _TEST_CAPABILITIES[operation]
        plan = {
            **supplied_plan,
            "schema_version": "kaims.execution-plan.v2",
            "tenant_id": tenant_id,
            "incident_id": incident_id,
            "plan_id": str(plan_id),
            "actions": [{
                "action_id": operation,
                "connector_id": connector_id,
                "target_resource_id": target,
                "inputs": {"operation": operation},
                "safety_binding": {
                    "capability": {
                        "capability_id": capability_id,
                        "connector_id": connector_id,
                        "operation": operation,
                        "allowed_resource_ids": [target],
                    },
                    "credential": {
                        "reference": str(connection.get("credential_ref") or "vault://test/credential"),
                        "tenant_id": tenant_id,
                        "connector_id": connector_id,
                        "resource_ids": [target],
                    },
                    "blast_radius": {
                        "target_resource_id": target,
                        "affected_resource_ids": [target],
                    },
                    "preflight": {
                        "capability_id": capability_id,
                        "target_resource_id": target,
                    },
                },
            }],
            "commands": commands,
            "scripts": scripts,
            "queries": queries,
            "preflight": list(supplied_plan.get("preflight") or []),
            "validation_commands": list(supplied_plan.get("validation_commands") or []),
            "validation_endpoints": list(supplied_plan.get("validation_endpoints") or []),
            "rollback_commands": list(supplied_plan.get("rollback_commands") or []),
            "rollback_mode": str(supplied_plan.get("rollback_mode") or "not_applicable"),
            "execution_ready": bool(supplied_plan.get("execution_ready", True)),
            "readiness_blocks": list(supplied_plan.get("readiness_blocks") or []),
            "mutating": bool(supplied_plan.get("mutating", True)),
            "plan_kind": str(supplied_plan.get("plan_kind") or "remediation"),
            "remediation_target": target,
            "service": str(supplied_plan.get("service") or metadata.get("service") or connection.get("service") or target),
        }
        plan["plan_fingerprint"] = canonical_plan_fingerprint(plan)
    target = str(
        plan.get("target_resource_id")
        or plan.get("remediation_target")
        or metadata.get("remediation_target")
        or metadata.get("service")
        or incident_id
    )
    connector_id = str(plan.get("connector_id") or "test-connector")
    plan.setdefault("expiry", datetime(2099, 1, 1, tzinfo=UTC).isoformat())
    plan = {
        **plan,
        "rca_version": str(plan.get("rca_version") or recommendation_id or "rca-test-v1"),
        "evidence_snapshot_id": str(plan.get("evidence_snapshot_id") or "snapshot-test-v1"),
        "recommendation_version": str(plan.get("recommendation_version") or recommendation_id),
        "remediation_target": target,
        "connector_id": connector_id,
    }
    plan["plan_fingerprint"] = canonical_plan_fingerprint(plan)
    rollback = plan.get("rollback") or plan.get("rollback_commands")
    metadata.update({
        "execution_plan": plan,
        "rca_version": plan["rca_version"],
        "evidence_snapshot_id": plan["evidence_snapshot_id"],
        "recommendation_version": plan["recommendation_version"],
        "target_resource_id": target,
        "connector_id": connector_id,
        "rollback_plan": rollback,
    })
    kwargs["metadata"] = metadata
    kwargs["tenant_id"] = tenant_id
    kwargs["plan_id"] = plan["plan_id"]
    kwargs["plan_fingerprint"] = plan["plan_fingerprint"]
    kwargs.setdefault("approval_expires_at", datetime(2099, 1, 1, tzinfo=UTC))
    return ApprovalModel(**kwargs)
