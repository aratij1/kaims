from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from common.orchestration.safe_remediation import BlastRadiusScope, CapabilitySpec


class RiskLevel(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ApprovalLevel(StrEnum):
    NONE = "none"
    HITL_APPROVER = "hitl_approver"
    ADMIN = "admin"


class CapabilityTrustLevel(StrEnum):
    EXPERIMENTAL = "experimental"
    HITL_ONLY = "hitl_only"
    TRUSTED = "trusted"
    AUTONOMOUS = "autonomous"


class CapabilityDefinition(BaseModel):
    model_config = ConfigDict(extra="forbid")

    capability_id: str
    description: str
    risk_level: RiskLevel
    supported_connectors: list[str]
    required_permissions: list[str]
    input_schema: dict[str, Any] = Field(default_factory=dict)
    preconditions: list[str] = Field(default_factory=list)
    dry_run_supported: bool
    validation: list[str]
    rollback_capability: str | None = None
    allowed_environments: list[str] = Field(default_factory=lambda: ["development", "test", "staging", "production"])
    maximum_blast_radius: BlastRadiusScope
    required_approval_level: ApprovalLevel
    trust_level: CapabilityTrustLevel = CapabilityTrustLevel.EXPERIMENTAL
    mutating: bool = True

    @field_validator("capability_id")
    @classmethod
    def capability_id_is_namespaced(cls, value: str) -> str:
        value = value.strip()
        if "." not in value or any(part == "" for part in value.split(".")):
            raise ValueError("capability_id must be a namespaced identifier")
        return value

    @model_validator(mode="after")
    def mutation_has_validation_and_governance(self) -> "CapabilityDefinition":
        if not self.supported_connectors:
            raise ValueError("capability requires at least one supported connector")
        if self.mutating and not self.validation:
            raise ValueError("mutating capability requires validation")
        if self.trust_level == CapabilityTrustLevel.AUTONOMOUS and self.required_approval_level != ApprovalLevel.NONE:
            raise ValueError("autonomous trust cannot require approval")
        return self


class CapabilityDecision(BaseModel):
    allowed: bool
    reason_codes: list[str] = Field(default_factory=list)
    required_approval_level: ApprovalLevel
    capability: CapabilityDefinition


_BLAST_ORDER = {
    BlastRadiusScope.RESOURCE: 0,
    BlastRadiusScope.SINGLE_SERVICE: 1,
    BlastRadiusScope.MULTI_SERVICE: 2,
    BlastRadiusScope.ENVIRONMENT: 3,
    BlastRadiusScope.UNKNOWN: 4,
}


class CapabilityRegistry:
    def __init__(self, capabilities: list[CapabilityDefinition] | None = None) -> None:
        self._capabilities: dict[str, CapabilityDefinition] = {}
        for capability in capabilities or []:
            self.register(capability)

    def register(self, capability: CapabilityDefinition) -> None:
        if capability.capability_id in self._capabilities:
            raise ValueError(f"capability {capability.capability_id} is already registered")
        self._capabilities[capability.capability_id] = capability

    def get(self, capability_id: str) -> CapabilityDefinition:
        try:
            return self._capabilities[capability_id]
        except KeyError as exc:
            raise KeyError(f"unregistered capability {capability_id}") from exc

    def list(self) -> list[CapabilityDefinition]:
        return [self._capabilities[key] for key in sorted(self._capabilities)]

    def evaluate(
        self,
        capability_id: str,
        *,
        connector_id: str,
        environment: str,
        blast_radius: BlastRadiusScope,
        parameters: dict[str, Any],
    ) -> CapabilityDecision:
        capability = self.get(capability_id)
        reasons: list[str] = []
        if connector_id not in capability.supported_connectors:
            reasons.append("unsupported_connector")
        if environment not in capability.allowed_environments:
            reasons.append("environment_not_allowed")
        if _BLAST_ORDER[blast_radius] > _BLAST_ORDER[capability.maximum_blast_radius]:
            reasons.append("blast_radius_exceeds_limit")
        required = capability.input_schema.get("required") if isinstance(capability.input_schema, dict) else []
        if isinstance(required, list) and any(name not in parameters for name in required):
            reasons.append("required_parameters_missing")
        if capability.trust_level in {CapabilityTrustLevel.EXPERIMENTAL, CapabilityTrustLevel.HITL_ONLY}:
            if capability.required_approval_level == ApprovalLevel.NONE:
                reasons.append("untrusted_capability_requires_hitl")
        return CapabilityDecision(
            allowed=not reasons,
            reason_codes=reasons,
            required_approval_level=capability.required_approval_level,
            capability=capability,
        )

    def bind(
        self,
        capability_id: str,
        *,
        connector_id: str,
        allowed_resource_ids: list[str],
    ) -> CapabilitySpec:
        capability = self.get(capability_id)
        if connector_id not in capability.supported_connectors:
            raise ValueError("connector is not supported by registered capability")
        return CapabilitySpec(
            capability_id=capability.capability_id,
            connector_id=connector_id,
            operation=capability.capability_id.split(".", 1)[1],
            allowed_resource_ids=allowed_resource_ids,
            required_permissions=capability.required_permissions,
            mutating=capability.mutating,
            reversible=bool(capability.rollback_capability),
            dry_run_supported=capability.dry_run_supported,
            validation_required=True,
            registered=True,
        )


def _definition(
    capability_id: str,
    connector: str,
    risk: RiskLevel,
    permission: str,
    *,
    rollback: str | None = None,
    blast: BlastRadiusScope = BlastRadiusScope.SINGLE_SERVICE,
    approval: ApprovalLevel = ApprovalLevel.HITL_APPROVER,
    required: list[str] | None = None,
    mutating: bool = True,
    trust: CapabilityTrustLevel = CapabilityTrustLevel.HITL_ONLY,
    allowed_environments: list[str] | None = None,
) -> CapabilityDefinition:
    return CapabilityDefinition(
        capability_id=capability_id,
        description=capability_id.replace(".", " ").replace("_", " "),
        risk_level=risk,
        supported_connectors=[connector],
        required_permissions=[permission],
        input_schema={"type": "object", "required": required or [], "additionalProperties": False},
        preconditions=["target identity verified", "connector permission verified"],
        dry_run_supported=True,
        validation=["target health verified", "original alert state evaluated"],
        rollback_capability=rollback,
        allowed_environments=(
            allowed_environments
            if allowed_environments is not None
            else ["development", "test", "staging", "production"]
        ),
        maximum_blast_radius=blast,
        required_approval_level=approval,
        trust_level=trust,
        mutating=mutating,
    )


def default_capability_registry() -> CapabilityRegistry:
    rows = [
        _definition("kubernetes.restart_workload", "kubernetes", RiskLevel.MEDIUM, "deployments.patch", rollback="kubernetes.rollback_deployment"),
        _definition("kubernetes.rollback_deployment", "kubernetes", RiskLevel.HIGH, "deployments.patch"),
        _definition("kubernetes.scale_workload", "kubernetes", RiskLevel.HIGH, "deployments.patch", required=["replicas"]),
        _definition("linux.restart_service", "ssh-linux", RiskLevel.MEDIUM, "service.restart", rollback="linux.restart_service"),
        _definition("windows.restart_service", "windows-powershell", RiskLevel.MEDIUM, "service.restart", rollback="windows.restart_service"),
        _definition("database.kill_session", "mysql", RiskLevel.HIGH, "session.kill", required=["session_id"]),
        _definition("database.failover", "mysql", RiskLevel.CRITICAL, "database.failover", blast=BlastRadiusScope.ENVIRONMENT, approval=ApprovalLevel.ADMIN),
        _definition(
            "database.collect_diagnostics", "mysql", RiskLevel.LOW, "diagnostics.read",
            approval=ApprovalLevel.NONE, mutating=False, trust=CapabilityTrustLevel.TRUSTED,
        ),
        _definition("kafka.rebalance", "kafka", RiskLevel.HIGH, "consumer_group.rebalance"),
        _definition("kafka.restart_consumer", "kafka", RiskLevel.MEDIUM, "consumer.restart"),
        _definition("cache.clear_cache", "redis", RiskLevel.HIGH, "cache.clear"),
        _definition("cloud.restart_vm", "cloud-api", RiskLevel.HIGH, "vm.restart"),
        _definition("cloud.scale_instance_group", "cloud-api", RiskLevel.HIGH, "instance_group.scale", required=["desired_capacity"]),
        _definition("pipeline.restart_job", "pipeline-api", RiskLevel.MEDIUM, "job.restart"),
        _definition("airflow.retry_task", "airflow", RiskLevel.MEDIUM, "task.retry", required=["dag_id", "task_id", "run_id"]),
        _definition("jenkins.rollback_deployment", "jenkins", RiskLevel.HIGH, "job.build", rollback="jenkins.rollback_deployment"),
        _definition("terraform.rollback", "terraform", RiskLevel.CRITICAL, "state.apply", blast=BlastRadiusScope.ENVIRONMENT, approval=ApprovalLevel.ADMIN),
        _definition("application.invoke_recovery_endpoint", "custom-api", RiskLevel.MEDIUM, "endpoint.invoke", required=["endpoint_id"]),
        _definition(
            "application.restart_service",
            "api",
            RiskLevel.MEDIUM,
            "service.restart",
            rollback="application.restart_service",
            allowed_environments=["development", "test", "staging", "production", "demo"],
        ),
        _definition(
            "application.scale_workload", "api", RiskLevel.HIGH, "service.scale",
            required=["replicas"], rollback="application.scale_workload",
        ),
    ]
    return CapabilityRegistry(rows)
