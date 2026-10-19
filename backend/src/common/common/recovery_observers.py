"""Operator-managed recovery checks shared by plan compilation and closure."""

from __future__ import annotations

import math
from hashlib import sha256
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

from common.orchestration.execution_plan_contract import ValidatorSpec

REQUIRED_RECOVERY_KINDS = {
    "availability",
    "alert_clearance",
    "error_rate",
    "latency",
    "dependency_health",
    "critical_alerts",
}


class ObserverSource(BaseModel):
    model_config = ConfigDict(extra="forbid")
    source_id: str = Field(min_length=1)
    tenant_id: str = Field(min_length=1)
    adapter: Literal["prometheus"] = "prometheus"
    endpoint: str
    bearer_token_env: str | None = Field(default=None, pattern=r"^[A-Za-z_][A-Za-z0-9_]*$")

    @model_validator(mode="after")
    def valid_endpoint(self):
        url = urlsplit(self.endpoint)
        if (
            url.scheme not in {"http", "https"}
            or not url.hostname
            or url.username
            or url.password
            or url.query
            or url.fragment
            or url.hostname in {"169.254.169.254", "metadata.google.internal"}
        ):
            raise ValueError("observer endpoint must be a configured HTTP(S) base URL without credentials")
        return self


class RegisteredRecoveryCheck(BaseModel):
    model_config = ConfigDict(extra="forbid")
    spec: ValidatorSpec
    query: str = Field(min_length=1, max_length=16000)
    step_seconds: int = Field(default=15, ge=1, le=60)

    @model_validator(mode="after")
    def query_is_bound(self):
        expected = "promql:sha256:" + sha256(self.query.encode()).hexdigest()
        if self.spec.check_reference != expected:
            raise ValueError("validator check_reference must bind the exact approved PromQL")
        if self.spec.evaluation_operator not in {"eq", "ne", "lt", "lte", "gt", "gte"}:
            raise ValueError("Prometheus requires a numeric comparison operator")
        try:
            threshold = float(self.spec.threshold)
        except (TypeError, ValueError) as exc:
            raise ValueError("Prometheus requires a finite numeric threshold") from exc
        if not math.isfinite(threshold):
            raise ValueError("Prometheus requires a finite numeric threshold")
        if math.ceil(max(300, self.spec.observation_window_seconds) / self.step_seconds) + 1 > 10000:
            raise ValueError("observation window exceeds the sample budget")
        window = max(60, self.spec.observation_window_seconds)
        if self.spec.minimum_sample_count > window // self.step_seconds + 1:
            raise ValueError("minimum_sample_count exceeds the configured observation window")
        return self


class RecoveryProfile(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tenant_id: str = Field(min_length=1)
    environment: str = Field(min_length=1)
    target_resource_id: str = Field(min_length=1)
    alert_name: str = Field(min_length=1)
    operator_verified_incident_ids: list[UUID] = Field(default_factory=list, max_length=500)
    additional_alert_names: list[str] = Field(default_factory=list, max_length=8)
    required_alert_labels: dict[str, str] = Field(default_factory=dict, max_length=16)
    allow_operator_verified_closure: bool = False
    allow_automatic_observation: bool = False
    checks: list[RegisteredRecoveryCheck] = Field(min_length=6, max_length=32)

    @property
    def key(self) -> tuple[str, str, str, str]:
        return self.tenant_id, self.environment, self.target_resource_id, self.alert_name

    @model_validator(mode="after")
    def complete_binding(self):
        names = [self.alert_name, *self.additional_alert_names]
        if any(not name.strip() for name in names) or len(set(names)) != len(names):
            raise ValueError("assessment alert families must be nonempty and unique")
        if any(not key.strip() or not value.strip() for key, value in self.required_alert_labels.items()):
            raise ValueError("required alert labels must contain exact nonempty keys and values")
        specs = [check.spec for check in self.checks]
        if len({spec.validator_id for spec in specs}) != len(specs):
            raise ValueError("duplicate validator identity")
        if not REQUIRED_RECOVERY_KINDS.issubset({spec.kind for spec in specs}):
            raise ValueError("profile must register all six core recovery signals")
        if any(
            spec.tenant_id != self.tenant_id or spec.target_resource_id != self.target_resource_id for spec in specs
        ):
            raise ValueError("validator tenant/target must match the recovery profile")
        return self

    def specs(self) -> list[dict]:
        return [check.spec.model_dump(mode="json") for check in self.checks]


class RecoveryObserverRegistry(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal["kaims.recovery-observers.v1"] = "kaims.recovery-observers.v1"
    sources: list[ObserverSource] = Field(default_factory=list)
    profiles: list[RecoveryProfile] = Field(default_factory=list)

    @model_validator(mode="after")
    def unique_and_scoped(self):
        sources = {(source.tenant_id, source.source_id): source for source in self.sources}
        if len(sources) != len(self.sources):
            raise ValueError("duplicate recovery source or profile")
        profiles_by_key: dict[tuple, list[RecoveryProfile]] = {}
        for profile in self.profiles:
            peers = profiles_by_key.setdefault(profile.key, [])
            for peer in peers:
                # Distinct explicit incident batches may contain different full
                # alert families with the same primary alert. Never allow
                # overlapping or unbounded duplicate registrations.
                if (not profile.allow_operator_verified_closure or not peer.allow_operator_verified_closure
                        or not profile.operator_verified_incident_ids or not peer.operator_verified_incident_ids
                        or set(profile.operator_verified_incident_ids) & set(peer.operator_verified_incident_ids)):
                    raise ValueError("duplicate recovery source or profile")
            peers.append(profile)
        for profile in self.profiles:
            for check in profile.checks:
                spec = check.spec
                if (
                    profile.tenant_id,
                    spec.connector_id,
                ) not in sources or spec.authoritative_source != spec.connector_id:
                    raise ValueError("validator must reference an observer source in its tenant")
        return self

    def profile_for(self, *, tenant_id: str, environment: str, target: str, alert_name: str) -> RecoveryProfile | None:
        key = (tenant_id, environment, target, alert_name)
        matches = [profile for profile in self.profiles if profile.key == key]
        # Execution lookup has no incident identity and cannot disambiguate
        # registrations that are restricted to separate incident batches.
        return matches[0] if len(matches) == 1 else None

    def assessment_profile_for(self, *, tenant_id: str, environment: str, target: str,
                               alerts: list[dict], incident_id: UUID | str | None = None) -> RecoveryProfile | None:
        names = {alert["name"] for alert in alerts}
        matches = [profile for profile in self.profiles
            if (profile.tenant_id, profile.environment, profile.target_resource_id) == (tenant_id, environment, target)
            and profile.allow_operator_verified_closure
            and (not profile.operator_verified_incident_ids or (incident_id is not None and UUID(str(incident_id)) in profile.operator_verified_incident_ids))
            and {profile.alert_name, *profile.additional_alert_names} == names
            and all(all((alert.get("labels") or {}).get(key) == value
                        for key, value in profile.required_alert_labels.items()) for alert in alerts)]
        # Ambiguous operator registrations are not closure authority.
        return matches[0] if len(matches) == 1 else None

    def source_for(self, spec: ValidatorSpec) -> ObserverSource:
        return next(
            source
            for source in self.sources
            if (source.tenant_id, source.source_id)
            == (
                spec.tenant_id,
                spec.connector_id,
            )
        )


def load_recovery_observer_registry(path: str) -> RecoveryObserverRegistry:
    """Read only operator configuration; never load locations supplied by a plan."""
    target = Path(path)
    if not target.is_absolute() and not target.is_file():
        for parent in Path(__file__).resolve().parents:
            if (parent / "pyproject.toml").is_file():
                target = parent / target
                break
    return RecoveryObserverRegistry.model_validate_json(target.read_text(encoding="utf-8"))
