from __future__ import annotations

import ipaddress
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit

from uuid import NAMESPACE_URL, uuid5

from ai_workbench_common.agentic import AgentContext, BaseAgent
from common.models import RemediationAction, RemediationStatus, ResolutionReport
from common.orchestration.execution_plan_contract import ValidatorSpec, canonical_plan_fingerprint, verify_plan_fingerprint
from common.orchestration.outcome_validation import (
    ClosedLoopAction,
    ClosedLoopDecision,
    ClosedLoopState,
    ValidationCheck,
    ValidationObservation,
    ValidationPlan,
    ValidationOutcome,
    decide_closed_loop,
    decide_outcome_validation,
)
from common.resolution_lifecycle import LifecycleActor, ResolutionState, extract_lifecycle, transition_lifecycle


def _validation_urls(plan: dict) -> tuple[list[str], int]:
    # v1 URL validation is permanently non-executable. The tuple remains only
    # for compatibility telemetry while producers migrate to ValidatorSpec.
    return [], 0


def _validation_endpoints(plan: dict[str, Any]) -> list[dict[str, str]]:
    return []


def _typed_validators(action: RemediationAction, plan: dict[str, Any]) -> list[ValidatorSpec]:
    supplied = plan.get("validators") if isinstance(plan.get("validators"), list) else []
    registry = action.parameters.get("validator_registry_snapshot")
    registry = registry if isinstance(registry, list) else []
    registered = {
        str(item.get("validator_id") or ""): item
        for item in registry
        if isinstance(item, dict) and str(item.get("validator_id") or "")
    }
    accepted: list[ValidatorSpec] = []
    for payload in supplied:
        if not isinstance(payload, dict):
            continue
        try:
            spec = ValidatorSpec.model_validate(payload)
        except ValueError:
            continue
        registry_payload = registered.get(spec.validator_id)
        if (
            registry_payload != spec.model_dump(mode="json")
            or spec.tenant_id != action.tenant_id
            or spec.target_resource_id != action.target
        ):
            continue
        accepted.append(spec)
    return accepted


def _safe_validation_url(url: str) -> bool:
    try:
        parsed = urlsplit(str(url or "").strip())
        hostname = str(parsed.hostname or "").strip().lower().rstrip(".")
        if parsed.scheme not in {"http", "https"} or not hostname or parsed.username or parsed.password:
            return False
        if hostname in {"localhost", "metadata.google.internal"} or hostname.endswith(".localhost"):
            return False
        try:
            address = ipaddress.ip_address(hostname)
        except ValueError:
            return True
        return not any(
            (
                address.is_loopback,
                address.is_link_local,
                address.is_multicast,
                address.is_unspecified,
                address.is_reserved,
            )
        )
    except ValueError:
        return False


def _approved_plan_integrity(action: RemediationAction, plan: dict[str, Any]) -> bool:
    contract = action.parameters.get("execution_contract")
    if not isinstance(contract, dict) or contract.get("schema_version") != "kaims.remediation.v3":
        return False
    if plan.get("schema_version") != "kaims.execution-plan.v2" or not verify_plan_fingerprint(plan):
        return False
    unsigned_contract = {key: value for key, value in contract.items() if key != "binding_fingerprint"}
    fingerprint = str(plan.get("plan_fingerprint") or "")
    governance_bound = all(
        str(plan.get(key) or "").strip()
        for key in ("rca_version", "evidence_snapshot_id", "recommendation_version")
    )
    return bool(
        governance_bound
        and str(contract.get("binding_fingerprint") or "") == canonical_plan_fingerprint(unsigned_contract)
        and contract.get("plan") == plan
        and str(contract.get("plan_id") or "") == str(plan.get("plan_id") or "")
        and str(contract.get("plan_fingerprint") or "") == fingerprint
        and str(action.parameters.get("approved_plan_fingerprint") or "") == fingerprint
        and str(contract.get("execution_id") or "") == str(action.id)
        and str((contract.get("target") or {}).get("name") or "") == str(action.target)
    )


def _stability_window(action: RemediationAction, plan: dict[str, Any], *, observed_at: datetime) -> tuple[bool, float, int]:
    required_seconds = max(60, min(int(plan.get("stability_window_seconds") or 300), 3600))
    completed_at = action.completed_at
    if completed_at is None:
        return False, 0.0, required_seconds
    if completed_at.tzinfo is None:
        completed_at = completed_at.replace(tzinfo=timezone.utc)
    elapsed = max(0.0, (observed_at - completed_at.astimezone(timezone.utc)).total_seconds())
    return elapsed >= required_seconds, elapsed, required_seconds


class ClosureValidationAgent(BaseAgent):
    name = "validation-agent"

    async def can_execute(self, context: AgentContext) -> bool:
        return "remediation-action" in context.previous_agent_results

    async def execute(self, context: AgentContext) -> ResolutionReport:
        action_payload = context.previous_agent_results.get("remediation-action")
        if not isinstance(action_payload, dict):
            raise ValueError("AgentContext.previous_agent_results['remediation-action'] is required")
        report = await self.validate(RemediationAction.model_validate(action_payload))
        context.set_result(self.name, report.model_dump(mode="json"))
        return report

    async def validate(self, action: RemediationAction) -> ResolutionReport:
        execution_plan = action.parameters.get("execution_plan")
        execution_plan = execution_plan if isinstance(execution_plan, dict) else {}
        _, supplied_count = _validation_urls(execution_plan)
        diagnostic_closure = bool(action.parameters.get("diagnostic_closure")) and action.status == RemediationStatus.SKIPPED
        if diagnostic_closure:
            details = action.parameters.get("diagnostic_details")
            details = details if isinstance(details, dict) else {}
            validation = {
                "diagnostic_completed": True,
                "corrective_action_executed": False,
                "evidence_recorded": bool(details or execution_plan),
                "execution_not_applicable": True,
            }
            lifecycle = extract_lifecycle(action.parameters, action.metadata)
            watch_only_authorized = action.parameters.get("watch_only_closure") is True
            return ResolutionReport(
                tenant_id=action.tenant_id,
                id=uuid5(NAMESPACE_URL, f"kaiops:closure:{action.id}:diagnostic"),
                incident_id=action.incident_id,
                recommendation_id=action.recommendation_id,
                resolution_plan_id=action.resolution_plan_id,
                plan_fingerprint=action.plan_fingerprint,
                approval_id=action.approval_id,
                remediation_action_id=action.id,
                closure_kind="diagnostic",
                closure_status="diagnostic_complete",
                root_cause=str(action.parameters.get("root_cause") or "Diagnostic analysis completed"),
                impact=str(action.parameters.get("impact") or "No confirmed recoverable service impact"),
                action_taken=action.output or "Diagnostic-only plan completed; no corrective action executed.",
                validation=validation,
                alerts_cleared=False,
                health_restored=False,
                knowledge_base_entry=f"Incident {action.incident_id} remains open after diagnostic analysis; no corrective operation or recovery validation was performed. Details: {details}",
                lessons_learned=[
                    "Diagnostic completion does not establish alert clearance or service recovery.",
                    "Attach a reviewed corrective playbook if future matching incidents require automated remediation.",
                ],
                metadata={
                    "closure_kind": "diagnostic",
                    "watch_only_authorized": watch_only_authorized,
                    "incident_terminal": watch_only_authorized,
                    "diagnostic_details": details,
                    **({"resolution_lifecycle": lifecycle} if lifecycle else {}),
                },
            )
        validation: dict[str, bool] = {
            "remediation_succeeded": action.status == RemediationStatus.SUCCEEDED,
            "approved_plan_fingerprint_preserved": _approved_plan_integrity(action, execution_plan),
        }
        execution_result = action.parameters.get("execution_result")
        execution_result = execution_result if isinstance(execution_result, dict) else {}
        recovery_evidence = execution_result.get("recovery_evidence")
        recovery_evidence = recovery_evidence if isinstance(recovery_evidence, dict) else {}
        # Retain this executor assertion only as an audit signal. It is never a
        # closure input; the validation service collects its own observations.
        executor_recovery_validated = bool(
            execution_result.get("recovery_validated") is True
            and recovery_evidence.get("recovery_validated") is True
            and recovery_evidence.get("executed") is True
            and str(execution_result.get("build_result") or "").upper() == "SUCCESS"
        )
        validation["executor_recovery_validated"] = executor_recovery_validated
        governed_validators = _typed_validators(action, execution_plan)
        supplied_validators = execution_plan.get("validators") if isinstance(execution_plan.get("validators"), list) else []
        supplied_observations = action.parameters.get("validation_observations")
        supplied_observations = supplied_observations if isinstance(supplied_observations, list) else []
        supplied_pre_state = action.parameters.get("pre_state_validation_observations")
        supplied_pre_state = supplied_pre_state if isinstance(supplied_pre_state, list) else []
        observations: list[dict[str, Any]] = []
        pre_state_observations: list[dict[str, Any]] = []
        validator_results: dict[str, bool] = {}
        passed_kinds: set[str] = set()
        observed_at = datetime.now(timezone.utc)
        completed_at = action.completed_at
        if completed_at is not None:
            completed_at = completed_at.replace(tzinfo=timezone.utc) if completed_at.tzinfo is None else completed_at.astimezone(timezone.utc)
        stability_required = max(60, min(int(execution_plan.get("stability_window_seconds") or 300), 3600))
        validator_windows_complete = True
        for index, validator in enumerate(governed_validators, start=1):
            for item in supplied_pre_state:
                if not isinstance(item, dict) or str(item.get("validator_id") or "") != validator.validator_id:
                    continue
                try:
                    if item.get("phase", "pre_state") != "pre_state":
                        continue
                    pre_observation = ValidationObservation.model_validate({**item, "phase": "pre_state"})
                except ValueError:
                    continue
                if (
                    str(pre_observation.execution_id) == str(action.id)
                    and pre_observation.plan_fingerprint == str(execution_plan.get("plan_fingerprint") or "")
                    and pre_observation.connector_id == validator.connector_id
                    and pre_observation.target_resource_id == validator.target_resource_id
                    and pre_observation.observed_at.tzinfo is not None
                    and pre_observation.observed_at <= observed_at
                ):
                    pre_state_observations.append({
                        **pre_observation.model_dump(mode="json"), "kind": validator.kind,
                    })
            samples: list[tuple[datetime, dict[str, Any]]] = []
            for item in supplied_observations:
                if not isinstance(item, dict) or str(item.get("validator_id") or "") != validator.validator_id:
                    continue
                try:
                    if item.get("phase", "post_state") != "post_state":
                        continue
                    observation = ValidationObservation.model_validate({**item, "phase": "post_state"})
                except ValueError:
                    continue
                if (
                    str(observation.execution_id) != str(action.id)
                    or observation.plan_fingerprint != str(execution_plan.get("plan_fingerprint") or "")
                    or observation.connector_id != validator.connector_id
                    or observation.target_resource_id != validator.target_resource_id
                ):
                    continue
                timestamp = observation.observed_at
                if timestamp.tzinfo is None or timestamp.astimezone(timezone.utc) > observed_at:
                    continue
                if completed_at is None or timestamp < completed_at:
                    continue
                window_start = observation.observation_window_start
                if window_start is not None and (window_start.tzinfo is None or window_start < completed_at):
                    continue
                samples.append((timestamp.astimezone(timezone.utc), observation.model_dump(mode="json")))
            samples.sort(key=lambda row: row[0])
            passed = len({timestamp for timestamp, _ in samples}) >= validator.minimum_sample_count and all(item.get("passed") is True for _, item in samples)
            required_window = max(stability_required, validator.observation_window_seconds)
            window_complete = bool(samples) and (samples[-1][0] - samples[0][0]).total_seconds() >= required_window
            validator_windows_complete = validator_windows_complete and window_complete
            validation[f"validator_{index}"] = passed
            validator_results[validator.validator_id] = passed
            if passed:
                passed_kinds.add(validator.kind)
            observations.extend({**item, "kind": validator.kind} for _, item in samples)
        validation["validation_supplied"] = bool(supplied_validators)
        validation["validation_executable"] = bool(supplied_validators) and len(governed_validators) == len(supplied_validators)
        required_kinds = {
            str(item).strip().lower()
            for item in execution_plan.get(
                "required_validation_kinds",
                ["availability", "alert_clearance", "error_rate", "latency", "dependency_health", "critical_alerts"],
            )
            if str(item).strip()
        }
        independent_checks_passed = bool(governed_validators) and all(
            passed for name, passed in validation.items() if name.startswith("validator_")
        ) and required_kinds.issubset(passed_kinds)
        validation["independent_checks_passed"] = independent_checks_passed
        elapsed_stability_passed, stability_elapsed, stability_required = _stability_window(
            action,
            execution_plan,
            observed_at=observed_at,
        )
        stability_passed = elapsed_stability_passed and validator_windows_complete
        recovery_checks = {
            "triggering_alert_cleared": "alert_clearance" in passed_kinds,
            "availability_recovered": "availability" in passed_kinds,
            "error_rate_recovered": "error_rate" in passed_kinds,
            "latency_within_slo": "latency" in passed_kinds,
            "dependency_health_stable": "dependency_health" in passed_kinds,
            "no_new_critical_alerts": "critical_alerts" in passed_kinds,
            "stability_window_completed": stability_passed,
        }
        if "business" in required_kinds:
            recovery_checks["business_check_passed"] = "business" in passed_kinds
        validation.update(recovery_checks)
        validation["alerts_cleared"] = recovery_checks["triggering_alert_cleared"]
        validation["all_recovery_checks_passed"] = all(recovery_checks.values())
        restored = (
            validation["remediation_succeeded"]
            and validation["validation_supplied"]
            and validation["validation_executable"]
            and validation["approved_plan_fingerprint_preserved"]
            and validation["independent_checks_passed"]
            and validation["all_recovery_checks_passed"]
        )
        rollback_action = next(
            (
                str(item.get("rollback_action"))
                for item in execution_plan.get("actions", [])
                if isinstance(item, dict) and str(item.get("rollback_action") or "").strip()
            ),
            None,
        )
        collection = action.parameters.get("recovery_observation_collection")
        collection = collection if isinstance(collection, dict) else {}
        collection_pending = (
            collection.get("status") in {"warming_up", "unavailable"}
            and validation["approved_plan_fingerprint_preserved"]
            and validation["validation_executable"]
            and not any(item.get("passed") is False for item in observations)
        )
        outcome_decision = decide_outcome_validation(
            execution_id=action.id,
            incident_id=action.incident_id,
            plan_fingerprint=str(execution_plan.get("plan_fingerprint") or ""),
            target_resource_id=action.target,
            execution_succeeded=validation["remediation_succeeded"],
            integrity_preserved=validation["approved_plan_fingerprint_preserved"],
            checks=recovery_checks,
            independent_checks_passed=independent_checks_passed,
            stability_passed=stability_passed,
            stability_window_seconds=stability_required,
            observation_ids=[str(item.get("result_checksum")) for item in observations],
            rollback_action=rollback_action,
            collection_pending=collection_pending,
        )
        signal_by_kind = {
            "alert_clearance": "original_alert",
            "availability": "service_health",
            "error_rate": "metric",
            "latency": "slo",
            "dependency_health": "dependency_health",
            "critical_alerts": "original_alert",
            "business_transaction": "synthetic_probe",
            "data_integrity": "metric",
            "database_replication": "dependency_health",
            "queue_lag": "metric",
        }
        remediation_plan = action.parameters.get("remediation_plan")
        remediation_plan = remediation_plan if isinstance(remediation_plan, dict) else {}
        typed_checks = [
                ValidationCheck(
                    check_id=validator.validator_id,
                    signal=signal_by_kind.get(validator.kind, "metric"),
                    connector_id=validator.connector_id,
                    target_resource_id=validator.target_resource_id,
                    check_reference=validator.check_reference,
                    expected_condition=validator.expected_condition,
                    required=True,
                    independent=True,
                )
                for validator in governed_validators
            ]
        maximum_attempts = max(1, min(int(action.parameters.get("maximum_autonomous_attempts") or 2), 3))
        validation_attempt = max(1, int(action.parameters.get("validation_attempt") or 1))
        has_original_alert_check = any(check.signal == "original_alert" for check in typed_checks)
        validation_plan = None
        if typed_checks and has_original_alert_check:
            validation_plan = ValidationPlan(
                execution_id=action.id,
                incident_id=action.incident_id,
                plan_fingerprint=str(execution_plan.get("plan_fingerprint") or ""),
                target_resource_id=str(action.target),
                checks=typed_checks,
                stability_window_seconds=stability_required,
                maximum_autonomous_attempts=maximum_attempts,
                rollback_capability=str(remediation_plan.get("rollback_capability") or "") or None,
            )
            closed_loop_decision = decide_closed_loop(
                validation_plan,
                execution_succeeded=validation["remediation_succeeded"],
                observations=validator_results,
                stability_window_complete=stability_passed,
                attempt=min(validation_attempt, validation_plan.maximum_autonomous_attempts),
                rollback_attempted=bool(action.parameters.get("rollback_attempted")),
                rollback_succeeded=bool(action.parameters.get("rollback_succeeded")),
                collection_pending=collection_pending,
            )
        else:
            at_limit = validation_attempt >= maximum_attempts
            closed_loop_decision = ClosedLoopDecision(
                state=ClosedLoopState.ESCALATED if at_limit else ClosedLoopState.VALIDATION_FAILED,
                next_action=ClosedLoopAction.ESCALATE_TO_HITL if at_limit else ClosedLoopAction.RECOLLECT_EVIDENCE,
                closure_authorized=False,
                attempt=min(validation_attempt, maximum_attempts),
                reason_codes=["canonical_validation_plan_missing", "original_alert_check_missing"],
                missing_checks=["original_alert"],
            )
        restored = restored and outcome_decision.closure_authorized
        restored = restored and closed_loop_decision.closure_authorized
        stability_pending = (
            outcome_decision.outcome == ValidationOutcome.PENDING_STABILITY
            and validation["validation_executable"]
            and closed_loop_decision.next_action == ClosedLoopAction.OBSERVE
            and (collection_pending or all(
                passed for name, passed in recovery_checks.items() if name != "stability_window_completed"
            ))
        )
        closure_status = "closed" if restored else "pending_stability" if stability_pending else "validation_failed"
        lifecycle = extract_lifecycle(action.parameters, action.metadata)
        # Closure never reclassifies an executor failure. The remediation
        # service owns that attempt outcome and the event handler will not
        # normally invoke closure for it. Keeping the lifecycle unchanged here
        # also makes the public validator safe for diagnostic/API callers.
        if lifecycle and action.status == RemediationStatus.SUCCEEDED:
            if lifecycle.get("state") == ResolutionState.EXECUTING.value:
                lifecycle = transition_lifecycle(
                    lifecycle,
                    ResolutionState.VALIDATING,
                    actor=LifecycleActor.REMEDIATION,
                    execution={"action_id": str(action.id), "status": action.status.value},
                )
            lifecycle = transition_lifecycle(
                lifecycle,
                ResolutionState.RECOVERED if restored else ResolutionState.PENDING_STABILITY if stability_pending else ResolutionState.FAILED_RETRYABLE,
                actor=LifecycleActor.CLOSURE,
                reason_code=None if restored else "stability_window_incomplete" if stability_pending else "recovery_validation_failed",
                validation={"checks": validation, "passed": restored},
            )
        action_taken = action.output or action.action_type
        return ResolutionReport(
            tenant_id=action.tenant_id,
            id=uuid5(
                NAMESPACE_URL,
                f"kaiops:closure:{action.id}:{'recovered' if restored else closure_status}",
            ),
            incident_id=action.incident_id,
            recommendation_id=action.recommendation_id,
            resolution_plan_id=action.resolution_plan_id,
            plan_fingerprint=action.plan_fingerprint,
            approval_id=action.approval_id,
            remediation_action_id=action.id,
            closure_kind="recovery" if restored else "validation",
            closure_status=closure_status,
            root_cause=str(action.parameters.get("root_cause") or execution_plan.get("root_cause") or "Cause not established"),
            impact=str(action.parameters.get("impact") or "Customer and business impact are not quantified"),
            action_taken=action_taken,
            validation=validation,
            alerts_cleared=validation["alerts_cleared"],
            health_restored=restored,
            knowledge_base_entry=(
                f"Incident {action.incident_id} validation after {action.action_type}: {validation}."
            ),
            lessons_learned=[
                "Compare alert onset with deployment/change windows.",
                "Prefer reversible remediation for high-confidence deployment regressions.",
                "Require an explicit health endpoint or governed recovery query before closure.",
            ],
            metadata={
                "recovery_observation_collection": collection,
                "outcome_validation": outcome_decision.model_dump(mode="json"),
                "validation_plan": validation_plan.model_dump(mode="json") if validation_plan else None,
                "closed_loop_validation": closed_loop_decision.model_dump(mode="json"),
                "independent_validation_observations": observations,
                "pre_state_validation_observations": pre_state_observations,
                "recovery_comparison": {
                    "pre_state_observation_ids": [str(item.get("result_checksum")) for item in pre_state_observations],
                    "post_state_observation_ids": [str(item.get("result_checksum")) for item in observations],
                    "target_resource_id": str(action.target),
                    "measured": bool(pre_state_observations and observations),
                },
                "stability_window": {
                    "required_seconds": stability_required,
                    "elapsed_seconds": round(stability_elapsed, 3),
                    "observed_at": observed_at.isoformat(),
                    "status": "recovered" if restored else "pending" if stability_pending else "failed",
                },
                **({"resolution_lifecycle": lifecycle} if lifecycle else {}),
            },
        )
