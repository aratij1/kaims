from datetime import datetime, timedelta, timezone

from common.incident_status import reduce_incident_status
from common.resolution_lifecycle import ResolutionState, initial_plan_state


NOW = datetime(2026, 8, 19, 12, 0, tzinfo=timezone.utc)


def test_commands_cannot_advance_a_non_ready_plan() -> None:
    plan = {
        "commands": ["kubectl rollout restart deployment/api"],
        "execution_ready": False,
        "mutating": True,
        "diagnostic_only": True,
        "plan_kind": "diagnostic",
    }
    assert initial_plan_state(plan, requires_approval=True) == ResolutionState.DIAGNOSTIC_ONLY


def test_only_ready_mutating_plan_enters_approval() -> None:
    plan = {
        "commands": ["kubectl rollout restart deployment/api"],
        "execution_ready": True,
        "mutating": True,
        "diagnostic_only": False,
        "plan_kind": "corrective",
    }
    assert initial_plan_state(plan, requires_approval=True) == ResolutionState.AWAITING_APPROVAL


def test_new_approval_supersedes_an_older_policy_block() -> None:
    result = reduce_incident_status(
        projection_status="awaiting_approval",
        projection_updated_at=NOW - timedelta(hours=1),
        canonical_status="approved",
        canonical_updated_at=NOW,
        approval_status="approved",
        approval_updated_at=NOW,
        action_status="policy_blocked",
        action_updated_at=NOW - timedelta(days=1),
    )

    assert result["status"] == "approved"
    assert result["source"] == "approval"


def test_failed_execution_supersedes_stale_approved_incident() -> None:
    result = reduce_incident_status(
        projection_status="approved",
        projection_updated_at=NOW - timedelta(minutes=2),
        canonical_status="approved",
        canonical_updated_at=NOW - timedelta(minutes=2),
        approval_status="approved",
        approval_updated_at=NOW - timedelta(minutes=2),
        action_status="execution_failed",
        action_updated_at=NOW,
    )

    assert result["status"] == "failed"
    assert result["source"] == "remediation_action"


def test_new_investigation_projection_supersedes_old_failed_attempt() -> None:
    result = reduce_incident_status(
        projection_status="investigating",
        projection_updated_at=NOW,
        canonical_status="failed",
        canonical_updated_at=NOW - timedelta(days=1),
        approval_status="rejected",
        approval_updated_at=NOW - timedelta(hours=2),
        action_status="skipped",
        action_updated_at=NOW - timedelta(hours=1),
    )

    assert result["status"] == "investigating"
    assert result["source"] == "projection"
    assert "supersedes" in result["reason"]


def test_successful_execution_enters_validation_until_closure() -> None:
    result = reduce_incident_status(
        projection_status="remediating",
        projection_updated_at=NOW - timedelta(minutes=1),
        canonical_status="remediating",
        canonical_updated_at=NOW - timedelta(minutes=1),
        approval_status="approved",
        approval_updated_at=NOW - timedelta(minutes=5),
        action_status="succeeded",
        action_updated_at=NOW,
    )

    assert result["status"] == "validating"


def test_verified_closure_is_monotonic_even_if_stale_action_arrives() -> None:
    result = reduce_incident_status(
        projection_status="closed",
        projection_updated_at=NOW - timedelta(minutes=2),
        canonical_status="closed",
        canonical_updated_at=NOW - timedelta(minutes=2),
        approval_status="approved",
        approval_updated_at=NOW - timedelta(minutes=1),
        action_status="running",
        action_updated_at=NOW,
    )

    assert result["status"] == "closed"
    assert result["source"] == "closure"


def test_manual_closure_does_not_claim_validated_recovery() -> None:
    result = reduce_incident_status(
        projection_status="closed",
        canonical_status="closed",
        closure_kind="manual",
    )

    assert result["status"] == "closed"
    assert result["source"] == "closure"
    assert "administratively closed" in result["reason"]
    assert "without a technical recovery claim" in result["reason"]


def test_diagnostic_closure_does_not_claim_validated_recovery() -> None:
    result = reduce_incident_status(
        projection_status="closed",
        canonical_status="closed",
        closure_kind="diagnostic",
    )

    assert result["status"] == "closed"
    assert "Diagnostic work was completed" in result["reason"]
    assert "without a technical recovery claim" in result["reason"]


def test_lifecycle_state_awaiting_approval_is_not_regressed_by_newer_coarse_canonical_timestamp() -> None:
    result = reduce_incident_status(
        projection_status="investigating",
        projection_updated_at=NOW - timedelta(minutes=10),
        canonical_status="investigating",
        canonical_updated_at=NOW,
        lifecycle_state="AWAITING_APPROVAL",
    )

    assert result["status"] == "awaiting_approval"
    assert result["source"] == "projection"


def test_granular_projection_status_is_not_regressed_by_newer_coarse_canonical_timestamp() -> None:
    for expected_status, lifecycle_state in (
        ("waiting_for_human", "WAITING_FOR_HUMAN"),
        ("plan_ready", "PLAN_READY"),
        ("awaiting_approval", "AWAITING_APPROVAL"),
        ("remediating", "EXECUTING"),
        ("validating", "VALIDATING"),
    ):
        result = reduce_incident_status(
            projection_status=expected_status,
            projection_updated_at=NOW - timedelta(minutes=5),
            canonical_status="investigating",
            canonical_updated_at=NOW,
            lifecycle_state=lifecycle_state,
        )
        assert result["status"] == expected_status
        assert result["source"] == "projection"
