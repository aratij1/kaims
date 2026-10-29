from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


SUCCESS_TERMINAL_STATUSES = frozenset({"closed", "resolved"})
TERMINAL_STATUSES = frozenset({*SUCCESS_TERMINAL_STATUSES, "cancelled", "canceled"})
ACTIVE_ACTION_STATUSES = frozenset(
    {"pending", "dispatching", "executor_accepted", "queued", "running", "verifying", "rolling_back"}
)
FAILED_ACTION_STATUSES = frozenset(
    {
        "failed",
        "rejected",
        "skipped",
        "dispatch_failed",
        "execution_failed",
        "validation_failed",
        "timed_out",
        "cancelled",
        "canceled",
        "rollback_failed",
        "manual_intervention_required",
    }
)
PENDING_APPROVAL_STATUSES = frozenset(
    {"awaiting_approval", "pending_approval", "pending", "queued", "draft", "standby", "required"}
)
APPROVED_STATUSES = frozenset({"approved", "approve", "modified", "modify"})
COARSE_INITIAL_STATUSES = frozenset({"", "open", "investigating", "detected"})
GRANULAR_WORKFLOW_STATUSES = frozenset(
    {
        "waiting_for_human",
        "rca_ready",
        "plan_ready",
        "awaiting_approval",
        "remediating",
        "validating",
    }
)
LIFECYCLE_STATE_STATUS_MAP: dict[str, str] = {
    "waiting_for_human": "waiting_for_human",
    "rca_ready": "rca_ready",
    "plan_ready": "plan_ready",
    "awaiting_approval": "awaiting_approval",
    "executing": "remediating",
    "validating": "validating",
    "closed": "closed",
    "collection_blocked": "failed",
    "investigation_failed": "failed",
    "execution_failed": "failed",
    "validation_failed": "failed",
    "escalated": "failed",
}


def _status(value: Any) -> str:
    return str(value or "").strip().lower().replace("-", "_").replace(" ", "_")


def _timestamp(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, str) and value.strip():
        try:
            parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    return datetime.min.replace(tzinfo=timezone.utc)


def _action_incident_status(action_status: str) -> tuple[str, str] | None:
    if action_status in ACTIVE_ACTION_STATUSES:
        return "remediating", "The latest remediation action is active."
    if action_status in {"succeeded", "completed"}:
        return "validating", "Remediation completed and recovery validation is pending."
    if action_status in {"awaiting_approval", "policy_blocked"}:
        return "awaiting_approval", "Execution is waiting for an operator decision."
    if action_status in FAILED_ACTION_STATUSES:
        return "failed", "The latest remediation or recovery action failed."
    if action_status == "rolled_back":
        return "failed", "The remediation was rolled back and requires review."
    return None


def reduce_incident_status(
    *,
    projection_status: Any = None,
    projection_updated_at: Any = None,
    canonical_status: Any = None,
    canonical_updated_at: Any = None,
    approval_status: Any = None,
    approval_updated_at: Any = None,
    action_status: Any = None,
    action_updated_at: Any = None,
    closure_kind: Any = None,
    lifecycle_state: Any = None,
) -> dict[str, str]:
    """Return one lifecycle status from the latest durable incident facts.

    Explicit approval and executor records are stronger than optimistic UI or
    projection state. Successful closure is monotonic. A newer approval may
    supersede an older policy block or failed attempt, while a newer failed
    execution must supersede a stale canonical ``approved`` value.
    """

    projection = _status(projection_status)
    canonical = _status(canonical_status)
    approval = _status(approval_status)
    action = _status(action_status)
    closure = _status(closure_kind)
    mapped_lifecycle = LIFECYCLE_STATE_STATUS_MAP.get(_status(lifecycle_state), "")
    if mapped_lifecycle and projection in COARSE_INITIAL_STATUSES:
        projection = mapped_lifecycle

    if canonical in SUCCESS_TERMINAL_STATUSES or projection in SUCCESS_TERMINAL_STATUSES:
        status = "closed" if "closed" in {canonical, projection} else "resolved"
        if closure == "manual":
            reason = "An authorized operator administratively closed the incident without a technical recovery claim."
        elif closure == "observed_recovery":
            reason = "Recovery independently verified after a repair outside the KaiMS executor."
        elif closure == "diagnostic":
            reason = "Diagnostic work was completed and closed without a technical recovery claim."
        else:
            reason = "Recovery validation closed the incident."
        return {"status": status, "source": "closure", "reason": reason}
    if canonical in {"cancelled", "canceled"} or projection in {"cancelled", "canceled"}:
        return {"status": "cancelled", "source": "incident", "reason": "The incident was explicitly cancelled."}

    approval_at = _timestamp(approval_updated_at)
    action_at = _timestamp(action_updated_at)
    canonical_at = _timestamp(canonical_updated_at)
    projection_at = _timestamp(projection_updated_at)

    action_fact = _action_incident_status(action)

    # A fresh analysis can deliberately reopen an incident after an older
    # approval or execution attempt. The materialized projection is the durable
    # result of that analysis; stale action/approval/canonical rows must not
    # keep the read model pinned to a superseded failure. Successful closure
    # remains monotonic because it is handled above.
    if (
        projection
        and projection_at > max(canonical_at, approval_at, action_at)
    ):
        return {
            "status": projection,
            "source": "projection",
            "reason": "A newer persisted lifecycle projection supersedes earlier approval or remediation attempts.",
        }

    if action_fact is not None and action_at >= approval_at:
        status, reason = action_fact
        return {"status": status, "source": "remediation_action", "reason": reason}

    if approval in APPROVED_STATUSES and approval_at >= action_at:
        return {
            "status": "approved",
            "source": "approval",
            "reason": "Approval is recorded; execution is the next required lifecycle action.",
        }
    if approval in PENDING_APPROVAL_STATUSES and approval_at >= action_at:
        return {
            "status": "awaiting_approval",
            "source": "approval",
            "reason": "The current remediation plan is waiting for approval.",
        }
    if approval in {"rejected", "reject", "denied"} and approval_at >= action_at:
        return {"status": "failed", "source": "approval", "reason": "Automation was rejected and requires escalation."}
    if action_fact is not None:
        status, reason = action_fact
        return {"status": status, "source": "remediation_action", "reason": reason}

    # A failed canonical record is stronger than a non-terminal projection, but
    # otherwise prefer whichever of the two materialized incident facts is newer.
    if canonical == "failed" and canonical_at >= projection_at:
        return {"status": "failed", "source": "incident", "reason": "The canonical incident lifecycle failed."}
    if canonical in COARSE_INITIAL_STATUSES and (
        projection in GRANULAR_WORKFLOW_STATUSES or mapped_lifecycle == "failed"
    ):
        return {
            "status": projection,
            "source": "projection",
            "reason": "Derived from the current incident lifecycle projection state.",
        }
    fallback = canonical if canonical_at >= projection_at else projection
    fallback_source = "incident" if canonical_at >= projection_at else "projection"
    fallback = fallback or canonical or projection or "open"
    return {"status": fallback, "source": fallback_source, "reason": "Derived from the latest persisted incident state."}
