"""Preserve evidence sufficiency gaps across investigation handoffs."""
import json


def investigation_gaps(analysis: dict, report: dict) -> list:
    result = report.get("rca_result") or {}
    def items(value):
        return value if isinstance(value, list) else [value] if value else []
    values = [*items(analysis.get("missing_evidence")), *items(report.get("missing_sources")), *items(result.get("missing_evidence"))]
    gaps, seen = [], set()
    for value in values:
        value = dict(value) if isinstance(value, dict) else str(value).strip()
        if not value:
            continue
        identity = json.dumps(value, sort_keys=True) if isinstance(value, dict) else value
        if identity not in seen:
            gaps.append(value)
            seen.add(identity)
    return gaps


def blocking_investigation_gaps(analysis: dict, report: dict) -> list:
    gaps = investigation_gaps(analysis, report)
    if not analysis.get("evidence_used"):
        gaps.append({
            "category": "validation",
            "question": "Review the retained incident evidence and publish an RCA with explicit source citations, or explain why none supports the diagnostic candidate.",
            "reason": "The RCA synthesis contains no validated citations; collected context alone cannot establish causality.",
            "candidate_connectors": [],
        })
    return investigation_gaps({"missing_evidence": gaps}, {})


def requirement_blocks_recollection(row: dict, rca_version: int) -> bool:
    """Reuse active work, but do not treat old collected work as a new RCA's answer."""
    return (int(row.get("rca_version") or 0) == rca_version
            or str(row.get("status") or "") not in {"collected", "satisfied", "cancelled", "failed", "expired"})


def incident_collection_window(alert, now):
    """Anchor causal follow-up collection to incident onset, including delayed RCA."""
    from datetime import UTC, timedelta
    now = now.astimezone(UTC).replace(microsecond=0)
    start = alert.starts_at.astimezone(UTC).replace(microsecond=0)
    end = alert.ends_at.astimezone(UTC).replace(microsecond=0) if alert.ends_at else start + timedelta(minutes=15)
    return start - timedelta(minutes=15), min(now, max(start, end) + timedelta(minutes=15))


def unattempted_requirement_connector(requirement, authorized, jobs):
    """Reconciliation must not restart active work or reselect exhausted sources."""
    from common.context_enrichment_contract import next_authorized_enrichment_connector
    activity = [job for job in jobs if str(job.get("requirement_id")) == str(requirement.requirement_id)]
    if any(job.get("status") in {"scheduled", "collecting", "retry", "collected"} for job in activity):
        return None
    return next_authorized_enrichment_connector(
        candidate_connectors=requirement.candidate_connectors,
        authorized_connectors=authorized,
        attempted_connectors={str(job.get("connector_id") or "") for job in activity},
    )


def collection_attempt_limit(explicit_gap, rejected):
    """Retry source availability, not deterministic contract incompatibility."""
    if explicit_gap in {"NO_MATCHING_APPROVED_EVIDENCE", "TRACE_NOT_FOUND_OR_EXPIRED",
                        "APPLICATION_DATABASE_SCOPE_NOT_CONFIGURED", "INVALID_OBSERVATION_WINDOW"}:
        return 1
    codes = {str(item.get("code") or "") for item in rejected}
    if codes & {"UNSUPPORTED_EVIDENCE_CATEGORY", "EVIDENCE_BINDING_MISMATCH", "EVIDENCE_REQUIRED_FIELD_MISSING"}:
        return 1
    return 4


def requirement_reconciliation_needed(requirement, authorized, jobs, status):
    """An owner request never prevents collection from a newly available source."""
    if unattempted_requirement_connector(requirement, authorized, jobs):
        return True
    activity = [job for job in jobs if str(job.get("requirement_id")) == str(requirement.requirement_id)]
    return not activity and status not in {"human_requested", "assignment_blocked", "blocked"}
