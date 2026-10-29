from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
from typing import Any


@dataclass(frozen=True, slots=True)
class EvidenceQuality:
    accepted_evidence: int
    independent_sources: int
    direct_evidence: int
    fresh_direct_evidence: int
    average_reliability: float
    contradictory: bool
    sufficiency: str
    confidence_ceiling: float
    reasons: tuple[str, ...]


_DIRECT_SIGNALS = {
    "stack_trace",
    "error_code",
    "metric_anomaly",
    "trace_error",
    "deployment_change",
    "code_finding",
    "alert_payload",
}

_SOURCE_FAMILIES = {
    "alert": "alerting",
    "alertmanager": "alerting",
    "prometheus": "metrics",
    "metric": "metrics",
    "metrics": "metrics",
    "telemetry": "metrics",
    "log": "logs",
    "logs": "logs",
    "opensearch": "logs",
    "elasticsearch": "logs",
    "ticket": "tickets",
    "jira": "tickets",
    "code": "code",
    "github": "code",
    "gitlab": "code",
}

_SOURCE_RELIABILITY = {
    "metrics": 0.92,
    "logs": 0.9,
    "code": 0.86,
    "alerting": 0.82,
    "tickets": 0.62,
    "rag": 0.58,
    "unknown": 0.45,
}


def _source_family(value: Any) -> str:
    source = str(value or "unknown").strip().lower()
    return _SOURCE_FAMILIES.get(source, source)


def assess_evidence_quality(
    evidence: list[dict[str, Any]],
    *,
    accepted_ids: list[str],
    alternative_causes: list[Any] | None = None,
    reference_time: datetime | None = None,
    max_direct_age_seconds: float = 3600.0,
) -> EvidenceQuality:
    accepted = set(accepted_ids)
    rows = [row for row in evidence if str(row.get("evidence_id") or "") in accepted]
    unique_rows: list[dict[str, Any]] = []
    fingerprints: set[str] = set()
    for row in rows:
        identity = str(row.get("uri") or row.get("path") or "").strip().lower()
        content = str(row.get("snippet") or row.get("message") or row.get("content") or "").strip().lower()
        # Evidence with neither a stable URI nor content cannot be proven to be a
        # duplicate; retain it by its evidence id instead of collapsing all such rows.
        fingerprint_basis = f"{identity}|{content}" if identity or content else f"id:{row.get('evidence_id')}"
        fingerprint = hashlib.sha256(fingerprint_basis.encode()).hexdigest()
        if fingerprint in fingerprints:
            continue
        fingerprints.add(fingerprint)
        unique_rows.append(row)
    rows = unique_rows
    # Connector aliases backed by the same underlying signal are one source,
    # not independent corroboration (for example Prometheus + telemetry).
    sources = {_source_family(row.get("source")) for row in rows}
    direct = sum(
        1
        for row in rows
        if _DIRECT_SIGNALS.intersection(str(signal).lower() for signal in row.get("diagnostic_signals", []))
        or row.get("signal_counts")
    )
    now = reference_time.astimezone(timezone.utc) if reference_time else None
    fresh_direct = 0
    reliabilities: list[float] = []
    for row in rows:
        family = _source_family(row.get("source"))
        try:
            reliability = float(row.get("reliability_score", _SOURCE_RELIABILITY.get(family, 0.55)))
        except (TypeError, ValueError):
            reliability = _SOURCE_RELIABILITY.get(family, 0.55)
        reliabilities.append(max(0.0, min(reliability, 1.0)))
        signals = {str(signal).lower() for signal in row.get("diagnostic_signals", [])}
        if not (_DIRECT_SIGNALS.intersection(signals) or row.get("signal_counts")):
            continue
        timestamp = next((row.get(key) for key in ("observed_at", "timestamp", "created_at", "updated_at") if row.get(key)), None)
        if not now or not timestamp:
            fresh_direct += 1
            continue
        try:
            observed = datetime.fromisoformat(str(timestamp).replace("Z", "+00:00"))
            if observed.tzinfo is None:
                observed = observed.replace(tzinfo=timezone.utc)
            if abs((now - observed.astimezone(timezone.utc)).total_seconds()) <= max_direct_age_seconds:
                fresh_direct += 1
        except ValueError:
            pass
    average_reliability = sum(reliabilities) / len(reliabilities) if reliabilities else 0.0
    contradiction = any(
        bool(row.get("contradictory")) or str(row.get("stance") or "").lower() in {"contradicts", "conflicts"}
        for row in rows
    )
    alternatives = [item for item in (alternative_causes or []) if str(item or "").strip()]
    reasons: list[str] = []
    if not rows:
        reasons.append("No accepted evidence supports the causal claim.")
        return EvidenceQuality(0, 0, 0, 0, 0.0, contradiction, "insufficient", 0.35, tuple(reasons))
    if len(sources) < 2:
        reasons.append("Only one independent evidence source supports the causal claim.")
    if not direct:
        reasons.append("No direct causal signal was identified in accepted evidence.")
    elif reference_time and not fresh_direct:
        reasons.append("Direct evidence is stale relative to the incident window.")
    if average_reliability < 0.6:
        reasons.append("Accepted evidence has low average source reliability.")
    if contradiction:
        reasons.append("Accepted evidence contains a contradiction.")
    if len(alternatives) > 2 and direct < 2:
        reasons.append("Multiple viable hypotheses remain unresolved.")
    if contradiction:
        ceiling, sufficiency = 0.49, "conflicting"
    elif len(sources) >= 2 and direct >= 1 and (not reference_time or fresh_direct >= 1) and average_reliability >= 0.6:
        ceiling, sufficiency = 0.95, "sufficient"
    elif direct >= 1:
        ceiling, sufficiency = 0.69, "partial"
    else:
        ceiling, sufficiency = 0.55, "partial"
    if reference_time and direct and not fresh_direct:
        ceiling, sufficiency = min(ceiling, 0.59), "stale"
    return EvidenceQuality(len(rows), len(sources), direct, fresh_direct, round(average_reliability, 4), contradiction, sufficiency, ceiling, tuple(reasons))


def remediation_quality_gate(
    remediation: dict[str, Any],
    *,
    rca_confidence: float,
    impact_confidence: float,
    risk: str,
    environment: str,
    fallback_used: bool,
    evidence_quality: dict[str, Any] | None = None,
    context_degraded: bool = False,
) -> dict[str, Any]:
    validation = remediation.get("validation_commands") or remediation.get("validation_queries") or remediation.get("validation_steps") or []
    rollback = remediation.get("rollback_commands") or remediation.get("rollback_plan") or remediation.get("rollback_steps") or []
    commands = remediation.get("commands") or []
    approval = str(remediation.get("approval_required") or "").strip().lower()
    destructive = bool(remediation.get("destructive")) or any(
        marker in str(command).lower()
        for command in commands
        for marker in ("delete ", "drop ", "truncate ", "rm -", "destroy", "failover")
    )
    mutation_markers = (" restart ", " rollout undo ", " scale ", " apply ", "flushdb", "failover")
    mutating = remediation.get("mutating")
    if mutating is None:
        mutating = destructive or any(
            any(marker in f" {str(command).lower()} " for marker in mutation_markers)
            for command in commands
        )
    executable_prefixes = ("kubectl ", "curl ", "mysql ", "redis-cli ", "terraform ", "ansible-playbook ")
    executable_validation = [item for item in validation if str(item).strip().lower().startswith(executable_prefixes)]
    executable_rollback = [item for item in rollback if str(item).strip().lower().startswith(executable_prefixes)]
    blockers: list[str] = []
    if rca_confidence < 0.65:
        blockers.append("RCA confidence is below 0.65.")
    if impact_confidence < 0.55:
        blockers.append("Impact confidence is below 0.55.")
    if not executable_validation:
        blockers.append("No executable validation checks are defined.")
    if mutating and not executable_rollback:
        blockers.append("Mutating commands lack an executable rollback or compensation plan.")
    if fallback_used:
        blockers.append("A model fallback contributed to the recommendation.")
    if evidence_quality and evidence_quality.get("sufficiency") != "sufficient":
        blockers.append("Accepted evidence is not sufficient and independently corroborated.")
    if context_degraded:
        blockers.append("One or more context connectors failed or exceeded the collection budget.")
    mandatory = (
        destructive
        or risk in {"high", "critical"}
        or (environment.lower() in {"prod", "production"} and approval not in {"false", "none", "automatic"})
    )
    return {
        "passed": not blockers,
        "blocking_reasons": list(blockers),
        "trusted_for_auto_execution": not blockers and not mandatory and rca_confidence >= 0.85,
        "requires_human_review": bool(blockers) or mandatory,
        "mandatory_approval": mandatory,
        "destructive": destructive,
        "mutating": bool(mutating),
        "blockers": blockers,
        "validation_present": bool(executable_validation),
        "rollback_present": bool(executable_rollback) or not bool(mutating),
    }
