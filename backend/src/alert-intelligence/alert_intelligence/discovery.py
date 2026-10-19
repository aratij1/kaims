from __future__ import annotations

import hashlib
from typing import Any

from common.models import Alert, AlertSeverity, EvidenceReference, Incident, IncidentCandidate


def _category(text: str) -> str:
    lowered = text.lower()
    categories = (
        ("security", ("unauthorized", "forbidden", "credential", "security")),
        ("database", ("database", "mysql", "postgres", "sql", "replica")),
        ("dependency", ("connection refused", "upstream", "dependency", "dns")),
        ("capacity", ("cpu", "memory", "disk", "saturation", "throttl")),
        ("latency", ("latency", "timeout", "slow")),
        ("availability", ("unavailable", "down", "outage", "5xx", "503")),
        ("deployment", ("deployment", "release", "rollback", "revision")),
    )
    for name, tokens in categories:
        if any(token in lowered for token in tokens):
            return name
    return "application-error"


def _impact(alert: Alert) -> tuple[str, str, str, str]:
    text = f"{alert.name} {alert.description}".lower()
    if any(token in text for token in ("outage", "unavailable", "down", "data loss")):
        return (
            "Service availability is materially impaired.",
            "Customers may be unable to complete the affected business journey.",
            "all-users",
            "urgent",
        )
    if any(token in text for token in ("error", "failed", "timeout", "latency", "degraded")):
        return (
            "The service is degraded or repeatedly failing an operational action.",
            "A subset of requests or dependent workflows may fail or slow down.",
            "single-service",
            "normal",
        )
    return (
        "An operational anomaly requires verification.",
        "No confirmed customer impact is available from the current evidence.",
        "single-instance",
        "normal",
    )


def _fallback_actionability(alert: Alert) -> tuple[bool, str]:
    # The alert's own annotations (e.g. an Alertmanager rule's "summary") often
    # carry the clearest actionability signal even when "description" doesn't
    # repeat it verbatim, so both must be checked, not description alone.
    annotation_text = " ".join(str(value) for value in alert.annotations.values())
    text = f"{alert.name} {alert.description} {annotation_text}".lower()
    noise = (
        "cleaning up inactive",
        "cleanup completed",
        "retrying export",
        "failed to search jira for fingerprint",
        "onboarding-smoke-test",
        "test alert",
    )
    if any(token in text for token in noise):
        return False, "Known routine, test, retry, or KaiOps-internal integration noise."
    actionable = any(
        token in text
        for token in (
            "unavailable",
            "unreachable",
            "outage",
            "connection refused",
            "fatal",
            "data loss",
            "does not exist",
            "authentication",
            "timeout",
            "deadline exceeded",
            "error scraping",
            "cannot scrape",
            "failed",
            "failure",
            "latency",
            "degraded",
            "above threshold",
            "row count is high",
            "disk space low",
            "saturation",
        )
    )
    severity = str(getattr(alert.severity, "value", alert.severity) or "").strip().lower()
    actionable = actionable or severity in {"high", "critical"}
    return (
        actionable,
        "Signal indicates a persistent failure requiring operator investigation."
        if actionable
        else "Current evidence does not establish an operator-actionable incident.",
    )


def build_incident_candidate(alert: Alert, incident: Incident, llm: dict[str, Any] | None = None) -> IncidentCandidate:
    llm = llm if isinstance(llm, dict) else {}
    technical_impact, business_impact, scope, urgency = _impact(alert)
    correlation = alert.metadata.get("correlation") if isinstance(alert.metadata.get("correlation"), dict) else {}
    source_event_id = str(alert.labels.get("source_event_id") or alert.labels.get("opensearch_document_id") or alert.id)
    evidence_uri = str(
        alert.labels.get("log_source_path")
        or alert.annotations.get("generatorURL")
        or alert.labels.get("email_message_id")
        or f"alert://{alert.id}"
    )
    evidence = [
        EvidenceReference(
            evidence_id=f"alert:{source_event_id}",
            source=alert.source,
            uri=evidence_uri,
            summary=alert.description[:1000],
            observed_at=alert.starts_at,
            confidence=1.0,
            attributes={
                "service": alert.service,
                "environment": alert.environment,
                "occurrence_count": str(alert.labels.get("occurrence_count") or "1"),
                "log_level": str(alert.labels.get("log_level") or ""),
            },
        )
    ]
    similar: list[dict[str, Any]] = []
    if correlation.get("matched_alert_id"):
        similar.append(
            {
                "alert_id": str(correlation.get("matched_alert_id")),
                "correlation_id": str(correlation.get("matched_correlation_id") or ""),
                "score": float(correlation.get("score") or 0.0),
            }
        )
    correlation_key = str(
        alert.fingerprint
        or alert.labels.get("discovery_fingerprint")
        or alert.correlation_id
        or alert.id
    )
    idempotency_key = hashlib.sha256(
        f"incident-candidate|{correlation_key}|{alert.service}|{alert.environment}".encode()
    ).hexdigest()[:40]
    try:
        recommended = AlertSeverity(str(llm.get("recommended_severity") or alert.severity.value).lower())
    except ValueError:
        recommended = alert.severity
    occurrence_count = int(str(alert.labels.get("occurrence_count") or "1"))
    fallback_confidence = 0.80 if alert.severity == AlertSeverity.CRITICAL else (0.70 if occurrence_count >= 2 else 0.55)
    try:
        confidence = float(llm.get("confidence") or max(fallback_confidence, float(correlation.get("score") or 0.0)))
    except (TypeError, ValueError):
        confidence = 0.55
    fallback_actionable, fallback_reason = _fallback_actionability(alert)
    llm_actionable = llm.get("actionable")
    if isinstance(llm_actionable, str):
        llm_actionable = llm_actionable.strip().lower() in {"1", "true", "yes"}
    actionable = bool(llm_actionable) if isinstance(llm_actionable, bool) else fallback_actionable
    return IncidentCandidate(
        incident_id=str(incident.id),
        jira_key=str(alert.labels.get("ticket_id") or alert.labels.get("jira_issue_key") or "") or None,
        source_event_ids=[source_event_id],
        idempotency_key=idempotency_key,
        correlation_key=correlation_key,
        application=str(alert.labels.get("application") or alert.labels.get("project_name") or alert.service),
        service=str(llm.get("service") or alert.service),
        environment=str(llm.get("environment") or alert.environment),
        category=str(llm.get("category") or _category(f"{alert.name} {alert.description}")),
        title=str(llm.get("title") or f"{alert.service}: {alert.name}")[:255],
        description=str(llm.get("description") or alert.description),
        initial_hypothesis=str(
            llm.get("initial_hypothesis")
            or f"The {alert.service} signal is likely caused by a {_category(alert.description)} condition."
        ),
        technical_impact=str(llm.get("technical_impact") or technical_impact),
        business_impact=str(llm.get("business_impact") or business_impact),
        affected_users=str(llm.get("affected_users") or "unknown"),
        scope=str(llm.get("scope") or scope),
        urgency=str(llm.get("urgency") or urgency),
        actionable=actionable,
        actionability_reason=str(llm.get("actionability_reason") or fallback_reason),
        recommended_severity=recommended,
        confidence=max(0.0, min(1.0, confidence)),
        evidence=evidence,
        similar_incidents=similar,
        model_provider=str(llm.get("model_provider") or "heuristic-fallback"),
        model_name=str(llm.get("model_name") or "deterministic-discovery-v1"),
        model_version=str(llm.get("model_version") or "v1"),
        reasoning=str(llm.get("reasoning") or "Candidate derived from normalized alert and correlation evidence."),
    )
