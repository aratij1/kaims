"""Retire ineligible queued analysis before collecting context or calling models."""
from datetime import UTC, datetime
import re
from uuid import UUID, NAMESPACE_URL, uuid5
from common.database import AnalysisRequestRecord, AuditLogRecord, IncidentRecord

TERMINAL_REQUEST_STATES = {"complete", "completed", "failed", "timed_out", "expired", "cancelled", "superseded"}


def retirement_reason(alert, incident_status, request=None, now=None):
    labels = alert.labels or {}
    from common.signal_scope import demo_analysis_enabled, is_demo_signal
    signal = {"labels": labels, "name": alert.name, "source": getattr(alert, "source", ""),
              "service": alert.service, "environment": getattr(alert, "environment", "")}
    if is_demo_signal(signal) and not demo_analysis_enabled(signal):
        return "DEMO_ANALYSIS_RETIRED"
    if (str(labels.get("synthetic", "")).lower() in {"true", "1", "yes"}
        or str(labels.get("event_mode", "")).lower() in {"synthetic", "test", "validation", "simulation"}
        or str(labels.get("event_authenticity", "")).lower() == "synthetic"
        or re.fullmatch(r"ServiceDown-E2E-\d{14}", alert.name)
        or alert.service in {"kaiops-fault-lab", "kaiops-fault-lab-service", "httpbin-failure-lab"}):
        return "SYNTHETIC_ANALYSIS_RETIRED"
    if str(incident_status).lower() in {"closed", "resolved", "recovered", "cancelled"}:
        return "TERMINAL_INCIDENT_ANALYSIS_RETIRED"
    if request:
        if request.status in TERMINAL_REQUEST_STATES:
            return "TERMINAL_ANALYSIS_REQUEST_RETIRED"
        expires = request.expires_at
        if expires and (expires if expires.tzinfo else expires.replace(tzinfo=UTC)) <= (now or datetime.now(UTC)):
            return "EXPIRED_ANALYSIS_REQUEST_RETIRED"
    return None


async def retire_ineligible_analysis(session, alert, incident, request_id=None, *, actor="context-agent"):
    persisted = await session.get(IncidentRecord, incident.id)
    if persisted and persisted.tenant_id != alert.tenant_id:
        raise ValueError("Queued analysis incident tenant mismatch")
    request = await session.get(AnalysisRequestRecord, UUID(str(request_id)), with_for_update=True) if request_id else None
    if request and (request.tenant_id != alert.tenant_id or request.incident_id != incident.id):
        raise ValueError("Queued analysis request binding mismatch")
    reason = retirement_reason(alert, persisted.status if persisted else incident.status, request)
    if not reason:
        return None
    now = datetime.now(UTC)
    if request and request.status not in TERMINAL_REQUEST_STATES:
        request.status = "timed_out" if reason == "EXPIRED_ANALYSIS_REQUEST_RETIRED" else "failed"
        request.terminal_reason = reason
        request.completed_at = now
    identity = request_id or alert.id
    audit_id = uuid5(NAMESPACE_URL, f"analysis-admission:{alert.tenant_id}:{identity}:{reason}")
    if await session.get(AuditLogRecord, audit_id) is None:
        session.add(AuditLogRecord(id=audit_id, tenant_id=alert.tenant_id, actor=actor,
            action="analysis.queue.retired", resource_type="incident", resource_id=str(incident.id),
            payload={"reason": reason, "analysis_request_id": str(request_id) if request_id else None,
                     "alert_id": str(alert.id)}))
    return reason
