from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import uuid4
import pytest
from sqlalchemy import select, func
from common.analysis_admission import retirement_reason, retire_ineligible_analysis
from common.database import AnalysisRequestRecord, AuditLogRecord, IncidentRecord
from common.models import Alert, Incident, AlertSeverity


def alert(**kwargs):
    return Alert(tenant_id="tenant-a", source="prometheus", service="api-gateway", name="HighLatency",
        description="Observed latency", severity=AlertSeverity.CRITICAL, **kwargs)


def test_active_work_is_preserved_but_expired_and_terminal_work_is_retired():
    now = datetime.now(UTC)
    request = SimpleNamespace(status="published", expires_at=now + timedelta(minutes=5))
    assert retirement_reason(alert(), "investigating", request, now) is None
    request.expires_at = now - timedelta(seconds=1)
    assert retirement_reason(alert(), "investigating", request, now) == "EXPIRED_ANALYSIS_REQUEST_RETIRED"
    assert retirement_reason(alert(), "closed") == "TERMINAL_INCIDENT_ANALYSIS_RETIRED"
    for status in ("complete", "completed"):
        request.status = status
        assert retirement_reason(alert(), "investigating", request, now) == "TERMINAL_ANALYSIS_REQUEST_RETIRED"


@pytest.mark.parametrize("labels", [{"synthetic": "true"}, {"event_mode": "simulation"}, {"event_authenticity": "synthetic"}])
def test_synthetic_work_does_not_enter_context_collection(labels):
    assert retirement_reason(alert(labels=labels), "investigating") == "SYNTHETIC_ANALYSIS_RETIRED"


@pytest.mark.asyncio
async def test_expiry_is_durable_audited_and_tenant_bound(sqlite_session_factory):
    item = alert()
    incident = Incident(tenant_id="tenant-a", service=item.service, severity=item.severity, title=item.name)
    key = uuid4()
    async with sqlite_session_factory() as session:
        session.add(IncidentRecord(id=incident.id, tenant_id="tenant-a", service=item.service, environment="prod",
            severity="critical", status="investigating", title=item.name, payload={}))
        request = AnalysisRequestRecord(request_id=key, tenant_id="tenant-a", incident_id=incident.id, alert_id=item.id,
            expected_recommendation_id=uuid4(), mode="fresh", status="published", delivery="published",
            expires_at=datetime.now(UTC) - timedelta(minutes=1))
        session.add(request)
        await session.flush()
        assert await retire_ineligible_analysis(session, item, incident, str(key)) == "EXPIRED_ANALYSIS_REQUEST_RETIRED"
        await session.flush()
        assert request.status == "timed_out"
        assert request.completed_at is not None
        assert await session.scalar(select(func.count()).select_from(AuditLogRecord)) == 1
        request.status = "complete"
        assert await retire_ineligible_analysis(session, item, incident, str(key)) == "TERMINAL_ANALYSIS_REQUEST_RETIRED"
        assert request.status == "complete"  # Expiry must never overwrite a committed result.
        request.tenant_id = "tenant-b"
        with pytest.raises(ValueError, match="binding mismatch"):
            await retire_ineligible_analysis(session, item, incident, str(key))
