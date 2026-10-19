from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from common.database import (
    ContextEnrichmentJobRecord, ContextEvidenceRequirementRecord,
    HumanEvidenceRequestRecord, IncidentCorrelationOwnershipRecord, IncidentProjectionRecord,
    IncidentRecord,
)
from common.repository import ContextEnrichmentRepository, IncidentRepository


@pytest.mark.asyncio
async def test_new_incident_uses_detected_lifecycle_before_analysis(sqlite_session_factory):
    now = datetime.now(UTC)
    incident_id = uuid4()
    async with sqlite_session_factory() as session:
        session.add(IncidentCorrelationOwnershipRecord(
            tenant_id="new-incident", project_id="commerce", environment="test", service="checkout",
            correlation_key="new", correlation_family_id=uuid4(), correlation_generation=1,
            canonical_incident_id=incident_id, first_seen_at=now, last_seen_at=now,
            correlation_window_expires_at=now + timedelta(hours=1), lifecycle_state="investigating",
        ))
        session.add(IncidentProjectionRecord(
            incident_id=incident_id, tenant_id="new-incident", service="checkout", environment="test",
            severity="high", status="investigating", lifecycle_state="DETECTED",
            first_seen_at=now, projection_payload={},
        ))
        await session.commit()
        page = await IncidentRepository(session).list_unified_inbox(tenant_id="new-incident", project_id="commerce")
        assert page["rows"][0]["row"]["status"] == "detected"


@pytest.mark.asyncio
async def test_closed_incident_does_not_reopen_in_operations_projection(sqlite_session_factory):
    incident_id = uuid4()
    async with sqlite_session_factory() as session:
        session.add(IncidentRecord(id=incident_id, tenant_id="closed-test", service="api",
                                   environment="test", severity="high", status="closed", title="Closed", payload={}))
        session.add(IncidentProjectionRecord(incident_id=incident_id, tenant_id="closed-test", service="api",
            environment="test", severity="high", status="closed", lifecycle_state="COLLECTING",
            first_seen_at=datetime.now(UTC), projection_payload={}))
        await session.commit()
        state = await ContextEnrichmentRepository(session).incident_operations_state(tenant_id="closed-test", incident_id=incident_id)
        assert state["lifecycle_state"] == "CLOSED"
        assert state["next_action"]["type"] == "REVIEW_CLOSURE"


@pytest.mark.asyncio
@pytest.mark.parametrize("can_continue,request_status,job_status,expected", [
    (True, "pending", "collecting", "collecting"),
    (True, "pending", "retry", "collecting"),
    (False, "pending", "collecting", "waiting_for_human"),
    (True, "pending", "completed", "waiting_for_human"),
    (True, "assignment_blocked", "completed", "collection_blocked"),
    (True, "assignment_blocked", "collecting", "collecting"),
])
async def test_inbox_uses_actual_blocking_work(sqlite_session_factory, can_continue, request_status, job_status, expected):
    now = datetime.now(UTC)
    incident_id, requirement_id = uuid4(), uuid4()
    async with sqlite_session_factory() as session:
        session.add(IncidentCorrelationOwnershipRecord(
            tenant_id="progress", project_id="commerce", environment="test", service="checkout",
            correlation_key="progress", correlation_family_id=uuid4(), correlation_generation=1,
            canonical_incident_id=incident_id, first_seen_at=now, last_seen_at=now,
            correlation_window_expires_at=now + timedelta(hours=1), lifecycle_state="waiting_for_human",
        ))
        session.add(IncidentProjectionRecord(
            incident_id=incident_id, tenant_id="progress", service="checkout", environment="test",
            severity="high", status="waiting_for_human", lifecycle_state="WAITING_FOR_HUMAN",
            first_seen_at=now, projection_payload={},
        ))
        session.add(ContextEvidenceRequirementRecord(
            requirement_id=requirement_id, tenant_id="progress", incident_id=incident_id, rca_version=1,
            requirement_key="metrics", category="metrics", question="Metric?", reason="Confirm cause",
            priority="high", collection_mode="automatic", status="human_requested", candidate_connectors=[],
        ))
        session.add(HumanEvidenceRequestRecord(
            tenant_id="progress", incident_id=incident_id, requirement_id=requirement_id,
            due_at=now + timedelta(hours=1), acceptable_format="source", hypothesis_impact="cause",
            status=request_status, investigation_can_continue=can_continue,
        ))
        session.add(ContextEnrichmentJobRecord(
            tenant_id="progress", incident_id=incident_id, requirement_id=requirement_id,
            connector_id="metrics", idempotency_key="progress", observation_start=now,
            observation_end=now, status=job_status,
        ))
        await session.commit()
        repo = IncidentRepository(session)
        page = await repo.list_unified_inbox(tenant_id="progress", project_id="commerce")
        assert page["rows"][0]["row"]["status"] == expected
        assert page["view_counts"]["needs_me"] == int(expected != "collecting")
        assert page["view_counts"]["kai_handling"] == int(expected == "collecting")
        detail = await ContextEnrichmentRepository(session).incident_operations_state(tenant_id="progress", incident_id=incident_id)
        assert detail["lifecycle_state"] == expected.upper()
        other = await repo.list_unified_inbox(tenant_id="progress", project_id="different")
        assert other["rows"] == []
