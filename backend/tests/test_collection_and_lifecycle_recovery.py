"""
Tests for collection blockage fixes, responder assignment fallbacks,
and lifecycle transition idempotency.
"""
from datetime import UTC, datetime, timedelta
from uuid import uuid4
import pytest

from common.context_enrichment_contract import (
    _CANONICAL_CATEGORY,
    _REQUIREMENT_CONNECTORS,
    _CATEGORY_ALIASES,
    build_evidence_requirements,
)
from common.database import (
    IncidentRecord,
    IncidentProjectionRecord,
)
from common.repository import ContextEnrichmentRepository


def test_database_and_validation_canonical_mappings_and_connectors():
    """Verify database and validation are recognized canonical categories with active connectors."""
    assert "database" in _CANONICAL_CATEGORY
    assert _CANONICAL_CATEGORY["database"] == "metrics"
    assert "validation" in _CANONICAL_CATEGORY
    assert _CANONICAL_CATEGORY["validation"] == "knowledge"

    # Verify candidate connectors are defined and not empty
    assert len(_REQUIREMENT_CONNECTORS["database"]) > 0
    assert "discovery-mcp" in _REQUIREMENT_CONNECTORS["database"]
    assert "prometheus" in _REQUIREMENT_CONNECTORS["database"]

    assert len(_REQUIREMENT_CONNECTORS["validation"]) > 0
    assert "discovery-mcp" in _REQUIREMENT_CONNECTORS["validation"]

    # Verify aliases
    assert _CATEGORY_ALIASES["db"] == "database"
    assert _CATEGORY_ALIASES["data"] == "database"


def test_build_evidence_requirements_with_database_and_validation():
    """Verify build_evidence_requirements retains connectors and does not strip them to empty."""
    incident_id = uuid4()
    now = datetime.now(UTC)

    reqs = build_evidence_requirements(
        tenant_id="tenant-test",
        incident_id=incident_id,
        rca_version=1,
        missing_evidence=[
            {"category": "database", "question": "Check database connection pool metrics and lock latency."},
            {"category": "validation", "question": "Validate post-recovery service metrics and error rates."},
            {"category": "db", "question": "Inspect database slow query logs."},
        ],
        now=now,
    )

    assert len(reqs) == 3
    db_req = next(r for r in reqs if r.category == "database" and "connection" in r.question)
    val_req = next(r for r in reqs if r.category == "validation")
    alias_req = next(r for r in reqs if r.category == "database" and "slow query" in r.question)

    # Candidate connectors must NOT be stripped to empty
    assert len(db_req.candidate_connectors) >= 1
    assert "discovery-mcp" in db_req.candidate_connectors
    assert db_req.collection_mode == "automatic"

    assert len(val_req.candidate_connectors) >= 1
    assert "discovery-mcp" in val_req.candidate_connectors
    assert val_req.collection_mode == "automatic"

    assert len(alias_req.candidate_connectors) >= 1
    assert alias_req.category == "database"


@pytest.mark.asyncio
async def test_resolve_human_evidence_responder_safe_fallback(sqlite_session_factory):
    """Verify responder resolution safely falls back to IncidentRecord and SRE on-call."""
    incident_id = uuid4()

    async with sqlite_session_factory() as session:
        session.add(
            IncidentRecord(
                id=incident_id,
                tenant_id="tenant-test",
                title="Payments checkout latency high",
                severity="high",
                status="investigating",
                service="payments-service",
                environment="prod",
                payload={"owner": "payment-lead@kaims.local"},
            )
        )
        await session.commit()

    async with sqlite_session_factory() as session:
        repo = ContextEnrichmentRepository(session)
        assignment = await repo.resolve_human_evidence_responder(
            tenant_id="tenant-test",
            incident_id=incident_id,
        )
        assert assignment is not None
        assert assignment["identity"] == "payment-lead@kaims.local"
        assert assignment["source"] == "incident_assignment"


@pytest.mark.asyncio
async def test_resolve_human_evidence_responder_tenant_fallback(sqlite_session_factory):
    """When no specific owner or onboarding record exists, falls back safely to sre-oncall@kaims.local."""
    incident_id = uuid4()

    async with sqlite_session_factory() as session:
        session.add(
            IncidentRecord(
                id=incident_id,
                tenant_id="tenant-unonboarded",
                title="Unknown service latency",
                severity="medium",
                status="investigating",
                service="unknown-service",
                environment="prod",
                payload={},
            )
        )
        await session.commit()

    async with sqlite_session_factory() as session:
        repo = ContextEnrichmentRepository(session)
        assignment = await repo.resolve_human_evidence_responder(
            tenant_id="tenant-unonboarded",
            incident_id=incident_id,
        )
        assert assignment is not None
        assert assignment["identity"] == "sre-oncall@kaims.local"
        assert assignment["source"] == "tenant_fallback"


@pytest.mark.asyncio
async def test_human_fallback_validation_not_immediately_blocked(sqlite_session_factory):
    """When automated collection falls back, technical connector failure remains blocked, while manual review is permitted."""
    incident_id = uuid4()
    now = datetime.now(UTC)

    requirement = build_evidence_requirements(
        tenant_id="tenant-test",
        incident_id=incident_id,
        rca_version=1,
        missing_evidence=[{"category": "validation", "question": "Review test validation citations"}],
        now=now,
    )[0]

    async with sqlite_session_factory() as session:
        session.add(
            IncidentRecord(
                id=incident_id,
                tenant_id="tenant-test",
                title="Service validation check",
                severity="warning",
                status="investigating",
                service="order-service",
                environment="prod",
                payload={"owner": "order-sre@kaims.local"},
            )
        )
        repo = ContextEnrichmentRepository(session)
        await repo.upsert_context_evidence_requirements([requirement])
        await session.commit()

    async with sqlite_session_factory() as session:
        repo = ContextEnrichmentRepository(session)
        # 1. Automatic connector fallback must remain blocked (not converted to questionnaire)
        auto_request = await repo.create_human_evidence_request(
            automatic_fallback=True,
            tenant_id="tenant-test",
            incident_id=incident_id,
            requirement_id=requirement.requirement_id,
            expected_responder="order-sre@kaims.local",
            assignment_source="incident_assignment",
            assignment_failure_reason=None,
            due_at=now + timedelta(hours=1),
            acceptable_format="Markdown summary",
            evidence_already_checked=["discovery-mcp"],
            hypothesis_impact="Validation impact",
            investigation_can_continue=True,
        )
        assert auto_request is None
        current = await repo.context_evidence_requirement(
            tenant_id="tenant-test", requirement_id=requirement.requirement_id
        )
        assert current["status"] == "blocked"

        # 2. Manual human evidence request is allowed for validation review
        manual_request = await repo.create_human_evidence_request(
            automatic_fallback=False,
            tenant_id="tenant-test",
            incident_id=incident_id,
            requirement_id=requirement.requirement_id,
            expected_responder="order-sre@kaims.local",
            assignment_source="incident_assignment",
            assignment_failure_reason=None,
            due_at=now + timedelta(hours=1),
            acceptable_format="Markdown summary",
            evidence_already_checked=["discovery-mcp"],
            hypothesis_impact="Validation impact",
            investigation_can_continue=True,
        )
        assert manual_request is not None
        assert manual_request.status == "pending"
        assert manual_request.expected_responder == "order-sre@kaims.local"


@pytest.mark.asyncio
async def test_lifecycle_transition_idempotency_and_versioning(sqlite_session_factory):
    """Verify transition_incident_lifecycle is strictly idempotent and tracks sequence correctly."""
    incident_id = uuid4()
    now = datetime.now(UTC)

    requirement = build_evidence_requirements(
        tenant_id="tenant-test",
        incident_id=incident_id,
        rca_version=1,
        missing_evidence=[{"category": "metrics", "question": "Check replication lag"}],
        now=now,
    )[0]

    async with sqlite_session_factory() as session:
        session.add(
            IncidentRecord(
                id=incident_id,
                tenant_id="tenant-test",
                title="Database replication delay",
                severity="high",
                status="investigating",
                service="mysql-replica",
                environment="prod",
                payload={},
            )
        )
        session.add(
            IncidentProjectionRecord(
                incident_id=incident_id,
                alert_id=uuid4(),
                tenant_id="tenant-test",
                service="mysql-replica",
                environment="prod",
                severity="high",
                status="investigating",
                lifecycle_state="DETECTED",
                lifecycle_version=1,
            )
        )
        repo = ContextEnrichmentRepository(session)
        await repo.upsert_context_evidence_requirements([requirement])
        await session.commit()

    async with sqlite_session_factory() as session:
        repo = ContextEnrichmentRepository(session)
        idempotency_key = f"trans-req-ident:{incident_id}"

        # First transition: DETECTED -> REQUIREMENTS_IDENTIFIED
        t1 = await repo.transition_incident_lifecycle(
            tenant_id="tenant-test",
            incident_id=incident_id,
            target_state="REQUIREMENTS_IDENTIFIED",
            expected_version=1,
            actor="test-orchestrator",
            reason="Requirements generated from initial alert",
            idempotency_key=idempotency_key,
        )
        assert t1["idempotent"] is False
        assert t1["new_state"] == "REQUIREMENTS_IDENTIFIED"
        assert t1["version"] == 2

        # Duplicate transition with same idempotency key must return idempotent=True without creating new row
        t2 = await repo.transition_incident_lifecycle(
            tenant_id="tenant-test",
            incident_id=incident_id,
            target_state="REQUIREMENTS_IDENTIFIED",
            expected_version=1,
            actor="test-orchestrator",
            reason="Requirements generated from initial alert",
            idempotency_key=idempotency_key,
        )
        assert t2["idempotent"] is True
        assert t2["transition_id"] == t1["transition_id"]

        # Stale version rejection
        with pytest.raises(RuntimeError) as exc_info:
            await repo.transition_incident_lifecycle(
                tenant_id="tenant-test",
                incident_id=incident_id,
                target_state="COLLECTING",
                expected_version=1,  # Version is now 2
                actor="test-orchestrator",
                reason="Attempting collection with stale version",
                idempotency_key=f"trans-collect:{incident_id}",
            )
        assert "STALE_LIFECYCLE_VERSION" in str(exc_info.value)
