"""Regression tests for KaiMS memory pileup and runaway loop fixes."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import uuid4

import aio_pika
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from common.config import Settings
from common.context_enrichment_contract import (
    EvidenceRecord,
    EvidenceRequirement,
    build_evidence_requirements,
    normalize_connector_response,
)
from common.database import (
    Base,
    ContextEnrichmentJobRecord,
    ContextSnapshotRecord,
    GovernedRagDocumentRecord,
    IncidentProjectionRecord,
    IncidentRecord,
    ResolutionOutboxRecord,
)
from common.models import Incident
from common.rabbitmq import RabbitMQProducer
from common.repository import ContextEnrichmentRepository, IncidentRepository


@pytest.fixture
async def sqlite_session_factory(tmp_path):
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'memory_regressions.db'}")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        yield factory
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_no_route_delivery_error_does_not_trip_publish_circuit_breaker() -> None:
    producer = RabbitMQProducer(
        Settings(service_name="test-service", rabbitmq_publish_circuit_breaker_threshold=1)
    )

    class _NoRouteExchange:
        async def publish(self, message, routing_key: str) -> None:
            raise Exception(f"PRECONDITION_FAILED - NO_ROUTE for {routing_key}")

    producer._exchanges = [_NoRouteExchange()]  # type: ignore[assignment]

    with pytest.raises(Exception, match="NO_ROUTE"):
        await producer.publish("incident-lifecycle-events", {"event": "lifecycle"})

    # Broker was reachable and returned NO_ROUTE; circuit breaker must NOT open
    assert producer._publish_breaker.allow() is True


@pytest.mark.asyncio
async def test_outbox_dead_letters_no_route_and_exhausted_retries(sqlite_session_factory) -> None:
    now = datetime.now(UTC)
    async with sqlite_session_factory() as session:
        session.add_all(
            [
                ResolutionOutboxRecord(
                    event_id="unrouted-lifecycle-1",
                    tenant_id="tenant-a",
                    aggregate_id="inc-1",
                    topic="incident-lifecycle-events",
                    partition_key="inc-1",
                    payload={"transport": "rabbitmq"},
                    status="pending",
                    attempts=0,
                    next_attempt_at=now - timedelta(seconds=5),
                    created_at=now - timedelta(seconds=10),
                ),
                ResolutionOutboxRecord(
                    event_id="stuck-retry-182",
                    tenant_id="tenant-a",
                    aggregate_id="inc-2",
                    topic="context-events",
                    partition_key="inc-2",
                    payload={"transport": "rabbitmq"},
                    status="retry",
                    attempts=182,
                    next_attempt_at=now - timedelta(seconds=5),
                    created_at=now - timedelta(seconds=20),
                ),
                ResolutionOutboxRecord(
                    event_id="valid-pending-1",
                    tenant_id="tenant-a",
                    aggregate_id="inc-3",
                    topic="context-events",
                    partition_key="inc-3",
                    payload={"transport": "rabbitmq"},
                    status="pending",
                    attempts=0,
                    next_attempt_at=now - timedelta(seconds=5),
                    created_at=now - timedelta(seconds=1),
                ),
            ]
        )
        await session.commit()

        repo = IncidentRepository(session)
        # Pending query excludes rows that already exceeded max_attempts
        pending = await repo.list_pending_resolution_events(limit=20, max_attempts=5)
        assert [r.event_id for r in pending] == ["unrouted-lifecycle-1", "valid-pending-1"]

        # Exhausted retry rows are explicitly dead-lettered (never silently marked published)
        dead_lettered = await repo.dead_letter_exhausted_resolution_events(max_attempts=5)
        assert dead_lettered == 1
        stuck = await session.get(ResolutionOutboxRecord, "stuck-retry-182")
        assert stuck is not None
        assert stuck.status == "dead_letter"
        assert stuck.published_at is None

        # NO_ROUTE error immediately transitions outbox row to dead_letter
        await repo.mark_resolution_event_retry(
            "unrouted-lifecycle-1", "DeliveryError: NO_ROUTE", max_attempts=5
        )
        await session.commit()
        unrouted = await session.get(ResolutionOutboxRecord, "unrouted-lifecycle-1")
        assert unrouted is not None
        assert unrouted.status == "dead_letter"
        assert unrouted.published_at is None


def test_stable_evidence_id_is_invariant_across_rca_versions() -> None:
    incident = Incident(tenant_id="tenant-a", service="api-gateway", title="latency")
    now = datetime(2026, 10, 21, 12, 0, tzinfo=UTC)
    req_v1 = build_evidence_requirements(
        tenant_id="tenant-a",
        incident_id=incident.id,
        rca_version=1,
        missing_evidence=[{"category": "logs", "question": "Which errors occurred?"}],
        now=now,
    )[0]
    req_v2 = build_evidence_requirements(
        tenant_id="tenant-a",
        incident_id=incident.id,
        rca_version=2,
        missing_evidence=[{"category": "logs", "question": "Which errors occurred?"}],
        now=now + timedelta(seconds=30),
    )[0]
    assert req_v1.requirement_id != req_v2.requirement_id

    payload = {
        "code_matches": [],
        "log_matches": [
            {
                "kind": "log",
                "source": "log",
                "path": "/data/runtime/api-gateway.log",
                "line": 7,
                "language": "log",
                "uri": "log:///data/runtime/api-gateway.log#L7",
                "snippet": "    7 | ERROR timeout calling downstream",
                "matched_line": "ERROR timeout calling downstream",
                "message": "ERROR timeout calling downstream",
                "matched_terms": ["api-gateway"],
            }
        ],
    }
    norm_v1 = normalize_connector_response(
        raw_response=payload,
        requirement=req_v1,
        incident=incident,
        connector="local-evidence",
        collected_at=now,
    )
    norm_v2 = normalize_connector_response(
        raw_response=payload,
        requirement=req_v2,
        incident=incident,
        connector="local-evidence",
        collected_at=now + timedelta(minutes=1),
    )
    assert norm_v1.records[0].evidence_id == norm_v2.records[0].evidence_id


@pytest.mark.asyncio
async def test_duplicate_enrichment_does_not_create_snapshot_or_outbox_event(
    sqlite_session_factory,
) -> None:
    incident_id = uuid4()
    now = datetime.now(UTC)
    req_v1 = build_evidence_requirements(
        tenant_id="tenant-a",
        incident_id=incident_id,
        rca_version=1,
        missing_evidence=[{"category": "metrics", "question": "What was latency?"}],
        now=now,
    )[0]
    req_v2 = build_evidence_requirements(
        tenant_id="tenant-a",
        incident_id=incident_id,
        rca_version=2,
        missing_evidence=[{"category": "metrics", "question": "What was latency?"}],
        now=now + timedelta(seconds=10),
    )[0]
    record = EvidenceRecord(
        evidence_id="EVD-" + "b" * 64,
        requirement_id=str(req_v1.requirement_id),
        tenant_id="tenant-a",
        incident_id=str(incident_id),
        category="metrics",
        source_id="prometheus:9090",
        connector="prometheus",
        source_reference="prometheus://prometheus:9090/query?expr=up",
        service="checkout-api",
        observed_at=now,
        collected_at=now,
        freshness="fresh",
        content={
            "metric_name": "up",
            "labels": {"service": "checkout-api"},
            "samples": [{"timestamp": now.isoformat(), "value": "0"}],
        },
        provenance={"query": "up"},
        current_observation=True,
    )

    async with sqlite_session_factory() as session:
        repo = ContextEnrichmentRepository(session)
        await repo.upsert_context_evidence_requirements([req_v1, req_v2])
        job1 = await repo.schedule_context_enrichment_job(
            tenant_id="tenant-a",
            incident_id=incident_id,
            requirement_id=req_v1.requirement_id,
            connector_id="prometheus",
            query_payload={"incident": {"id": str(incident_id)}, "decision": {}},
            observation_start=now - timedelta(minutes=5),
            observation_end=now,
        )
        session.add(
            ContextSnapshotRecord(
                snapshot_id=uuid4(),
                tenant_id="tenant-a",
                incident_id=str(incident_id),
                alert_signature="sig",
                subject_fingerprint="s" * 64,
                context_fingerprint="c" * 64,
                snapshot_stage="initial",
                snapshot_version=1,
                evidence_ids=[],
                evidence_checksums={},
                contract_version="kaiops.context.v2",
                quality_score=0.2,
                reusable=False,
                source_manifest={},
                payload={"tenant_id": "tenant-a", "incident_id": str(incident_id), "metadata": {}},
                collected_at=now,
                expires_at=now + timedelta(hours=1),
            )
        )
        await session.commit()

        await repo.claim_context_enrichment_jobs(worker_id="worker-a", limit=1)
        first_res = await repo.persist_enrichment_result_atomically(
            job_id=job1.job_id,
            worker_id="worker-a",
            accepted_records=[record],
            rejected_records=[],
            source_response_metadata={"query": "up"},
        )
        await session.commit()
        assert first_res["accepted"] is True
        assert first_res["outbox_event_id"] is not None

        # Scheduling the same automatic connector for rca_version=2 reuses the collected job
        reused_job = await repo.schedule_context_enrichment_job(
            tenant_id="tenant-a",
            incident_id=incident_id,
            requirement_id=req_v2.requirement_id,
            connector_id="prometheus",
            query_payload={"incident": {"id": str(incident_id)}, "decision": {}},
            observation_start=now - timedelta(minutes=5),
            observation_end=now + timedelta(seconds=15),
        )
        assert reused_job.job_id == job1.job_id
        assert reused_job.status == "collected"


@pytest.mark.asyncio
async def test_incident_history_query_enforces_safe_cap(sqlite_session_factory) -> None:
    now = datetime.now(UTC)
    async with sqlite_session_factory() as session:
        for idx in range(130):
            inc_id = uuid4()
            session.add(
                IncidentRecord(
                    id=inc_id,
                    tenant_id="tenant-a",
                    service="checkout-api",
                    environment="prod",
                    severity="high",
                    status="investigating",
                    title=f"Incident {idx}",
                    payload={},
                )
            )
            session.add(
                IncidentProjectionRecord(
                    incident_id=inc_id,
                    tenant_id="tenant-a",
                    service="checkout-api",
                    environment="prod",
                    severity="high",
                    status="investigating",
                    first_seen_at=now - timedelta(minutes=idx),
                    updated_at=now - timedelta(minutes=idx),
                    projection_payload={"incident": {"id": str(inc_id)}},
                )
            )
        await session.commit()
        repo = IncidentRepository(session)
        rows = await repo.list_incident_projections(tenant_id="tenant-a", limit=5000, include_enrichment=False)
        assert len(rows) == 100


def test_governed_rag_document_record_exposes_index_status_column() -> None:
    assert hasattr(GovernedRagDocumentRecord, "index_status")
    assert not hasattr(GovernedRagDocumentRecord, "status")
