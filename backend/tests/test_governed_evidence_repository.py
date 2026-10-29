import importlib.util
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest
from common.database import (
    AuditLogRecord,
    ContextSnapshotRecord,
    GovernedRagDocumentRecord,
    IncidentInvestigationBindingRecord,
    IncidentProjectionRecord,
    ResolutionOutboxRecord,
)
from common.models import Alert, Incident
from common.repository import IncidentRepository
from sqlalchemy import func, select


async def seed_binding(session, tenant_id: str, *, alert_id=None):
    now = datetime.now(UTC)
    incident_id, alert_id = uuid4(), alert_id or uuid4()
    analysis_id, snapshot_id, recommendation_id = uuid4(), uuid4(), uuid4()
    fingerprint, evidence_id, uri = "a" * 64, "evidence-1", "prometheus://query/test"
    session.add(ContextSnapshotRecord(
        snapshot_id=snapshot_id, tenant_id=tenant_id, incident_id=str(incident_id),
        source_incident_id=str(incident_id), alert_signature="signature",
        subject_fingerprint="b" * 64, context_fingerprint=fingerprint,
        contract_version="kaiops.context.v2", quality_score=0.9, reusable=True,
        source_manifest={}, payload={"metadata": {
            "alert_id": str(alert_id), "project_id": "project",
            "context_evidence": {"telemetry": [{
                "evidence_id": evidence_id, "citation": uri, "tenant_id": tenant_id,
            }]},
        }}, collected_at=now, expires_at=now + timedelta(hours=1),
    ))
    session.add(AuditLogRecord(
        id=recommendation_id, tenant_id=tenant_id, actor="agent",
        action="recommendation.generated", resource_type="incident",
        resource_id=str(incident_id), payload={"metadata": {
            "alert_id": str(alert_id), "project_id": "project",
            "analysis_request_id": str(analysis_id), "context_snapshot_id": str(snapshot_id),
            "context_fingerprint": fingerprint, "evidence_ids": [evidence_id],
        }},
    ))
    session.add(IncidentInvestigationBindingRecord(
        binding_id=recommendation_id, tenant_id=tenant_id, project_id="project",
        incident_id=incident_id, alert_id=alert_id, analysis_request_id=analysis_id,
        context_snapshot_id=snapshot_id, context_fingerprint=fingerprint,
        recommendation_id=recommendation_id, rca_version=1, status="grounded",
        created_at=now, expires_at=now + timedelta(hours=1),
    ))
    session.add(IncidentProjectionRecord(
        incident_id=incident_id, alert_id=alert_id, recommendation_id=recommendation_id,
        tenant_id=tenant_id, service="payments", environment="prod", status="investigating",
        first_seen_at=now, projection_payload={},
    ))
    await session.commit()
    return {
        "incident_id": incident_id, "alert_id": alert_id, "analysis_request_id": analysis_id,
        "context_snapshot_id": snapshot_id, "context_fingerprint": fingerprint,
        "recommendation_id": recommendation_id, "rca_version": 1,
        "evidence_ids": [evidence_id], "source_uris": [uri],
    }


def documents():
    return [{"document_kind": kind, "title": f"{kind} title", "content": "x" * 40} for kind in (
        "incident", "jira", "runbook", "deployment", "change", "dependency", "remediation",
    )]


def load_context_app_module():
    path = Path("ai-workbench/src/context-agent/app.py")
    spec = importlib.util.spec_from_file_location("governed_context_agent_app", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_crawled_evidence_builds_complete_source_grounded_draft_bundle():
    module = load_context_app_module()
    documents = module._crawled_incident_document_bundle(
        alert_name="Gateway latency",
        service="api-gateway",
        environment="prod",
        evidence_rows=[{
            "evidence_id": "evidence-1",
            "source_uri": "prometheus://query/latency",
            "content": {"metric_name": "latency_p99", "value": "3.4"},
        }],
    )

    assert {item["document_kind"] for item in documents} == set(module.INCIDENT_DOCUMENT_KINDS)
    runbook = next(item for item in documents if item["document_kind"] == "runbook")
    assert "evidence-1" in runbook["content"]
    assert "prometheus://query/latency" in runbook["content"]
    assert "latency_p99" in runbook["content"]
    assert "operator verification required" in runbook["content"]


@pytest.mark.asyncio
async def test_crawler_creates_idempotent_drafts_from_verified_snapshot_before_rca_acceptance(
    sqlite_session_factory,
):
    module = load_context_app_module()
    async with sqlite_session_factory() as session:
        binding = await seed_binding(session, "tenant-a")
        recommendation = await session.get(AuditLogRecord, binding["recommendation_id"])
        recommendation.payload = {**recommendation.payload, "metadata": {
            **recommendation.payload["metadata"], "evidence_ids": [],
        }}
        await session.commit()
        candidate = {
            "alert_id": str(binding["alert_id"]), "binding": binding,
            "snapshot_evidence": [{
                "evidence_id": "evidence-1", "citation": "prometheus://query/test",
                "content": {"metric_name": "latency_p99", "value": "3.4"},
            }],
        }
        repo = IncidentRepository(session)
        alert = Alert(tenant_id="tenant-a", source="prometheus", name="Gateway latency",
                      service="payments", environment="prod", description="p99 latency is above threshold")
        incident = Incident(
            id=binding["incident_id"], tenant_id="tenant-a", service="payments", title="Gateway latency",
        )

        assert await module._create_crawled_evidence_drafts(
            repo, tenant_id="tenant-a", candidate=candidate, alert=alert, incident=incident,
        ) == len(module.INCIDENT_DOCUMENT_KINDS)
        assert await module._create_crawled_evidence_drafts(
            repo, tenant_id="tenant-a", candidate=candidate, alert=alert, incident=incident,
        ) == 0


class ConfirmingIndexConnector:
    def __init__(self) -> None:
        self.documents: list[dict] = []

    async def index_governed_document(self, document):
        indexed = {
            "document_id": str(document.document_id), "tenant_id": document.tenant_id,
            "content": document.content, "content_checksum": document.content_checksum,
            "kind": document.document_kind,
        }
        self.documents.append(indexed)
        return {**indexed, "indexed": 1, "metadata": indexed}

    async def verify_index_receipt(self, receipt, *, expected_checksum):
        assert receipt["content_checksum"] == expected_checksum
        assert receipt["indexed"] == 1

    def search(self, query: str, *, tenant_id: str) -> list[dict]:
        return [row for row in self.documents if row["tenant_id"] == tenant_id and query in row["content"]]


@pytest.mark.asyncio
async def test_approved_remediation_is_reused_as_historical_knowledge_for_future_incident(
    sqlite_session_factory,
):
    async with sqlite_session_factory() as session:
        binding = await seed_binding(session, "tenant-a")
        repo = IncidentRepository(session)
        draft = (await repo.create_evidence_rag_drafts(
            tenant_id="tenant-a", created_by="author", binding=binding,
            documents=[{"document_kind": "remediation", "title": "Prior checkout recovery",
                        "content": "future-checkout-evidence confirmed rollback recovery"}],
            evidence_ids=binding["evidence_ids"], source_uris=binding["source_uris"],
        ))[0]
        reviewed = await repo.review_evidence_rag_draft(
            tenant_id="tenant-a", draft_id=draft["draft_id"], expected_row_version=1,
            title=draft["title"], content=draft["content"], review_notes="verified",
            reviewed_by="reviewer-a",
        )
        _, event = await repo.approve_evidence_rag_draft(
            tenant_id="tenant-a", draft_id=draft["draft_id"],
            expected_row_version=reviewed["row_version"], approved_by="approver-a",
        )
        await session.commit()

    module = load_context_app_module()
    connector = ConfirmingIndexConnector()
    module.vector_connector = lambda: connector
    worker_app = SimpleNamespace(state=SimpleNamespace(session_factory=sqlite_session_factory))
    await module._index_governed_document(worker_app, event)

    async with sqlite_session_factory() as session:
        tenant_rows = await IncidentRepository(session).list_retrievable_governed_rag_documents(
            tenant_id="tenant-a",
        )
        other_rows = await IncidentRepository(session).list_retrievable_governed_rag_documents(
            tenant_id="tenant-b",
        )
    assert len(tenant_rows) == 1
    assert tenant_rows[0].index_receipt["content_checksum"] == tenant_rows[0].content_checksum
    assert connector.search("future-checkout-evidence", tenant_id="tenant-a")
    assert connector.search("future-checkout-evidence", tenant_id="tenant-b") == []
    assert other_rows == []


@pytest.mark.asyncio
async def test_evidence_draft_requires_review_approval_before_grounding(sqlite_session_factory):
    async with sqlite_session_factory() as session:
        binding = await seed_binding(session, "tenant-a")
        repo = IncidentRepository(session)
        draft = (await repo.create_evidence_rag_drafts(
            tenant_id="tenant-a", created_by="author", binding=binding,
            documents=[{"document_kind": "remediation", "title": "Reviewed recovery",
                        "content": "verify recovery evidence before reusing this remediation"}],
            evidence_ids=binding["evidence_ids"], source_uris=binding["source_uris"],
        ))[0]
        assert await repo.list_retrievable_governed_rag_documents(tenant_id="tenant-a") == []
        with pytest.raises(RuntimeError, match="direct approval"):
            await repo.approve_evidence_rag_draft(
                tenant_id="tenant-a", draft_id=draft["draft_id"],
                expected_row_version=1, approved_by="approver",
            )


@pytest.mark.asyncio
async def test_published_ai_evidence_can_be_revised_without_mutating_it(sqlite_session_factory):
    async with sqlite_session_factory() as session:
        binding = await seed_binding(session, "tenant-a")
        repo = IncidentRepository(session)
        original = (await repo.create_evidence_rag_drafts(
            tenant_id="tenant-a", created_by="ai-agent", binding=binding,
            documents=[{"document_kind": "incident", "title": "AI incident evidence",
                        "content": "Generated evidence grounded in linked source records."}],
            evidence_ids=binding["evidence_ids"], source_uris=binding["source_uris"],
        ))[0]
        reviewed = await repo.review_evidence_rag_draft(
            tenant_id="tenant-a", draft_id=original["draft_id"], expected_row_version=1,
            title=original["title"], content=original["content"], review_notes=None,
            reviewed_by="operator-a",
        )
        await repo.approve_evidence_rag_draft(
            tenant_id="tenant-a", draft_id=original["draft_id"],
            expected_row_version=reviewed["row_version"], approved_by="approver-a",
        )
        revision = await repo.revise_evidence_rag_draft(
            tenant_id="tenant-a", draft_id=original["draft_id"], created_by="operator-b",
        )
        rows = await repo.list_evidence_rag_drafts(
            tenant_id="tenant-a", alert_id=binding["alert_id"], document_kind="incident",
        )

    assert revision["draft_id"] != original["draft_id"]
    assert revision["document_version"] == 2
    assert revision["status"] == "draft"
    assert revision["content"] == original["content"]
    assert revision["evidence_ids"] == original["evidence_ids"]
    assert {row["status"] for row in rows} == {"approved_pending_index", "draft"}


@pytest.mark.asyncio
async def test_concurrent_identical_draft_creation_returns_same_active_draft(sqlite_session_factory):
    async with sqlite_session_factory() as session:
        binding = await seed_binding(session, "tenant-a")
        repo = IncidentRepository(session)
        kwargs = dict(
            tenant_id="tenant-a", created_by="author", binding=binding,
            documents=[{"document_kind": "incident", "title": "Stable identity",
                        "content": "same incident evidence draft content"}],
            evidence_ids=binding["evidence_ids"], source_uris=binding["source_uris"],
        )
        first = await repo.create_evidence_rag_drafts(**kwargs)
        second = await repo.create_evidence_rag_drafts(**kwargs)
    assert first[0]["draft_id"] == second[0]["draft_id"]


@pytest.mark.asyncio
async def test_tenant_slug_collision_and_shared_alert_remain_isolated(sqlite_session_factory):
    shared_alert = uuid4()
    async with sqlite_session_factory() as session:
        a = await seed_binding(session, "tenant-a", alert_id=shared_alert)
        b = await seed_binding(session, "tenant_a", alert_id=shared_alert)
        for tenant, binding in (("tenant-a", a), ("tenant_a", b)):
            await IncidentRepository(session).create_evidence_rag_drafts(
                tenant_id=tenant, created_by="engineer", binding=binding,
                documents=documents(), evidence_ids=binding["evidence_ids"],
                source_uris=binding["source_uris"],
            )
        await session.commit()
        rows_a = await IncidentRepository(session).list_evidence_rag_drafts(
            tenant_id="tenant-a", alert_id=shared_alert,
        )
        rows_b = await IncidentRepository(session).list_evidence_rag_drafts(
            tenant_id="tenant_a", alert_id=shared_alert,
        )
    assert len(rows_a) == len(rows_b) == 7
    assert {row["draft_id"] for row in rows_a}.isdisjoint(row["draft_id"] for row in rows_b)
    assert {row["document_kind"] for row in rows_a} == {row["document_kind"] for row in rows_b}


@pytest.mark.asyncio
async def test_review_concurrency_and_immutable_incident_jira_approval(sqlite_session_factory):
    async with sqlite_session_factory() as session:
        binding = await seed_binding(session, "tenant-a")
        drafts = await IncidentRepository(session).create_evidence_rag_drafts(
            tenant_id="tenant-a", created_by="engineer", binding=binding,
            documents=documents(), evidence_ids=binding["evidence_ids"],
            source_uris=binding["source_uris"],
        )
        await session.commit()
        repo = IncidentRepository(session)
        approved_ids = []
        for kind in ("incident", "jira"):
            draft = next(row for row in drafts if row["document_kind"] == kind)
            reviewed = await repo.review_evidence_rag_draft(
                tenant_id="tenant-a", draft_id=draft["draft_id"], expected_row_version=1,
                title=draft["title"], content=draft["content"] + " reviewed",
                review_notes=None, reviewed_by="reviewer",
            )
            stale = await repo.review_evidence_rag_draft(
                tenant_id="tenant-a", draft_id=draft["draft_id"], expected_row_version=1,
                title=draft["title"], content="y" * 40, review_notes=None, reviewed_by="other",
            )
            assert stale is None
            result = await repo.approve_evidence_rag_draft(
                tenant_id="tenant-a", draft_id=draft["draft_id"],
                expected_row_version=reviewed["row_version"], approved_by="administrator",
            )
            approved_ids.append(result[1]["document_id"])
        await session.commit()
        kinds = set((await session.execute(select(GovernedRagDocumentRecord.document_kind))).scalars())
        audit_count = await session.scalar(select(func.count()).select_from(AuditLogRecord).where(
            AuditLogRecord.action == "rag.document.approved",
        ))
        outbox_count = await session.scalar(select(func.count()).select_from(ResolutionOutboxRecord).where(
            ResolutionOutboxRecord.topic == "rag.document.approved",
        ))
    assert len(set(approved_ids)) == 2
    assert {"incident", "jira"}.issubset(kinds)
    assert audit_count == outbox_count == 2


@pytest.mark.asyncio
async def test_unrecognized_evidence_and_cross_tenant_mutation_are_blocked(sqlite_session_factory):
    async with sqlite_session_factory() as session:
        binding = await seed_binding(session, "tenant-a")
        bad = dict(binding)
        with pytest.raises(RuntimeError, match="accepted bound snapshot"):
            await IncidentRepository(session).create_evidence_rag_drafts(
                tenant_id="tenant-a", created_by="engineer", binding=bad,
                documents=documents(), evidence_ids=["forged"], source_uris=bad["source_uris"],
            )
        drafts = await IncidentRepository(session).create_evidence_rag_drafts(
            tenant_id="tenant-a", created_by="engineer", binding=binding,
            documents=documents(), evidence_ids=binding["evidence_ids"],
            source_uris=binding["source_uris"],
        )
        await session.commit()
        draft = drafts[0]
        result = await IncidentRepository(session).review_evidence_rag_draft(
            tenant_id="tenant_a", draft_id=draft["draft_id"], expected_row_version=1,
            title=draft["title"], content="z" * 40, review_notes=None, reviewed_by="intruder",
        )
    assert result is None


@pytest.mark.asyncio
async def test_approved_replacement_increments_version_and_index_gate_is_explicit(sqlite_session_factory):
    async with sqlite_session_factory() as session:
        binding = await seed_binding(session, "tenant-a")
        repo = IncidentRepository(session)
        first = (await repo.create_evidence_rag_drafts(
            tenant_id="tenant-a", created_by="engineer", binding=binding,
            documents=documents(), evidence_ids=binding["evidence_ids"],
            source_uris=binding["source_uris"],
        ))[0]
        reviewed = await repo.review_evidence_rag_draft(
            tenant_id="tenant-a", draft_id=first["draft_id"], expected_row_version=1,
            title=first["title"], content=first["content"] + " reviewed",
            review_notes=None, reviewed_by="reviewer",
        )
        approved = await repo.approve_evidence_rag_draft(
            tenant_id="tenant-a", draft_id=first["draft_id"],
            expected_row_version=reviewed["row_version"], approved_by="administrator",
        )
        await session.commit()
        assert await repo.list_retrievable_governed_rag_documents(tenant_id="tenant-a") == []
        await repo.mark_governed_rag_document_indexed(
            tenant_id="tenant-a", document_id=approved[1]["document_id"],
            index_receipt={
                "document_id": approved[1]["document_id"],
                "content_checksum": approved[1]["content_checksum"], "indexed": 1,
            },
        )
        assert len(await repo.list_retrievable_governed_rag_documents(tenant_id="tenant-a")) == 1
        replacements = await repo.create_evidence_rag_drafts(
            tenant_id="tenant-a", created_by="engineer", binding=binding,
            documents=documents(), evidence_ids=binding["evidence_ids"],
            source_uris=binding["source_uris"],
        )
    incident_replacement = next(row for row in replacements if row["document_kind"] == "incident")
    assert incident_replacement["document_version"] == 2
    assert incident_replacement["draft_id"] != first["draft_id"]



class FlakyVectorConnector:
    def __init__(self, *, fail: bool = True) -> None:
        self.fail = fail
        self.upsert_calls = 0
        self.documents: dict[str, dict] = {}

    async def index_governed_document(self, document):
        self.upsert_calls += 1
        if self.fail:
            raise RuntimeError("vector store connection refused")
        indexed = {
            "document_id": str(document.document_id),
            "tenant_id": document.tenant_id,
            "content": document.content,
            "content_checksum": document.content_checksum,
            "kind": document.document_kind,
        }
        self.documents[str(document.document_id)] = indexed
        return {**indexed, "indexed": 1, "metadata": indexed}

    async def verify_index_receipt(self, receipt, *, expected_checksum):
        if self.fail:
            raise RuntimeError("vector store receipt verification unavailable")
        assert receipt["content_checksum"] == expected_checksum
        assert receipt["indexed"] == 1


@pytest.mark.asyncio
async def test_indexing_recovery_lifecycle_pending_failed_stale_indexing_and_fallback(
    sqlite_session_factory,
):
    from uuid import NAMESPACE_URL, UUID, uuid5
    from common.database import RunbookVersionRecord

    source_ref = "runbook://payments/gateway-timeout"
    rb_id = uuid5(NAMESPACE_URL, f"kaiops:runbook:tenant-a:{source_ref}")

    async with sqlite_session_factory() as session:
        repo = IncidentRepository(session)
        draft = await repo.create_knowledge_rag_draft(
            tenant_id="tenant-a",
            created_by="operator-a",
            document_kind="runbook",
            source_ref=source_ref,
            title="Payments Gateway Timeout Runbook",
            content=(
                "# Payments Gateway Timeout Runbook\n\n"
                "## Observed Symptoms\nUpstream pool saturation on payments.\n\n"
                "## Remediation Steps\n1. `kubectl top pods`\n2. `kubectl rollout restart deploy/payments`\n"
            ),
            metadata={
                "service": "payments",
                "environment": "prod",
                "alert_name": "PaymentGatewayTimeout",
                "alert_signature": "sig-payments-timeout",
            },
        )
        reviewed = await repo.review_knowledge_rag_draft(
            tenant_id="tenant-a",
            draft_id=draft["draft_id"],
            expected_row_version=draft["row_version"],
            title=draft["title"],
            content=draft["content"],
            review_notes="Validated steps against incident telemetry",
            reviewed_by="reviewer-a",
        )
        assert reviewed is not None
        approved_draft, event_payload = await repo.approve_knowledge_rag_draft(
            tenant_id="tenant-a",
            draft_id=draft["draft_id"],
            expected_row_version=reviewed["row_version"],
            approved_by="approver-a",
        )
        await session.commit()
        doc_id = UUID(str(event_payload["document_id"]))
        event_id = f"rag-document-approved:{doc_id}"

        # 1. Initial state after approval: pending index, outbox event persisted, picked up by reconciliation query
        outbox_row = await session.scalar(
            select(ResolutionOutboxRecord).where(ResolutionOutboxRecord.event_id == event_id)
        )
        assert outbox_row is not None
        assert outbox_row.topic == "rag.document.approved"
        due_initial = await repo.list_due_governed_rag_index_retries(retry_limit=5)
        assert [str(row.document_id) for row in due_initial] == [str(doc_id)]
        assert await repo.list_retrievable_governed_rag_documents(tenant_id="tenant-a") == []

        # Verify MySQL fallback retrieval works while indexing is pending, and remains tenant-scoped
        # and approval-gated.
        fallback_tenant_a = await repo.find_learned_runbooks(
            tenant_id="tenant-a",
            service="payments",
            environment="prod",
            alert_signature="sig-payments-timeout",
            alert_name="PaymentGatewayTimeout",
        )
        assert len(fallback_tenant_a) == 1
        assert fallback_tenant_a[0]["runbook_id"] == str(rb_id)
        assert fallback_tenant_a[0]["approval_status"] == "approved"

        fallback_tenant_b = await repo.find_learned_runbooks(
            tenant_id="tenant-b",
            service="payments",
            environment="prod",
            alert_signature="sig-payments-timeout",
            alert_name="PaymentGatewayTimeout",
        )
        assert fallback_tenant_b == []

    # 2. Vector store unavailable during worker reconciliation pass -> transitions to failed with backoff
    module = load_context_app_module()
    connector = FlakyVectorConnector(fail=True)
    module.vector_connector = lambda: connector
    worker_app = SimpleNamespace(state=SimpleNamespace(session_factory=sqlite_session_factory))

    processed = await module._run_governed_rag_retry_pass(worker_app)
    assert processed == 0
    assert connector.upsert_calls == 1

    async with sqlite_session_factory() as session:
        repo = IncidentRepository(session)
        doc = await session.get(GovernedRagDocumentRecord, doc_id)
        assert doc is not None
        assert doc.index_status == "failed"
        assert doc.index_attempts == 1
        assert "vector store connection refused" in (doc.index_error or "")
        assert doc.next_index_attempt_at is not None
        assert await repo.list_retrievable_governed_rag_documents(tenant_id="tenant-a") == []
        # Backoff window has not elapsed yet
        assert await repo.list_due_governed_rag_index_retries(retry_limit=5) == []

        # 3. Simulate worker in-flight ("indexing") lease: active lease is protected, expired lease is recovered
        doc.index_status = "indexing"
        doc.last_index_attempt_at = datetime.now(UTC)
        await session.commit()

        assert await repo.list_due_governed_rag_index_retries(retry_limit=5, stale_indexing_seconds=60.0) == []
        assert await repo.claim_governed_rag_document_for_indexing(
            tenant_id="tenant-a", document_id=doc_id, stale_indexing_seconds=60.0
        ) is None

        # Age the "indexing" lease past stale_indexing_seconds to simulate a worker crash mid-indexing
        doc.last_index_attempt_at = datetime.now(UTC) - timedelta(seconds=120)
        await session.commit()
        due_stale = await repo.list_due_governed_rag_index_retries(retry_limit=5, stale_indexing_seconds=60.0)
        assert [str(row.document_id) for row in due_stale] == [str(doc_id)]

    # 4. Vector store recovers -> background retry pass claims stale/failed doc, upserts, verifies receipt, marks indexed
    connector.fail = False
    recovered = await module._run_governed_rag_retry_pass(worker_app, stale_indexing_seconds=60.0)
    assert recovered == 1
    assert connector.upsert_calls == 2
    assert len(connector.documents) == 1

    async with sqlite_session_factory() as session:
        repo = IncidentRepository(session)
        doc = await session.get(GovernedRagDocumentRecord, doc_id)
        version_row = await session.get(RunbookVersionRecord, (rb_id, 1))
        assert doc is not None
        assert doc.index_status == "indexed"
        assert doc.index_attempts == 2
        assert doc.index_error is None
        assert doc.next_index_attempt_at is None
        assert doc.index_receipt["content_checksum"] == doc.content_checksum
        assert doc.indexed_at is not None
        assert version_row is not None
        assert version_row.content["index_status"] == "indexed"
        retrievable = await repo.list_retrievable_governed_rag_documents(tenant_id="tenant-a")
        assert [str(r.document_id) for r in retrievable] == [str(doc_id)]

    # 5. Repeated delivery & duplicate indexing events are idempotent no-ops once indexed
    await module._index_governed_document(worker_app, event_payload)
    assert connector.upsert_calls == 2
    assert len(connector.documents) == 1


@pytest.mark.asyncio
async def test_manual_retry_endpoint_resets_exhausted_attempts_and_handles_transient_vector_failure(
    sqlite_session_factory,
):
    from uuid import UUID

    async with sqlite_session_factory() as session:
        binding = await seed_binding(session, "tenant-a")
        repo = IncidentRepository(session)
        draft = (await repo.create_evidence_rag_drafts(
            tenant_id="tenant-a",
            created_by="author",
            binding=binding,
            documents=[{
                "document_kind": "remediation",
                "title": "Dead-lettered recovery doc",
                "content": "verified remediation steps for manual retry recovery test",
            }],
            evidence_ids=binding["evidence_ids"],
            source_uris=binding["source_uris"],
        ))[0]
        reviewed = await repo.review_evidence_rag_draft(
            tenant_id="tenant-a",
            draft_id=draft["draft_id"],
            expected_row_version=1,
            title=draft["title"],
            content=draft["content"],
            review_notes="verified",
            reviewed_by="reviewer-a",
        )
        _, event = await repo.approve_evidence_rag_draft(
            tenant_id="tenant-a",
            draft_id=draft["draft_id"],
            expected_row_version=reviewed["row_version"],
            approved_by="approver-a",
        )
        doc_id = UUID(str(event["document_id"]))
        doc = await session.get(GovernedRagDocumentRecord, doc_id)
        assert doc is not None
        doc.index_status = "failed"
        doc.index_attempts = 5
        doc.index_error = "exhausted retries"
        doc.next_index_attempt_at = datetime.now(UTC) - timedelta(minutes=10)
        await session.commit()

        # Automatic retry loop stops after retry_limit=5
        assert await repo.list_due_governed_rag_index_retries(retry_limit=5) == []

    module = load_context_app_module()
    connector = FlakyVectorConnector(fail=True)
    module.vector_connector = lambda: connector
    module.app.state.session_factory = sqlite_session_factory
    retry_req = module.GovernedRagIndexRetryRequest(tenant_scope="tenant-a", requested_by="operator-a")

    # Manual retry while vector store is still down resets attempts to 0, tries once (attempts=1),
    # and returns structured status instead of raising HTTP 500.
    failed_resp = await module.retry_governed_rag_index(str(doc_id), retry_req)
    assert failed_resp["status"] == "retry_requested"
    assert failed_resp["indexing_status"] == "failed"
    assert "vector store connection refused" in (failed_resp["indexing_error"] or "")

    async with sqlite_session_factory() as session:
        doc = await session.get(GovernedRagDocumentRecord, doc_id)
        assert doc is not None
        assert doc.index_attempts == 1
        assert doc.index_status == "failed"

    # Manual retry when vector store is healthy succeeds immediately
    connector.fail = False
    ok_resp = await module.retry_governed_rag_index(str(doc_id), retry_req)
    assert ok_resp["status"] == "retry_requested"
    assert ok_resp["indexing_status"] == "indexed"
    assert ok_resp["indexing_error"] is None
