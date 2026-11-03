from __future__ import annotations

import importlib.util
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from uuid import NAMESPACE_URL, UUID, uuid4, uuid5

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import event
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

ROOT = Path(__file__).resolve().parents[2]
for rel in (
    "backend/src/common",
    "backend/src/monitoring-adapter",
    "backend/src/remediation-engine",
    "backend/src/closure-service",
    "ai-workbench/src/common",
    "ai-workbench/src/context-agent",
    "ai-workbench/src/resolution-agent",
):
    candidate = str(ROOT / rel)
    if candidate not in sys.path:
        sys.path.insert(0, candidate)

from ai_workbench_common.models import Context  # noqa: E402
from closure_service.validation import ClosureValidationAgent  # noqa: E402
from common.database import (  # noqa: E402
    Base,
    ContextSnapshotRecord,
    GovernedRagDocumentRecord,
    HumanEvidenceRequestRecord,
    IncidentProjectionRecord,
    IncidentRecord,
    KnowledgeRagDraftRecord,
    RunbookVersionRecord,
)
from common.models import (  # noqa: E402
    Alert,
    AlertSeverity,
    Incident,
    RemediationAction,
    RemediationStatus,
)
from common.orchestration.execution_plan import resolve_execution_plan  # noqa: E402
from common.orchestration.execution_plan_contract import (  # noqa: E402
    canonical_plan_fingerprint,
    verify_plan_fingerprint,
)
from common.repository import ContextEnrichmentRepository, IncidentRepository  # noqa: E402
from monitoring_adapter.landing_pad_normalizer import normalize_landing_pad_alert  # noqa: E402


def _load_module(name: str, rel_path: str):
    if name in sys.modules:
        return sys.modules[name]
    path = ROOT / rel_path
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


monitoring_app_module = _load_module(
    "monitoring_adapter_qual_audit", "backend/src/monitoring-adapter/app.py"
)
resolution_app_module = _load_module(
    "resolution_agent_qual_audit", "ai-workbench/src/resolution-agent/app.py"
)
remediation_app_module = _load_module(
    "remediation_engine_qual_audit", "backend/src/remediation-engine/app.py"
)
closure_app_module = _load_module(
    "closure_service_qual_audit", "backend/src/closure-service/app.py"
)


class _OfflineModelGateway:
    async def generate(self, request):
        raise RuntimeError("offline qualification test - use deterministic fallback")


async def _noop_async(*_args, **_kwargs):
    return None


resolution_app_module.agent.model_gateway = _OfflineModelGateway()
resolution_app_module.agent.runtime.max_attempts = 1
resolution_app_module.agent._judge_groundedness = _noop_async
resolution_app_module.agent._publish_evaluation = lambda **_kwargs: None
resolution_app_module._ensure_global_knowledge_loaded = _noop_async


@pytest.fixture()
async def session_factory(tmp_path: Path):
    db_file = tmp_path / "qualification_audit.sqlite"
    engine = create_async_engine(f"sqlite+aiosqlite:///{db_file}")

    @event.listens_for(engine.sync_engine, "connect")
    def _register_sqlite_locks(dbapi_connection, _connection_record):
        dbapi_connection.create_function("GET_LOCK", 2, lambda _name, _timeout: 1)
        dbapi_connection.create_function("RELEASE_LOCK", 1, lambda _name: 1)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        yield factory
    finally:
        await engine.dispose()


def _test_observer_profile(service: str = "orders-db", tenant_id: str = "tenant-qual-a") -> dict:
    kinds = [
        "availability",
        "alert_clearance",
        "error_rate",
        "latency",
        "dependency_health",
        "critical_alerts",
    ]
    return {
        "observer_id": f"{service}-test-observer",
        "service": service,
        "environment": "test",
        "connector_id": "prometheus-test-observer",
        "validators": [
            {
                "validator_id": f"val-{service}-{kind}",
                "tenant_id": tenant_id,
                "connector_id": "prometheus-test-observer",
                "target_resource_id": service,
                "kind": kind,
                "check_reference": f"promql:{service}:{kind}",
                "expected_condition": f"{kind} healthy",
                "evaluation_operator": "eq",
                "threshold": True,
                "observation_window_seconds": 60,
                "minimum_sample_count": 2,
                "timeout_seconds": 10,
                "authoritative_source": "prometheus-test-observer",
                "onboarding_registry_reference": f"validator-registry:val-{service}-{kind}",
            }
            for kind in kinds
        ],
    }


# ============================================================================
# Case D: Jira Route Shadowing & Webhook Authentication Verification
# ============================================================================


def test_case_d_jira_webhook_routing_auth_and_generic_provider_isolation(
    session_factory, monkeypatch
) -> None:
    monkeypatch.setattr(monitoring_app_module, "JIRA_WEBHOOK_SECRET", "test-jira-secret-999")
    monitoring_app_module.settings.database_enabled = True
    monitoring_app_module.app.state.session_factory = session_factory
    processed_events: list[tuple[dict, str | None]] = []

    async def _fake_process_jira(payload: dict, trace_id: str | None) -> None:
        processed_events.append((payload, trace_id))

    monkeypatch.setattr(monitoring_app_module, "_process_jira_webhook", _fake_process_jira)

    client = TestClient(monitoring_app_module.app)
    jira_payload = {
        "webhookEvent": "jira:issue_created",
        "issue": {
            "key": "OPS-404",
            "fields": {
                "summary": "DatabaseReplicaLag on orders-db",
                "description": "Replica lag > 30s on orders-db",
                "priority": {"name": "High"},
                "status": {"name": "Open"},
            },
        },
    }

    # 1. Missing webhook token on POST /api/v1/alerts/jira must return 401 (NOT quarantined from /{provider})
    resp_missing = client.post("/api/v1/alerts/jira", json=jira_payload)
    assert resp_missing.status_code == 401
    assert "Jira webhook token" in resp_missing.json()["detail"]

    # 2. Wrong webhook token on POST /api/v1/alerts/jira must return 401
    resp_wrong = client.post(
        "/api/v1/alerts/jira",
        json=jira_payload,
        headers={"X-Webhook-Token": "wrong-secret"},
    )
    assert resp_wrong.status_code == 401

    # 3. Valid X-Webhook-Token on POST /api/v1/alerts/jira reaches ingest_jira_webhook and returns 200
    resp_valid = client.post(
        "/api/v1/alerts/jira",
        json=jira_payload,
        headers={"X-Webhook-Token": "test-jira-secret-999", "X-Trace-Id": "trace-jira-1"},
    )
    assert resp_valid.status_code == 200
    assert resp_valid.json() == {
        "received": True,
        "webhookEvent": "jira:issue_created",
        "ticket_id": "OPS-404",
    }
    assert len(processed_events) == 1
    assert processed_events[0][1] == "trace-jira-1"

    # 4. Valid X-Jira-Webhook-Secret header on POST /api/v1/tickets/jira also returns 200
    resp_tickets = client.post(
        "/api/v1/tickets/jira",
        json=jira_payload,
        headers={"X-Jira-Webhook-Secret": "test-jira-secret-999"},
    )
    assert resp_tickets.status_code == 200
    assert resp_tickets.json()["ticket_id"] == "OPS-404"
    assert len(processed_events) == 2

    # 5. Unregistered generic provider webhook on POST /api/v1/alerts/{provider} remains quarantined
    resp_generic = client.post(
        "/api/v1/alerts/datadog",
        json={"title": "Datadog synthetic alert", "service": "orders-db"},
    )
    assert resp_generic.status_code == 200
    assert resp_generic.json()["status"] == "quarantined"
    assert resp_generic.json()["provider"] == "datadog"


# ============================================================================
# Case A: Known-Runbook Qualification, Plan Fingerprinting & Approval Gates
# ============================================================================


@pytest.mark.asyncio
async def test_case_a_known_runbook_governed_plan_and_approval_enforcement(
    session_factory, monkeypatch, clear_execution_catalog_cache
) -> None:
    tenant_id = "tenant-qual-a"
    service = "orders-db"
    alert_name = "DatabaseReplicaLag"
    source_ref = "runbook://orders-db/replica-lag-v1"
    rb_id = uuid5(NAMESPACE_URL, f"kaiops:runbook:{tenant_id}:{source_ref}")

    async with session_factory() as session:
        repo = IncidentRepository(session)
        draft = await repo.create_knowledge_rag_draft(
            tenant_id=tenant_id,
            created_by="author@kaims.local",
            document_kind="runbook",
            source_ref=source_ref,
            title="Runbook: orders-db - DatabaseReplicaLag",
            content=(
                "# Runbook: orders-db - DatabaseReplicaLag\n\n"
                "## Symptoms & Root Cause\n"
                "Read replica apply thread stalled due to long-running reporting query.\n\n"
                "## Business Impact\n"
                "Stale order history reads for customer portal.\n\n"
                "## Remediation Steps\n"
                "- `kubectl rollout restart deployment/orders-db-replica -n test`\n\n"
                "## Validation\n"
                "Verify replica lag < 5s for 60s.\n\n"
                "## Rollback\n"
                "`kubectl rollout undo deployment/orders-db-replica -n test`\n"
            ),
            metadata={
                "service": service,
                "alert_name": alert_name,
                "environment": "test",
                "approval_expires_at": (datetime.now(UTC) + timedelta(days=30)).isoformat(),
            },
        )
        reviewed = await repo.review_knowledge_rag_draft(
            tenant_id=tenant_id,
            draft_id=draft["draft_id"],
            expected_row_version=draft["row_version"],
            title=draft["title"],
            content=draft["content"],
            review_notes="Reviewed known runbook for orders-db",
            reviewed_by="reviewer@kaims.local",
        )
        assert reviewed is not None
        approved = await repo.approve_knowledge_rag_draft(
            tenant_id=tenant_id,
            draft_id=draft["draft_id"],
            expected_row_version=reviewed["row_version"],
            approved_by="approver@kaims.local",
        )
        assert approved is not None
        _, doc_payload = approved
        await repo.mark_governed_rag_document_indexed(
            tenant_id=tenant_id,
            document_id=doc_payload["document_id"],
            index_receipt={
                "document_id": doc_payload["document_id"],
                "content_checksum": doc_payload["content_checksum"],
                "indexed": 1,
            },
        )
        await session.commit()

        # Verify retrievable governed document for tenant-qual-a (and tenant isolation)
        retrievable = await repo.list_retrievable_governed_rag_documents(
            tenant_id=tenant_id, document_kind="runbook"
        )
        assert len(retrievable) == 1
        assert retrievable[0].content_checksum == doc_payload["content_checksum"]
        assert await repo.list_retrievable_governed_rag_documents(tenant_id="other-tenant") == []

        gov = await repo.get_runbook_governance(str(rb_id), 1, tenant_id=tenant_id)
        assert gov is not None
        assert gov["status"] == "approved"
        runbook_checksum = gov["payload"]["checksum_sha256"]

    # Verify missing recovery observer in recovery-observers.json produces non-executable / blocked plan
    monkeypatch.setenv("ENVIRONMENT", "test")
    monkeypatch.setenv(
        "RECOVERY_OBSERVER_REGISTRY_PATH",
        str(ROOT / "backend/config/recovery-observers.json"),
    )
    alert_unregistered = Alert(
        id=uuid4(),
        tenant_id=tenant_id,
        source="prometheus",
        name=alert_name,
        description="Replica lag > 30s on orders-db",
        service=service,
        environment="test",
        severity=AlertSeverity.CRITICAL,
    )
    plan_without_observer = resolve_execution_plan(
        alert=alert_unregistered,
        workflow_name="orders-db-remediation",
        requires_approval=True,
        risk_tier="medium",
        execution_mode="governed",
        resolution_hints="kubectl rollout restart deployment/orders-db-replica -n test",
        evidence_basis=["ev-orders-db-1"],
        incident_id=uuid4(),
        root_cause="Read replica apply thread stalled",
        confidence=0.91,
    )
    assert plan_without_observer["schema_version"] == "kaims.execution-plan.v2"
    assert plan_without_observer["execution_ready"] is False
    assert verify_plan_fingerprint(plan_without_observer) is True

    # Verify registered recovery observer profile produces valid governed v2 execution plan with validators
    alert_registered = Alert(
        id=uuid4(),
        tenant_id="default",
        source="prometheus",
        name="KaiOpsServiceDown",
        description="api-gateway service is down",
        service="api-gateway",
        environment="prod",
        severity=AlertSeverity.CRITICAL,
    )
    governed_plan = resolve_execution_plan(
        alert=alert_registered,
        workflow_name="api-gateway-remediation",
        requires_approval=True,
        risk_tier="medium",
        execution_mode="governed",
        resolution_hints="Restart api-gateway service",
        evidence_basis=["ev-api-gateway-1"],
        incident_id=uuid4(),
        root_cause="Container unresponsive",
        confidence=0.95,
    )
    assert governed_plan["schema_version"] == "kaims.execution-plan.v2"
    assert len(governed_plan["validators"]) >= 1
    assert verify_plan_fingerprint(governed_plan) is True

    # Verify _resolution_requires_approval defaults to True (human approval preserved)
    assert remediation_app_module._resolution_requires_approval(
        {"decision": {"requires_approval": True}, "recommendation": {"confidence": 0.99}}
    ) is True

    # Verify _require_persisted_approved_runbook succeeds for matching durable checksum and blocks tampering
    remediation_app_module.settings.database_enabled = True
    remediation_app_module.app.state.session_factory = session_factory
    approval_obj = SimpleNamespace(
        tenant_id=tenant_id,
        approver_role="HITL_APPROVER",
        metadata={
            "execution_plan": {
                "runbook_governance_id": str(rb_id),
                "playbook_version": 1,
                "runbook_checksum": runbook_checksum,
            }
        },
    )
    await remediation_app_module._require_persisted_approved_runbook(approval_obj)

    approval_obj.metadata["execution_plan"]["runbook_checksum"] = "sha256:tampered"
    with pytest.raises(remediation_app_module.PolicyViolation, match="checksum"):
        await remediation_app_module._require_persisted_approved_runbook(approval_obj)

    # Verify missing, naive (non-timezone-aware), and expired approval_expires_at are blocked
    async with session_factory() as session:
        repo = IncidentRepository(session)
        rb_missing_exp = uuid4()
        await repo.approve_runbook_version(
            runbook_id=str(rb_missing_exp),
            version=1,
            approved_by="approver@kaims.local",
            tenant_id=tenant_id,
            payload={"checksum_sha256": "sha256:valid-1", "reviewed_by": "independent-reviewer"},
        )
        rb_naive_exp = uuid4()
        await repo.approve_runbook_version(
            runbook_id=str(rb_naive_exp),
            version=1,
            approved_by="approver@kaims.local",
            tenant_id=tenant_id,
            payload={
                "checksum_sha256": "sha256:valid-2",
                "approval_expires_at": "2099-01-01T00:00:00",
                "reviewed_by": "independent-reviewer",
            },
        )
        rb_alt_checksum = uuid4()
        await repo.approve_runbook_version(
            runbook_id=str(rb_alt_checksum),
            version=1,
            approved_by="approver@kaims.local",
            tenant_id=tenant_id,
            payload={
                "checksum": "sha256:alternate-field-only",
                "approval_expires_at": "2099-01-01T00:00:00+00:00",
                "reviewed_by": "independent-reviewer",
            },
        )
        await session.commit()

    with pytest.raises(remediation_app_module.PolicyViolation, match="expiry is missing"):
        await remediation_app_module._require_persisted_approved_runbook(
            SimpleNamespace(
                tenant_id=tenant_id,
                approver_role="HITL_APPROVER",
                metadata={
                    "execution_plan": {
                        "runbook_governance_id": str(rb_missing_exp),
                        "playbook_version": 1,
                        "runbook_checksum": "sha256:valid-1",
                    }
                },
            )
        )

    with pytest.raises(remediation_app_module.PolicyViolation, match="timezone-aware"):
        await remediation_app_module._require_persisted_approved_runbook(
            SimpleNamespace(
                tenant_id=tenant_id,
                approver_role="HITL_APPROVER",
                metadata={
                    "execution_plan": {
                        "runbook_governance_id": str(rb_naive_exp),
                        "playbook_version": 1,
                        "runbook_checksum": "sha256:valid-2",
                    }
                },
            )
        )

    with pytest.raises(remediation_app_module.PolicyViolation, match="checksum"):
        await remediation_app_module._require_persisted_approved_runbook(
            SimpleNamespace(
                tenant_id=tenant_id,
                approver_role="HITL_APPROVER",
                metadata={
                    "execution_plan": {
                        "runbook_governance_id": str(rb_alt_checksum),
                        "playbook_version": 1,
                        "runbook_checksum": "sha256:alternate-field-only",
                    }
                },
            )
        )


# ============================================================================
# Case B: Unknown-Runbook Human-in-the-Loop, Opt-In Draft & Separation of Duties
# ============================================================================


@pytest.mark.asyncio
async def test_case_b_unknown_runbook_human_input_draft_review_and_separation_of_duties(
    session_factory,
) -> None:
    tenant_id = "tenant-qual-b"
    service = "payment-settlement-worker"
    alert_name = "SettlementBatchCursorStuck"
    incident_id = uuid4()
    snapshot_id = uuid4()

    alert = Alert(
        id=uuid4(),
        tenant_id=tenant_id,
        source="prometheus",
        name=alert_name,
        description="Settlement batch cursor stuck on shard 4 for > 15m",
        service=service,
        environment="test",
        severity=AlertSeverity.CRITICAL,
    )
    initial_context = Context(
        tenant_id=tenant_id,
        incident_id=incident_id,
        alert=alert,
        runbook="",
        metadata={
            "analysis_request_id": str(uuid4()),
            "context_snapshot_id": str(snapshot_id),
            "context_fingerprint": "b" * 64,
            "context_subject_fingerprint": f"subj-{service}",
            "correlation_id": f"corr-{incident_id}",
            "rca_version": 1,
            "document_available": False,
            "context_quality": {
                "quality_score": 0.45,
                "reusable": False,
                "valid": True,
                "rca_ready": False,
                "impact_ready": False,
                "execution_ready": False,
                "discovery_degraded": True,
                "missing_required": ["runbook"],
                "present": ["logs", "metrics"],
            },
        },
    )

    now = datetime.now(UTC)
    async with session_factory() as session:
        session.add(
            IncidentRecord(
                id=incident_id,
                tenant_id=tenant_id,
                title=alert_name,
                severity="critical",
                status="investigating",
                service=service,
                environment="test",
                payload={"id": str(incident_id), "alert_ids": [str(alert.id)], "status": "investigating"},
            )
        )
        session.add(
            IncidentProjectionRecord(
                incident_id=incident_id,
                tenant_id=tenant_id,
                alert_id=alert.id,
                service=service,
                environment="test",
                severity="critical",
                status="investigating",
                lifecycle_state="INVESTIGATING",
                projection_payload={},
            )
        )
        session.add(
            ContextSnapshotRecord(
                snapshot_id=snapshot_id,
                tenant_id=tenant_id,
                incident_id=str(incident_id),
                source_incident_id=str(incident_id),
                alert_signature=f"sig-{alert_name}",
                subject_fingerprint=f"subj-{service}",
                context_fingerprint="b" * 64,
                snapshot_stage="initial",
                snapshot_version=1,
                evidence_ids=[],
                evidence_checksums={},
                contract_version="kaiops.context.v2",
                quality_score=0.45,
                reusable=False,
                source_manifest={},
                payload=initial_context.model_dump(mode="json"),
                collected_at=now,
                expires_at=now + timedelta(hours=1),
            )
        )
        await session.commit()

    resolution_app_module.settings.database_enabled = True
    resolution_app_module.app.state.session_factory = session_factory
    rec_1 = await resolution_app_module._resolve_context(initial_context)
    inc_model = Incident(
        id=incident_id,
        tenant_id=tenant_id,
        service=service,
        environment="test",
        severity=AlertSeverity.CRITICAL,
        title=alert_name,
    )
    await resolution_app_module._persist_resolution_event(
        app=resolution_app_module.app,
        context=initial_context,
        incident=inc_model,
        recommendation=rec_1,
        decision_payload={},
    )

    async with session_factory() as session:
        inc_row = await session.get(IncidentRecord, incident_id)
        assert inc_row is not None and inc_row.status == "waiting_for_human"
        enrichment_repo = ContextEnrichmentRepository(session)
        ops_state = await enrichment_repo.incident_operations_state(
            tenant_id=tenant_id, incident_id=incident_id
        )
        assert ops_state["lifecycle_state"] == "COLLECTING"
        reqs = await enrichment_repo.list_context_evidence_requirements(
            tenant_id=tenant_id, incident_id=incident_id
        )
        runbook_req = next(r for r in reqs if r["category"] in {"runbook", "knowledge"})
        req_uuid = UUID(str(runbook_req["requirement_id"]))

        # 1. Human response WITHOUT create_runbook_draft does NOT create a draft
        no_draft_res = await enrichment_repo.record_human_evidence_response(
            tenant_id=tenant_id,
            incident_id=incident_id,
            requirement_id=req_uuid,
            response={
                "response": "Initial observation without requesting runbook draft creation.",
                "responder_id": "oncall-1@kaims.local",
                "responded_at": datetime.now(UTC).isoformat(),
                "observed_symptoms": "Cursor lock contention on shard 4.",
                "remediation_steps": "1. `kubectl rollout restart deployment/payment-settlement-worker -n test`",
                "create_runbook_draft": False,
            },
        )
        assert no_draft_res["knowledge_draft_id"] is None
        assert no_draft_res["runbook_status"] is None

        # Reset the request status to pending so we can test submitting WITH create_runbook_draft=True
        req_record = await session.get(HumanEvidenceRequestRecord, UUID(str(no_draft_res["request_id"])))
        assert req_record is not None
        req_record.status = "pending"
        req_record.response_payload = {}
        await session.flush()

        # 2. Human response WITH create_runbook_draft=True creates a DRAFT (not auto-approved!)
        draft_res = await enrichment_repo.record_human_evidence_response(
            tenant_id=tenant_id,
            incident_id=incident_id,
            requirement_id=req_uuid,
            response={
                "response": "Restart payment-settlement-worker deployment to release stale shard 4 lock.",
                "responder_id": "oncall-1@kaims.local",
                "responded_at": datetime.now(UTC).isoformat(),
                "observed_symptoms": "Shard 4 cursor lock held by orphaned worker pod.",
                "root_cause": "Orphaned worker pod held advisory lock after network partition.",
                "business_impact": "Settlement batch completion delayed by 15 minutes.",
                "remediation_steps": (
                    "1. `kubectl rollout restart deployment/payment-settlement-worker -n test`\n"
                    "2) `kubectl rollout status deployment/payment-settlement-worker -n test --timeout=120s`\n"
                    "+ `curl -fsS http://payment-settlement-worker.test.svc/healthz`\n"
                    "- `kubectl rollout restart deployment/payment-settlement-worker -n test; rm -rf /`\n"
                    "* `kubectl rollout restart deployment/payment-settlement-worker -n test && id`\n"
                    "3. `kubectl rollout restart deployment/payment-settlement-worker -n test | cat`\n"
                    "4. `kubectl rollout restart deployment/$(whoami) -n test`\n"
                ),
                "create_runbook_draft": True,
            },
        )
        await session.commit()

        assert draft_res["knowledge_draft_id"] is not None
        assert draft_res["runbook_status"] == "draft"
        assert draft_res.get("governed_document") is None
        assert draft_res.get("governed_document_id") is None

        draft_uuid = UUID(str(draft_res["knowledge_draft_id"]))
        draft_row = await session.get(KnowledgeRagDraftRecord, draft_uuid)
        assert draft_row is not None
        assert draft_row.status == "draft"
        assert draft_row.row_version == 1

        # Verify draft RunbookVersionRecord is persisted as 'draft' (not 'approved') before review/approval
        draft_rb_id = uuid5(NAMESPACE_URL, f"kaiops:runbook:{tenant_id}:{draft_row.source_ref}")
        draft_rb_row = await session.get(RunbookVersionRecord, (draft_rb_id, 1))
        assert draft_rb_row is not None
        assert draft_rb_row.approval_status == "draft"
        assert draft_rb_row.content.get("approval_status") == "draft"

        # Verify human-guided remediation command normalization and shell-injection rejection
        enriched_snap = await session.get(ContextSnapshotRecord, UUID(str(draft_res["context_snapshot_id"])))
        assert enriched_snap is not None
        resumed_ctx = Context.model_validate(enriched_snap.payload)
        resumed_rec = await resolution_app_module._resolve_context(resumed_ctx)
        assert "kubectl rollout restart deployment/payment-settlement-worker -n test" in resumed_rec.commands
        assert (
            "kubectl rollout status deployment/payment-settlement-worker -n test --timeout=120s"
            in resumed_rec.commands
        )
        assert "curl -fsS http://payment-settlement-worker.test.svc/healthz" in resumed_rec.commands
        assert not any(
            any(tok in cmd for tok in (";", "&&", "|", "$(", "rm -rf"))
            for cmd in resumed_rec.commands
        )

        inc_repo = IncidentRepository(session)
        # 3. Direct approval before review is blocked
        with pytest.raises(RuntimeError, match="direct approval is prohibited"):
            await inc_repo.approve_knowledge_rag_draft(
                tenant_id=tenant_id,
                draft_id=draft_uuid,
                expected_row_version=1,
                approved_by="approver@kaims.local",
            )

        # 4. Review transitions status to 'reviewed', updates content, and increments row_version to 2
        reviewed_markdown = draft_row.content + "\n<!-- reviewed by SRE -->\n"
        reviewed = await inc_repo.review_knowledge_rag_draft(
            tenant_id=tenant_id,
            draft_id=draft_uuid,
            expected_row_version=1,
            title=draft_row.title,
            content=reviewed_markdown,
            review_notes="Verified remediation commands for payment-settlement-worker",
            reviewed_by="sre-reviewer@kaims.local",
        )
        assert reviewed is not None
        assert reviewed["status"] == "reviewed"
        assert reviewed["row_version"] == 2

        # 5. Stale row_version=1 review is rejected
        stale = await inc_repo.review_knowledge_rag_draft(
            tenant_id=tenant_id,
            draft_id=draft_uuid,
            expected_row_version=1,
            title=draft_row.title,
            content=reviewed_markdown,
            review_notes="Stale review",
            reviewed_by="other@kaims.local",
        )
        assert stale is None

        # 6. Separation of duties: same actor cannot review and approve
        with pytest.raises(RuntimeError, match="different reviewer"):
            await inc_repo.approve_knowledge_rag_draft(
                tenant_id=tenant_id,
                draft_id=draft_uuid,
                expected_row_version=2,
                approved_by="sre-reviewer@kaims.local",
            )

        # 7. Distinct approver succeeds and persists GovernedRagDocumentRecord + RunbookVersionRecord
        approved_tuple = await inc_repo.approve_knowledge_rag_draft(
            tenant_id=tenant_id,
            draft_id=draft_uuid,
            expected_row_version=2,
            approved_by="sre-approver@kaims.local",
        )
        await session.commit()
        assert approved_tuple is not None
        approved_draft, approved_doc = approved_tuple
        assert approved_draft["status"] == "approved_pending_index"

        doc_record = await session.get(GovernedRagDocumentRecord, UUID(str(approved_doc["document_id"])))
        assert doc_record is not None
        assert doc_record.review_status == "approved"
        assert doc_record.index_status == "pending"
        approved_rb_row = await session.get(RunbookVersionRecord, (draft_rb_id, 1))
        assert approved_rb_row is not None
        assert approved_rb_row.approval_status == "approved"
        assert approved_rb_row.content.get("checksum_sha256") == doc_record.content_checksum


# ============================================================================
# Cases C1 & C2: Remediation Failure & Failed Recovery Validation Must Not Close
# ============================================================================


@pytest.mark.asyncio
async def test_cases_c1_and_c2_failed_remediation_or_failed_recovery_never_closes_incident_or_jira(
    session_factory, monkeypatch
) -> None:
    tenant_id = "tenant-qual-c"
    service = "orders-db"
    observer_profile = _test_observer_profile(service=service, tenant_id=tenant_id)
    validators = observer_profile["validators"]

    plan = {
        "schema_version": "kaims.execution-plan.v2",
        "plan_id": str(uuid4()),
        "tenant_id": tenant_id,
        "rca_version": "rca-v1",
        "evidence_snapshot_id": "snap-v1",
        "recommendation_version": "rec-v1",
        "validation_endpoints": [],
        "validators": validators,
        "required_validation_kinds": [v["kind"] for v in validators],
        "stability_window_seconds": 60,
    }
    plan["plan_fingerprint"] = canonical_plan_fingerprint(plan)

    jira_sync_outcomes: list[dict] = []
    original_sync = closure_app_module._sync_closure_to_jira

    async def _spy_jira_sync(incident_payload, report):
        res = await original_sync(incident_payload, report)
        jira_sync_outcomes.append(res)
        return res

    jira_http_requests: list[tuple[str, str, dict | None]] = []

    class _FakeJiraResponse:
        status_code = 200

        def __init__(self, data: dict | None = None):
            self._data = data or {}

        def json(self) -> dict:
            return self._data

    class _FakeJiraClient:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        async def post(self, url: str, json: dict | None = None, **kwargs):
            jira_http_requests.append(("POST", url, json))
            return _FakeJiraResponse({"id": "1001"})

        async def get(self, url: str, **kwargs):
            jira_http_requests.append(("GET", url, None))
            return _FakeJiraResponse({"transitions": [{"id": "31", "name": "Done"}]})

    monkeypatch.setenv("JIRA_API_BASE_URL", "https://jira.example.test")
    monkeypatch.setenv("JIRA_API_EMAIL", "bot@example.test")
    monkeypatch.setenv("JIRA_API_TOKEN", "dummy-test-token")
    import httpx

    monkeypatch.setattr(httpx, "AsyncClient", _FakeJiraClient)
    monkeypatch.setattr(closure_app_module, "_sync_closure_to_jira", _spy_jira_sync)
    closure_app_module.settings.database_enabled = True
    closure_app_module.app.state.session_factory = session_factory

    class _DummyProducer:
        async def publish(self, *args, **kwargs):
            return None

    closure_app_module.app.state.producer = _DummyProducer()

    # --- Case C1: Remediation execution FAILS ---
    incident_c1 = uuid4()
    async with session_factory() as session:
        session.add(
            IncidentRecord(
                id=incident_c1,
                tenant_id=tenant_id,
                title="Orders DB Failure C1",
                severity="critical",
                status="remediating",
                service=service,
                environment="test",
                ticket_id="OPS-C1",
                payload={
                    "id": str(incident_c1),
                    "status": "remediating",
                    "ticket_id": "OPS-C1",
                    "metadata": {"jira_issue_key": "OPS-C1"},
                },
            )
        )
        await session.commit()

    failed_action = RemediationAction(
        tenant_id=tenant_id,
        incident_id=incident_c1,
        action_type="restart_pod",
        target=service,
        status=RemediationStatus.FAILED,
        error="Kubernetes API timeout during rollout restart",
        completed_at=datetime.now(UTC) - timedelta(seconds=120),
        parameters={"execution_plan": plan, "approved_plan_fingerprint": plan["plan_fingerprint"]},
    )
    report_c1 = await ClosureValidationAgent().validate(failed_action)
    assert report_c1.validation["remediation_succeeded"] is False
    assert report_c1.health_restored is False
    assert report_c1.alerts_cleared is False
    assert report_c1.closure_status == "validation_failed"

    await closure_app_module._persist_closure_event(
        app=closure_app_module.app,
        action=failed_action,
        report=report_c1,
        source_payload={"source": "closure-validation"},
        sync_jira=True,
    )
    async with session_factory() as session:
        inc_c1_row = await session.get(IncidentRecord, incident_c1)
        assert inc_c1_row is not None
        assert inc_c1_row.status != "closed"
    assert len(jira_sync_outcomes) == 1
    assert jira_sync_outcomes[0]["status"] == "validation_pending"
    assert jira_sync_outcomes[0]["transitioned"] is False
    assert not any("/transitions" in url for _, url, _ in jira_http_requests)

    # --- Case C2: Remediation SUCCEEDS, but independent recovery checks FAIL ---
    incident_c2 = uuid4()
    async with session_factory() as session:
        session.add(
            IncidentRecord(
                id=incident_c2,
                tenant_id=tenant_id,
                title="Orders DB Failure C2",
                severity="critical",
                status="remediating",
                service=service,
                environment="test",
                ticket_id="OPS-C2",
                payload={
                    "id": str(incident_c2),
                    "status": "remediating",
                    "ticket_id": "OPS-C2",
                    "metadata": {"jira_issue_key": "OPS-C2"},
                },
            )
        )
        await session.commit()

    now = datetime.now(UTC)
    action_c2 = RemediationAction(
        tenant_id=tenant_id,
        incident_id=incident_c2,
        action_type="restart_pod",
        target=service,
        status=RemediationStatus.SUCCEEDED,
        completed_at=now - timedelta(seconds=120),
        parameters={
            "execution_plan": plan,
            "approved_plan_fingerprint": plan["plan_fingerprint"],
            "validator_registry_snapshot": validators,
            "execution_result": {
                "executed": True,
                "build_result": "SUCCESS",
                "recovery_validated": True,
                "recovery_evidence": {"executed": True, "recovery_validated": True},
            },
            # Post-state observations report passed=False (alert still firing / latency still breached)
            "validation_observations": [
                {
                    "validator_id": v["validator_id"],
                    "execution_id": "placeholder",
                    "plan_fingerprint": plan["plan_fingerprint"],
                    "connector_id": v["connector_id"],
                    "target_resource_id": service,
                    "observed_at": (now - timedelta(seconds=offset)).isoformat(),
                    "passed": False,
                    "result_checksum": f"sha256:{'f' * 64}",
                }
                for v in validators
                for offset in (65, 5)
            ],
        },
    )
    contract_c2 = {
        "schema_version": "kaims.remediation.v3",
        "execution_id": str(action_c2.id),
        "plan_id": str(plan["plan_id"]),
        "plan_fingerprint": plan["plan_fingerprint"],
        "target": {"name": action_c2.target},
        "plan": plan,
    }
    contract_c2["binding_fingerprint"] = canonical_plan_fingerprint(contract_c2)
    action_c2.parameters["execution_contract"] = contract_c2
    for obs in action_c2.parameters["validation_observations"]:
        obs["execution_id"] = str(action_c2.id)

    report_c2 = await ClosureValidationAgent().validate(action_c2)
    assert report_c2.validation["remediation_succeeded"] is True
    assert report_c2.validation["executor_recovery_validated"] is True
    assert report_c2.validation["independent_checks_passed"] is False
    assert report_c2.health_restored is False
    assert report_c2.alerts_cleared is False
    assert report_c2.closure_status == "validation_failed"

    await closure_app_module._persist_closure_event(
        app=closure_app_module.app,
        action=action_c2,
        report=report_c2,
        source_payload={"source": "closure-validation"},
        sync_jira=True,
    )
    async with session_factory() as session:
        inc_c2_row = await session.get(IncidentRecord, incident_c2)
        assert inc_c2_row is not None
        assert inc_c2_row.status != "closed"
    assert len(jira_sync_outcomes) == 2
    assert jira_sync_outcomes[1]["status"] == "validation_pending"
    assert jira_sync_outcomes[1]["transitioned"] is False
    assert not any("/transitions" in url for _, url, _ in jira_http_requests)


# ============================================================================
# Cases E & F: OpenSearch/File Logs, Email & Landing-Pad Ingestion Qualification
# ============================================================================


@pytest.mark.asyncio
async def test_cases_e_and_f_log_email_and_landing_pad_ingestion_qualification(monkeypatch) -> None:
    published_alerts: list[Alert] = []

    async def _capture_alert(alert: Alert) -> None:
        published_alerts.append(alert)

    monkeypatch.setattr(monitoring_app_module, "_publish_ingested_alert", _capture_alert)
    monkeypatch.setattr(monitoring_app_module, "CENTRALIZED_JIRA_ROUTING_ENABLED", False)
    monkeypatch.setattr(monitoring_app_module, "EMAIL_JIRA_ROUTING_ENABLED", False)
    monkeypatch.setattr(monitoring_app_module, "OPENSEARCH_LOG_JIRA_ROUTING_ENABLED", False)
    monkeypatch.setattr(monitoring_app_module, "NONACTIONABLE_ALERT_PUBLISH_ENABLED", True)

    # Case E: Log ingestion via _process_log_line (used by file-log & OpenSearch pollers)
    log_record = {
        "timestamp": datetime.now(UTC).isoformat(),
        "service": "orders-db",
        "environment": "test",
        "level": "ERROR",
        "line": "FATAL deadlock detected in replication apply worker",
        "message": "FATAL deadlock detected in replication apply worker",
        "tenant_id": "tenant-qual-ef",
        "source_path": "opensearch://logs-orders-db/doc-1",
    }
    await monitoring_app_module._process_log_line(log_record)
    assert len(published_alerts) == 1
    assert published_alerts[0].service == "orders-db"
    assert published_alerts[0].severity in {AlertSeverity.HIGH, AlertSeverity.CRITICAL, AlertSeverity.WARNING}

    # Case F1: Email ingestion via _process_polled_email (used by IMAP email poller)
    email_record = {
        "message_id": "<alert-orders-db-001@monitoring.example.com>",
        "subject": "[CRITICAL] orders-db replication lag alert",
        "sender": "alerts@monitoring.example.com",
        "body": "Service: orders-db\nEnvironment: test\nSeverity: critical\nReplication lag is 48s.",
        "service": "orders-db",
        "environment": "test",
        "severity": "critical",
        "tenant_id": "tenant-qual-ef",
    }
    await monitoring_app_module._process_polled_email(email_record)
    assert len(published_alerts) == 2

    # Case F2: Landing-pad normalization deterministic fingerprint & schema
    raw_lp = {
        "source": "landing-pad",
        "name": "DatabaseReplicaLag",
        "service": "orders-db",
        "environment": "test",
        "severity": "critical",
        "description": "Replica lag exceeded 30s threshold",
        "labels": {"tenant_id": "tenant-qual-ef", "cluster": "test-cluster-1"},
    }
    from monitoring_adapter.dedup import compute_fingerprint

    norm_1 = normalize_landing_pad_alert(raw_lp, raw_lp)
    norm_2 = normalize_landing_pad_alert(raw_lp, raw_lp)
    assert norm_1["service"] == "orders-db"
    assert norm_1["severity"] == "critical"
    alert_1 = monitoring_app_module._build_alert_from_payload(norm_1)
    alert_2 = monitoring_app_module._build_alert_from_payload(norm_2)
    assert alert_1.service == alert_2.service == "orders-db"
    fp_1 = compute_fingerprint(norm_1)
    fp_2 = compute_fingerprint(norm_2)
    assert fp_1 == fp_2
    assert len(fp_1) >= 16
