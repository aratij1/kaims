import hashlib
import importlib.util
import json
import sys
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest
from common.continuous_learning import FailurePattern, IncidentEvidence
from common.database import (
    IncidentEvidenceRecord,
    KnowledgeRagDraftRecord,
    LearningAuditRecord,
    RunbookApprovalRecord,
    RunbookOutcomeRecord,
    RunbookVersionRecord,
)
from common.models import EvidenceReference
from common.repository import IncidentRepository
from sqlalchemy import event, select
from uuid import uuid4


def load_module():
    name = "knowledge_development_worker_app_test"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, Path("backend/src/knowledge-development-worker/app.py"))
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def digest(payload: dict) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()


def test_kaims_workspace_is_the_tenant_wide_development_scope() -> None:
    module = load_module()
    assert module._in_application_scope("KaiMS", service="api-gateway") is True
    assert module._in_application_scope("payments", service="api-gateway") is False


@pytest.mark.asyncio
async def test_incident_evidence_creates_and_revises_complete_document_set(sqlite_session_factory) -> None:
    module = load_module()
    evidence = IncidentEvidence(
        incident_id="incident-docs", service="checkout", environment="prod",
        alert_type="HighErrorRate", symptoms=["HTTP 5xx exceeded threshold"],
    )
    async with sqlite_session_factory() as session:
        first = await module._upsert_knowledge_documents(session, evidence, tenant_id="default")
        await session.commit()
        rows = (await session.execute(select(KnowledgeRagDraftRecord))).scalars().all()
        assert first == {"created": 5, "updated": 0, "unchanged": 0}
        assert {row.document_kind for row in rows} == {"runbook", "change", "deployment", "validation", "resolution_catalog"}
        assert all((row.metadata_payload or {}).get("context_eligible") is False for row in rows)

        revised = evidence.model_copy(update={"symptoms": ["HTTP 5xx exceeded threshold", "Checkout requests failed"]})
        second = await module._upsert_knowledge_documents(session, revised, tenant_id="default")
        await session.commit()
        assert second["updated"] >= 2
        assert (await session.execute(select(KnowledgeRagDraftRecord))).scalars().all()[0].row_version >= 1


@pytest.mark.asyncio
async def test_cold_start_creates_non_executable_diagnostic_candidate(sqlite_session_factory) -> None:
    module = load_module()
    pattern = FailurePattern(
        pattern_id="pattern-1", issue_signature="a" * 64, service="api-gateway",
        environment="prod", alert_type="latency", incident_ids=["incident-1"],
        occurrence_frequency=1, common_symptoms=["p99 latency exceeded 3 seconds"],
        evidence_references=[
            EvidenceReference(evidence_id="METRIC-1", source="prometheus", uri="prometheus://query/1", summary="p99 high"),
            EvidenceReference(evidence_id="LOG-1", source="opensearch", uri="opensearch://logs/1", summary="request timeout"),
        ], confidence=.57,
    )
    quality = {
        "passed": False,
        "checks": {"independent_sources": True, "no_conflicts": True},
        "metrics": {"independent_sources": 2, "confidence": .57},
    }
    async with sqlite_session_factory() as session:
        assert await module._draft_candidate(session, pattern, quality, tenant_id="tenant-a") is True
        # SQLite does not autoincrement BigInteger primary keys; production MySQL does.
        next(item for item in session.new if isinstance(item, LearningAuditRecord)).sequence_id = 1
        await session.commit()
        row = (await session.execute(select(RunbookVersionRecord))).scalar_one()

    assert row.approval_status == "draft"
    assert row.content["catalog_stage"] == "diagnostic_candidate"
    assert row.content["execution_eligible"] is False
    assert row.content["remediation_steps"] == []
    assert row.content["promotion_requirements"]


@pytest.mark.asyncio
async def test_new_incident_can_bootstrap_evidence_work_without_inventing_remediation(sqlite_session_factory) -> None:
    module = load_module()
    pattern = FailurePattern(
        pattern_id="pattern-new", issue_signature="b" * 64, service="checkout",
        environment="prod", alert_type="error-rate", incident_ids=["incident-new"],
        occurrence_frequency=1, common_symptoms=["HTTP 5xx rate increased"],
        evidence_references=[
            EvidenceReference(evidence_id="METRIC-2", source="prometheus", uri="prometheus://query/2", summary="5xx high"),
        ], confidence=.47,
    )
    quality = {
        "passed": False,
        "checks": {"independent_sources": False, "no_conflicts": True},
        "metrics": {"independent_sources": 1, "confidence": .47},
    }
    async with sqlite_session_factory() as session:
        assert await module._draft_candidate(
            session, pattern, quality, allow_evidence_work=True, tenant_id="tenant-a"
        ) is True
        next(item for item in session.new if isinstance(item, LearningAuditRecord)).sequence_id = 1
        await session.commit()
        row = (await session.execute(select(RunbookVersionRecord))).scalar_one()

    assert row.content["catalog_stage"] == "evidence_work_candidate"
    assert row.content["execution_eligible"] is False
    assert row.content["remediation_steps"] == []
    assert row.content["validation_steps"] == []
    assert row.content["rollback_steps"] == []


@pytest.mark.asyncio
async def test_learning_report_is_tenant_scoped_and_verifies_audit_hashes(sqlite_session_factory) -> None:
    module = load_module()
    module.app.state.session_factory = sqlite_session_factory
    tenant_a_runbook = uuid4()
    tenant_b_runbook = uuid4()
    valid_payload = {"incident_id": "incident-a", "successful": True}
    invalid_payload = {"incident_id": "incident-a", "successful": False}

    async with sqlite_session_factory() as session:
        session.add_all([
            RunbookOutcomeRecord(tenant_id="tenant-a", incident_id="incident-a", runbook_id=tenant_a_runbook, runbook_version=1, reviewed=True, successful=True, validation={"passed": True}),
            RunbookOutcomeRecord(tenant_id="tenant-b", incident_id="incident-b", runbook_id=tenant_b_runbook, runbook_version=2, reviewed=False, successful=False, validation={"passed": False}),
            LearningAuditRecord(sequence_id=1, tenant_id="tenant-a", actor="reviewer-a", action="runbook.execution.recorded", resource_type="runbook", resource_id=str(tenant_a_runbook), payload=valid_payload, payload_sha256=digest(valid_payload)),
            LearningAuditRecord(sequence_id=2, tenant_id="tenant-a", actor="reviewer-a", action="runbook.execution.recorded", resource_type="runbook", resource_id=str(tenant_a_runbook), payload=invalid_payload, payload_sha256="0" * 64),
            LearningAuditRecord(sequence_id=3, tenant_id="tenant-b", actor="reviewer-b", action="runbook.execution.recorded", resource_type="runbook", resource_id=str(tenant_b_runbook), payload={"incident_id": "incident-b"}, payload_sha256="0" * 64),
        ])
        await session.commit()

    result = await module.report(tenant_id="tenant-a")

    assert result["outcome_summary"] == {"total": 1, "reviewed": 1, "successful": 1, "failed": 0, "success_rate": 1.0}
    assert [row["incident_id"] for row in result["outcomes"]] == ["incident-a"]
    assert {row["hash_verified"] for row in result["learning_audit"]} == {True, False}
    assert all(row["actor"] == "reviewer-a" for row in result["learning_audit"])


def test_platform_workspace_is_tenant_wide_scope() -> None:
    module = load_module()
    assert module._in_application_scope("Platform", service="api-gateway") is True
    assert module._in_application_scope("KaiMS", service="mysql") is True
    assert module._in_application_scope("api-gateway", service="mysql") is False


def test_learning_success_requires_closed_independently_validated_recovery() -> None:
    module = load_module()
    incident_id = uuid4()
    action_id = uuid4()
    report_id = uuid4()
    observation = {
        "phase": "post_state",
        "execution_id": str(action_id),
        "passed": True,
        "result_checksum": "sha256:" + "a" * 64,
    }
    report_payload = {
        "closure_status": "closed",
        "remediation_action_id": str(action_id),
        "health_restored": True,
        "alerts_cleared": True,
        "action_taken": "restarted payment service",
        "validation": {
            "independent_checks_passed": True,
            "all_recovery_checks_passed": True,
        },
        "metadata": {
            "stability_window": {"status": "recovered"},
            "independent_validation_observations": [observation],
        },
    }
    report = SimpleNamespace(id=report_id, payload=report_payload, root_cause="service process stalled")
    incident = SimpleNamespace(
        id=incident_id,
        status="closed",
        service="payments",
        environment="prod",
        title="Payments unavailable",
        payload={},
        ticket_id=None,
        created_at=None,
    )
    action = SimpleNamespace(id=action_id, status="succeeded", payload={}, action_type="restart")

    evidence = module._build_evidence(report, incident, action)
    assert evidence.resolution_successful is True
    assert evidence.reviewed is True

    invalid_cases = [
        ("incident", "status", "failed"),
        ("report_status", "closure_status", "pending_stability"),
        ("missing_stability", "stability_window", None),
        ("pending_stability", "stability_window", {"status": "pending"}),
        ("failed_stability", "stability_window", {"status": "failed"}),
        ("missing_validation", "validation", {}),
        ("missing_observation", "observations", []),
        ("failed_observation", "observation_passed", False),
        ("failed_action", "action_status", "failed"),
    ]
    for _, case, value in invalid_cases:
        incident.status = "closed"
        action.status = "succeeded"
        report.payload = dict(report_payload)
        report.payload["metadata"] = {
            "stability_window": {"status": "recovered"},
            "independent_validation_observations": [dict(observation)],
        }
        if case == "status":
            incident.status = value
        elif case == "closure_status":
            report.payload["closure_status"] = value
        elif case == "stability_window":
            if value is None:
                report.payload["metadata"].pop("stability_window")
            else:
                report.payload["metadata"]["stability_window"] = value
        elif case == "validation":
            report.payload["validation"] = value
        elif case == "observations":
            report.payload["metadata"]["independent_validation_observations"] = value
        elif case == "observation_passed":
            report.payload["metadata"]["independent_validation_observations"][0]["passed"] = value
        elif case == "action_status":
            action.status = value

        evidence = module._build_evidence(report, incident, action)
        assert evidence.resolution_successful is not True
        assert evidence.reviewed is False


@pytest.mark.asyncio
async def test_report_preserves_evidence_metadata_without_loading_raw_documents(sqlite_session_factory) -> None:
    module = load_module()
    module.app.state.session_factory = sqlite_session_factory
    async with sqlite_session_factory() as session:
        session.add(IncidentEvidenceRecord(
            tenant_id="tenant-metadata", incident_id="large-evidence", issue_signature="c" * 64,
            service="checkout", environment="prod", alert_type="latency", reviewed=True,
            evidence={"raw": "x" * 1000000},
        ))
        await session.commit()
    statements = []
    engine = sqlite_session_factory.kw["bind"].sync_engine
    def capture(connection, cursor, statement, parameters, context, executemany):
        if "FROM incident_evidence" in statement:
            statements.append(statement)
    event.listen(engine, "before_cursor_execute", capture)
    try:
        result = await module.report(tenant_id="tenant-metadata")
    finally:
        event.remove(engine, "before_cursor_execute", capture)
    assert result["evidence_count"] == 1
    assert result["recent_evidence"][0]["service"] == "checkout"
    assert result["recent_evidence"][0]["reviewed"] is True
    assert statements and all("incident_evidence.evidence," not in sql and "incident_evidence.evidence " not in sql for sql in statements)


@pytest.mark.asyncio
async def test_report_page_joins_complete_version_key_and_keeps_tenant_scope(sqlite_session_factory) -> None:
    module = load_module()
    runbook = uuid4()
    async with sqlite_session_factory() as session:
        for version, tenant in ((1, "tenant-a"), (2, "tenant-a"), (3, "tenant-b")):
            session.add(RunbookVersionRecord(
                runbook_id=runbook, version=version, tenant_id=tenant,
                issue_signature="d" * 64, owner="reviewer", risk_level="low",
                required_approval="human", content={"version": version},
            ))
        await session.commit()
        rows = (await session.execute(module._recent_report_records(
            RunbookVersionRecord, "tenant-a", RunbookVersionRecord.created_at, 1,
        ))).scalars().all()
    assert len(rows) == 1
    assert rows[0].tenant_id == "tenant-a"
    assert rows[0].version == 2


def test_catalog_promotion_requires_success_and_complete_recovery_controls() -> None:
    module = load_module()
    content = {
        "catalog_stage": "resolution_candidate",
        "knowledge_quality": {"passed": True},
        "remediation_steps": ["restart confirmed unhealthy replica"],
        "validation_steps": ["verify latency recovers"],
        "rollback_steps": ["restore previous replica"],
    }
    assert module._promotion_readiness(content, reviewed_success=True) == []
    assert "a reviewed successful recovery is required" in module._promotion_readiness(content, reviewed_success=False)
    assert "rollback steps are incomplete" in module._promotion_readiness({**content, "rollback_steps": []}, reviewed_success=True)


@pytest.mark.asyncio
async def test_catalog_governance_requires_internal_token_and_distinct_checksum_bound_review(
    sqlite_session_factory, monkeypatch,
) -> None:
    import httpx

    module = load_module()
    runbook_id = uuid4()
    content = {"source": "operator_evidence_response", "version": 1}
    content_sha = module._hash({key: value for key, value in content.items() if key != "version"})
    monkeypatch.setattr(module.settings, "service_internal_token", "worker-test-secret")
    monkeypatch.setattr(module.app.state, "session_factory", sqlite_session_factory, raising=False)
    async with sqlite_session_factory() as session:
        session.add(RunbookVersionRecord(
            runbook_id=runbook_id,
            version=1,
            tenant_id="tenant-a",
            issue_signature="b" * 64,
            approval_status="draft",
            owner="test",
            risk_level="medium",
            required_approval="mandatory",
            content={**content, "content_sha256": content_sha},
        ))
        await session.commit()

    transport = httpx.ASGITransport(app=module.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://worker") as client:
        route = f"/catalog/{runbook_id}/versions/1/review"
        request = {
            "tenant_id": "tenant-a",
            "actor": "reviewer@example.test",
            "decision": "review",
            "expected_content_sha256": content_sha,
        }
        assert (await client.post(route, json=request)).status_code == 403
        assert (
            await client.post(
                route,
                json=request,
                headers={"x-kaiops-internal-token": "wrong-secret"},
            )
        ).status_code == 403
        monkeypatch.setattr(module.settings, "service_internal_token", "")
        assert (await client.post(route, json=request)).status_code == 503
        monkeypatch.setattr(module.settings, "service_internal_token", "worker-test-secret")
        headers = {"x-kaiops-internal-token": "worker-test-secret"}
        reviewed = await client.post(route, json=request, headers=headers)
        assert reviewed.status_code == 200
        assert reviewed.json()["status"] == "review_pending"

        same_actor = await client.post(route, json={**request, "decision": "approve"}, headers=headers)
        assert same_actor.status_code == 409
        approved = await client.post(
            route,
            json={**request, "actor": "approver@example.test", "decision": "approve"},
            headers=headers,
        )
        assert approved.status_code == 200
        assert approved.json()["status"] == "approved"

    async with sqlite_session_factory() as session:
        approval = (await session.execute(select(RunbookApprovalRecord))).scalar_one()
        assert approval.tenant_id == "tenant-a"
        assert approval.reviewer == "reviewer@example.test"
        assert approval.approver == "approver@example.test"
        assert approval.content_sha256 == content_sha
        repo = IncidentRepository(session)
        assert await repo.get_approved_runbook_version(
            tenant_id="tenant-a", runbook_id=str(runbook_id), version=1,
        ) is not None
        assert await repo.get_approved_runbook_version(
            tenant_id="tenant-b", runbook_id=str(runbook_id), version=1,
        ) is None


@pytest.mark.asyncio
async def test_catalog_governance_fails_closed_for_stale_checksum_missing_review_and_other_tenant(
    sqlite_session_factory, monkeypatch,
) -> None:
    import httpx

    module = load_module()
    runbook_id = uuid4()
    content = {"source": "operator_evidence_response", "version": 1}
    content_sha = module._hash({key: value for key, value in content.items() if key != "version"})
    monkeypatch.setattr(module.settings, "service_internal_token", "worker-test-secret")
    monkeypatch.setattr(module.app.state, "session_factory", sqlite_session_factory, raising=False)
    async with sqlite_session_factory() as session:
        session.add(RunbookVersionRecord(
            runbook_id=runbook_id,
            version=1,
            tenant_id="tenant-a",
            issue_signature="d" * 64,
            approval_status="draft",
            owner="test",
            risk_level="medium",
            required_approval="mandatory",
            content={**content, "content_sha256": content_sha},
        ))
        await session.commit()

    transport = httpx.ASGITransport(app=module.app)
    headers = {"x-kaiops-internal-token": "worker-test-secret"}
    async with httpx.AsyncClient(transport=transport, base_url="http://worker") as client:
        route = f"/catalog/{runbook_id}/versions/1/review"
        payload = {
            "tenant_id": "tenant-a",
            "actor": "approver@example.test",
            "decision": "approve",
            "expected_content_sha256": content_sha,
        }
        assert (await client.post(route, json={**payload, "tenant_id": "tenant-b"}, headers=headers)).status_code == 404
        assert (await client.post(route, json={**payload, "expected_content_sha256": "e" * 64}, headers=headers)).status_code == 409
        assert (await client.post(route, json=payload, headers=headers)).status_code == 409
        async with sqlite_session_factory() as session:
            candidate = await session.get(RunbookVersionRecord, (runbook_id, 1))
            candidate.content = {**candidate.content, "remediation_steps": ["changed after review"]}
            await session.commit()
        assert (await client.post(route, json=payload, headers=headers)).status_code == 409


@pytest.mark.asyncio
async def test_legacy_approval_route_delegates_to_shared_review_and_approval_gates(
    sqlite_session_factory, monkeypatch,
) -> None:
    import httpx

    module = load_module()
    runbook_id = uuid4()
    content = {"source": "operator_evidence_response", "version": 1}
    content_sha = module._hash({key: value for key, value in content.items() if key != "version"})
    monkeypatch.setattr(module.settings, "service_internal_token", "worker-test-secret")
    monkeypatch.setattr(module.app.state, "session_factory", sqlite_session_factory, raising=False)
    async with sqlite_session_factory() as session:
        session.add(RunbookVersionRecord(
            runbook_id=runbook_id,
            version=1,
            tenant_id="tenant-legacy",
            issue_signature="1" * 64,
            approval_status="draft",
            owner="test",
            risk_level="medium",
            required_approval="mandatory",
            content={**content, "content_sha256": content_sha},
        ))
        await session.commit()

    transport = httpx.ASGITransport(app=module.app)
    headers = {"x-kaiops-internal-token": "worker-test-secret"}
    async with httpx.AsyncClient(transport=transport, base_url="http://worker") as client:
        route = f"/runbooks/{runbook_id}/approve?version=1"
        payload = {
            "tenant_id": "tenant-legacy",
            "actor": "reviewer@example.test",
            "decision": "review",
            "expected_content_sha256": content_sha,
        }
        assert (await client.post(route, json=payload, headers=headers)).json()["status"] == "review_pending"
        approved = await client.post(
            route,
            json={**payload, "actor": "approver@example.test", "decision": "approve"},
            headers=headers,
        )
        assert approved.status_code == 200
        assert approved.json()["status"] == "approved"


@pytest.mark.asyncio
async def test_orphan_legacy_approval_cannot_authorize_a_runbook(sqlite_session_factory) -> None:
    runbook_id = uuid4()
    async with sqlite_session_factory() as session:
        session.add(RunbookVersionRecord(
            runbook_id=runbook_id,
            version=1,
            tenant_id="tenant-a",
            issue_signature="2" * 64,
            approval_status="approved",
            owner="test",
            risk_level="medium",
            required_approval="mandatory",
            content={"content_sha256": "3" * 64},
        ))
        session.add(RunbookApprovalRecord(
            runbook_id=runbook_id,
            version=1,
            status="approved",
            reviewer=None,
            approver="legacy-approver",
            approver_role="ADMINISTRATOR",
            tenant_id=None,
            content_sha256=None,
        ))
        await session.commit()
        governed = await IncidentRepository(session).get_approved_runbook_version(
            tenant_id="tenant-a", runbook_id=str(runbook_id), version=1,
        )
    assert governed is None


def test_runbook_approval_migration_backfills_only_exact_version_tenant_matches() -> None:
    migration = Path("backend/database/migrations/20261030_runbook_approval_tenant_and_four_eyes.sql")
    sql = migration.read_text(encoding="utf-8")
    assert "tenant_id VARCHAR(128) NULL" in sql
    assert "reviewer VARCHAR(255) NULL" in sql
    assert "content_sha256 VARCHAR(64) NULL" in sql
    assert "information_schema.columns" in sql
    assert "information_schema.statistics" in sql
    assert "versions.runbook_id = approvals.runbook_id" in sql
    assert "versions.version = approvals.version" in sql
    assert "WHERE approvals.tenant_id IS NULL" in sql
