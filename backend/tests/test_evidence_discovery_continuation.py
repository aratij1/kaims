from contextlib import asynccontextmanager
from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest

from common.context_enrichment_contract import discovery_evidence_requirements
from common.investigation_gaps import requirement_reconciliation_needed


def test_unclassified_question_launches_discovery_without_claiming_it_answered():
    kwargs = dict(tenant_id="tenant", incident_id=uuid4(), rca_version=1,
                  missing_evidence=["Determine which configuration caused the outage"], now=datetime.now(UTC))
    requirements = discovery_evidence_requirements(**kwargs)
    assert [row.category for row in requirements] == ["validation", "metrics", "logs", "deployment", "topology"]
    assert requirements[0].question == kwargs["missing_evidence"][0]
    assert not requirements[0].candidate_connectors
    assert all(row.collection_mode == "automatic" for row in requirements[1:])
    assert all(not row.evidence_ids and row.status == "identified" for row in requirements)
    assert [r.requirement_id for r in requirements] == [r.requirement_id for r in discovery_evidence_requirements(**kwargs)]
    later = discovery_evidence_requirements(**{**kwargs, "rca_version": 2},
        previous_requirements=[row.model_dump(mode="json") for row in requirements])
    assert [row.category for row in later] == ["validation"]
    # Reconciliation of the same RCA must retain its in-flight discovery jobs.
    same = discovery_evidence_requirements(**kwargs,
        previous_requirements=[row.model_dump(mode="json") for row in requirements])
    assert [r.requirement_id for r in same] == [r.requirement_id for r in requirements]


def test_explicit_evidence_category_does_not_launch_duplicate_broad_probes():
    rows = discovery_evidence_requirements(tenant_id="tenant", incident_id=uuid4(), rca_version=1,
        missing_evidence=[{"category": "metrics", "question": "Was CPU saturated?"}], now=datetime.now(UTC))
    assert len(rows) == 1


@pytest.mark.parametrize("category", ["metrics", "logs", "traces", "topology", "deployment", "change", "source_code"])
def test_technical_followup_has_one_registry_aware_default_route(category):
    args = dict(tenant_id="tenant", incident_id=uuid4(), rca_version=1, now=datetime.now(UTC))
    rows = discovery_evidence_requirements(**args, missing_evidence=[{"category": category, "question": "Inspect the incident window"}])
    assert rows[0].candidate_connectors[0] == "discovery-mcp"
    assert len(rows[0].candidate_connectors) <= 2
    assert "vector-db" not in rows[0].candidate_connectors
    explicit = discovery_evidence_requirements(**args, missing_evidence=[{
        "category": category, "question": "Inspect a configured source", "candidate_connectors": ["dedicated-source"]}])
    assert explicit[0].candidate_connectors == ["dedicated-source"]


def test_followup_reuses_reviewed_sources_but_preserves_explicit_questions():
    rows = discovery_evidence_requirements(tenant_id="tenant", incident_id=uuid4(), rca_version=2,
        missing_evidence=["Identify the failed consumer", {"category": "metrics", "question": "Which queue grew?"}],
        reviewed_sources={"telemetry": 8, "logs": 5, "changes": 3, "topology": 2}, now=datetime.now(UTC))
    assert [row.category for row in rows] == ["validation", "metrics"]
    assert rows[0].question == "Identify the failed consumer"
    assert rows[1].question == "Which queue grew?"
    assert all(row.status == "identified" and not row.evidence_ids for row in rows)


def test_followup_only_probes_sources_not_yet_reviewed():
    rows = discovery_evidence_requirements(tenant_id="tenant", incident_id=uuid4(), rca_version=1,
        missing_evidence=["Identify the failed consumer"], reviewed_sources={"telemetry": 8, "logs": 5},
        now=datetime.now(UTC))
    assert [row.category for row in rows] == ["validation", "deployment", "topology"]


@pytest.mark.parametrize("status", ["human_requested", "assignment_blocked", "blocked", "dead_letter"])
def test_manual_or_failed_state_does_not_hide_newly_available_source(status):
    requirement = SimpleNamespace(requirement_id="r", candidate_connectors=["prometheus", "discovery-mcp"])
    jobs = [{"requirement_id": "r", "connector_id": "discovery-mcp", "status": "dead_letter"}]
    assert requirement_reconciliation_needed(requirement, {"prometheus"}, jobs, status)
    assert not requirement_reconciliation_needed(requirement, {"discovery-mcp"}, jobs, status)
    assert not requirement_reconciliation_needed(requirement, {"prometheus"},
        [*jobs, {"requirement_id": "r", "connector_id": "prometheus", "status": "collecting"}], status)


@pytest.mark.asyncio
async def test_reconciler_refreshes_onboarding_and_recovers_waiting_requirement(monkeypatch):
    from test_context_knowledge_strategy import load_context_app_module, make_alert, make_incident
    module = load_context_app_module()
    alert = make_alert()
    incident = make_incident(alert)
    gap = {"category": "metrics", "question": "Was CPU saturated?", "candidate_connectors": ["prometheus"]}
    requirement = discovery_evidence_requirements(tenant_id=alert.tenant_id, incident_id=incident.id,
        rca_version=1, missing_evidence=[gap], now=datetime.now(UTC))[0]
    repository = SimpleNamespace(
        retire_closed_incident_collection_jobs=AsyncMock(return_value={"jobs_retired": 0}),
        active_incident_gap_candidates=AsyncMock(return_value=[{"incident_id": str(incident.id),
            "rca_version": 1, "alert_id": str(alert.id), "gaps": [gap],
            "context": {"alert": alert.model_dump(mode="json")}, "incident": incident.model_dump(mode="json")}]),
        list_context_evidence_requirements=AsyncMock(return_value=[{**requirement.model_dump(mode="json"), "status": "assignment_blocked"}]),
        list_context_enrichment_activity=AsyncMock(return_value={"jobs": []}),
        reconcile_requirement_coverage_from_ledger=AsyncMock(return_value={}),
    )
    integrations = AsyncMock(return_value=[{"provider": "prometheus"}])
    monkeypatch.setattr(module, "ContextEnrichmentRepository", lambda session: repository)
    monkeypatch.setattr(module, "IncidentRepository", lambda session: SimpleNamespace(resolve_context_integrations=integrations))
    session = SimpleNamespace(rollback=AsyncMock())
    @asynccontextmanager
    async def factory():
        yield session
    monkeypatch.setattr(module.app.state, "session_factory", factory, raising=False)
    result = await module._reconcile_context_enrichment_tenant(module.ContextEnrichmentReconcileRequest(
        tenant_id=alert.tenant_id, dry_run=True))
    assert result["errors"] == []
    assert result["jobs_scheduled"] == 1
    assert result["human_requests_created"] == 0
    assert integrations.await_args.kwargs["tenant_id"] == alert.tenant_id
