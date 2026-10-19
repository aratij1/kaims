from common.investigation_gaps import investigation_gaps

def test_source_coverage_does_not_erase_grounding_gaps():
    assert investigation_gaps({"missing_evidence": ["dependency health"]}, {"missing_sources": [], "rca_result": {"missing_evidence": ["direct causal evidence", "dependency health"]}}) == ["dependency health", "direct causal evidence"]

def test_combines_missing_sources_with_rca_requirements():
    assert investigation_gaps({}, {"missing_sources": ["traces"], "rca_result": {"missing_evidence": ["traces", "incident-window resource metrics"]}}) == ["traces", "incident-window resource metrics"]

def test_empty_report_does_not_invent_gaps():
    assert investigation_gaps({}, {}) == []


def test_configuration_and_window_errors_are_not_retried():
    from common.investigation_gaps import collection_attempt_limit
    for code in ("APPLICATION_DATABASE_SCOPE_NOT_CONFIGURED", "INVALID_OBSERVATION_WINDOW"):
        assert collection_attempt_limit(code, []) == 1
    assert collection_attempt_limit("PROMETHEUS_TEMPORARILY_UNAVAILABLE", []) == 4


def test_structured_gap_preserves_connector_scope():
    gap = {"category": "traces", "question": "Inspect span failure", "candidate_connectors": ["jaeger"]}
    assert investigation_gaps({"missing_evidence": [gap]}, {"rca_result": {"missing_evidence": [gap]}}) == [gap]


def test_missing_citations_create_explicit_review_work():
    from common.investigation_gaps import blocking_investigation_gaps
    from common.context_enrichment_contract import build_evidence_requirements
    from datetime import datetime, UTC
    from uuid import uuid4
    gaps = blocking_investigation_gaps({"evidence_used": []}, {"conclusive": True})
    requirements = build_evidence_requirements(tenant_id="test", incident_id=uuid4(), rca_version=2, missing_evidence=gaps, now=datetime.now(UTC))
    assert len(requirements) == 1
    assert requirements[0].candidate_connectors == []
    assert "citations" in requirements[0].question


def test_prose_gap_is_not_silently_dropped():
    from common.context_enrichment_contract import build_evidence_requirements
    from datetime import datetime, UTC
    from uuid import uuid4
    question = "Confirm the exact configuration change causing the issue."
    requirements = build_evidence_requirements(tenant_id="test", incident_id=uuid4(), rca_version=2, missing_evidence=[question], now=datetime.now(UTC))
    assert len(requirements) == 1
    assert requirements[0].question == question
    assert requirements[0].candidate_connectors == []


def test_recollection_reuses_active_work_and_reopens_explicit_old_gaps():
    from common.investigation_gaps import requirement_blocks_recollection
    assert requirement_blocks_recollection({"rca_version": 1, "status": "collecting"}, 2)
    assert requirement_blocks_recollection({"rca_version": 2, "status": "collected"}, 2)
    assert not requirement_blocks_recollection({"rca_version": 1, "status": "collected"}, 2)


def test_text_gap_is_not_split_into_characters():
    assert investigation_gaps({"missing_evidence": "Confirm memory pressure"}, {}) == ["Confirm memory pressure"]


def test_delayed_rca_collects_incident_window_not_today():
    from common.investigation_gaps import incident_collection_window
    from datetime import datetime, UTC, timedelta
    from types import SimpleNamespace
    onset = datetime(2026, 9, 11, 12, tzinfo=UTC)
    start, end = incident_collection_window(SimpleNamespace(starts_at=onset, ends_at=None), onset + timedelta(days=1))
    assert start == onset - timedelta(minutes=15)
    assert end == onset + timedelta(minutes=30)


def test_reconciliation_uses_next_source_and_preserves_active_work():
    from common.investigation_gaps import unattempted_requirement_connector
    from types import SimpleNamespace
    requirement = SimpleNamespace(requirement_id="r", candidate_connectors=["prometheus", "discovery-mcp"])
    dead = {"requirement_id": "r", "connector_id": "prometheus", "status": "dead_letter"}
    authorized = {"prometheus", "discovery-mcp"}
    assert unattempted_requirement_connector(requirement, authorized, [dead]) == "discovery-mcp"
    for status in ["scheduled", "collecting", "retry", "collected", "dead_letter"]:
        other = {"requirement_id": "r", "connector_id": "discovery-mcp", "status": status}
        assert unattempted_requirement_connector(requirement, authorized, [dead, other]) is None


def test_structured_model_gaps_plan_automatic_collection():
    from ai_workbench_common.prompts import PROMPT_IDENTIFY_ROOT_CAUSE
    from common.context_enrichment_contract import build_evidence_requirements
    from datetime import datetime, UTC
    from uuid import uuid4
    assert "missing_evidence must be an array of objects" in PROMPT_IDENTIFY_ROOT_CAUSE
    gaps = investigation_gaps({"missing_evidence": [
        {"category": "metrics", "question": "Was api-gateway CPU saturated at onset?", "reason": "Test resource saturation."},
        {"category": "deployment", "question": "What changed before api-gateway latency began?", "reason": "Test change correlation."},
    ]}, {})
    requirements = build_evidence_requirements(tenant_id="test", incident_id=uuid4(), rca_version=1, missing_evidence=gaps, now=datetime.now(UTC))
    assert [r.category for r in requirements] == ["metrics", "deployment"]
    assert all(r.collection_mode == "automatic" and r.candidate_connectors for r in requirements)
    assert all(r.status == "identified" and not r.evidence_ids for r in requirements)


def test_unsupported_categories_cannot_schedule_uningestible_evidence():
    from common.context_enrichment_contract import build_evidence_requirements
    from datetime import datetime, UTC
    from uuid import uuid4
    requirements = build_evidence_requirements(tenant_id="test", incident_id=uuid4(), rca_version=1,
        missing_evidence=[{"category": "validation", "question": "Confirm causality", "candidate_connectors": ["prometheus"]}, "database"], now=datetime.now(UTC))
    assert len(requirements) == 2
    assert all(not r.candidate_connectors and r.collection_mode == "connector_required" for r in requirements)


def test_deterministic_contract_failure_does_not_repeat_four_times():
    from common.investigation_gaps import collection_attempt_limit
    for code in ["UNSUPPORTED_EVIDENCE_CATEGORY", "EVIDENCE_BINDING_MISMATCH", "EVIDENCE_REQUIRED_FIELD_MISSING"]:
        assert collection_attempt_limit("", [{"code": code}]) == 1
    assert collection_attempt_limit("", [{"code": "PROMETHEUS_SERIES_INCOMPLETE"}]) == 4
    assert collection_attempt_limit("", []) == 4
