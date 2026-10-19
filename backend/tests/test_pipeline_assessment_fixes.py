from datetime import UTC, datetime
from uuid import uuid4
import pytest
from resolution_agent.impact_claim import evaluated_impact_claim
from resolution_agent.evidence import EvidenceCompiler

@pytest.mark.parametrize("category,kind", [("traces","trace"),("changes","change"),("source_code","code"),("dependencies","dependency")])
def test_provider_does_not_replace_evidence_category(category, kind):
    rows = EvidenceCompiler().compile([{"category": category, "source": "docker", "citation": "https://evidence.local/record/1", "summary": "Recorded observation", "observed_at": datetime.now(UTC).isoformat()}],tenant_id="default",incident_id=uuid4(),service="gateway",environment="prod")
    assert rows[0].source_type == kind
    assert rows[0].source_uri == "https://evidence.local/record/1"


def assessment():
    return {"observed_impact":"Checkout requests failed during the incident.", "evidence_used":["metric-1","trace-1"], "confidence_score": .8, "context_readiness":{"ready":True}}


def evidence():
    return [{"evidence_id":f"{kind}-1", "source_type":kind, "source_uri":f"{kind}://record/1", "incident_window_relation":"during", "current_operational_evidence":True} for kind in ["metric","trace"]]


def test_impact_assessment_replaces_the_initial_placeholder():
    claim = evaluated_impact_claim(assessment(), "Checkout requests failed during the incident.", evidence())
    assert claim["status"] == "OBSERVED"
    assert claim["supporting_evidence_ids"] == ["metric-1","trace-1"]


def test_observed_service_impact_is_independent_of_downstream_risk_summary():
    claim = evaluated_impact_claim(
        assessment(),
        "Checkout requests failed; downstream fulfilment could be delayed.",
        evidence(),
    )
    assert claim["status"] == "OBSERVED"
    assert claim["statement"] == "Checkout requests failed during the incident."


@pytest.mark.parametrize("case",["missing_citations","alert_only","outside_window","stale","external","risk","not_ready","low_confidence"])
def test_impact_does_not_promote_unsupported_assessments(case):
    a=assessment(); rows=evidence()
    if case == "missing_citations": a["evidence_used"] = ["invented"]
    if case == "alert_only": rows[0]["source_type"] = "alert"
    if case == "outside_window": rows[0]["incident_window_relation"] = "after"
    if case == "stale": rows[0]["current_operational_evidence"] = False
    if case == "external": a["external_knowledge_used"] = True
    if case == "risk": a["observed_impact"] = "Checkout may be unavailable."
    if case == "not_ready": a["context_readiness"] = {"ready":False}
    if case == "low_confidence": a["confidence_score"] = .2
    assert evaluated_impact_claim(a, "Recorded impact assessment", rows)["status"] == "NOT_ESTABLISHED"


def test_model_input_does_not_lose_traces_and_changes_behind_logs():
    from resolution_agent.evidence import balanced_evidence
    rows = [{"source":"logs", "evidence_id":f"log-{i}"} for i in range(100)]
    rows += [{"source":"traces", "evidence_id":"trace-1"}, {"source":"changes", "evidence_id":"change-1"}]
    selected = balanced_evidence(rows, limit=24)
    assert len(selected) == 24
    assert {"trace-1","change-1"} <= {row["evidence_id"] for row in selected}
