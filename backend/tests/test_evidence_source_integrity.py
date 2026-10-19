from datetime import UTC, datetime
from uuid import uuid4

import pytest
from common.evidence_source_policy import is_alert_artifact_reference, log_observed_at
from common.context_enrichment_contract import normalize_connector_response
from common.models import Incident
from resolution_agent.evidence import EvidenceCompiler
from resolution_agent.investigation import IterativeInvestigator
from context_agent.connectors import LocalEvidenceConnector
from common.context_enrichment_contract import EvidenceRequirement


def _requirement(incident, category):
    now = datetime.now(UTC)
    return EvidenceRequirement(requirement_id=uuid4(), tenant_id=incident.tenant_id,
        incident_id=incident.id, rca_version=1, category=category, question="Source observation?",
        reason="Verify cause", priority="high", collection_mode="automatic",
        candidate_connectors=["local-evidence"], created_at=now, updated_at=now)


def test_derived_log_diagnosis_is_guidance_not_independent_operational_evidence():
    now = datetime.now(UTC)
    incident = Incident(tenant_id="test", service="node-exporter", title="Disk full")
    row = {"source": "log", "uri": "log://diagnosis/node-exporter#L1", "signal_type": "log_diagnosis",
        "message": "Structured log diagnosis: error (1)", "observed_at": now.isoformat()}
    normalized = normalize_connector_response(raw_response={"evidence": [row]}, requirement=_requirement(incident, "logs"),
        incident=incident, connector="discovery-mcp", collected_at=now)
    assert normalized.records == []
    assert normalized.rejected[0]["code"] == "DERIVED_SUMMARY_NOT_SOURCE_LOG"
    compiled = EvidenceCompiler().compile([row], tenant_id="test", incident_id=incident.id, service="node-exporter", environment="prod", collected_at=now)
    assert compiled[0].current_operational_evidence is False
    assert compiled[0].metadata["guidance_only"] is True


@pytest.mark.parametrize("path", [
    "log:///data/landing/failed/alert.json#L8",
    "log:///data/landing/processed/alert.log",
    "file:///workspace/backend/ingested_alerts/event.json",
    "log:///data/%6canding/failed/alert.json",
])
def test_ingestion_artifacts_cannot_be_operational_logs(path):
    now = datetime.now(UTC)
    row = {"uri": path, "source": "log", "message": "api timeout", "observed_at": now.isoformat()}
    assert is_alert_artifact_reference(path)
    incident = Incident(tenant_id="test", service="api", title="latency")
    result = normalize_connector_response(raw_response={"evidence": [row]}, requirement=_requirement(incident, "logs"), incident=incident, connector="local-evidence", collected_at=now)
    assert result.records == []
    assert result.rejected[0]["code"] == "ALERT_ARTIFACT_NOT_OPERATIONAL_LOG"
    assert EvidenceCompiler().compile([row], tenant_id="test", incident_id=incident.id, service="api", environment="test") == []


def test_undated_record_cannot_become_current_when_normalized_and_compiled():
    now = datetime.now(UTC)
    incident = Incident(tenant_id="test", service="api", title="latency")
    result = normalize_connector_response(raw_response={"evidence": [{"uri": "log:///var/log/api.log", "message": "timeout"}]}, requirement=_requirement(incident, "logs"), incident=incident, connector="local-evidence", collected_at=now)
    row = result.records[0]
    assert row.current_observation is False
    assert row.freshness == "unknown"
    compiled = EvidenceCompiler().compile([row.model_dump(mode="json")], tenant_id="test", incident_id=incident.id, service="api", environment="test")
    assert compiled[0].current_operational_evidence is False


def test_real_log_timestamp_is_preserved_and_landing_files_are_not_discovered(tmp_path):
    runtime = tmp_path / "runtime"
    landing = tmp_path / "landing" / "failed"
    runtime.mkdir(); landing.mkdir(parents=True)
    (runtime / "api.log").write_text("2026-09-13T10:00:00Z api timeout")
    (landing / "alert.json").write_text('{"message": "api timeout"}')
    connector = LocalEvidenceConnector()
    rows = connector._search([tmp_path], connector._log_suffixes, ["api"], "log")
    assert len(rows) == 1
    assert rows[0]["observed_at"] == "2026-09-13T10:00:00+00:00"
    assert log_observed_at("api timeout") is None


def test_slow_parent_span_does_not_prove_a_slow_dependency():
    claim = {"claim": "An unhealthy downstream dependency is degrading api."}
    row = {"source_type": "trace", "metadata": {"dependency_edges": [{"upstream": "api", "downstream": "db"}], "slowest_spans": [{"service": "api", "duration_ms": 900}]}}
    assert not IterativeInvestigator._structured_mechanism_support(claim, row)
    row["metadata"]["slowest_spans"][0]["service"] = "db"
    assert IterativeInvestigator._structured_mechanism_support(claim, row)


def test_unrelated_container_failure_does_not_prove_dependency():
    row = {"source_type": "dependency", "service": "api", "metadata": {"healthy": False, "runtime_state": "exited"}}
    assert not IterativeInvestigator._structured_mechanism_support({"claim": "An unhealthy dependency"}, row)


@pytest.mark.asyncio
@pytest.mark.parametrize("enabled", [False, True])
async def test_impact_model_is_separately_opt_in_and_summary_is_not_observation(monkeypatch, enabled):
    from unittest.mock import AsyncMock
    from ai_workbench_common.models import Context
    from common.models import Alert, AlertSeverity
    from resolution_agent.graph import ResolutionIntelligenceAgent

    monkeypatch.setenv("RESOLUTION_DEEP_ANALYSIS_ENABLED", "false")
    monkeypatch.setenv("RESOLUTION_IMPACT_ANALYSIS_ENABLED", str(enabled))
    agent = ResolutionIntelligenceAgent()
    agent._generate_with_fallback = AsyncMock(return_value={
        "model": "test", "content": '{"impact_summary":"A hypothesis only", "evidence_used":[]}',
        "usage": {"provider": "test", "task": "impact"},
    })
    context = Context(tenant_id="test", incident_id=uuid4(), alert=Alert(
        tenant_id="test", name="Latency", source="test", service="api", description="Test observation", severity=AlertSeverity.HIGH))
    state = await agent.impact_analysis({"context": context, "root_cause": "Unconfirmed",
        "gathered_context": {"discovery_evidence": [], "context_quality": {}}, "model_usage": []})
    assert agent._generate_with_fallback.await_count == int(enabled)
    assert agent.deep_analysis_enabled is False
    assert state["impact_analysis"]["observed_impact"] == ""

@pytest.mark.parametrize('passes', [1, 3])
def test_trace_structure_survives_recompilation_without_nested_metadata(passes):
    now = datetime.now(UTC)
    incident = Incident(tenant_id='test', service='api', title='latency')
    row = {'source': 'trace', 'uri': 'jaeger://trace/slow', 'observed_at': now.isoformat(),
           'summary': 'Slow database path', 'metadata': {
               'slowest_spans': [{'service': 'adapter', 'duration_ms': 4000,
                                  'tags': {'db.system': 'mysql'}}],
               'dependency_edges': [{'upstream': 'api', 'downstream': 'adapter'}],
               'duration_ms': 14000, 'current_operational_evidence': True}}
    row['metadata'] = {'metadata': {'metadata': row['metadata']}}
    compiler = EvidenceCompiler()
    for _ in range(passes):
        compiled = compiler.compile([row], tenant_id='test', incident_id=incident.id,
            service='api', environment='prod', collected_at=now)[0]
        assert compiled.metadata['duration_ms'] == 14000
        assert compiled.metadata['slowest_spans'][0]['duration_ms'] == 4000
        assert 'metadata' not in compiled.metadata
        assert IterativeInvestigator._structured_mechanism_support(
            {'claim': 'A slow downstream dependency degrades api'}, compiled.model_dump(mode='json'))
        row = compiled.model_dump(mode='json')

def test_connector_normalization_keeps_trace_diagnostics_for_causal_compiler():
    now = datetime.now(UTC)
    incident = Incident(tenant_id='test', service='api', title='latency')
    raw = {'source': 'trace', 'uri': 'jaeger://trace/slow', 'trace_id': 'slow',
           'observed_at': now.isoformat(), 'service': 'api', 'duration_ms': 14000,
           'slowest_spans': [{'service': 'adapter', 'duration_ms': 4000,
                             'tags': {'db.system': 'mysql'}}],
           'dependency_edges': [{'upstream': 'api', 'downstream': 'adapter'}]}
    response = normalize_connector_response(raw_response={'evidence': [raw]},
        requirement=_requirement(incident, 'traces'), incident=incident,
        connector='discovery-mcp', collected_at=now)
    assert len(response.records) == 1
    compiled = EvidenceCompiler().compile([response.records[0].model_dump(mode='json')],
        tenant_id='test', incident_id=incident.id, service='api', environment='prod', collected_at=now)[0]
    assert compiled.metadata['trace_id'] == 'slow'
    assert compiled.metadata['duration_ms'] == 14000
    assert IterativeInvestigator._structured_mechanism_support(
        {'claim': 'A downstream dependency degrades api'}, compiled.model_dump(mode='json'))
