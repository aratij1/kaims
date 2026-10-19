from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from common.database import AuditLogRecord, ContextSnapshotRecord, IncidentInvestigationBindingRecord, IncidentProjectionRecord, IncidentRecord
from common.repository import ContextEnrichmentRepository
from common.incident_command_contract import build_incident_command_workspace

@pytest.mark.asyncio
@pytest.mark.parametrize("claim_status", ["UNCONFIRMED", "GROUNDED"])
@pytest.mark.parametrize("fallback", [False, True])
@pytest.mark.parametrize("chain_as_text", [False, True])
async def test_inconclusive_rca_preserves_recorded_context_findings(sqlite_session_factory, claim_status, fallback, chain_as_text) -> None:

    incident_id, alert_id, snapshot_id, recommendation_id = uuid4(), uuid4(), uuid4(), uuid4()
    analysis_id = uuid4()
    now = datetime.now(UTC)
    async with sqlite_session_factory() as session:
        session.add(IncidentRecord(
            id=incident_id, tenant_id="tenant-a", service="api-gateway", environment="prod",
            severity="critical", status="investigating", title="api-gateway latency", payload={},
        ))
        session.add(ContextSnapshotRecord(
            snapshot_id=snapshot_id, tenant_id="tenant-a", incident_id=str(incident_id),
            alert_signature="signature", subject_fingerprint="s" * 64,
            context_fingerprint="c" * 64, contract_version="kaiops.context.v2",
            quality_score=0.7, reusable=False, source_manifest={},
            evidence_ids=["TRACE-bound", "RESOURCE-bound"],
            payload={"metadata": {
                "context_evidence": {
                    "traces": [{
                        "evidence_id": "TRACE-bound", "category": "traces",
                        "connector": "jaeger", "source_uri": "jaeger://trace/abc123",
                        "current_operational_evidence": True,
                    }],
                    "resource": [{
                        "evidence_id": "RESOURCE-bound", "category": "resource",
                        "connector": "docker", "source_uri": "docker://kaims/api-gateway/stats",
                        "current_operational_evidence": True,
                    }],
                },
            }},
            collected_at=now, expires_at=now + timedelta(hours=1),
        ))
        session.add(IncidentInvestigationBindingRecord(
            tenant_id="tenant-a", project_id="project-a", incident_id=incident_id,
            alert_id=alert_id, analysis_request_id=analysis_id, context_snapshot_id=snapshot_id,
            context_fingerprint="c" * 64, recommendation_id=recommendation_id,
            evidence_ids=["TRACE-bound", "RESOURCE-bound"],
            rca_version=1, status="insufficient_evidence", created_at=now,
            expires_at=now + timedelta(hours=1),
        ))
        session.add(IncidentProjectionRecord(
            incident_id=incident_id, alert_id=alert_id, recommendation_id=recommendation_id,
            tenant_id="tenant-a", service="api-gateway", environment="prod",
            status="investigating", first_seen_at=now, projection_payload={},
        ))
        session.add(AuditLogRecord(
            id=recommendation_id, tenant_id="tenant-a", actor="resolution-agent",
            action="recommendation.generated", resource_type="incident",
            resource_id=str(incident_id), payload={"recommended_action": "Inspect proxy exit and memory history", "impact": "Checkout requests may time out; customer impact is unconfirmed.", "metadata": {
                "model_usage": [{"task": "rca", "fallback": True}] if fallback else [],
                "analysis_request_id": str(analysis_id), "project_id": "project-a",
                "alert_id": str(alert_id), "context_snapshot_id": str(snapshot_id),
                "context_fingerprint": "c" * 64,
                "evidence_ids": ["TRACE-bound", "RESOURCE-bound"],
                "iterative_investigation": {"rca_result": {"claims": [{
                    "kind": "CAUSAL", "status": claim_status,
                    "statement": "A configuration change affected the proxy.",
                    "supporting_evidence_ids": ["TRACE-bound", "RESOURCE-bound"],
                }]}},
                "rca_analysis": {
                    "evidence_used": ["TRACE-bound", "RESOURCE-bound"],
                    "root_cause": "Investigation inconclusive: no causal mechanism established.",
                    "supporting_signals": ["The proxy exited with status 137."],
                    "causal_chain": "The HTTP probe failed after the proxy stopped." if chain_as_text else ["The HTTP probe failed after the proxy stopped."],
                    "grounding_notes": "Exit status alone does not establish why it stopped.",
                    "missing_evidence": ["Confirm the failure mechanism."],
                    "contradictions": [],
                    "alternative_causes": [{"cause": "Resource pressure", "falsification_check": "Inspect memory history."}],
                },
            }},
        ))
        await session.flush()
        repo = ContextEnrichmentRepository(session)
        state = await repo.incident_operations_state(tenant_id="tenant-a", incident_id=incident_id)

    workspace = state["investigation_workspace"]
    assert workspace["impact"]["statement"] == "Checkout requests may time out; customer impact is unconfirmed."
    assert workspace["impact"]["status"] == "unconfirmed"
    attached_by_id = {row["evidence_id"]: row for row in workspace["evidence"]}
    assert attached_by_id["TRACE-bound"]["citation"] == "jaeger://trace/abc123"
    assert attached_by_id["TRACE-bound"]["current_observation"] is True
    assert attached_by_id["RESOURCE-bound"]["citation"] == "docker://kaims/api-gateway/stats"
    assert attached_by_id["RESOURCE-bound"]["current_observation"] is True
    assert workspace["evidence_summary"]["rca_bound_records"] == 2
    assert workspace["evidence_summary"]["traceable_citations"] == 2

    read_model = build_incident_command_workspace(
        incident_id=str(incident_id), incident={"incident_id": str(incident_id)}, operations=state,
    )
    grounding = next(score for score in read_model.evidence.scores if score.key == "grounding_coverage")
    assert grounding.percent == 100
    assert grounding.status == "available"
    rca = workspace["rca"]
    assert rca["status"] == ("insufficient_evidence" if claim_status == "GROUNDED" else "unconfirmed")
    assert rca["grounded"] is False
    assert rca["claims"][0]["status"] == claim_status
    assert rca["supporting_signals"] == ["The proxy exited with status 137."]
    assert rca["causal_chain"] == ["The HTTP probe failed after the proxy stopped."]
    assert rca["grounding_notes"].startswith("Exit status alone does not establish why it stopped.")
    assert ("model fallback" in rca["grounding_notes"]) == fallback
    assert rca["contradictions"] == []
    assert rca["alternative_causes"] == [{"cause": "Resource pressure", "falsification_check": "Inspect memory history."}]
    assert workspace["resolution"]["status"] == "blocked"
    assert workspace["resolution"]["proposed_remedy"] == "Inspect proxy exit and memory history"
    assert rca["timeline"]["causal_sequence_recorded"] is False
    assert rca["timeline"]["missing_event_times"] == 2
    assert all(event["occurred_at"] is None for event in rca["timeline"]["events"])
