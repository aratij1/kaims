"""Deterministic synthesis of a tested, bounded stopped-workload diagnosis."""

from datetime import UTC, datetime

from common.models import Recommendation

from resolution_agent.investigation import IterativeInvestigator


def stopped_workload_recommendation(context, report):
    if report.get("conclusive") is not True:
        return None
    conclusion = report.get("conclusion") or {}
    hypothesis = next(
        (h for h in report.get("hypotheses", []) if h.get("hypothesis_id") == conclusion.get("hypothesis_id")), {}
    )
    if hypothesis.get("mechanism") != "runtime_stopped":
        return None
    accepted = set(conclusion.get("evidence_ids") or [])
    supporting = [
        row
        for row in report.get("evidence", [])
        if row.get("evidence_id") in accepted
        and row.get("current_operational_evidence") is True
        and IterativeInvestigator._structured_mechanism_support(hypothesis, row)
    ]
    sources = {IterativeInvestigator._source(row) for row in supporting}
    if not {"topology", "telemetry"}.issubset(sources):
        return None
    confidence = float(conclusion.get("confidence") or 0)
    if confidence < 0.65:
        return None
    evidence_ids = sorted({row["evidence_id"] for row in supporting})
    runtime = next(row for row in supporting if row["source_type"] == "topology")
    probe = next(row for row in supporting if IterativeInvestigator._source(row) == "telemetry")
    samples = probe["metadata"].get("values") or [probe["metadata"]["value"]]
    probe_at = datetime.fromtimestamp(float(samples[-1][0]), tz=UTC).isoformat()
    statement = f"The {context.alert.service} workload stopped, causing its HTTP endpoint to be unavailable."
    impact = (f"The independent HTTP probe could not reach {context.alert.service}. "
              "Customer counts and business losses are not established.")
    limitation = "The underlying reason for the process exit is not established by this bounded diagnosis."
    sequence = [
        {
            "event": f"The {context.alert.service} workload exited",
            "timestamp": hypothesis["stopped_at"],
            "evidence_ids": [runtime["evidence_id"]],
        },
        {
            "event": "The independent HTTP probe reported failure after the exit",
            "timestamp": probe_at,
            "evidence_ids": [probe["evidence_id"]],
        },
    ]
    from common.rca_timeline import build_rca_timeline

    return Recommendation(
        tenant_id=context.tenant_id,
        incident_id=context.incident_id,
        severity=context.alert.severity,
        root_cause=statement,
        confidence=confidence,
        impact=impact,
        risk="medium",
        recommended_action=("Restore availability by starting the verified stopped workload, "
                            "then independently validate recovery. Investigate the reason for its exit separately."),
        rationale="Recorded workload exit and a later failed probe corroborate the current failure mechanism. "
        + limitation,
        metadata={
            "analysis_engine": "verified-runtime-recovery.v1",
            "rca_status": "grounded",
            "confidence_kind": "tested_mechanism",
            "confidence_actionable": True,
            "resolution_outcome": "current_failure_mechanism_confirmed",
            "evidence_ids": evidence_ids,
            "evidence_quality": {
                "evidence_coverage": min(1.0, len(sources) / 2),
                "citation_coverage": len(evidence_ids) / max(1, len(report.get("evidence", []))),
                "evidence_fresh": True,
                "conflict_count": 0,
                "independent_source_count": len(sources),
                "direct_observation_count": len(supporting),
                "sufficiency": "sufficient",
            },
            "quality_gate": {
                "passed": True,
                "requires_human_review": True,
                "trusted_for_auto_execution": False,
                "blocking_reasons": [],
            },
            "rca_analysis": {
                "root_cause": statement,
                "confidence_score": confidence,
                "evidence_used": evidence_ids,
                "missing_evidence": [],
                "conflicting_evidence": [],
                "limitations": [limitation],
                "follow_up_questions": ["Why did the workload exit?"],
                "causal_chain": [event["event"] for event in sequence],
                "timeline": build_rca_timeline(sequence, supporting, evidence_ids),
            },
            "impact_analysis": {
                "analysis_engine": "verified-runtime-recovery.v1",
                "impact_summary": impact,
                "observed_impact": f"The independent HTTP probe reported {context.alert.service} as unreachable.",
                "confidence_score": confidence,
                "evidence_used": evidence_ids,
                "context_readiness": {"ready": True},
                "external_knowledge_used": False,
                "limitations": ["Customer and business impact are unquantified."],
            },
        },
    )
