import pytest
from common.incident_command_contract import build_incident_command_workspace
from pydantic import ValidationError


def test_overview_defers_raw_reports_without_mutating_evidence_or_readiness():
    import copy
    incident = {"incident_id": "incident-1", "context": {"metadata": {
        "context_evidence": {"logs": [{"message": "durable evidence"}]},
        "investigation_report": {"raw": "large report"}, "context_collected_at": "2026-10-17",
    }}, "recommendation": {"metadata": {
        "iterative_investigation": {"raw": "large report"},
        "rca_analysis": {"status": "insufficient_evidence"}, "execution_plan": {"status": "blocked"},
    }}}
    original = copy.deepcopy(incident)
    full = build_incident_command_workspace(incident_id="incident-1", incident=incident, operations={"incident_id": "incident-1"})
    brief = build_incident_command_workspace(
        incident_id="incident-1", incident=incident, operations={"incident_id": "incident-1"}, include_source_records=False,
    )
    assert incident == original
    assert full.incident["context"]["metadata"]["context_evidence"] == original["context"]["metadata"]["context_evidence"]
    assert brief.incident["context"]["metadata"] == {"context_collected_at": "2026-10-17"}
    assert brief.incident["recommendation"]["metadata"] == {
        "rca_analysis": {"status": "insufficient_evidence"}, "execution_plan": {"status": "blocked"},
    }
    assert brief.evidence == full.evidence


def test_command_workspace_composes_matching_read_models() -> None:
    workspace = build_incident_command_workspace(
        incident_id="incident-1",
        incident={"incident_id": "incident-1", "updated_at": "2026-09-01T10:00:00Z"},
        operations={"incident_id": "incident-1", "lifecycle_version": 7},
    )

    assert workspace.schema_version == "kaiops.incident-command.v2"
    assert workspace.incident["incident_id"] == "incident-1"
    assert workspace.operations["lifecycle_version"] == 7
    assert len(workspace.revision) == 64


def test_command_workspace_owns_evidence_scores_and_binding_blockers() -> None:
    workspace = build_incident_command_workspace(
        incident_id="incident-1",
        incident={"incident_id": "incident-1"},
        operations={
            "incident_id": "incident-1",
            "context": {"snapshot_id": "snapshot-new", "quality": {"quality_score": 0.82}},
            "investigation_workspace": {
                "binding": {"context_snapshot_id": "snapshot-bound"},
                "evidence_summary": {
                    "latest_context_records": 12,
                    "bound_snapshot_records": 10,
                    "rca_bound_records": 5,
                    "traceable_citations": 4,
                    "unresolved_bindings": 1,
                },
                "rca": {"status": "investigating", "conflicting_evidence": ["conflict"]},
                "requirements": [{"status": "collecting"}, {"status": "resolved"}],
                "resolution": {"status": "blocked"},
            },
        },
    )

    assert workspace.evidence.counts.latest_context_records == 12
    assert workspace.evidence.counts.open_requirements == 1
    assert workspace.evidence.counts.open_conflicts == 1
    assert workspace.evidence.binding_consistent is False
    assert workspace.evidence.scores[0].percent == 82
    assert workspace.evidence.scores[1].ratio is not None
    assert workspace.evidence.scores[1].ratio.percent == 80
    assert "RCA_SNAPSHOT_STALE" in workspace.evidence.blockers
    assert "RCA_EVIDENCE_BINDING_UNRESOLVED" in workspace.evidence.blockers
    assert "RCA_NOT_GROUNDED" in workspace.evidence.blockers
    assert "RESOLUTION_NOT_READY" in workspace.evidence.blockers
    assert workspace.evidence.scores[2].status == "blocked"


def test_command_workspace_flags_exhausted_evidence_collection() -> None:
    workspace = build_incident_command_workspace(
        incident_id="incident-1",
        incident={"incident_id": "incident-1"},
        operations={
            "incident_id": "incident-1",
            "investigation_workspace": {
                "requirements": [
                    {"status": "blocked"},
                    {"status": "assignment_blocked"},
                    {"status": "collected"},
                ],
            },
        },
    )

    # Both open requirements have dead-ended (retry budget exhausted, no
    # authorized human responder) - nothing is still in flight, so the
    # operator can be offered a partial-evidence recommendation instead of
    # an indefinite "not ready" with no path forward.
    assert workspace.evidence.counts.open_requirements == 2
    assert workspace.evidence.counts.exhausted_requirements == 2
    assert workspace.evidence.counts.pending_requirements == 0
    assert workspace.evidence.evidence_collection_exhausted is True


def test_command_workspace_evidence_collection_not_exhausted_while_pending() -> None:
    workspace = build_incident_command_workspace(
        incident_id="incident-1",
        incident={"incident_id": "incident-1"},
        operations={
            "incident_id": "incident-1",
            "investigation_workspace": {
                "requirements": [
                    {"status": "blocked"},
                    {"status": "human_requested"},
                ],
            },
        },
    )

    # One requirement is still waiting on a human response - collection is
    # not exhausted yet, so this must not be offered as operator-reviewable.
    assert workspace.evidence.counts.exhausted_requirements == 1
    assert workspace.evidence.counts.pending_requirements == 1
    assert workspace.evidence.evidence_collection_exhausted is False


def test_command_workspace_no_open_requirements_is_not_exhausted() -> None:
    workspace = build_incident_command_workspace(
        incident_id="incident-1",
        incident={"incident_id": "incident-1"},
        operations={
            "incident_id": "incident-1",
            "investigation_workspace": {"requirements": [{"status": "collected"}]},
        },
    )

    # No declared gaps at all is a different, better state than "gaps exist
    # but we gave up" - it must not be reported as evidence_collection_exhausted.
    assert workspace.evidence.counts.open_requirements == 0
    assert workspace.evidence.evidence_collection_exhausted is False


def test_command_workspace_rejects_mixed_incident_identity() -> None:
    with pytest.raises(ValidationError, match="operations identity does not match"):
        build_incident_command_workspace(
            incident_id="incident-1",
            incident={"incident_id": "incident-1"},
            operations={"incident_id": "incident-2"},
        )


def test_command_workspace_revision_changes_with_lifecycle_version() -> None:
    first = build_incident_command_workspace(
        incident_id="incident-1",
        incident={"incident_id": "incident-1", "updated_at": "2026-09-01T10:00:00Z"},
        operations={"incident_id": "incident-1", "lifecycle_version": 7},
    )
    second = build_incident_command_workspace(
        incident_id="incident-1",
        incident={"incident_id": "incident-1", "updated_at": "2026-09-01T10:00:00Z"},
        operations={"incident_id": "incident-1", "lifecycle_version": 8},
    )

    assert first.revision != second.revision


def test_command_deduplicates_projection_without_changing_source_evidence():
    import copy
    context = {"metadata": {"evidence": [{"id": "e1", "value": "x" * 10000}]}}
    recommendation = {"root_cause": "Recorded hypothesis"}
    incident = {
        "incident_id": "incident-1", "context": context,
        "recommendation": recommendation,
        "projection_payload": {
            "context": copy.deepcopy(context), "context_metadata": copy.deepcopy(context["metadata"]),
            "recommendation": copy.deepcopy(recommendation), "status": "closed",
            "incident_lifecycle": {"assessment_id": "assessment-1"},
        },
    }
    original = copy.deepcopy(incident)
    command = build_incident_command_workspace(
        incident_id="incident-1", incident=incident, operations={"incident_id": "incident-1"},
    )
    assert incident == original
    assert command.incident["context"] == context
    assert command.incident["recommendation"] == recommendation
    assert command.incident["projection_payload"] == {
        "status": "closed", "incident_lifecycle": {"assessment_id": "assessment-1"},
    }


def test_command_preserves_distinct_and_projection_only_evidence():
    incident = {
        "incident_id": "incident-1", "context": {"metadata": {"version": 2}},
        "projection_payload": {
            "context": {"metadata": {"version": 1}}, "context_metadata": {"version": 1},
            "recommendation": {"root_cause": "Historical hypothesis"},
        },
    }
    command = build_incident_command_workspace(
        incident_id="incident-1", incident=incident, operations={"incident_id": "incident-1"},
    )
    assert command.incident == incident


@pytest.mark.parametrize('field', ['recommendation_id', 'context_snapshot_id'])
def test_command_rejects_mixed_recommendation_generations(field):
    incident = {'incident_id': 'i', 'recommendation_id': 'r', 'recommendation': {'id': 'r', 'metadata': {'context_snapshot_id': 's'}}}
    binding = {'recommendation_id': 'r', 'context_snapshot_id': 's'}
    binding[field] = 'another-generation'
    with pytest.raises(ValidationError, match='does not match command operations'):
        build_incident_command_workspace(incident_id='i', incident=incident,
            operations={'incident_id': 'i', 'investigation_workspace': {'binding': binding}})


def test_command_allows_new_context_without_relabelling_frozen_rca():
    command = build_incident_command_workspace(incident_id='i',
        incident={'incident_id':'i', 'recommendation_id':'r', 'recommendation':{'id':'r', 'metadata':{'context_snapshot_id':'frozen'}}},
        operations={'incident_id':'i','context':{'snapshot_id':'new'}, 'investigation_workspace':{'binding':{'recommendation_id':'r','context_snapshot_id':'frozen'}}})
    assert not command.evidence.binding_consistent
    assert command.evidence.bound_snapshot_id == 'frozen'


def test_compact_workspace_omits_debug_packages_but_preserves_execution_and_binding():
    metadata={'context_package':{'raw':'x'*10000}, 'context_graph':{'edges':['x']},
        'rag_index':{'debug':'x'}, 'model_calls':[{'payload':'x'*1000}],
        'candidate_execution_plan':{'commands':['draft']},'model_proposed_execution_plan':{'commands':['draft']},
        'execution_plan':{'execution_ready':False},'context_snapshot_id':'snapshot-1'}
    incident={'incident_id':'i','recommendation':{'metadata':metadata},'context':{'metadata':metadata}}
    compact=build_incident_command_workspace(incident_id='i',incident=incident,operations={'incident_id':'i'},include_source_records=False)
    full=build_incident_command_workspace(incident_id='i',incident=incident,operations={'incident_id':'i'})
    assert compact.incident['recommendation']['metadata']=={'execution_plan':{'execution_ready':False},'context_snapshot_id':'snapshot-1'}
    assert full.incident['recommendation']['metadata']==metadata
    assert 'model_calls' in metadata
