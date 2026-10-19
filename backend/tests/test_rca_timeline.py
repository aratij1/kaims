from common.rca_timeline import build_rca_timeline, causal_steps


def test_legacy_chain_is_not_split_into_characters():
    assert causal_steps("Process exhausted memory") == ["Process exhausted memory"]


def test_timeline_uses_source_times_and_orders_observations():
    result = build_rca_timeline(None, [
        {"id": "b", "observed_at": "2026-10-15T10:02:00Z", "summary": "Failed health check"},
        {"id": "a", "observed_at": "2026-10-15T10:01:00Z", "summary": "Process exited"},
    ], ["a", "b"])
    assert [event["evidence_ids"] for event in result["events"]] == [["a"], ["b"]]
    assert result["causal_sequence_recorded"] is False


def test_model_times_are_ignored_and_all_citations_must_resolve():
    result = build_rca_timeline([
        {"event": "Process exited", "occurred_at": "1900-01-01", "causal_role": "trigger", "evidence_ids": ["a"]},
        {"event": "Invented cause", "evidence_ids": ["a", "missing"]},
    ], [{"id": "a", "observed_at": "2026-10-15T10:01:00Z"}], ["a"])
    assert len(result["events"]) == 1
    assert result["events"][0]["occurred_at"].startswith("2026-10-15")
    assert result["events"][0]["rca_cited"] is True
    assert result["rejected_events"][0]["reason"] == "UNRESOLVED_EVENT_EVIDENCE"


def test_collection_time_is_not_failure_time():
    result = build_rca_timeline(None, [{"id": "a", "collected_at": "2026-10-16T10:01:00Z"}], ["a"])
    assert result["events"][0]["occurred_at"] is None
    assert result["ordering"] == "partial"
    assert result["missing_event_times"] == 1


def test_background_context_is_not_presented_as_incident_chronology():
    result = build_rca_timeline(None, [
        {"id": "code", "summary": "Historical source snippet", "observed_at": "2026-09-01"},
        {"id": "log", "summary": "Service exited", "observed_at": "2026-10-15"},
    ], ["log"])
    assert [event["event"] for event in result["events"]] == ["Service exited"]
    assert build_rca_timeline(None, [{"id": "code"}])["events"] == []
