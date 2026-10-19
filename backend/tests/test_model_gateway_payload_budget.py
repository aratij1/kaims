from __future__ import annotations

import json
from datetime import datetime, timezone
from uuid import uuid4

from ai_workbench_common.model_gateway import HttpModelGateway


def test_compacted_payload_is_json_serializable_with_native_context_types():
    timestamp = datetime(2026, 10, 15, tzinfo=timezone.utc)
    identifier = uuid4()
    payload, _ = HttpModelGateway("http://model-router")._compact_payload({
        "alert": {"starts_at": timestamp, "id": identifier},
        "discovery_evidence": [{"evidence_id": "metric-1", "observed_at": timestamp}],
    })
    transmitted = json.loads(json.dumps(payload))
    assert transmitted["alert"]["id"] == str(identifier)
    assert transmitted["discovery_evidence"][0]["observed_at"] == str(timestamp)


def test_resolution_model_payload_is_compacted_without_losing_identity() -> None:
    gateway = HttpModelGateway("http://model-router", max_payload_bytes=8_000)
    payload = {
        "service": "payments-api",
        "environment": "prod",
        "root_cause": "connection pool exhaustion",
        "raw_payload": "secret/noisy" * 2_000,
        "discovery_evidence": [
            {"evidence_id": f"ev-{index}", "snippet": "x" * 5_000}
            for index in range(50)
        ],
    }

    compacted, budget = gateway._compact_payload(payload)

    assert compacted["service"] == "payments-api"
    assert compacted["environment"] == "prod"
    assert compacted["root_cause"] == "connection pool exhaustion"
    assert "raw_payload" not in compacted
    assert budget["trimmed"] is True
    assert budget["sent_bytes"] <= budget["budget_bytes"]
    assert len(json.dumps(compacted).encode("utf-8")) <= 8_000


def test_small_resolution_payload_is_not_marked_trimmed() -> None:
    gateway = HttpModelGateway("http://model-router", max_payload_bytes=8_000)
    payload = {"service": "inventory", "evidence": [{"evidence_id": "ev-1", "snippet": "healthy"}]}

    compacted, budget = gateway._compact_payload(payload)

    assert compacted == payload
    assert budget["trimmed"] is False


def test_nested_investigation_payload_keeps_citations_within_budget():
    gateway = HttpModelGateway("http://model-router", max_payload_bytes=8000)
    payload = {"service": "api-gateway", "iterative_investigation": {
        "hypotheses": [{"claim": "slow dependency", "details": "x" * 12000} for _ in range(20)],
        "conclusion": {"evidence_ids": ["TRACE-1"], "claim": "slow dependency"},
    }, "discovery_evidence": [{"evidence_id": "TRACE-1", "citation": "jaeger://trace/1", "snippet": "x" * 12000}]}
    compacted, budget = gateway._compact_payload(payload)
    assert budget["sent_bytes"] <= 8000
    assert compacted["discovery_evidence"][0]["evidence_id"] == "TRACE-1"
    assert compacted["iterative_investigation"]["conclusion"]["evidence_ids"] == ["TRACE-1"]


def test_evidence_budget_retains_late_runtime_and_metric_facts():
    gateway = HttpModelGateway("http://model-router", max_payload_bytes=8000)
    rows = [{"evidence_id": f"LOG-{i}", "source": "log", "snippet": "service startup"} for i in range(35)]
    rows += [{"evidence_id": "METRIC-UP", "source": "metric", "metadata": {"value": 1}, "snippet": "up=1"},
             {"evidence_id": "RUNTIME-EXIT", "source": "dependency", "metadata": {"healthy": False, "exit_code": 137}, "snippet": "container exited"}]
    payload = {"discovery_evidence": rows, "investigation_report": {"hypotheses": [{"description": "x" * 10000} for _ in range(30)]}}
    sent, budget = gateway._compact_payload(payload)
    by_id = {row["evidence_id"]: row for row in sent["discovery_evidence"]}
    assert set(by_id) == {row["evidence_id"] for row in rows}
    assert by_id["RUNTIME-EXIT"]["metadata"]["healthy"] is False
    assert by_id["METRIC-UP"]["metadata"]["value"] == 1
    assert budget["evidence_sent"] == 37 and budget["evidence_omitted"] == 0
    assert budget["sent_bytes"] <= 8000


def test_evidence_overflow_preserves_source_diversity_and_citation_identity():
    gateway = HttpModelGateway("http://model-router", max_payload_bytes=8000)
    rows = [{"evidence_id": f"LOG-{i}", "source": "log", "uri": "log://" + "x" * 600, "snippet": "x" * 10000} for i in range(50)]
    rows += [{"evidence_id": "METRIC-UNIQUE", "source": "metric", "snippet": "value=0"}, {"evidence_id": "DEPENDENCY-UNIQUE", "source": "dependency", "snippet": "unhealthy"}]
    sent, budget = gateway._compact_payload({"evidence": rows, "conclusion": {"evidence_ids": ["METRIC-UNIQUE", "DEPENDENCY-UNIQUE"]}})
    ids = {row["evidence_id"] for row in sent["evidence"]}
    assert {"METRIC-UNIQUE", "DEPENDENCY-UNIQUE"} <= ids
    assert sent["conclusion"]["evidence_ids"] == ["METRIC-UNIQUE", "DEPENDENCY-UNIQUE"]
    assert budget["evidence_omitted"] > 0
    assert budget["sent_bytes"] <= 8000
