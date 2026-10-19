from datetime import UTC, datetime
from uuid import uuid4

import httpx
import pytest

from ai_workbench_common.models import Context
from common.models import Alert
from resolution_agent.diagnostic_planner import observed_targets, diagnostic_choices, choose_diagnostic
from resolution_agent.investigation import IterativeInvestigator


def context():
    return Context(tenant_id="tenant-a", incident_id=uuid4(), alert=Alert(
        tenant_id="tenant-a", source="prometheus", service="rabbitmq", name="KaiOpsDeadLettersIncreasing",
        description="Messages entered a dead-letter queue", environment="prod"))


def observation():
    return {"evidence_id": "metric-failure", "source_type": "metric", "tenant_id": "tenant-a",
            "environment": "prod", "current_operational_evidence": True, "incident_window_relation": "during",
            "metadata": {"metric": {"__name__": "kaiops_dead_letter_events_total", "provider": "rabbitmq",
                                    "job": "kaiops-resolution-agent", "queue": "context-events"},
                         "values": [[1, "0"], [2, "3"]]}}


def test_counter_routes_to_observed_failing_consumer_not_healthy_broker():
    ctx = context()
    assert observed_targets(ctx, [observation()]) == {"resolution-agent": ["metric-failure"]}
    choices = diagnostic_choices(IterativeInvestigator(), ctx, [observation()], [], {})
    consumer = next(c for c in choices if c["tool"] == "logs.search" and c["target_evidence_ids"])
    assert consumer["arguments"]["service"] == "resolution-agent"
    assert consumer["arguments"]["related_to"] == "rabbitmq"
    assert consumer["arguments"]["tenant_id"] == ctx.tenant_id
    assert consumer["arguments"]["target_labels"] == {}
    assert consumer["arguments"]["start_time"]


@pytest.mark.parametrize("key,value", [("tenant_id", "another-tenant"), ("environment", "test"),
                                      ("incident_window_relation", "after"), ("current_operational_evidence", False)])
def test_unbound_or_historical_observation_cannot_expand_scope(key, value):
    row = observation()
    row[key] = value
    assert observed_targets(context(), [row]) == {}


def test_zero_counter_does_not_invent_a_failed_consumer():
    row = observation()
    row["metadata"]["values"] = [[1, "0"], [2, "0"]]
    assert observed_targets(context(), [row]) == {}


def test_container_inventory_is_not_a_candidate_causal_change():
    import json
    inventory = {"source_type": "change", "current_operational_evidence": True,
                 "summary": json.dumps({"project": "kaims", "service": "rabbitmq",
                                        "created_at": "2026-10-17", "status": "Up 4 hours (healthy)"})}
    assert IterativeInvestigator._leading_diagnostic_candidate([inventory]) is None
    real_change = {**inventory, "summary": json.dumps({"status": "deployed", "created_at": "2026-10-17", "revision": "abc"})}
    assert IterativeInvestigator._leading_diagnostic_candidate([real_change]) == real_change


def test_already_reviewed_root_logs_do_not_hide_observed_consumer_diagnostics():
    ctx = context()
    reviewed = {"evidence_id": "broker-log", "source_type": "log", "service": "rabbitmq"}
    choices = diagnostic_choices(IterativeInvestigator(), ctx, [reviewed, observation()], [], {})
    log_choices = [c for c in choices if c["tool"] == "logs.search"]
    assert log_choices
    assert all(c["arguments"]["service"] == "resolution-agent" for c in log_choices)


@pytest.mark.asyncio
@pytest.mark.parametrize("model_id,expected", [("invented-command", "bounded_fallback"), ("known", "ai_selected")])
async def test_ai_can_only_select_an_existing_readonly_choice(model_id, expected):
    choice = {"id": "known", "tool": "logs.search", "arguments": {"service": "resolution-agent"},
              "question": "Which handler failed?", "target_evidence_ids": ["metric-failure"]}
    def respond(request):
        return httpx.Response(200, json={"content": {"choice_id": model_id,
            "question": "Which handler failed?", "arguments": {"service": "untrusted-target"},
            "commands": ["untrusted-command"]}})
    async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
        selected, receipt = await choose_diagnostic(context(), [observation()], [], [choice], client=client)
    assert selected == choice
    assert selected["arguments"]["service"] == "resolution-agent"
    assert receipt["status"] == expected
    assert "commands" not in receipt


@pytest.mark.asyncio
async def test_investigation_records_bounded_ai_decisions_without_promoting_them_to_proof(monkeypatch):
    monkeypatch.setenv("RESOLUTION_DIAGNOSIS_PLANNER_ENABLED", "true")
    async def select(ctx, evidence, hypotheses, choices):
        selected = choices[0] if choices else None
        return selected, {"status": "ai_selected", "question": "Test the leading explanation"}
    monkeypatch.setattr("resolution_agent.diagnostic_planner.choose_diagnostic", select)
    class Client:
        async def call(self, tool_name, arguments):
            return {"evidence": []}
    investigator = IterativeInvestigator(client=Client())
    investigator.max_steps = 4
    report = await investigator.investigate(context())
    assert len(report["diagnostic_decisions"]) == 2
    assert report["conclusive"] is False
    assert all(step["tool_name"] in investigator.SOURCE_TOOL.values() for step in report["steps"])
