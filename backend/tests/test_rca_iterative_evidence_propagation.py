import json

import pytest
from uuid import uuid4

from common.models import Alert, AlertSeverity, Incident
from ai_workbench_common.models import Context
from model_router import ModelRouter
from model_router.router import ModelProvider, ModelResponse, build_usage
from resolution_agent import ResolutionIntelligenceAgent


class _CitingProvider(ModelProvider):
    """Always cites whatever evidence id the test passes it, so the test
    controls exactly which id is asserted valid/invalid rather than depending
    on model behavior."""

    def __init__(self, name: str, cite: str) -> None:
        super().__init__(name)
        self._cite = cite

    async def generate(self, prompt: str, payload: dict) -> ModelResponse:
        self._ensure_available()
        self.breaker.record_success()
        content_obj = {
            "root_cause": "Trace-corroborated dependency failure caused the outage.",
            "causal_chain": "The dependency failure caused request retries and exhausted the service connection pool.",
            "confidence_score": 0.9,
            "evidence_used": [self._cite],
            "alternative_causes": [],
            "grounding_notes": "Grounded in the conclusive iterative investigation.",
        }
        return ModelResponse(
            content=json.dumps(content_obj),
            usage=build_usage(
                provider=self.name,
                model=f"{self.name}-model",
                input_tokens=50,
                output_tokens=25,
                input_cost_per_million=1.0,
                output_cost_per_million=2.0,
            ),
        )


def _router(cite: str) -> ModelRouter:
    return ModelRouter(
        providers={
            "gpt-5": _CitingProvider("gpt-5", cite),
            "gpt-4o": _CitingProvider("gpt-4o", cite),
            "claude": _CitingProvider("claude", cite),
            "local-llama": _CitingProvider("local-llama", cite),
        }
    )


def _context(*, iterative_investigation: dict) -> Context:
    alert = Alert(
        tenant_id="tenant-a",
        source="prometheus",
        name="DiscoveryMcpUnreachable",
        service="discovery-mcp",
        severity=AlertSeverity.CRITICAL,
        description="discovery-mcp is unreachable; endpoint down",
    )
    incident = Incident(service="discovery-mcp", severity=AlertSeverity.CRITICAL, title=alert.name)
    return Context(
        tenant_id=alert.tenant_id,
        incident_id=incident.id,
        alert=alert,
        metadata={"iterative_investigation": iterative_investigation},
    )


@pytest.mark.asyncio
async def test_conclusive_iterative_investigation_evidence_is_recognized_as_valid_citation() -> None:
    # This id exists ONLY in the iterative investigation's conclusion, never
    # in discovery_evidence - proving the widening in generate_rca() (not a
    # pre-existing discovery-mcp evidence id) is what makes it valid.
    trace_evidence_id = "TRACE-8deacba0-conclusive-only"
    context = _context(
        iterative_investigation={
            "conclusive": True,
            "conclusion": {"confidence": 0.863, "evidence_ids": [trace_evidence_id]},
        }
    )
    context.metadata["context_quality"] = {"execution_ready": False, "discovery_degraded": False}
    agent = ResolutionIntelligenceAgent(model_router=_router(trace_evidence_id))
    state = await agent.collect_context({"context": context})
    state = await agent.generate_rca(state)

    rca_analysis = state["rca_analysis"]
    # The core claim under test: an id that exists ONLY in the conclusive
    # iterative investigation's evidence_ids - never in discovery_evidence -
    # is recognized as a valid citation target once generate_rca() widens
    # valid_ids for a conclusive investigation.
    assert trace_evidence_id in rca_analysis["evidence_used"]
    assert rca_analysis["evidence_validation"]["available_count"] >= 1
    assert not rca_analysis.get("context_degraded", False)
    assert "discovery_evidence" not in rca_analysis.get("missing_evidence", [])
    assert rca_analysis["causal_chain"] == ["The dependency failure caused request retries and exhausted the service connection pool."]


@pytest.mark.asyncio
async def test_non_conclusive_iterative_investigation_does_not_widen_valid_evidence() -> None:
    # Negative test: when the iterative investigation is NOT conclusive, its
    # evidence ids must not be recognized - the non-conclusive path is
    # unchanged from before this fix.
    trace_evidence_id = "TRACE-not-yet-conclusive"
    context = _context(
        iterative_investigation={
            "conclusive": False,
            "conclusion": {"confidence": 0.4, "evidence_ids": [trace_evidence_id]},
        }
    )
    agent = ResolutionIntelligenceAgent(model_router=_router(trace_evidence_id))
    state = await agent.collect_context({"context": context})
    state = await agent.generate_rca(state)

    rca_analysis = state["rca_analysis"]
    assert trace_evidence_id not in rca_analysis["evidence_used"]
    assert rca_analysis["confidence_score"] <= 0.49  # empty-citation ceiling still applies
