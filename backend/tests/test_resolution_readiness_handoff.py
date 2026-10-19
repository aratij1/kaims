import importlib.util
from pathlib import Path
from uuid import uuid4

from ai_workbench_common.models import Context
from common.models import Alert, AlertSeverity, Recommendation

_APP_PATH = Path(__file__).resolve().parents[2] / "ai-workbench" / "src" / "resolution-agent" / "app.py"
_APP_SPEC = importlib.util.spec_from_file_location("readiness_handoff_resolution_app", _APP_PATH)
assert _APP_SPEC and _APP_SPEC.loader
resolution_app = importlib.util.module_from_spec(_APP_SPEC)
_APP_SPEC.loader.exec_module(resolution_app)


def test_outstanding_causal_gaps_cannot_advance_to_rca_ready():
    metadata = {"rca_status": "grounded", "iterative_investigation": {"conclusive": True},
                "rca_analysis": {"evidence_used": ["trace-1"], "missing_evidence": ["dependency diagnostics"]},
                "execution_plan": {"execution_ready": True, "mutating": True}}
    assert resolution_app._resolution_projection_status(metadata, requires_approval=True) == "investigating"
    context = Context(tenant_id="tenant-a", incident_id=uuid4(), alert=Alert(tenant_id="tenant-a", source="prometheus",
        service="checkout", name="Latency", description="latency"))
    recommendation = Recommendation(tenant_id="tenant-a", incident_id=context.incident_id,
        root_cause="Outbound connection timeouts", confidence=.8, impact="Slow requests",
        recommended_action="Scale deployment", severity=AlertSeverity.HIGH, rationale="trace observations",
        risk="high", metadata=metadata)
    plan = resolution_app._apply_catalog_plan(recommendation, context)
    assert recommendation.metadata["rca_status"] == "insufficient_evidence"
    assert recommendation.metadata["rca_handoff_blockers"] == ["declared evidence gaps remain"]
    assert plan["execution_ready"] is False


def test_catalog_handoff_preserves_evidence_readiness_block() -> None:
    alert = Alert(
        tenant_id="tenant-a",
        source="prometheus",
        name="KaiOpsServiceDown",
        service="kaiops-discovery-mcp",
        environment="prod",
        severity=AlertSeverity.CRITICAL,
        description="service is unreachable",
    )
    context = Context(tenant_id="tenant-a", incident_id=alert.id, alert=alert)
    recommendation = Recommendation(
        tenant_id="tenant-a",
        incident_id=context.incident_id,
        root_cause="Investigation inconclusive",
        confidence=0.38,
        impact="Impact is not established",
        recommended_action="Collect evidence",
        severity=AlertSeverity.CRITICAL,
        rationale="Causal evidence is incomplete",
        commands=[],
        risk="high",
        metadata={
            "rca_analysis": {
                "context_readiness": {"score": 0.38, "ready": False, "source_coverage": 0.25},
            },
            "execution_plan": {
                "execution_ready": False,
                "readiness_blocks": [],
            },
        },
    )

    plan = resolution_app._apply_catalog_plan(recommendation, context)

    assert plan["execution_ready"] is False
    assert any("38% RCA-ready" in reason for reason in plan["readiness_blocks"])


def test_intake_route_cannot_waive_later_plan_approval(monkeypatch):
    alert = Alert(tenant_id='tenant-a', source='prometheus',name='KaiOpsServiceDown',
        service='api-gateway',environment='prod',severity=AlertSeverity.CRITICAL,description='service unavailable')
    context=Context(tenant_id='tenant-a',incident_id=alert.id,alert=alert,
        metadata={'orchestration_decision':{'requires_approval':False}})
    recommendation=Recommendation(tenant_id='tenant-a',incident_id=context.incident_id,
        root_cause='Service process stopped',confidence=.95,impact='HTTP service unavailable',
        recommended_action='restart service',severity=AlertSeverity.CRITICAL,rationale='Independent observations',risk='high',
        metadata={'rca_status':'grounded','evidence_ids':['metric:probe','topology:exit'],
            'iterative_investigation':{'conclusive':True,'status':'conclusive',
               'conclusion':{'confidence':.95,'independent_source_count':2,'evidence_ids':['metric:probe','topology:exit']}},
            'rca_analysis':{'context_readiness':{'score':1.,'ready':True},'evidence_used':['metric:probe','topology:exit']}})
    plan=resolution_app._apply_catalog_plan(recommendation,context,{'requires_approval':False})
    assert plan['requires_approval'] is True
    assert recommendation.metadata['resolution_control']['approval_required'] is True
    assert recommendation.metadata['resolution_lifecycle']['state']=='awaiting_approval'
