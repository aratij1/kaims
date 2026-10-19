from uuid import UUID
import pytest
from sqlalchemy import select,func
from common.diagnostic_runbooks import diagnostic_template,diagnostic_tools,ensure_diagnostic_runbook
from common.database import RunbookVersionRecord
from common.repository import IncidentRepository
from common.models import ApplicationRegistration

SCOPE=dict(tenant_id='tenant-a',application='shop',service='checkout',environment='prod',alert_family='CheckoutHttp5xx')


def test_cold_start_template_is_guidance_not_causal_or_execution_authority():
    plan=diagnostic_template(**SCOPE)
    assert plan['readonly_tools']==['logs.search','telemetry.search','traces.search','code.search']
    assert plan['impact_checks'] and plan['resolution_requirements']
    assert not plan['execution_eligible'] and not plan['context_eligible']
    assert plan['remediation_steps']==[]
    assert 'evidence' not in plan and 'root_cause' not in plan


@pytest.mark.parametrize('key,value',[('tenant_id','other'),('service','other'),('environment','test')])
def test_diagnostic_guidance_is_scope_bound(key,value):
    plan=diagnostic_template(**SCOPE)
    scope={k:SCOPE[k] for k in ['tenant_id','service','environment']};scope[key]=value
    assert diagnostic_tools(plan,**scope)==[]


def test_diagnostic_plan_cannot_register_commands_or_unapproved_tools():
    plan=diagnostic_template(**SCOPE)
    plan['readonly_tools']=['docker.restart','rm -rf /','code.search','code.search']
    assert diagnostic_tools(plan,tenant_id='tenant-a',service='checkout',environment='prod')==['code.search']


@pytest.mark.asyncio
async def test_new_family_is_durable_idempotent_and_tenant_isolated(sqlite_session_factory):
    async with sqlite_session_factory() as session:
        first=await ensure_diagnostic_runbook(session,**SCOPE)
        await session.commit()
        second=await ensure_diagnostic_runbook(session,**SCOPE)
        other=await ensure_diagnostic_runbook(session,**{**SCOPE,'tenant_id':'tenant-b'})
        await session.commit()
        assert first==second
        assert first['runbook_id']!=other['runbook_id']
        assert await session.scalar(select(func.count()).select_from(RunbookVersionRecord))==2
        row=await session.get(RunbookVersionRecord,(UUID(first['runbook_id']),1))
        assert row.approval_status=='draft' and row.success_count==0
        row.approval_status='disabled';await session.commit()
        disabled=await ensure_diagnostic_runbook(session,**SCOPE)
        assert not disabled['diagnostic_eligible'] and disabled['readonly_tools']==[]


@pytest.mark.asyncio
async def test_onboarding_persists_baseline_in_same_transaction(sqlite_session_factory):
    app=ApplicationRegistration(tenant_id='tenant-a',name='shop',owner_team='ops',namespace='shop',technology='python',metrics_endpoint='http://shop/metrics')
    async with sqlite_session_factory() as session:
        await IncidentRepository(session).save_application(app)
        await session.commit()
        row=await session.scalar(select(RunbookVersionRecord))
        assert row.content['alert_family']=='application_baseline'
        assert row.content['application']=='shop'
        assert row.owner=='ops'


@pytest.mark.asyncio
async def test_project_onboarding_also_persists_baseline(sqlite_session_factory):
    async with sqlite_session_factory() as session:
        await IncidentRepository(session).save_onboarding_state(tenant_id='tenant-a',project_name='shop',provider_name='prometheus',project_payload={'name':'shop'},connectivity_payload={'ok':True},environment='prod')
        await session.commit()
        row=await session.scalar(select(RunbookVersionRecord))
        assert row.content['alert_family']=='application_baseline'


@pytest.mark.asyncio
async def test_runbook_exists_before_first_context_collection(sqlite_session_factory,monkeypatch):
    from test_context_knowledge_strategy import load_context_app_module,make_alert,make_incident,CountingContextAgent
    module=load_context_app_module()
    class Collector(CountingContextAgent):
        async def collect_with_runtime(self,alert,incident):
            plan=alert.metadata['diagnostic_runbook']
            assert plan['diagnostic_eligible'] and not plan['execution_eligible']
            async with sqlite_session_factory() as session:
                assert await session.get(RunbookVersionRecord,(UUID(plan['runbook_id']),1)) is not None
            return await super().collect_with_runtime(alert,incident)
    monkeypatch.setattr(module,'agent',Collector())
    monkeypatch.setattr(module.settings,'database_enabled',True)
    monkeypatch.setattr(module.app.state,'session_factory',sqlite_session_factory,raising=False)
    alert=make_alert()
    result=await module._collect_context_with_strategy(module.app,alert,make_incident(alert),strategy_override='realtime')
    assert result.metadata['diagnostic_runbook']['alert_family']==alert.name
    assert not result.metadata['diagnostic_runbook']['execution_eligible']


def test_discovery_uses_runbook_guidance_but_targeted_gap_keeps_precedence():
    from context_agent.connectors import DiscoveryMCPConnector
    from common.models import Alert
    plan=diagnostic_template(**{**SCOPE,'alert_family':'ServiceDown'})
    alert=Alert(tenant_id='tenant-a',service='checkout',environment='prod',name='UnfamiliarSignal',source='custom',description='new signal',metadata={'diagnostic_runbook':plan})
    tools,reasons=DiscoveryMCPConnector._plan_discovery_tools(alert)
    assert 'topology.search' in tools and 'scoped_diagnostic_runbook' in reasons
    alert.metadata['context_requirement_category']='source_code'
    assert DiscoveryMCPConnector._plan_discovery_tools(alert)[0]==['code.search']


def test_rca_uses_diagnostic_order_without_granting_mutating_capabilities():
    from resolution_agent.investigation import IterativeInvestigator
    from ai_workbench_common.models import Context
    from common.models import Alert
    from uuid import uuid4
    plan=diagnostic_template(**SCOPE)
    plan['readonly_tools']=['traces.search','logs.search','telemetry.search']
    alert=Alert(tenant_id='tenant-a',service='checkout',environment='prod',name='Latency',source='prometheus',description='latency')
    context=Context(tenant_id='tenant-a',incident_id=uuid4(),alert=alert,metadata={'diagnostic_runbook':plan})
    tool,args=IterativeInvestigator()._select_tool(context=context,evidence=[],hypotheses=[],tool_counts={})
    assert tool=='traces.search' and args['service']=='checkout'

@pytest.mark.asyncio
async def test_model_stages_receive_guidance_separately_from_evidence():
    from types import SimpleNamespace
    from unittest.mock import AsyncMock
    from common.models import Alert
    from ai_workbench_common.models import Context
    from resolution_agent.graph import ResolutionIntelligenceAgent,ModelTask
    from uuid import uuid4
    plan=diagnostic_template(**SCOPE)
    context=Context(tenant_id='tenant-a',incident_id=uuid4(),alert=Alert(tenant_id='tenant-a',source='prometheus',name='Http5xx',service='checkout',environment='prod',description='errors'),metadata={'diagnostic_runbook':plan})
    gateway=SimpleNamespace(generate=AsyncMock(return_value={'model':'test','content':'{}','usage':{}}))
    agent=ResolutionIntelligenceAgent();agent.model_gateway=gateway
    for task in [ModelTask.RCA,ModelTask.IMPACT,ModelTask.FIX]:
        await agent._generate_with_fallback(context=context,task=task,prompt='Analyze',payload={'discovery_evidence':[]},fallback_content='unknown')
        request=gateway.generate.await_args.args[0]
        assert request.payload['diagnostic_guidance']['runbook_id']==plan['runbook_id']
        assert request.payload['discovery_evidence']==[]
        assert 'not observations' in request.prompt
