from datetime import datetime, timezone
from uuid import uuid4
import httpx
import pytest
from common.context_enrichment_contract import build_evidence_requirements, authorized_enrichment_connectors, next_authorized_enrichment_connector
from common.models import Alert, AlertSeverity
from context_agent.connectors import DiscoveryMCPConnector

@pytest.mark.parametrize('question,category',[
 ('Deployment history or recent changes for api-gateway','deployment'),
 ('Resource telemetry and data-path health during the incident window','metrics'),
 ('Dependency health and saturation metrics','topology'),
])
def test_legacy_requests_use_existing_discovery(question,category):
    requirement=build_evidence_requirements(tenant_id='t',incident_id=uuid4(),rca_version=1,missing_evidence=[question],now=datetime.now(timezone.utc))[0]
    assert requirement.category==category
    assert requirement.question==question
    assert next_authorized_enrichment_connector(candidate_connectors=requirement.candidate_connectors,authorized_connectors=authorized_enrichment_connectors(alert_metadata={},context_payload={}))=='discovery-mcp'


def test_unknown_prose_still_requires_a_scoped_source():
    requirement=build_evidence_requirements(tenant_id='t',incident_id=uuid4(),rca_version=1,missing_evidence=['Confirm legal approval'],now=datetime.now(timezone.utc))[0]
    assert requirement.category=='validation'
    assert requirement.candidate_connectors==[]


async def test_discovery_uses_project_metadata_even_when_labels_lack_project():
    requests=[]
    def handler(request):
        import json
        requests.append(json.loads(request.content))
        return httpx.Response(200,json={'result':{'evidence':[]}})
    alert=Alert(tenant_id='t',source='prometheus',name='ServiceDown',service='api-gateway',environment='prod',severity=AlertSeverity.HIGH,description='test',metadata={'project_id':'kaims'})
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        await DiscoveryMCPConnector()._call_mcp(client,'topology.search',['api-gateway'],alert)
    assert requests[0]['params']['arguments']['project']=='kaims'


def test_existing_resource_health_tool_is_selectable_for_targeted_collection():
    alert=Alert(tenant_id='t',source='prometheus',name='ResourcePressure',service='api-gateway',environment='prod',severity=AlertSeverity.HIGH,description='test',metadata={'context_requirement_category':'metrics','context_collection_tool':'resource-health.search'})
    tools,reasons=DiscoveryMCPConnector._plan_discovery_tools(alert)
    assert tools==['resource-health.search']
    assert reasons==['evidence_requirement']


@pytest.mark.parametrize('has_response',[False,True])
async def test_reconciliation_supersedes_unattempted_legacy_without_losing_human_response(sqlite_session_factory,has_response):
    from common.repository import ContextEnrichmentRepository
    from common.database import HumanEvidenceRequestRecord
    from sqlalchemy import select
    question='Deployment history or recent changes for api-gateway'
    request=build_evidence_requirements(tenant_id='t',incident_id=uuid4(),rca_version=1,missing_evidence=[question],now=datetime.now(timezone.utc))[0]
    legacy=request.model_copy(update={'requirement_id':uuid4(),'category':'validation','candidate_connectors':[],'collection_mode':'connector_required','status':'human_requested'})
    async with sqlite_session_factory() as session:
        repo=ContextEnrichmentRepository(session)
        old=(await repo.upsert_context_evidence_requirements([legacy]))[0]
        human=HumanEvidenceRequestRecord(tenant_id='t',incident_id=request.incident_id,requirement_id=legacy.requirement_id,due_at=datetime.now(timezone.utc),acceptable_format='source',hypothesis_impact='investigate',status='pending',response_payload={'observation':'retained'} if has_response else {})
        session.add(human);await session.flush()
        await repo.upsert_context_evidence_requirements([request]);await session.flush()
        assert old.status==('human_requested' if has_response else 'cancelled')
        assert human.status==('pending' if has_response else 'cancelled')
        assert human.response_payload==({'observation':'retained'} if has_response else {})
        again=await repo.upsert_context_evidence_requirements([request])
        assert again[0].requirement_id==request.requirement_id
