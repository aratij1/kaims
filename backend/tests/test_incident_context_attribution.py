import importlib.util
from pathlib import Path
from datetime import datetime,UTC
from uuid import uuid4
from common.models import Incident
from common.context_enrichment_contract import EvidenceRequirement, normalize_connector_response
from common.evidence_subject import metric_matches_subject

def test_fleet_query_records_other_targets_as_rejections():
 incident=Incident(tenant_id='tenant-a',service='kaiops-mysql-exporter',title='Exporter down')
 now=datetime.now(UTC)
 requirement=EvidenceRequirement(requirement_id=uuid4(),tenant_id=incident.tenant_id,incident_id=incident.id,rca_version=1,category='metrics',question='Is the affected target down?',reason='Prove target state',priority='high',collection_mode='automatic',candidate_connectors=['prometheus'],created_at=now,updated_at=now)
 result=normalize_connector_response(raw_response={'query':'up{job=~"kaiops-.*"} == 0','series':[{'metric':{'job':'kaiops-api-gateway'},'value':[now.timestamp(),'0']},{'metric':{'job':'kaiops-mysql-exporter'},'value':[now.timestamp(),'0']}]},requirement=requirement,incident=incident,connector='prometheus',collected_at=now)
 assert len(result.records)==1 and result.records[0].content['labels']['job']=='kaiops-mysql-exporter'
 assert result.rejected==[{'code':'METRIC_SUBJECT_MISMATCH','record_index':0}]

def test_service_scoped_source_search_cannot_return_frontend_fixtures(tmp_path,monkeypatch):
 spec=importlib.util.spec_from_file_location('scoped_discovery',Path('backend/src/discovery-mcp/app.py')); module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
 root=tmp_path/'backend'/'src';target=root/'api-gateway';target.mkdir(parents=True)
 (target/'app.py').write_text('api-gateway handles requests')
 fixtures=root/'frontend';fixtures.mkdir();(fixtures/'appHelpers.selection.test.ts').write_text('api-gateway kaiops-mysql-exporter error')
 monkeypatch.setenv('DISCOVERY_MCP_CODE_ROOTS',str(root));monkeypatch.setattr(module,'_project_catalog',lambda:{})
 assert module._call_tool('code.search',{'service':'kaiops-mysql-exporter','terms':['error']})['evidence']==[]
 rows=module._call_tool('code.search',{'service':'api-gateway','terms':['api-gateway','error']})['evidence']
 assert rows and all('/api-gateway/' in row['uri'] for row in rows)

import pytest
from unittest.mock import AsyncMock

def test_availability_alert_collects_runtime_evidence_without_waiting_for_rca():
 from common.models import Alert, AlertSeverity
 from context_agent.connectors import DiscoveryMCPConnector
 alert=Alert(source='prometheus',name='MySQLExporterDown',service='mysql-exporter',severity=AlertSeverity.CRITICAL,description='No metrics being scraped')
 tools,reasons=DiscoveryMCPConnector._plan_discovery_tools(alert)
 assert {'logs.search','topology.search','dependency-health.search','resource-health.search'} <= set(tools)
 assert 'availability_runtime_diagnostics' in reasons

@pytest.mark.asyncio
async def test_mysql_control_plane_is_not_default_application_database(monkeypatch):
 spec=importlib.util.spec_from_file_location('database_scope_discovery',Path('backend/src/discovery-mcp/app.py'));module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
 query=AsyncMock(return_value=[])
 monkeypatch.setattr(module,'_search_mysql',query)
 monkeypatch.setattr(module,'_mysql_connection_settings',lambda:{'db':'kaiops'})
 result=await module._call_mysql_tool({'service':'mysql-exporter','terms':['mysql','error']})
 assert result['evidence']==[] and result['evidence_gap']=='APPLICATION_DATABASE_SCOPE_NOT_CONFIGURED'
 query.assert_not_awaited()

@pytest.mark.asyncio
async def test_runtime_alias_self_check_is_not_an_upstream_dependency(monkeypatch):
 import httpx
 from test_collector_inbox_regressions import discovery,mock_http,NOW
 def handler(request):
  return httpx.Response(200,json=[{'Id':'target','Created':NOW.timestamp(),'Names':['/kaims-rs-redis-1'],'State':'exited','Status':'Exited (0)','Labels':{'com.docker.compose.project':'kaims','com.docker.compose.service':'rs-redis'}}])
 mock_http(monkeypatch,handler)
 result=await discovery._search_runtime_topology({'service':'robot-shop-redis'},health_only=True)
 row=result['evidence'][0]
 assert row['service']==row['related_to']=='robot-shop-redis'
 assert row['runtime_service']=='rs-redis' and row['runtime_state']=='exited'
