"""Bounded, auditable replay of a frozen 30-alert selection using gateway services.

Run inside the gateway environment. Preview is read-only. Submit uses the
normal durable analysis handoff and explicitly retains human approval.
"""
import asyncio
import json
import sys
from datetime import datetime, timezone
from uuid import UUID, uuid4, uuid5, NAMESPACE_URL
import httpx
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
import app as gateway
from common.config import Settings
from common.database import AlertRecord, AnalysisRequestRecord, ContextSnapshotRecord, IncidentInvestigationBindingRecord, ResolutionOutboxRecord

async def baseline(session, incident_id):
    version=await session.scalar(select(func.max(ContextSnapshotRecord.snapshot_version)).where(ContextSnapshotRecord.tenant_id=='default',ContextSnapshotRecord.incident_id==incident_id))
    rca=await session.scalar(select(func.max(IncidentInvestigationBindingRecord.rca_version)).where(IncidentInvestigationBindingRecord.tenant_id=='default',IncidentInvestigationBindingRecord.incident_id==UUID(incident_id)))
    return {'snapshot_version':version or 0,'rca_version':rca or 0}

async def main():
    settings=Settings()
    engine=create_async_engine(settings.database_url)
    factory=async_sessionmaker(engine,expire_on_commit=False)
    mode=sys.argv[1] if len(sys.argv)>1 else 'preview'
    report=globals().get('MANIFEST',{'selected_at':datetime.now(timezone.utc).isoformat(),'tenant_id':'default','alerts':[]})
    try:
        if mode=='preview':
            async with factory() as session:
                selected=(await session.execute(select(AlertRecord.id,AlertRecord.service,AlertRecord.source,AlertRecord.created_at).where(AlertRecord.tenant_id=='default').order_by(AlertRecord.created_at.desc(),AlertRecord.id.desc()).limit(30))).all()
            for ident,service,source,created in selected:
                row={'alert_id':str(ident),'service':service,'source':source,'created_at':str(created)}
                try:
                    alert,incident,decision,previous=await gateway._load_analysis_regeneration_subject(alert_id=str(ident),tenant_id='default',session_factory=factory)
                    row['incident_id']=str(incident.id)
                    async with factory() as session: row['before']=await baseline(session,str(incident.id))
                except Exception as exc:
                    row['selection_blocker']=str(getattr(exc,'detail',type(exc).__name__))
                report['alerts'].append(row)
        elif mode=='submit':
            assert len(report['alerts'])==30 and report['tenant_id']=='default'
            gateway.app.state.session_factory=factory
            # The existing durable outbox dispatcher publishes the committed
            # command; no second, untracked broker publisher is introduced.
            class OutboxOnly:
                async def publish(self,*args,**kwargs):
                    raise RuntimeError('Durable batch replay: dispatch through outbox')
            gateway.app.state.producer=OutboxOnly()
            submitted={}
            for row in report['alerts']:
                if 'incident_id' not in row: continue
                incident_id=row['incident_id']
                if incident_id in submitted:
                    row['replay']=dict(submitted[incident_id],shared_incident=True)
                    continue
                try:
                    alert,incident,existing,previous=await gateway._load_analysis_regeneration_subject(alert_id=row['alert_id'],tenant_id='default',session_factory=factory)
                    assert str(incident.id)==incident_id
                    request_id=str(uuid4())
                    decision={**existing,'workflow':'guided-remediation','requires_approval':True,'risk_tier':'high','execution_mode':'supervised','policy_version':'policy-v1','policy_reason':'User-requested 30-alert context and resolution verification; human approval retained.','flow_id':str(existing.get('flow_id') or incident.id),'analysis_request_id':request_id,'analysis_mode':'fresh','context_strategy':'realtime','force_full_analysis':True,'regeneration_requested':True,'rca_version':max(1,int(existing.get('rca_version') or 1))}
                    expected=gateway._analysis_recommendation_id(incident_id=incident.id,request_id=UUID(request_id))
                    delivery,effective,created=await gateway._publish_analysis_regeneration_command(request_id=request_id,tenant_id='default',alert=alert,incident=incident,decision=decision,expected_recommendation_id=expected)
                    row['replay']={'request_id':effective,'delivery':delivery,'created':created}
                    submitted[incident_id]=row['replay']
                except Exception as exc:
                    row['replay_error']=str(getattr(exc,'detail',type(exc).__name__))
        elif mode=='poll':
            operations={}
            async with httpx.AsyncClient(timeout=60) as client:
                for row in report['alerts']:
                    replay=row.get('replay',{})
                    if not replay.get('request_id'): continue
                    async with factory() as session:
                        request=await session.get(AnalysisRequestRecord,UUID(replay['request_id']))
                        row['request']={key:str(getattr(request,key)) if getattr(request,key) is not None else None for key in ('status','delivery','terminal_reason','recommendation_id','completed_at','expires_at')} if request else {'status':'missing'}
                        row['after']=await baseline(session,row['incident_id'])
                        rid=replay['request_id']
                        receipts={}
                        for stage,event_id in [('ingress','analysis-regeneration:'+rid),('context','context:'+row['incident_id']+':'+rid)]:
                            event=await session.get(ResolutionOutboxRecord,event_id)
                            receipts[stage]={'status':event.status,'published_at':str(event.published_at)} if event else {'status':'missing'}
                        binding=(await session.execute(select(IncidentInvestigationBindingRecord).where(IncidentInvestigationBindingRecord.tenant_id=='default',IncidentInvestigationBindingRecord.analysis_request_id==UUID(rid)))).scalars().first()
                        receipts['rca']={'version':binding.rca_version,'recommendation_id':str(binding.recommendation_id)} if binding else None
                        snapshot_id=uuid5(NAMESPACE_URL,f"kaims:context-snapshot:default:{row['incident_id']}:{rid}")
                        snapshot=await session.get(ContextSnapshotRecord,snapshot_id)
                        receipts['snapshot']={'id':str(snapshot.snapshot_id),'version':snapshot.snapshot_version,'normalized_evidence_id_count':len(snapshot.evidence_ids or []),'quality_score':float(snapshot.quality_score),'collected_at':str(snapshot.collected_at)} if snapshot else None
                        if snapshot:
                            metadata=(snapshot.payload or {}).get('metadata') or {}
                            receipts['snapshot']['payload_counts']={key:len(metadata.get(key) or []) for key in ('discovery_evidence','context_evidence') if isinstance(metadata.get(key),(list,dict))}
                            receipts['snapshot']['payload_shape']={key:type(metadata.get(key)).__name__ for key in ('discovery_evidence','context_evidence','context_sources')}
                        row['receipts']=receipts
                        expiry=request.expires_at.replace(tzinfo=timezone.utc) if request and request.expires_at.tzinfo is None else request.expires_at if request else None
                        row['deadline_exceeded']=bool(expiry and expiry<datetime.now(timezone.utc) and request.status not in ('complete','failed','cancelled'))
                    ident=row['incident_id']
                    if ident not in operations:
                        response=await client.get(f'http://context-agent:8000/incidents/{ident}/operations-state',params={'tenant_id':'default'})
                        if response.status_code!=200: operations[ident]={'http_status':response.status_code};continue
                        data=response.json();workspace=data.get('investigation_workspace',{})
                        operations[ident]={'lifecycle_state':data.get('lifecycle_state'),'rca_status':workspace.get('rca',{}).get('status'),'impact_status':workspace.get('impact',{}).get('status'),'next_action':data.get('next_action'),'requirements':[{'category':r.get('category'),'status':r.get('status')} for r in data.get('requirements',[])],'execution_status':data.get('execution',{}).get('status'),'validation_status':data.get('validation',{}).get('status')}
                    row['operations']=operations.get(ident)
        report['updated_at']=datetime.now(timezone.utc).isoformat()
        print(json.dumps(report,default=str))
    finally:
        await engine.dispose()

if __name__=='__main__':
    asyncio.run(main())
