from datetime import datetime,timezone,timedelta
from uuid import uuid4,uuid5,NAMESPACE_URL
import pytest
from sqlalchemy import select,func
from common.database import ContextSnapshotRecord,ResolutionOutboxRecord,AuditLogRecord
from common.repository import IncidentRepository

@pytest.mark.parametrize('case,coalesced', [('covered',True),('reference',True),('corrupt_reference',False),('operator',False),('explicit_record',False),('missing_successor',False),('lost_evidence',False),('expired',False),('other_tenant',False),('wrong_successor_snapshot',False)])
async def test_background_coalescing_requires_complete_durable_coverage(sqlite_session_factory,case,coalesced):
    incident=uuid4();old_id=uuid4();new_id=uuid4();now=datetime.now(timezone.utc)
    request=uuid5(NAMESPACE_URL,f'kaims:enriched-analysis:{old_id}')
    if case=='operator':request=uuid4()
    async with sqlite_session_factory() as session:
        repo=IncidentRepository(session)
        for ident,version,ids in [(old_id,1,['e1']),(new_id,2,['e2'] if case=='lost_evidence' else ['e1','e2'])]:
            session.add(ContextSnapshotRecord(snapshot_id=ident,tenant_id='t',incident_id=str(incident),alert_signature='a',subject_fingerprint='s',context_fingerprint=str(ident),snapshot_stage='enriched',snapshot_version=version,evidence_ids=ids,payload={'metadata':{'evidence_set_digest':'digest'}},expires_at=now+timedelta(hours=-1 if case=='expired' else 1)))
        if case!='missing_successor':
            session.add(ResolutionOutboxRecord(event_id=f'context-enriched:{incident}:digest',tenant_id='other' if case=='other_tenant' else 't',aggregate_id=str(incident),topic='context-events',partition_key='test',status='published',payload={'context':{'metadata':{'context_snapshot_id':str(old_id if case=='wrong_successor_snapshot' else new_id),'analysis_request_id':str(uuid5(NAMESPACE_URL,f'kaims:enriched-analysis:{new_id}'))}}}))
        if case in {'reference', 'corrupt_reference'}:
            from common.outbox_context import REFERENCE_VERSION, context_checksum
            snapshot = await session.get(ContextSnapshotRecord, new_id)
            context = {'tenant_id': 't', 'incident_id': str(incident), 'metadata': {
                'evidence_set_digest': 'digest', 'context_snapshot_id': str(new_id),
                'analysis_request_id': str(uuid5(NAMESPACE_URL, f'kaims:enriched-analysis:{new_id}'))}}
            snapshot.payload = context
            successor = await session.get(ResolutionOutboxRecord, f'context-enriched:{incident}:digest')
            successor.payload = {'context_ref': {'schema_version': REFERENCE_VERSION,
                'snapshot_id': str(new_id), 'context_sha256': context_checksum(context)
                if case == 'reference' else 'bad-checksum'}}
        if case=='explicit_record':
            await repo.create_or_reuse_analysis_request(request_id=request,tenant_id='t',incident_id=incident,alert_id=uuid4(),expected_recommendation_id=uuid4(),mode='fresh')
        await session.flush()
        for _ in range(2):
            result=await repo.coalesce_superseded_background_rca(tenant_id='t',incident_id=incident,snapshot_id=old_id,request_id=request)
            assert bool(result)==coalesced
        assert await session.scalar(select(func.count()).select_from(AuditLogRecord))==int(coalesced)
        assert await session.get(ContextSnapshotRecord,old_id) is not None
