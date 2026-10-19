"""Read only, request-specific RCA audit; no full context or credentials emitted."""
import asyncio,json
from uuid import UUID
from datetime import datetime,timezone
from sqlalchemy import select
from sqlalchemy.ext.asyncio import create_async_engine,async_sessionmaker
from common.config import Settings
from common.database import AnalysisRequestRecord,IncidentInvestigationBindingRecord,AuditLogRecord
async def main():
    engine=create_async_engine(Settings().database_url);factory=async_sessionmaker(engine);rows=[]
    try:
        async with factory() as session:
            for rid in REQUEST_IDS:
                req=await session.get(AnalysisRequestRecord,UUID(rid))
                binding=await session.scalar(select(IncidentInvestigationBindingRecord).where(IncidentInvestigationBindingRecord.analysis_request_id==UUID(rid),IncidentInvestigationBindingRecord.tenant_id=='default'))
                row={'request_id':rid,'incident_id':str(req.incident_id),'status':req.status,'delivery':req.delivery,'completed_at':str(req.completed_at),'reason':req.terminal_reason,'rca_version':binding.rca_version if binding else None,'evidence_count':len(binding.evidence_ids or []) if binding else None}
                if req.recommendation_id:
                    audit=await session.get(AuditLogRecord,req.recommendation_id)
                    metadata=(audit.payload or {}).get('metadata') or {} if audit else {}
                    row['rca_status']=metadata.get('rca_status')
                    row['missing_evidence_count']=len((metadata.get('rca_analysis') or {}).get('missing_evidence') or [])
                rows.append(row)
        print(json.dumps({'observed_at':datetime.now(timezone.utc).isoformat(),'requests':rows}))
    finally:await engine.dispose()
if __name__=='__main__':asyncio.run(main())
