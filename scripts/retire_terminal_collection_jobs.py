"""Preview or retire collection work for terminal incidents; retain an audit trail."""
from __future__ import annotations
import argparse
import asyncio
import json
from common.config import get_settings
from common.database import create_engine, create_session_factory
from common.repository import ContextEnrichmentRepository

async def run(tenant_id: str, *, apply: bool, limit: int, actor: str) -> dict:
    engine = create_engine(get_settings())
    try:
        async with create_session_factory(engine)() as session:
            result = await ContextEnrichmentRepository(session).retire_closed_incident_collection_jobs(
                tenant_id=tenant_id, actor=actor, limit=limit, dry_run=not apply,
            )
            if apply:
                await session.commit()
            else:
                await session.rollback()
            return result
    finally:
        await engine.dispose()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tenant', required=True)
    parser.add_argument('--apply', action='store_true', help='Retire eligible jobs and record the previous states in the audit log.')
    parser.add_argument('--limit', type=int, default=500)
    parser.add_argument('--actor', default='local-pipeline-maintenance')
    args = parser.parse_args()
    print(json.dumps(asyncio.run(run(args.tenant, apply=args.apply, limit=args.limit, actor=args.actor))))
