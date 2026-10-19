"""Read-only queue counters and durable workflow status; no payloads or credentials."""
import asyncio
import json
from datetime import datetime, timezone, timedelta
from urllib.parse import urlparse, unquote, quote
import httpx
from sqlalchemy import select, func, or_
from sqlalchemy.ext.asyncio import create_async_engine
from common.config import Settings
from common.database import Base

async def main():
    settings = Settings()
    url = urlparse(settings.rabbitmq_url)
    vhost = unquote(url.path[1:]) or "/"
    base = f"{'https' if url.scheme == 'amqps' else 'http'}://{url.hostname}:15672/api"
    auth = (unquote(url.username or "guest"), unquote(url.password or "guest"))
    output = {"observed_at": datetime.now(timezone.utc).isoformat(), "queues": [], "durable": {}}
    async with httpx.AsyncClient(timeout=15, auth=auth) as client:
        response = await client.get(base + "/queues/" + quote(vhost, safe=""))
        response.raise_for_status()
        for row in response.json():
            if not row['name'].startswith(settings.rabbitmq_queue_prefix + '.'):
                continue
            output['queues'].append({key: row.get(key) for key in ('name','messages_ready','messages_unacknowledged','consumers','state','message_stats')})
        response = await client.get(base + "/bindings/" + quote(vhost, safe=""))
        response.raise_for_status()
        output['bindings'] = [{k:r.get(k) for k in ('source','destination','routing_key')} for r in response.json() if r.get('destination','').startswith(settings.rabbitmq_queue_prefix + '.')]
    engine = create_async_engine(settings.database_url)
    try:
        async with engine.connect() as connection:
            for name in ('alerts','incidents','incident_occurrences','context_snapshots','context_evidence_requirements','context_enrichment_jobs','analysis_requests','resolution_outbox','governed_resolution_plans','approvals','actions','rca_reports'):
                table = Base.metadata.tables[name]
                summary = {}
                status = next((table.c[k] for k in ('status','decision','state') if k in table.c), None)
                if status is not None:
                    result = await connection.execute(select(status,func.count()).group_by(status))
                    summary['by_status'] = {str(row[0]):row[1] for row in result}
                summary['total'] = (await connection.execute(select(func.count()).select_from(table))).scalar()
                if 'created_at' in table.c:
                    summary['created_last_hour'] = (await connection.execute(select(func.count()).select_from(table).where(table.c.created_at >= datetime.now(timezone.utc)-timedelta(hours=1)))).scalar()
                if 'updated_at' in table.c and status is not None:
                    result = await connection.execute(select(status,func.min(table.c.updated_at),func.max(table.c.updated_at)).group_by(status))
                    summary['updated_range'] = {str(r[0]):[str(r[1]),str(r[2])] for r in result}
                output['durable'][name] = summary
            jobs = Base.metadata.tables['context_enrichment_jobs']
            now = datetime.now(timezone.utc)
            active = jobs.c.status.in_(['scheduled','retry','collecting'])
            expired = (jobs.c.status == 'collecting') & or_(jobs.c.lease_expires_at.is_(None), jobs.c.lease_expires_at < now)
            output['job_diagnostics'] = {
                'active': (await connection.execute(select(func.count()).select_from(jobs).where(active))).scalar(),
                'expired_collecting_leases': (await connection.execute(select(func.count()).select_from(jobs).where(expired))).scalar(),
                'due_scheduled_or_retry': (await connection.execute(select(func.count()).select_from(jobs).where(jobs.c.status.in_(['scheduled','retry']), jobs.c.available_at <= now))).scalar(),
            }
            result = await connection.execute(select(jobs.c.status, jobs.c.last_error).where(jobs.c.updated_at >= now-timedelta(hours=1)))
            errors = {}
            for status, error in result:
                if not error:
                    continue
                value = error.lower()
                label = next((label for label, words in [
                    ('missing_fields', ['missing required']),
                    ('unsupported_category', ['unsupported', 'not supported']),
                    ('no_evidence', ['no evidence', 'evidence was not returned', 'no records']),
                    ('timeout', ['timeout', 'timed out']),
                    ('connector_unavailable', ['unavailable', 'connection', 'refused']),
                    ('binding', ['binding', 'scope']),
                    ('expired', ['expired']),
                    ('invalid_evidence', ['invalid', 'rejected', 'validation']),
                ] if any(word in value for word in words)), 'other')
                key = str(status) + ':' + label
                errors[key] = errors.get(key, 0) + 1
            output['job_diagnostics']['last_hour_error_categories'] = errors
            outbox=Base.metadata.tables['resolution_outbox']
            result=await connection.execute(select(outbox.c.topic,func.count()).where(outbox.c.created_at >= now-timedelta(hours=1)).group_by(outbox.c.topic))
            output['outbox_topics_last_hour']={r[0]:r[1] for r in result}

    finally:
        await engine.dispose()
    print(json.dumps(output,default=str))

if __name__ == '__main__':
    asyncio.run(main())
