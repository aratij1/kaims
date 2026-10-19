"""Bounded recovery of the specifically diagnosed RCA coalescing sort error."""
import asyncio,json
from datetime import datetime,timezone
import aio_pika
from common.config import Settings
async def main():
    settings=Settings();conn=await aio_pika.connect_robust(settings.rabbitmq_url)
    held=[];restored=[];scanned=0;size=0
    try:
        ch=await conn.channel(publisher_confirms=True,on_return_raises=True)
        base=settings.rabbitmq_queue_prefix+'.resolution-agent.context-events'
        q=await ch.declare_queue(base+'.dlq',passive=True)
        await ch.declare_queue(base+'.deferred',durable=True)
        for _ in range(min(q.declaration_result.message_count,200)):
            msg=await q.get(fail=False,timeout=2)
            if msg is None:break
            held.append(msg);scanned+=1;size+=len(msg.body)
            try:doc=json.loads(msg.body)
            except ValueError:continue
            if not isinstance(doc,dict):continue
            err=str(doc.get('error') or '')
            failed=str(doc.get('failed_at') or '')
            payload=doc.get('payload')
            if ('Out of sort memory' in err and 'context_snapshots.snapshot_stage' in err
                    and failed>='2026-09-13T05:12:00' and doc.get('failed_topic')=='context-events'
                    and isinstance(payload,dict)):
                body=json.dumps({'payload':payload,'produced_at':failed},default=str).encode()
                await asyncio.wait_for(ch.default_exchange.publish(aio_pika.Message(body=body,content_type='application/json',delivery_mode=2,headers={'x-kaims-backlog-state':'replayed','x-kaims-recovery-reason':'coalescing_sort_query_fixed'}),routing_key=base+'.deferred',mandatory=True),timeout=10)
                await msg.ack();held.remove(msg)
                restored.append((payload.get('event_contract') or {}).get('event_id'))
            if size>=250*1024*1024:break
        print(json.dumps({'scanned':scanned,'restored':len(restored),'event_ids':restored,'observed_at':datetime.now(timezone.utc).isoformat()}))
    finally:
        for msg in held:
            if not msg.processed:await msg.reject(requeue=True)
        await conn.close()
if __name__=='__main__':asyncio.run(main())
