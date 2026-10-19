"""Exercise parking and replay on unique synthetic queues using real RabbitMQ."""
import asyncio
import json
from datetime import datetime, timezone, timedelta
from uuid import uuid4
import aio_pika
from common.config import Settings
from common.queue_backpressure import rebalance

async def main():
    url=Settings().rabbitmq_url
    name='backpressure-test-'+uuid4().hex
    connection=await aio_pika.connect_robust(url)
    channel=await connection.channel(publisher_confirms=True, on_return_raises=True)
    active=await channel.declare_queue(name,durable=True)
    try:
        old=json.dumps({'produced_at':(datetime.now(timezone.utc)-timedelta(minutes=10)).isoformat(),'payload':{'synthetic':True}}).encode()
        fresh=json.dumps({'produced_at':datetime.now(timezone.utc).isoformat(),'payload':{'fresh':True}}).encode()
        for body in [old]*4+[fresh]*2:
            await channel.default_exchange.publish(aio_pika.Message(body=body,delivery_mode=2),routing_key=name)
        first=await rebalance(url,name,high=5,low=2,minimum_age=300,batch=6)
        assert first['parked']==4, first
        deferred=await channel.declare_queue(name+'.deferred',passive=True)
        assert deferred.declaration_result.message_count==4
        # Only the two recent messages stayed active, byte for byte.
        for _ in range(2):
            message=await active.get(fail=False)
            assert message.body==fresh
            await message.ack()
        absent=await rebalance(url,name,high=5,low=2,minimum_age=300,batch=2)
        assert absent['replayed']==0
        observed=[]
        done=asyncio.Event()
        async def consume(message):
            assert message.body==old
            assert message.headers['x-kaims-backlog-state']=='replayed'
            observed.append(message.body)
            await message.ack()
            if len(observed)==4: done.set()
        tag=await active.consume(consume)
        replay1=await rebalance(url,name,high=5,low=2,minimum_age=300,batch=2)
        assert replay1['replayed']==2
        replay2=await rebalance(url,name,high=5,low=2,minimum_age=300,batch=2)
        assert replay2['replayed']==2
        await asyncio.wait_for(done.wait(),10)
        await active.cancel(tag)
        assert await deferred.get(fail=False) is None, 'deferred message remained after replay'
        print(json.dumps({'old_parked':4,'fresh_retained':2,'replay_without_consumers':0,'replayed':4,'byte_preservation':True,'namespace':name}))
    finally:
        for suffix in ('','.deferred'):
            queue=await channel.get_queue(name+suffix)
            await queue.delete(if_unused=False,if_empty=False)
        await connection.close()

if __name__=='__main__':
    asyncio.run(main())
