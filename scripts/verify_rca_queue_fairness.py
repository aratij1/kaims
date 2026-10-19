"""Isolated real-broker regression for deferred starvation and repeated parking."""
import asyncio,json
from datetime import datetime,timezone,timedelta
from uuid import uuid4
import aio_pika
from common.config import Settings
from common.queue_backpressure import rebalance

async def main():
    url=Settings().rabbitmq_url
    name='rca-fairness-test-'+uuid4().hex
    conn=await aio_pika.connect_robust(url)
    ch=await conn.channel(publisher_confirms=True,on_return_raises=True)
    worker=await conn.channel();await worker.set_qos(prefetch_count=1)
    active=await ch.declare_queue(name,durable=True)
    parked=await ch.declare_queue(name+'.deferred',durable=True)
    held=[];ready=asyncio.Event()
    async def hold(message):
        held.append(message);ready.set()
    queue=await worker.get_queue(name)
    tag=await queue.consume(hold)
    try:
        await ch.default_exchange.publish(aio_pika.Message(body=b'guard'),routing_key=name)
        await asyncio.wait_for(ready.wait(),5)
        fresh=json.dumps({'produced_at':datetime.now(timezone.utc).isoformat()}).encode()
        old=json.dumps({'produced_at':(datetime.now(timezone.utc)-timedelta(days=1)).isoformat()}).encode()
        for _ in range(3):await ch.default_exchange.publish(aio_pika.Message(body=fresh),routing_key=name)
        await ch.default_exchange.publish(aio_pika.Message(body=old,headers={'x-kaims-backlog-state':'deferred'}),routing_key=parked.name)
        outcome=await rebalance(url,name,high=5,low=2,batch=2)
        assert outcome['active_ready']==3 and outcome['replayed']==1,outcome
        for _ in range(3):
            msg=await active.get();assert msg.body==fresh;await msg.ack()
        for _ in range(4):await ch.default_exchange.publish(aio_pika.Message(body=fresh),routing_key=name)
        repeat=await rebalance(url,name,high=5,low=2,batch=1)
        assert repeat['active_ready']==5 and repeat['parked']==0,repeat
        msg=await active.get();assert msg.body==old and msg.headers['x-kaims-backlog-state']=='replayed';await msg.ack()
        print(json.dumps({'fair_replay_above_low':True,'no_reparking':True,'body_preserved':True,'namespace':name}))
    finally:
        await queue.cancel(tag)
        for msg in held:await msg.ack()
        await active.delete(if_unused=False,if_empty=False)
        await parked.delete(if_unused=False,if_empty=False)
        await conn.close()

if __name__=='__main__':asyncio.run(main())
