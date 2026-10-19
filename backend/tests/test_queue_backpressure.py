from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4
import json
import pytest
from common.queue_backpressure import old_enough, transfer, rebalance
from common.config import Settings
from common.database import ContextEnrichmentJobRecord
from common.repository import ContextEnrichmentRepository


def test_only_attributable_old_messages_are_deferred():
    now = datetime.now(timezone.utc)
    assert old_enough(json.dumps({'produced_at': (now-timedelta(minutes=10)).isoformat()}).encode(), 300, now)
    for body in (b'[]', b'null', b'bad', b'{}', b'{"produced_at":"2020-01-01"}', json.dumps({'produced_at':now.isoformat()}).encode()):
        assert not old_enough(body, 300, now)


def test_thresholds_fail_at_configuration_load():
    with pytest.raises(ValueError, match='must be below'):
        Settings(QUEUE_BACKLOG_LOW=20, QUEUE_BACKLOG_HIGH=10)


async def test_failed_parking_never_acknowledges_original():
    message = MagicMock(body=b'{}', headers={}, priority=0)
    for key in ('content_type','content_encoding','correlation_id','message_id','timestamp','type','app_id','reply_to'):
        setattr(message,key,None)
    message.ack=AsyncMock()
    channel=MagicMock()
    channel.default_exchange.publish=AsyncMock(side_effect=RuntimeError('unavailable'))
    with pytest.raises(RuntimeError):
        await transfer(channel,message,'test.deferred',deferred=True)
    message.ack.assert_not_awaited()


async def test_low_queue_with_no_workers_does_not_replay(monkeypatch):
    from common import queue_backpressure as module
    active=MagicMock()
    active.declaration_result.message_count=0
    active.declaration_result.consumer_count=0
    deferred=MagicMock(get=AsyncMock())
    deferred.declaration_result.message_count=10
    channel=MagicMock(set_qos=AsyncMock(),declare_queue=AsyncMock(side_effect=[MagicMock(),active,deferred]))
    connection=MagicMock(channel=AsyncMock(return_value=channel),close=AsyncMock())
    monkeypatch.setattr(module.aio_pika,'connect_robust',AsyncMock(return_value=connection))
    result=await rebalance('amqp://test','test.q')
    assert result['replayed']==0
    deferred.get.assert_not_awaited()
    connection.close.assert_awaited_once()


async def test_new_work_cannot_starve_retries_or_expired_leases(sqlite_session_factory):
    now=datetime.now(timezone.utc)
    incident=uuid4()
    async with sqlite_session_factory() as session:
        for index,status in enumerate(['scheduled']*12+['retry','collecting']):
            session.add(ContextEnrichmentJobRecord(
                job_id=uuid4(),tenant_id='test',incident_id=incident,
                requirement_id=uuid4(),connector_id='test',idempotency_key=str(uuid4()),
                query_payload={},observation_start=now-timedelta(hours=1),observation_end=now,
                status=status,available_at=now-timedelta(minutes=2),attempt_count=0,
                lease_owner='crashed' if status=='collecting' else None,
                lease_expires_at=now-timedelta(seconds=1) if status=='collecting' else None))
        await session.commit()
        jobs=await ContextEnrichmentRepository(session).claim_context_enrichment_jobs(worker_id='new-worker',limit=5)
        ids=[job['job_id'] for job in jobs]
        assert len(ids)==len(set(ids))==5
        # The leased rows retain their old lease owner only in the database
        # before claim; inspect remaining states to prove both lanes were taken.
        from sqlalchemy import select,func
        remaining=await session.scalar(select(func.count()).select_from(ContextEnrichmentJobRecord).where(ContextEnrichmentJobRecord.status=='retry'))
        assert remaining==0
        assert all(job['lease_owner']=='new-worker' for job in jobs)
        crashed=await session.scalar(select(func.count()).select_from(ContextEnrichmentJobRecord).where(ContextEnrichmentJobRecord.lease_owner=='crashed'))
        assert crashed==0
        assert sum(1 for job in jobs if job['attempt_count']==1)==5


async def test_hung_collection_releases_before_lease_and_does_not_block_siblings():
    import asyncio
    from common.enrichment_scheduler import run_leased_collection_batch
    completed=[]
    released=[]
    async def process(job):
        if job=='hung': await asyncio.Event().wait()
        completed.append(job)
    async def timeout(job): released.append(job)
    await run_leased_collection_batch(['hung','healthy'],process,timeout,timeout_seconds=0.02)
    assert completed==['healthy']
    assert released==['hung']


async def test_failed_batch_joins_siblings_before_starting_another():
    import asyncio
    from common.enrichment_scheduler import run_leased_collection_batch
    completed=[]
    async def process(job):
        if job=='failed': raise ValueError('synthetic failure')
        await asyncio.sleep(0.01)
        completed.append(job)
    with pytest.raises(ValueError):
        await run_leased_collection_batch(['failed','healthy'],process,AsyncMock())
    assert completed==['healthy']


async def test_failed_transfer_requeues_source_and_closes_controller(monkeypatch):
    from common import queue_backpressure as module
    message=MagicMock(body=json.dumps({'produced_at':'2020-01-01T00:00:00+00:00'}).encode(),processed=False)
    message.reject=AsyncMock()
    active=MagicMock(get=AsyncMock(return_value=message))
    active.declaration_result.message_count=2
    parked=MagicMock(name='parked')
    parked.declaration_result.message_count=0
    channel=MagicMock(set_qos=AsyncMock(),declare_queue=AsyncMock(side_effect=[MagicMock(),active,parked]))
    connection=MagicMock(channel=AsyncMock(return_value=channel),close=AsyncMock())
    monkeypatch.setattr(module.aio_pika,'connect_robust',AsyncMock(return_value=connection))
    monkeypatch.setattr(module,'transfer',AsyncMock(side_effect=RuntimeError('publish failed')))
    with pytest.raises(RuntimeError,match='publish failed'):
        await module.rebalance('amqp://test','test.q',high=2,low=0,batch=1)
    message.reject.assert_awaited_once_with(requeue=True)
    connection.close.assert_awaited_once()


@pytest.mark.parametrize('enabled,provider,secondary,expected', [
    (True,'rabbitmq',False,True), (True,'kafka',True,True),
    (True,'kafka',False,False), (False,'rabbitmq',True,False),
])
def test_controller_starts_for_primary_rabbitmq_without_secondary_publisher(enabled,provider,secondary,expected):
    from common.queue_backpressure import controller_enabled
    assert controller_enabled(enabled,provider,secondary) is expected


@pytest.mark.parametrize('depth,consumers,expected', [(16,2,1),(10,2,10),(49,2,1),(16,0,0)])
async def test_deferred_work_gets_a_bounded_turn_above_low_watermark(monkeypatch,depth,consumers,expected):
    from common import queue_backpressure as module
    active=MagicMock()
    active.name='test.q'
    active.declaration_result.message_count=depth
    active.declaration_result.consumer_count=consumers
    deferred=MagicMock(get=AsyncMock())
    deferred.declaration_result.message_count=120
    channel=MagicMock(set_qos=AsyncMock(),declare_queue=AsyncMock(side_effect=[MagicMock(),active,deferred]))
    connection=MagicMock(channel=AsyncMock(return_value=channel),close=AsyncMock())
    monkeypatch.setattr(module.aio_pika,'connect_robust',AsyncMock(return_value=connection))
    publish=AsyncMock()
    monkeypatch.setattr(module,'transfer',publish)
    result=await rebalance('amqp://test','test.q')
    assert result['replayed']==expected
    assert publish.await_count==expected
    assert depth+result['replayed']<=50


async def test_replayed_delivery_is_not_parked_again_when_load_returns(monkeypatch):
    from common import queue_backpressure as module
    message=MagicMock(body=b'{"produced_at":"2020-01-01T00:00:00+00:00"}',headers={'x-kaims-backlog-state':'replayed'},processed=False)
    message.reject=AsyncMock()
    active=MagicMock(get=AsyncMock(return_value=message))
    active.declaration_result.message_count=50
    deferred=MagicMock()
    deferred.declaration_result.message_count=120
    channel=MagicMock(set_qos=AsyncMock(),declare_queue=AsyncMock(side_effect=[MagicMock(),active,deferred]))
    connection=MagicMock(channel=AsyncMock(return_value=channel),close=AsyncMock())
    monkeypatch.setattr(module.aio_pika,'connect_robust',AsyncMock(return_value=connection))
    publish=AsyncMock()
    monkeypatch.setattr(module,'transfer',publish)
    result=await rebalance('amqp://test','test.q',batch=1)
    assert result['parked']==0
    publish.assert_not_awaited()
    message.reject.assert_awaited_once_with(requeue=True)
