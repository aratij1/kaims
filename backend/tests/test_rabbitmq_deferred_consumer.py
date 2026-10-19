from unittest.mock import AsyncMock,MagicMock
import pytest
from common.config import Settings
from common.rabbitmq import RabbitMQConsumer

@pytest.mark.parametrize('deferred',[False,True])
async def test_recovery_lane_does_not_duplicate_fresh_events_or_dead_letters(monkeypatch,deferred):
    from common import rabbitmq as module
    active=MagicMock(bind=AsyncMock());dlq=MagicMock(bind=AsyncMock())
    ch=MagicMock(set_qos=AsyncMock(),declare_exchange=AsyncMock(),declare_queue=AsyncMock(side_effect=[active,dlq]))
    connection=MagicMock(channel=AsyncMock(return_value=ch),close=AsyncMock())
    monkeypatch.setattr(module.aio_pika,'connect_robust',AsyncMock(return_value=connection))
    settings=Settings(SERVICE_NAME='resolution-agent',RABBITMQ_QUEUE_PREFIX='test',RABBITMQ_CONSUMER_PREFETCH_COUNT=2)
    consumer=RabbitMQConsumer(settings,'context-events',deferred=deferred)
    await consumer.start()
    names=[call.args[0] for call in ch.declare_queue.await_args_list]
    assert names==['test.resolution-agent.context-events'+('.deferred' if deferred else ''),'test.resolution-agent.context-events.dlq']
    ch.set_qos.assert_awaited_once_with(prefetch_count=1 if deferred else 2)
    assert active.bind.await_count==(0 if deferred else 1)
    dlq.bind.assert_awaited_once_with(consumer._exchange, routing_key="test.resolution-agent.context-events.dlq")
    await consumer.stop()
