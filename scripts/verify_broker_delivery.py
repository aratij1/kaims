"""Exercise real broker delivery on an isolated exchange; never publish incident events."""
import asyncio
import base64
import json
from contextlib import suppress
from uuid import uuid4

from aio_pika import Message
from common.config import Settings
from common.rabbitmq import RabbitMQConsumer, RabbitMQProducer, consume_forever


async def main():
    prefix = "architecture-review-" + uuid4().hex
    settings = Settings(SERVICE_NAME=prefix, RABBITMQ_EXCHANGE=prefix,
                        RABBITMQ_QUEUE_PREFIX=prefix, RABBITMQ_CONSUMER_MAX_RETRIES=1,
                        RABBITMQ_HANDLER_TIMEOUT_SECONDS=5)
    producer = RabbitMQProducer(settings)
    try:
        await producer.publish("delivery", {"event_id": "not-started"})
        raise AssertionError("unstarted publisher incorrectly reported success")
    except RuntimeError:
        pass
    consumer = RabbitMQConsumer(settings, "delivery")
    task = None
    calls = 0
    completed = asyncio.Event()
    async def handler(payload):
        nonlocal calls
        assert payload["event_id"] == prefix
        calls += 1
        if calls == 1:
            raise RuntimeError("isolated retry test")
        completed.set()
    try:
        await producer.start()
        await consumer.start()
        task = asyncio.create_task(consume_forever(consumer, handler))
        await producer.publish("delivery", {"event_id": prefix})
        await asyncio.wait_for(completed.wait(), 15)
        malformed = b"isolated malformed verification message"
        await producer._next_exchange().publish(Message(malformed), routing_key="delivery")
        dlq_name = f"{prefix}.{prefix}.delivery.dlq"
        dlq = await consumer._channel.get_queue(dlq_name)
        for _ in range(100):
            message = await dlq.get(fail=False)
            if message is not None:
                document = json.loads(message.body)
                assert base64.b64decode(document["raw_body_base64"]) == malformed
                await message.ack()
                break
            await asyncio.sleep(0.1)
        else:
            raise AssertionError("malformed message did not reach quarantine")
        assert calls == 2
        print(json.dumps({"unstarted_publish_rejected": True, "handler_retry_delivered": True,
                          "malformed_bytes_quarantined": True, "isolated_exchange": prefix}))
    finally:
        if task is not None:
            task.cancel()
            with suppress(asyncio.CancelledError):
                await task
        if consumer._channel is not None:
            for name in (f"{prefix}.{prefix}.delivery", f"{prefix}.{prefix}.delivery.dlq"):
                assert name.startswith("architecture-review-") and prefix in name
                queue = await consumer._channel.get_queue(name)
                await queue.delete(if_unused=False, if_empty=False)
            await consumer._exchange.delete(if_unused=False)
        await consumer.stop()
        await producer.stop()


if __name__ == "__main__":
    asyncio.run(main())
