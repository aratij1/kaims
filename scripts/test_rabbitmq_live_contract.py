"""Run isolated real-broker delivery checks inside an application container.

Uses its configured broker, but a unique exchange and queue prefix. Never
consumes application queues. Deletes only resources created by this run.
"""
import asyncio
import base64
import json
from uuid import uuid4

from aio_pika import Message
from common.config import get_settings
from common.rabbitmq import RabbitMQConsumer, RabbitMQProducer, consume_forever


async def main():
    run_id = "transport-review-" + uuid4().hex
    settings = get_settings().model_copy(update={
        "service_name": run_id, "rabbitmq_exchange": run_id,
        "rabbitmq_queue_prefix": run_id, "alert_processing_limit_enabled": False,
        "rabbitmq_transient_requeue_enabled": False, "rabbitmq_consumer_max_retries": 1,
        "rabbitmq_handler_timeout_seconds": 1.0, "rabbitmq_consumer_prefetch_count": 1,
    })
    producer = RabbitMQProducer(settings)
    consumers, tasks, results = [], [], []

    async def setup(topic, handler, overrides=None):
        cfg = settings.model_copy(update=overrides or {})
        consumer = RabbitMQConsumer(cfg, topic)
        await consumer.start()
        consumers.append(consumer)
        task = asyncio.create_task(consume_forever(consumer, handler))
        tasks.append(task)
        return consumer

    async def dlq(consumer):
        queue = await consumer._channel.get_queue(consumer._dlq_routing_key)
        for _ in range(120):
            msg = await queue.get(fail=False)
            if msg:
                result = json.loads(msg.body)
                await msg.ack()  # exclusively this run's test message
                return result
            await asyncio.sleep(0.05)
        raise AssertionError("Test DLQ delivery did not arrive")

    async def wait(event):
        await asyncio.wait_for(event.wait(), timeout=10)

    try:
        await producer.start()
        received = []
        happy = asyncio.Event()
        async def handle(payload):
            received.append(payload["event_id"])
            happy.set()
        c = await setup("success", handle)
        await producer.publish("success", {"event_id": "same-event"})
        await producer.publish("success", {"event_id": "same-event"})
        await wait(happy)
        await asyncio.sleep(0.3)
        assert received == ["same-event"], received
        results.append("successful delivery and duplicate suppression")

        retried = asyncio.Event()
        attempts = 0
        async def retry(payload):
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                raise ValueError("isolated recoverable example")
            retried.set()
        await setup("retry", retry)
        await producer.publish("retry", {"event_id": "retry-event"})
        await wait(retried)
        assert attempts == 2
        results.append("failed attempt retried successfully")

        async def failure(payload):
            raise ValueError("isolated terminal example")
        c = await setup("terminal", failure)
        await producer.publish("terminal", {"event_id": "failure-event"})
        dead = await dlq(c)
        assert dead["attempts"] == 2 and dead["failure_type"] == "builtins.ValueError"
        assert dead["message_identity"] == "failure-event"
        results.append("terminal failure durably quarantined with diagnostic type")

        async def hung(payload):
            await asyncio.Event().wait()
        c = await setup("timeout", hung, {"rabbitmq_handler_timeout_seconds": 0.05,
                                        "rabbitmq_consumer_max_retries": 0})
        await producer.publish("timeout", {"event_id": "hung-event"})
        assert (await dlq(c))["failure_type"] == "builtins.TimeoutError"
        results.append("hung handler bounded and quarantined")

        transient_calls = 0
        async def persistent_transient(payload):
            nonlocal transient_calls
            transient_calls += 1
            raise TimeoutError("isolated persistent dependency timeout")
        c = await setup("persistent-transient", persistent_transient, {
            "rabbitmq_transient_requeue_enabled": True,
            "rabbitmq_transient_max_requeues": 1, "rabbitmq_consumer_max_retries": 0,
        })
        dead = None
        await producer.publish("persistent-transient", {"event_id": "persistent-event"})
        dead = await dlq(c)
        assert transient_calls == 2 and dead["failure_type"] == "builtins.TimeoutError"
        results.append("persistent transient failure has a durable bounded redelivery budget")

        c = await setup("malformed", handle)
        await producer._next_exchange().publish(Message(b"invalid-json"), routing_key="malformed")
        dead = await dlq(c)
        assert base64.b64decode(dead["raw_body_base64"]) == b"invalid-json"
        results.append("malformed input preserved in quarantine")

        delivered = asyncio.Event()
        async def other_subscriber(payload):
            delivered.set()
        failed = await setup("fanout", failure)
        healthy = await setup("fanout", other_subscriber, {"service_name": run_id + "-other"})
        await producer.publish("fanout", {"event_id": "fanout-event"})
        await wait(delivered)
        await dlq(failed)
        other_queue = await healthy._channel.get_queue(healthy._dlq_routing_key)
        assert await other_queue.get(fail=False) is None
        results.append("subscriber failure does not contaminate other subscriber DLQ")

        try:
            await producer.publish("no-subscriber", {"event_id": "unroutable-event"})
        except Exception as exc:
            assert type(exc).__name__ in {"DeliveryError", "PublishError"}, type(exc).__name__
        else:
            raise AssertionError("Unroutable publish falsely reported success")
        results.append("unroutable publish rejected")
        print(json.dumps({"run_id": run_id, "passed": results, "count": len(results)}))
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        # Resource names come only from consumers created above. No pruning.
        for consumer in consumers:
            if consumer._channel:
                await consumer._queue.delete(if_unused=False, if_empty=False)
                queue = await consumer._channel.get_queue(consumer._dlq_routing_key)
                await queue.delete(if_unused=False, if_empty=False)
            await consumer.stop()
        if producer._channels:
            await producer._channels[0].exchange_delete(run_id)
        await producer.stop()


if __name__ == "__main__":
    asyncio.run(main())
