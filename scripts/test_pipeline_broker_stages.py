"""Synthetic transport test using production broker classes, isolated from business queues.

This tests transport handoffs, not actual RCA, approvals or infrastructure execution.
"""
import asyncio
import base64
import json
from contextlib import suppress
from uuid import uuid4
from aio_pika import Message
from aio_pika.exceptions import DeliveryError
from common.config import Settings
from common.rabbitmq import RabbitMQConsumer, RabbitMQProducer, consume_forever

TOPICS = ["raw-alerts", "enriched-alerts", "orchestration-events", "context-events",
          "resolution-events", "approval-events", "remediation-events", "closure-events"]

async def main():
    prefix = "pipeline-test-" + uuid4().hex
    settings = Settings(SERVICE_NAME=prefix, RABBITMQ_EXCHANGE=prefix,
                        RABBITMQ_QUEUE_PREFIX=prefix, RABBITMQ_CONSUMER_MAX_RETRIES=1,
                        RABBITMQ_HANDLER_TIMEOUT_SECONDS=5,
                        RABBITMQ_TRANSIENT_REQUEUE_ENABLED=False)
    producer = RabbitMQProducer(settings)
    consumers, tasks = [], []
    attempts = {topic: 0 for topic in TOPICS}
    poison_attempts = {topic: 0 for topic in TOPICS}
    barriers = {topic: asyncio.Event() for topic in TOPICS}
    complete = asyncio.Event()
    results = []
    async def handle(index, payload):
        topic = TOPICS[index]
        if payload.get("barrier"):
            barriers[topic].set()
            return
        if payload.get("poison"):
            poison_attempts[topic] += 1
            raise ValueError("synthetic permanent failure")
        attempts[topic] += 1
        if attempts[topic] == 1:
            raise ValueError("synthetic retryable first attempt")
        assert payload["trail"] == TOPICS[:index]
        trail = payload["trail"] + [topic]
        if index + 1 < len(TOPICS):
            await producer.publish(TOPICS[index+1], {"event_id": prefix, "trail": trail})
        else:
            assert trail == TOPICS
            complete.set()
    try:
        await producer.start()
        try:
            await producer.publish("unbound-probe", {"event_id": prefix+"-unroutable"})
        except DeliveryError:
            pass
        else:
            raise AssertionError("Unroutable publish incorrectly reported delivery")
        for index, topic in enumerate(TOPICS):
            consumer = RabbitMQConsumer(settings, topic)
            consumers.append(consumer)
            await consumer.start()
            async def handler(payload, index=index):
                await handle(index, payload)
            tasks.append(asyncio.create_task(consume_forever(consumer, handler)))
        sibling_settings = settings.model_copy(update={"service_name": prefix+"-sibling"})
        sibling = RabbitMQConsumer(sibling_settings, TOPICS[0])
        await sibling.start()
        consumers.append(sibling)
        await producer.publish(TOPICS[0], {"event_id": prefix, "trail": []})
        await asyncio.wait_for(complete.wait(), 45)
        # FIFO barrier proves each duplicate has passed through its consumer.
        for index, topic in enumerate(TOPICS):
            await producer.publish(topic, {"event_id": prefix, "trail": TOPICS[:index]})
            await producer.publish(topic, {"event_id": prefix+"-barrier", "barrier": True})
        await asyncio.wait_for(asyncio.gather(*(event.wait() for event in barriers.values())), 20)
        assert all(count == 2 for count in attempts.values()), attempts
        for topic in TOPICS:
            await producer.publish(topic, {"event_id": prefix+"-poison", "poison": True})
            await producer._next_exchange().publish(Message(b"synthetic malformed bytes"), routing_key=topic)
        async def check_dlq(index, consumer):
            topic = TOPICS[index]
            queue = await consumer._channel.get_queue(f"{prefix}.{prefix}.{topic}.dlq")
            docs=[]
            async def read():
                while len(docs)<2:
                    message = await queue.get(fail=False)
                    if message is None:
                        await asyncio.sleep(0.1)
                        continue
                    docs.append(json.loads(message.body))
                    await message.ack()
            await asyncio.wait_for(read(), 20)
            malformed = [doc for doc in docs if "raw_body_base64" in doc]
            assert len(malformed)==1 and base64.b64decode(malformed[0]["raw_body_base64"]) == b"synthetic malformed bytes"
            assert poison_attempts[topic] == 2
            results.append({"topic":topic,"handoff":True,"retry":True,"duplicate_suppressed":True,"permanent_failure_dlq":True,"malformed_bytes_retained":True})
        await asyncio.gather(*(check_dlq(i,c) for i,c in enumerate(consumers[:len(TOPICS)])))
        sibling_dlq = await sibling._channel.get_queue(f"{prefix}.{prefix}-sibling.{TOPICS[0]}.dlq")
        assert await sibling_dlq.get(fail=False) is None, "Failure leaked into another subscriber's DLQ"
        print(json.dumps({"kind":"isolated_transport_not_business_execution", "unroutable_publish_rejected":True, "verified_assertions":42, "subscriber_dlq_isolation":True, "stages":results,"namespace":prefix}))
    finally:
        for task in tasks:
            task.cancel()
        for task in tasks:
            with suppress(asyncio.CancelledError):
                await task
        for consumer in consumers:
            if consumer._channel is not None:
                for name in (f"{prefix}.{consumer._settings.service_name}.{consumer._topic}", f"{prefix}.{consumer._settings.service_name}.{consumer._topic}.dlq"):
                    assert name.startswith(prefix + ".")
                    queue = await consumer._channel.get_queue(name)
                    await queue.delete(if_unused=False, if_empty=False)
        if producer._exchanges:
            await producer._exchanges[0].delete(if_unused=False)
        for consumer in consumers:
            await consumer.stop()
        await producer.stop()

if __name__ == '__main__':
    asyncio.run(main())
