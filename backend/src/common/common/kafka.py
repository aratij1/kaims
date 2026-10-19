from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator, Awaitable, Callable
from datetime import datetime, timezone
from typing import Any, TypeVar

from aiokafka import AIOKafkaConsumer, AIOKafkaProducer
from pydantic import BaseModel

from common.config import Settings
from common.alert_processing_budget import run_handler
from common.logging import get_logger
from common.message_processing import ProcessedMessageCache, extract_message_identity, processing_cancelled
from common.resilience import CircuitBreaker, CircuitOpenError, retry_async

logger = get_logger(__name__)
T = TypeVar("T", bound=BaseModel)


def normalize_payload(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    if isinstance(value, dict):
        return {key: normalize_payload(item) for key, item in value.items()}
    if isinstance(value, list):
        return [normalize_payload(item) for item in value]
    return value


class KafkaProducer:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._producer: AIOKafkaProducer | None = None
        # retry_async below already retries a transient send failure; this
        # breaker additionally stops retrying-and-failing on every publish
        # during a sustained broker outage, so callers fail fast instead of
        # eating the full retry backoff on every message.
        self._publish_breaker = CircuitBreaker()

    async def start(self) -> None:
        if not self._settings.kafka_enabled:
            return
        last_error: Exception | None = None
        for attempt in range(1, self._settings.kafka_startup_attempts + 1):
            producer = AIOKafkaProducer(
                bootstrap_servers=self._settings.kafka_bootstrap_servers,
                value_serializer=lambda value: json.dumps(value, default=str).encode("utf-8"),
            )
            try:
                await producer.start()
                self._producer = producer
                logger.info("connected kafka producer", extra={"bootstrap": self._settings.kafka_bootstrap_servers})
                return
            except Exception as exc:
                last_error = exc
                await producer.stop()
                logger.warning(
                    "kafka producer not ready; retrying",
                    extra={
                        "attempt": attempt,
                        "attempts": self._settings.kafka_startup_attempts,
                        "bootstrap": self._settings.kafka_bootstrap_servers,
                        "error": str(exc),
                    },
                )
                await asyncio.sleep(self._settings.kafka_startup_retry_seconds)
        assert last_error is not None
        raise last_error

    async def stop(self) -> None:
        if self._producer is not None:
            await self._producer.stop()
        self._producer = None

    async def publish(self, topic: str, event: BaseModel | dict[str, Any], key: str | None = None) -> None:
        payload = normalize_payload(event)
        if self._producer is None:
            raise RuntimeError("Kafka producer is not started; event was not delivered")
        if not self._publish_breaker.allow():
            raise CircuitOpenError("kafka publish circuit breaker open: broker appears unreachable")

        async def send() -> None:
            assert self._producer is not None
            await self._producer.send_and_wait(topic, payload, key=key.encode("utf-8") if key else None)

        try:
            await retry_async(send)
        except Exception:
            self._publish_breaker.record_failure()
            raise
        else:
            self._publish_breaker.record_success()


class KafkaConsumer:
    def __init__(self, settings: Settings, topic: str) -> None:
        self._settings = settings
        self._topic = topic
        self._consumer: AIOKafkaConsumer | None = None

    async def start(self) -> None:
        if not self._settings.kafka_enabled:
            return
        last_error: Exception | None = None
        for attempt in range(1, self._settings.kafka_startup_attempts + 1):
            consumer = AIOKafkaConsumer(
                self._topic,
                bootstrap_servers=self._settings.kafka_bootstrap_servers,
                # Isolate each service+topic into its own consumer group, mirroring
                # RabbitMQ's `{prefix}.{service_name}.{topic}` queue naming
                # (common/rabbitmq.py). Without this, every service shared the
                # literal group id "kaiops" and any one member joining/leaving
                # triggered a group-wide rebalance for everyone, regardless of
                # which topic they actually cared about.
                group_id=f"{self._settings.kafka_group_id}.{self._settings.service_name}.{self._topic}",
                value_deserializer=lambda value: json.loads(value.decode("utf-8")),
                enable_auto_commit=False,
                session_timeout_ms=self._settings.kafka_session_timeout_ms,
                heartbeat_interval_ms=self._settings.kafka_heartbeat_interval_ms,
                max_poll_interval_ms=self._settings.kafka_max_poll_interval_ms,
            )
            try:
                await consumer.start()
                self._consumer = consumer
                logger.info(
                    "connected kafka consumer",
                    extra={"topic": self._topic, "bootstrap": self._settings.kafka_bootstrap_servers},
                )
                return
            except Exception as exc:
                last_error = exc
                await consumer.stop()
                logger.warning(
                    "kafka consumer not ready; retrying",
                    extra={
                        "topic": self._topic,
                        "attempt": attempt,
                        "attempts": self._settings.kafka_startup_attempts,
                        "bootstrap": self._settings.kafka_bootstrap_servers,
                        "error": str(exc),
                    },
                )
                await asyncio.sleep(self._settings.kafka_startup_retry_seconds)
        assert last_error is not None
        raise last_error

    async def stop(self) -> None:
        if self._consumer is not None:
            await self._consumer.stop()

    async def messages(self) -> AsyncIterator[dict[str, Any]]:
        if self._consumer is None:
            while True:
                await asyncio.sleep(3600)
        else:
            async for message in self._consumer:
                payload = message.value
                if isinstance(payload, dict):
                    yield payload


async def consume_forever(
    consumer: KafkaConsumer,
    handler: Callable[[dict[str, Any]], Awaitable[None]],
) -> None:
    await consumer.start()
    if consumer._consumer is None:
        while True:
            await asyncio.sleep(3600)

    dlq_producer = KafkaProducer(consumer._settings)
    try:
        await dlq_producer.start()
    except Exception:
        logger.exception("failed to initialize kafka dlq producer", extra={"topic": consumer._topic})

    processed_cache = ProcessedMessageCache()

    try:
        async for record in consumer._consumer:
            payload = record.value if isinstance(record.value, dict) else {}
            if await processing_cancelled(consumer._settings, payload):
                logger.warning("cancelled alert removed from kafka processing", extra={"topic": consumer._topic})
                await consumer._consumer.commit()
                continue
            identity = extract_message_identity(payload)
            if processed_cache.contains(identity):
                logger.info("skipping duplicate kafka message", extra={"topic": consumer._topic, "message_identity": identity})
                if consumer._consumer is not None:
                    await consumer._consumer.commit()
                continue

            attempts = 0
            max_retries = max(0, int(consumer._settings.kafka_consumer_max_retries or 0))
            should_commit = False
            try:
                while attempts <= max_retries:
                    try:
                        await run_handler(consumer._settings, consumer._topic, handler, payload)
                        processed_cache.mark(identity)
                        should_commit = True
                        break
                    except Exception:
                        attempts += 1
                        if attempts > max_retries:
                            raise
                        await asyncio.sleep(min(2**attempts, 5))
            except Exception as exc:
                logger.exception(
                    "failed to process kafka message",
                    extra={"topic": consumer._topic, "attempts": attempts, "max_retries": max_retries},
                )
                if dlq_producer._producer is not None:
                    dlq_topic = f"{consumer._topic}{consumer._settings.kafka_dlq_suffix}"
                    try:
                        await dlq_producer.publish(
                            dlq_topic,
                            {
                                "failed_topic": consumer._topic,
                                "payload": payload,
                                "error": str(exc),
                                "attempts": attempts,
                                "failed_at": datetime.now(timezone.utc).isoformat(),
                            },
                        )
                        processed_cache.mark(identity)
                        should_commit = True
                    except Exception:
                        logger.exception("failed to publish kafka dlq message", extra={"topic": dlq_topic})
            finally:
                if should_commit and consumer._consumer is not None:
                    await consumer._consumer.commit()
    finally:
        await dlq_producer.stop()
