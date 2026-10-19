from __future__ import annotations

import asyncio
import base64
import json
from collections.abc import AsyncIterator, Awaitable, Callable
from datetime import datetime, timezone
from typing import Any

import aio_pika
from aio_pika import DeliveryMode, ExchangeType, Message, RobustChannel, RobustConnection, RobustExchange, RobustQueue

from common.config import Settings
from common.alert_processing_budget import run_handler
from common.errors import sanitize_handler_failure_text
from common.logging import get_logger
from common.message_processing import ProcessedMessageCache, extract_message_identity, processing_cancelled
from common.resilience import CircuitBreaker, CircuitOpenError
from common.telemetry import DEAD_LETTER_EVENTS, QUEUE_AGE, QUEUE_DEPTH
from opentelemetry import propagate, trace

logger = get_logger(__name__)

# aio_pika's RobustConnection/RobustExchange retry a broken broker connection
# internally rather than raising promptly, so a publish() call can stall for a
# long time during an outage instead of failing fast. Bound each publish
# attempt and count timeouts/errors toward the breaker so a sustained outage
# fails new publishes immediately instead of piling up stalled callers.
_PUBLISH_TIMEOUT_SECONDS = 10.0


def _is_transient_handler_error(error: str) -> bool:
    normalized = str(error or "").strip().lower()
    return any(
        marker in normalized
        for marker in (
            "can't connect to mysql server",
            "connection refused",
            "producer is not started",
            "publisher is not started",
            "connection reset",
            "connection timed out",
            "temporary failure in name resolution",
            "name or service not known",
            "server has gone away",
            "lost connection to mysql",
            "circuit breaker open",
            "tool circuit open",
            "timeout",
            "timed out",
        )
    )


def normalize_payload(value: Any) -> Any:
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json")
    if isinstance(value, dict):
        return {key: normalize_payload(item) for key, item in value.items()}
    if isinstance(value, list):
        return [normalize_payload(item) for item in value]
    return value


class RabbitMQProducer:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._connection: RobustConnection | None = None
        self._channels: list[RobustChannel] = []
        self._exchanges: list[RobustExchange] = []
        self._next_exchange_index = 0
        self._publish_breaker = CircuitBreaker()

    async def start(self) -> None:
        if self._connection is not None:
            return
        attempts = max(1, int(self._settings.rabbitmq_startup_attempts or 1))
        retry_seconds = max(0.1, float(self._settings.rabbitmq_startup_retry_seconds or 0.1))
        pool_size = max(1, int(self._settings.rabbitmq_publisher_channel_pool_size or 1))
        for attempt in range(1, attempts + 1):
            try:
                self._connection = await aio_pika.connect_robust(self._settings.rabbitmq_url)
                for _ in range(pool_size):
                    channel = await self._connection.channel(publisher_confirms=True, on_return_raises=True)
                    exchange = await channel.declare_exchange(
                        self._settings.rabbitmq_exchange,
                        ExchangeType.TOPIC,
                        durable=True,
                    )
                    self._channels.append(channel)
                    self._exchanges.append(exchange)
                logger.info(
                    "connected rabbitmq producer",
                    extra={
                        "exchange": self._settings.rabbitmq_exchange,
                        "channel_pool_size": pool_size,
                    },
                )
                return
            except Exception:
                await self.stop()
                logger.warning(
                    "rabbitmq producer connect retry",
                    extra={
                        "attempt": attempt,
                        "max_attempts": attempts,
                        "retry_seconds": retry_seconds,
                    },
                    exc_info=True,
                )
                if attempt < attempts:
                    await asyncio.sleep(retry_seconds)
        raise RuntimeError("rabbitmq producer failed to connect after retries")

    async def stop(self) -> None:
        if self._connection is not None:
            await self._connection.close()
        self._connection = None
        self._channels = []
        self._exchanges = []
        self._next_exchange_index = 0

    def _next_exchange(self) -> RobustExchange:
        # Plain round-robin: a single int increment between awaits is not
        # preemptible in one asyncio event loop, so no lock is needed here.
        exchange = self._exchanges[self._next_exchange_index % len(self._exchanges)]
        self._next_exchange_index += 1
        return exchange

    async def publish(self, topic: str, event: dict[str, Any] | Any, key: str | None = None) -> None:
        if not self._exchanges:
            raise RuntimeError("RabbitMQ producer is not started; event was not delivered")
        if not self._publish_breaker.allow():
            raise CircuitOpenError("rabbitmq publish circuit breaker open: broker appears unreachable")
        payload = normalize_payload(event)
        envelope = {
            "topic": topic,
            "key": key,
            "payload": payload,
            "produced_at": datetime.now(timezone.utc).isoformat(),
        }
        body = json.dumps(envelope, default=str).encode("utf-8")
        routing_key = topic
        trace_headers: dict[str, str] = {}
        propagate.inject(trace_headers)
        try:
            await asyncio.wait_for(
                self._next_exchange().publish(
                    Message(
                        body,
                        content_type="application/json",
                        delivery_mode=DeliveryMode.PERSISTENT,
                        type=topic,
                        app_id="kaiops",
                        headers=trace_headers,
                    ),
                    routing_key=routing_key,
                ),
                timeout=_PUBLISH_TIMEOUT_SECONDS,
            )
        except Exception:
            self._publish_breaker.record_failure()
            raise
        else:
            self._publish_breaker.record_success()


class RabbitMQConsumer:
    def __init__(self, settings: Settings, topic: str, *, deferred: bool = False) -> None:
        self._settings = settings
        self._topic = topic
        self._deferred = deferred
        # Expose an observed zero before the first failure. Otherwise a healthy
        # restarted consumer has no failure series and cannot be verified.
        DEAD_LETTER_EVENTS.labels("rabbitmq", topic, "handler_failed").inc(0)
        self._connection: RobustConnection | None = None
        self._channel: RobustChannel | None = None
        self._exchange: RobustExchange | None = None
        self._queue: RobustQueue | None = None
        self._dlq_routing_key: str | None = None

    async def start(self) -> None:
        if self._connection is not None:
            return
        attempts = max(1, int(self._settings.rabbitmq_startup_attempts or 1))
        retry_seconds = max(0.1, float(self._settings.rabbitmq_startup_retry_seconds or 0.1))
        for attempt in range(1, attempts + 1):
            try:
                self._connection = await aio_pika.connect_robust(self._settings.rabbitmq_url)
                self._channel = await self._connection.channel(publisher_confirms=True, on_return_raises=True)
                # Bound how many unacked messages the broker will push to this
                # consumer at once. Without this, a channel drop mid-backlog can
                # leave thousands of delivered-but-unacked messages that all fail
                # to nack together (a single ExceptionGroup with one sub-exception
                # per message), and total in-flight work per consumer is otherwise
                # unbounded.
                await self._channel.set_qos(prefetch_count=1 if self._deferred else self._settings.rabbitmq_consumer_prefetch_count)
                self._exchange = await self._channel.declare_exchange(
                    self._settings.rabbitmq_exchange,
                    ExchangeType.TOPIC,
                    durable=True,
                )
                base_queue_name = f"{self._settings.rabbitmq_queue_prefix}.{self._settings.service_name}.{self._topic}"
                queue_name = base_queue_name + (".deferred" if self._deferred else "")
                self._queue = await self._channel.declare_queue(queue_name, durable=True)
                declaration = getattr(self._queue, "declaration_result", None)
                if declaration is not None:
                    QUEUE_DEPTH.labels("rabbitmq", queue_name).set(float(getattr(declaration, "message_count", 0) or 0))
                if not self._deferred:
                    await self._queue.bind(self._exchange, routing_key=self._topic)
                # A topic can have several independent subscribers. A shared
                # topic.dlq route would fan one subscriber's failure into all
                # their dead-letter queues. Keep the durable queue name stable.
                self._dlq_routing_key = f"{base_queue_name}.dlq"
                dlq_queue_name = f"{base_queue_name}.dlq"
                dlq_queue = await self._channel.declare_queue(dlq_queue_name, durable=True)
                await dlq_queue.bind(self._exchange, routing_key=self._dlq_routing_key)
                logger.info(
                    "connected rabbitmq consumer",
                    extra={
                        "topic": self._topic,
                        "queue": queue_name,
                        "dlq_queue": dlq_queue_name,
                        "exchange": self._settings.rabbitmq_exchange,
                    },
                )
                return
            except Exception:
                await self.stop()
                logger.warning(
                    "rabbitmq consumer connect retry",
                    extra={
                        "topic": self._topic,
                        "attempt": attempt,
                        "max_attempts": attempts,
                        "retry_seconds": retry_seconds,
                    },
                    exc_info=True,
                )
                if attempt < attempts:
                    await asyncio.sleep(retry_seconds)
        raise RuntimeError(f"rabbitmq consumer failed to connect after retries for topic {self._topic}")

    async def stop(self) -> None:
        if self._connection is not None:
            await self._connection.close()
        self._connection = None
        self._channel = None
        self._exchange = None
        self._queue = None
        self._dlq_routing_key = None

    async def messages(self) -> AsyncIterator[dict[str, Any]]:
        if self._queue is None:
            while True:
                await asyncio.sleep(3600)
        else:
            async with self._queue.iterator() as iterator:
                async for message in iterator:
                    async with message.process(requeue=False):
                        try:
                            decoded = json.loads(message.body.decode("utf-8"))
                        except (UnicodeDecodeError, json.JSONDecodeError):
                            logger.warning("failed to decode rabbitmq message", extra={"topic": self._topic})
                            continue
                        payload = decoded.get("payload") if isinstance(decoded, dict) else None
                        if isinstance(payload, dict):
                            yield payload


async def _quarantine_invalid_message(consumer: RabbitMQConsumer, message: Any, reason: str) -> None:
    """Acknowledge malformed input only after its exact bytes are durably quarantined."""
    try:
        if consumer._exchange is None or not consumer._dlq_routing_key:
            raise RuntimeError("dead-letter exchange is unavailable")
        envelope = {
            "failed_topic": consumer._topic, "error": reason,
            "raw_body_base64": base64.b64encode(message.body).decode("ascii"),
            "failed_at": datetime.now(timezone.utc).isoformat(),
        }
        await asyncio.wait_for(consumer._exchange.publish(
            Message(json.dumps(envelope).encode("utf-8"), content_type="application/json",
                    delivery_mode=DeliveryMode.PERSISTENT, type=consumer._dlq_routing_key, app_id="kaiops"),
            routing_key=consumer._dlq_routing_key,
        ), timeout=_PUBLISH_TIMEOUT_SECONDS)
    except Exception:
        await message.nack(requeue=True)
        return
    DEAD_LETTER_EVENTS.labels("rabbitmq", consumer._topic, reason).inc()
    await message.ack()


async def consume_forever(
    consumer: RabbitMQConsumer,
    handler: Callable[[dict[str, Any]], Awaitable[None]],
    failure_handler: Callable[[dict[str, Any], str], Awaitable[None]] | None = None,
) -> None:
    processed_cache = ProcessedMessageCache()
    while True:
        try:
            await consumer.start()
            if consumer._queue is None:
                await asyncio.sleep(1)
                continue

            async with consumer._queue.iterator() as iterator:
                async for message in iterator:
                    try:
                        decoded = json.loads(message.body.decode("utf-8"))
                    except (UnicodeDecodeError, json.JSONDecodeError):
                        logger.warning("failed to decode rabbitmq message", extra={"topic": consumer._topic})
                        await _quarantine_invalid_message(consumer, message, "decode_failed")
                        continue

                    payload = decoded.get("payload") if isinstance(decoded, dict) else None
                    if not isinstance(payload, dict):
                        await _quarantine_invalid_message(consumer, message, "invalid_payload")
                        continue

                    identity = extract_message_identity(payload)
                    if await processing_cancelled(consumer._settings, payload):
                        logger.warning("cancelled alert removed from rabbitmq processing", extra={"topic": consumer._topic, "message_identity": identity})
                        await message.ack()
                        continue
                    if processed_cache.contains(identity):
                        logger.info("skipping duplicate rabbitmq message", extra={"topic": consumer._topic, "message_identity": identity})
                        await message.ack()
                        continue

                    attempts = 0
                    max_retries = max(0, int(consumer._settings.rabbitmq_consumer_max_retries or 0))
                    success = False
                    dlq_published = False

                    last_error = ""
                    failure_type = ""
                    produced_at = decoded.get("produced_at") if isinstance(decoded, dict) else None
                    if produced_at:
                        try:
                            produced = datetime.fromisoformat(str(produced_at).replace("Z", "+00:00"))
                            QUEUE_AGE.labels("rabbitmq", consumer._topic).observe(max(0.0, (datetime.now(timezone.utc) - produced).total_seconds()))
                        except (TypeError, ValueError):
                            pass
                    parent_context = propagate.extract(dict(getattr(message, "headers", None) or {}))
                    while attempts <= max_retries:
                        try:
                            with trace.get_tracer("kaiops.rabbitmq").start_as_current_span("rabbitmq.consume", context=parent_context) as span:
                                span.set_attribute("messaging.system", "rabbitmq")
                                span.set_attribute("messaging.destination.name", consumer._topic)
                                await run_handler(consumer._settings, consumer._topic, handler, payload)
                            success = True
                            processed_cache.mark(identity)
                            break
                        except Exception as exc:
                            # Includes asyncio.TimeoutError: without a bound here a
                            # single hung downstream call could block this consumer
                            # (and its whole prefetch batch) indefinitely.
                            last_error = str(exc) or exc.__class__.__name__
                            failure_type = f"{type(exc).__module__}.{type(exc).__qualname__}"
                            attempts += 1
                            if attempts > max_retries:
                                break
                            await asyncio.sleep(min(2**attempts, 5))

                    if success:
                        await message.ack()
                        continue

                    logger.error(
                        "failed to process rabbitmq message: topic=%s identity=%s attempts=%s error=%s",
                        consumer._topic,
                        identity,
                        attempts,
                        last_error,
                        extra={
                            "topic": consumer._topic,
                            "attempts": attempts,
                            "max_retries": max_retries,
                            "error": last_error,
                            "message_identity": identity,
                        },
                    )
                    if (
                        consumer._settings.rabbitmq_transient_requeue_enabled
                        and _is_transient_handler_error(last_error)
                    ):
                        headers = dict(getattr(message, "headers", None) or {})
                        maximum = consumer._settings.rabbitmq_transient_max_requeues
                        try:
                            redeliveries = max(0, int(headers.get("kaiops-transient-requeues", 0)))
                        except (TypeError, ValueError):
                            redeliveries = maximum
                        if redeliveries < maximum:
                            await asyncio.sleep(min(5.0, max(1.0, float(attempts))))
                            headers["kaiops-transient-requeues"] = redeliveries + 1
                            try:
                                # Default exchange targets this exact subscriber
                                # queue; republishing to the topic would duplicate
                                # deliveries to every other subscriber.
                                await asyncio.wait_for(consumer._channel.default_exchange.publish(
                                    Message(message.body, headers=headers, delivery_mode=DeliveryMode.PERSISTENT,
                                            content_type="application/json", app_id="kaiops", type=consumer._topic),
                                    routing_key=consumer._queue.name, mandatory=True,
                                ), timeout=_PUBLISH_TIMEOUT_SECONDS)
                            except Exception:
                                logger.exception("transient retry handoff failed; preserving original delivery")
                                await message.nack(requeue=True)
                            else:
                                await message.ack()
                            continue
                    if consumer._exchange is not None and consumer._dlq_routing_key:
                        try:
                            if failure_handler is not None:
                                try:
                                    # last_error is kept raw for the log line
                                    # above, the DLQ envelope below, and the
                                    # transient-retry heuristic -- all
                                    # operator/internal-only. failure_handler
                                    # persists into a field a service can
                                    # read back through a normal successful
                                    # request and display to an operator, so
                                    # it gets the sanitized text instead.
                                    await asyncio.wait_for(
                                        failure_handler(payload, sanitize_handler_failure_text(last_error)),
                                        timeout=_PUBLISH_TIMEOUT_SECONDS,
                                    )
                                except Exception:
                                    logger.exception(
                                        "failed to persist rabbitmq terminal handler state",
                                        extra={"topic": consumer._topic, "message_identity": identity},
                                    )
                                    # Preserve the delivery if its terminal state was not
                                    # persisted; a later retry can repair the handoff.
                                    raise
                            envelope = {
                                "failure_schema": "kaiops.message-failure.v1",
                                "failure_type": failure_type,
                                "failure_reason": sanitize_handler_failure_text(last_error),
                                "consumer_service": consumer._settings.service_name,
                                "message_identity": identity,
                                "failed_topic": consumer._topic,
                                "payload": payload,
                                "error": last_error or "handler_failed",
                                "attempts": attempts,
                                "failed_at": datetime.now(timezone.utc).isoformat(),
                            }
                            await asyncio.wait_for(consumer._exchange.publish(
                                Message(
                                    json.dumps(envelope, default=str).encode("utf-8"),
                                    content_type="application/json",
                                    delivery_mode=DeliveryMode.PERSISTENT,
                                    type=consumer._dlq_routing_key,
                                    app_id="kaiops",
                                ),
                                routing_key=consumer._dlq_routing_key,
                            ), timeout=_PUBLISH_TIMEOUT_SECONDS)
                            processed_cache.mark(identity)
                            dlq_published = True
                            DEAD_LETTER_EVENTS.labels("rabbitmq", consumer._topic, "handler_failed").inc()
                        except Exception:
                            logger.exception(
                                "failed to publish rabbitmq dlq message",
                                extra={"topic": consumer._topic, "dlq": consumer._dlq_routing_key},
                            )
                    if dlq_published:
                        await message.ack()
                        continue

                    await message.nack(requeue=True)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("rabbitmq consumer loop crashed; restarting", extra={"topic": consumer._topic})
            try:
                await consumer.stop()
            except Exception:
                logger.exception("rabbitmq consumer stop failed", extra={"topic": consumer._topic})
            await asyncio.sleep(1)
