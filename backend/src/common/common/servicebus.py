from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator, Awaitable, Callable
from datetime import datetime, timezone
from typing import Any

from common.config import Settings
from common.alert_processing_budget import run_handler
from common.logging import get_logger
from common.resilience import retry_async

logger = get_logger(__name__)


def normalize_payload(value: Any) -> Any:
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json")
    if isinstance(value, dict):
        return {key: normalize_payload(item) for key, item in value.items()}
    if isinstance(value, list):
        return [normalize_payload(item) for item in value]
    return value


def _full_topic_name(settings: Settings, topic: str) -> str:
    prefix = str(settings.azure_service_bus_topic_prefix or "kaiops").strip() or "kaiops"
    return f"{prefix}-{topic}".replace("_", "-")


def _extract_body_as_bytes(message: Any) -> bytes:
    body = getattr(message, "body", b"")
    if isinstance(body, (bytes, bytearray)):
        return bytes(body)
    try:
        return b"".join(bytes(chunk) for chunk in body)
    except Exception:
        return b""


class AzureServiceBusProducer:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._connection_string = str(settings.azure_service_bus_connection_string or "").strip()
        self._client: Any | None = None

    async def start(self) -> None:
        if not self._settings.azure_service_bus_enabled or not self._connection_string:
            return
        from azure.servicebus.aio import ServiceBusClient

        self._client = ServiceBusClient.from_connection_string(self._connection_string)
        logger.info("connected azure service bus producer")

    async def stop(self) -> None:
        if self._client is not None:
            await self._client.close()
        self._client = None

    async def publish(self, topic: str, event: Any, key: str | None = None) -> None:
        payload = normalize_payload(event)
        if self._client is None:
            raise RuntimeError("Azure Service Bus producer is not started; event was not delivered")

        full_topic = _full_topic_name(self._settings, topic)
        data = json.dumps(payload, default=str).encode("utf-8")

        async def send() -> None:
            from azure.servicebus import ServiceBusMessage

            assert self._client is not None
            sender = self._client.get_topic_sender(topic_name=full_topic)
            async with sender:
                message = ServiceBusMessage(data, subject=key or None)
                await sender.send_messages(message)

        await retry_async(send)


class AzureServiceBusConsumer:
    def __init__(self, settings: Settings, topic: str) -> None:
        self._settings = settings
        self._topic = topic
        self._connection_string = str(settings.azure_service_bus_connection_string or "").strip()
        self._client: Any | None = None
        self._topic_name = _full_topic_name(settings, topic)
        self._subscription_name = (
            f"{str(settings.azure_service_bus_subscription_prefix or 'kaiops').strip() or 'kaiops'}"
            f"-{settings.service_name}-{self._topic_name}"
        )
        self._subscription_name = self._subscription_name.replace("_", "-")
        self._dlq_topic_name = f"{self._topic_name}{settings.azure_service_bus_dlq_suffix}"

    async def start(self) -> None:
        if not self._settings.azure_service_bus_enabled or not self._connection_string:
            return
        from azure.servicebus.aio import ServiceBusClient

        self._client = ServiceBusClient.from_connection_string(self._connection_string)
        logger.info(
            "connected azure service bus consumer",
            extra={"topic": self._topic_name, "subscription": self._subscription_name},
        )

    async def stop(self) -> None:
        if self._client is not None:
            await self._client.close()
        self._client = None

    async def pull(self, max_messages: int | None = None) -> list[Any]:
        if self._client is None:
            return []

        receiver = self._client.get_subscription_receiver(
            topic_name=self._topic_name,
            subscription_name=self._subscription_name,
            max_wait_time=5,
        )
        async with receiver:
            return list(
                await receiver.receive_messages(
                    max_message_count=max_messages or self._settings.azure_service_bus_pull_max_messages,
                    max_wait_time=5,
                )
            )

    async def complete(self, message: Any) -> None:
        if self._client is None:
            return
        receiver = self._client.get_subscription_receiver(
            topic_name=self._topic_name,
            subscription_name=self._subscription_name,
            max_wait_time=5,
        )
        async with receiver:
            await receiver.complete_message(message)

    async def dead_letter(self, message: Any, reason: str = "handler_failed") -> None:
        if self._client is None:
            return
        receiver = self._client.get_subscription_receiver(
            topic_name=self._topic_name,
            subscription_name=self._subscription_name,
            max_wait_time=5,
        )
        async with receiver:
            await receiver.dead_letter_message(message, reason=reason, error_description=reason)

    async def messages(self) -> AsyncIterator[dict[str, Any]]:
        if self._client is None:
            while True:
                await asyncio.sleep(3600)
        else:
            while True:
                received = await self.pull()
                if not received:
                    await asyncio.sleep(1)
                    continue
                for message in received:
                    try:
                        payload = json.loads(_extract_body_as_bytes(message).decode("utf-8"))
                    except (UnicodeDecodeError, json.JSONDecodeError):
                        continue
                    if isinstance(payload, dict):
                        yield payload
                    await self.complete(message)


async def consume_forever(
    consumer: AzureServiceBusConsumer,
    handler: Callable[[dict[str, Any]], Awaitable[None]],
) -> None:
    await consumer.start()
    if consumer._client is None:
        while True:
            await asyncio.sleep(3600)

    try:
        receiver = consumer._client.get_subscription_receiver(
            topic_name=consumer._topic_name,
            subscription_name=consumer._subscription_name,
            max_wait_time=5,
        )
        async with receiver:
            while True:
                received = list(
                    await receiver.receive_messages(
                        max_message_count=consumer._settings.azure_service_bus_pull_max_messages,
                        max_wait_time=5,
                    )
                )
                if not received:
                    await asyncio.sleep(1)
                    continue

                for message in received:
                    try:
                        payload = json.loads(_extract_body_as_bytes(message).decode("utf-8"))
                    except (UnicodeDecodeError, json.JSONDecodeError):
                        logger.warning("failed to decode azure service bus message", extra={"topic": consumer._topic})
                        await receiver.dead_letter_message(message, reason="decode_failed", error_description="decode_failed")
                        continue
                    if not isinstance(payload, dict):
                        await receiver.dead_letter_message(message, reason="invalid_payload", error_description="invalid_payload")
                        continue

                    attempts = 0
                    max_retries = max(0, int(consumer._settings.azure_service_bus_consumer_max_retries or 0))
                    success = False
                    while attempts <= max_retries:
                        try:
                            await run_handler(consumer._settings, consumer._topic, handler, payload)
                            success = True
                            break
                        except Exception:
                            attempts += 1
                            if attempts > max_retries:
                                break
                            await asyncio.sleep(min(2**attempts, 5))

                    if success:
                        await receiver.complete_message(message)
                        continue

                    logger.error(
                        "failed to process azure service bus message",
                        extra={"topic": consumer._topic, "attempts": attempts, "max_retries": max_retries},
                    )
                    failed_at = datetime.now(timezone.utc).isoformat()
                    await receiver.dead_letter_message(
                        message,
                        reason=f"handler_failed:{failed_at}",
                        error_description="handler_failed",
                    )
    except asyncio.CancelledError:
        raise
    except Exception:
        logger.exception("azure service bus consumer loop crashed", extra={"topic": consumer._topic})
        raise
