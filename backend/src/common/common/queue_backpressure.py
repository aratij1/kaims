"""Recoverable parking of old ready RCA deliveries; never purge or bypass handlers."""
import asyncio
import json
import logging
from contextlib import suppress
from datetime import datetime, timezone
import aio_pika

logger = logging.getLogger(__name__)


def controller_enabled(enabled: bool, provider: str, secondary_rabbitmq: bool = False) -> bool:
    return enabled and (provider.strip().lower() == 'rabbitmq' or secondary_rabbitmq)


def old_enough(body: bytes, minimum_age: float, now: datetime) -> bool:
    try:
        document = json.loads(body)
        produced = datetime.fromisoformat(str(document['produced_at']).replace('Z', '+00:00'))
        if produced.tzinfo is None:
            return False
        return (now - produced).total_seconds() >= minimum_age
    except (ValueError, TypeError, KeyError, UnicodeDecodeError):
        return False


async def transfer(channel, message, destination: str, *, deferred: bool):
    headers = dict(message.headers or {})
    headers['x-kaims-backlog-state'] = 'deferred' if deferred else 'replayed'
    headers['x-kaims-backlog-transition-at'] = datetime.now(timezone.utc).isoformat()
    replacement = aio_pika.Message(
        body=message.body, headers=headers,
        content_type=message.content_type, content_encoding=message.content_encoding,
        delivery_mode=aio_pika.DeliveryMode.PERSISTENT,
        correlation_id=message.correlation_id, message_id=message.message_id,
        timestamp=message.timestamp, type=message.type, app_id=message.app_id,
        reply_to=message.reply_to, priority=message.priority,
    )
    # Parking must not expire the only remaining durable delivery. The business
    # handler still validates evidence freshness and governance after replay.
    await asyncio.wait_for(channel.default_exchange.publish(
        replacement, routing_key=destination, mandatory=True), timeout=10)
    await message.ack()


async def rebalance(broker_url: str, queue_name: str, *, high: int = 50, low: int = 10,
                    minimum_age: float = 300, batch: int = 10) -> dict:
    if not (0 <= low < high) or minimum_age < 0 or not 1 <= batch <= 100:
        raise ValueError('Invalid backlog thresholds')
    connection = await aio_pika.connect_robust(broker_url, timeout=10)
    pending = []
    result = {'queue': queue_name, 'parked': 0, 'replayed': 0}
    try:
        channel = await connection.channel(publisher_confirms=True, on_return_raises=True)
        # An exclusive lease prevents replicas from making opposing moves.
        await channel.declare_queue(queue_name + '.backlog-controller', exclusive=True, auto_delete=True)
        await channel.set_qos(prefetch_count=batch)
        active = await channel.declare_queue(queue_name, passive=True)
        parked = await channel.declare_queue(queue_name + '.deferred', durable=True)
        depth = active.declaration_result.message_count
        result['active_ready'] = depth
        result['deferred_ready'] = parked.declaration_result.message_count
        if depth >= high:
            source, destination, parking = active, parked.name, True
            limit = min(batch, depth - low)
        elif depth < high and active.declaration_result.consumer_count > 0:
            source, destination, parking = parked, active.name, False
            # Reserve progress for old work even when steady arrivals keep
            # the active queue above the low watermark. Stay below high.
            limit = min(batch if depth <= low else 1, high - depth)
        else:
            return result
        for _ in range(limit):
            message = await source.get(fail=False, timeout=2)
            if message is None:
                break
            pending.append(message)
            if parking:
                # Once restored, a delivery keeps its place in the active
                # FIFO. Its original timestamp must not cause endless parking.
                if (message.headers or {}).get('x-kaims-backlog-state') == 'replayed':
                    continue
                if not old_enough(message.body, minimum_age, datetime.now(timezone.utc)):
                    continue
            await transfer(channel, message, destination, deferred=parking)
            pending.remove(message)
            result['parked' if parking else 'replayed'] += 1
        return result
    finally:
        for message in pending:
            if not message.processed:
                with suppress(Exception):
                    await message.reject(requeue=True)
        await connection.close()


async def backlog_loop(settings):
    queue_name = f'{settings.rabbitmq_queue_prefix}.resolution-agent.context-events'
    while True:
        try:
            result = await rebalance(settings.rabbitmq_url, queue_name,
                high=settings.queue_backlog_high, low=settings.queue_backlog_low,
                minimum_age=settings.queue_backlog_age_seconds, batch=settings.queue_backlog_batch)
            if result['parked'] or result['replayed']:
                logger.info('RCA backlog transition: %s', result)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.warning('RCA backlog controller could not complete a cycle: %s', type(exc).__name__)
        await asyncio.sleep(settings.queue_backlog_poll_seconds)
