"""Queue inspection and exact-message actions shared by administrative APIs.

Inspection uses full AMQP bodies so displayed identities match mutations.
All scans are bounded and release unselected messages on failure.
"""
import hashlib
import json
from contextlib import suppress
from urllib.parse import unquote, urlparse
import aio_pika


def broker_vhost(url: str) -> str:
    return unquote(urlparse(url).path[1:]) or "/"


def queue_job_id(queue_name: str, body: bytes) -> str:
    return "job-" + hashlib.sha256(queue_name.encode() + b"\0" + body).hexdigest()[:24]


def describe_message(queue_name: str, body: bytes, redelivered: bool = False) -> dict:
    try:
        decoded = json.loads(body)
    except (ValueError, UnicodeDecodeError):
        decoded = None
    scopes = []
    def visit(value, depth=0):
        if not isinstance(value, dict) or depth > 6:
            return
        scopes.append(value)
        for key in ("payload", "context", "event_envelope", "identity", "alert", "incident"):
            visit(value.get(key), depth + 1)
    visit(decoded)
    def field(*keys, default=""):
        return next((str(scope[key]) for scope in scopes for key in keys
                     if isinstance(scope.get(key), (str, int)) and scope[key]), default)
    return {"job_id": queue_job_id(queue_name, body),
            "alert_id": field("alert_id"), "incident_id": field("incident_id"),
            "name": field("alert_name", "name", default="Queued event"),
            "service": field("service", default="unknown"),
            "severity": field("severity", default="unknown"),
            "redelivered": bool(redelivered), "payload_bytes": len(body),
            "payload_valid": isinstance(decoded, dict)}


async def sample_ready_messages(broker_url: str, queue_name: str, count: int = 25) -> list[dict]:
    connection = await aio_pika.connect_robust(broker_url, timeout=10)
    pending = []
    rows = []
    try:
        channel = await connection.channel()
        limit = max(1, min(count, 100))
        await channel.set_qos(prefetch_count=limit)
        queue = await channel.declare_queue(queue_name, passive=True)
        size = 0
        for _ in range(limit):
            message = await queue.get(fail=False, timeout=2)
            if message is None:
                break
            pending.append(message)
            rows.append(describe_message(queue_name, message.body, message.redelivered))
            size += len(message.body)
            if size >= 8 * 1024 * 1024:
                break
        return rows
    finally:
        for message in pending:
            with suppress(Exception):
                await message.reject(requeue=True)
        await connection.close()


async def mutate_ready_queue_job(*, broker_url: str, queue_name: str, job_id: str, rerun: bool, scan_limit: int = 100) -> bool:
    """Acknowledge one exact ready message, optionally republishing it at the queue tail.

    Non-matching messages are rejected with requeue=True. Messages already
    owned by a consumer are never interrupted or acknowledged here.
    """
    connection = await aio_pika.connect_robust(broker_url, timeout=10)
    pending: list[aio_pika.IncomingMessage] = []
    try:
        channel = await connection.channel(publisher_confirms=True, on_return_raises=True)
        bounded_limit = max(1, min(scan_limit, 100))
        await channel.set_qos(prefetch_count=bounded_limit)
        queue = await channel.declare_queue(queue_name, passive=True)
        for _ in range(bounded_limit):
            message = await queue.get(fail=False, timeout=2)
            if message is None:
                break
            if queue_job_id(queue_name, message.body) != job_id:
                pending.append(message)
                continue
            if rerun:
                replacement = aio_pika.Message(
                    body=message.body,
                    headers=dict(message.headers or {}),
                    content_type=message.content_type,
                    content_encoding=message.content_encoding,
                    delivery_mode=aio_pika.DeliveryMode.PERSISTENT,
                    correlation_id=message.correlation_id,
                    message_id=message.message_id,
                    timestamp=message.timestamp,
                    type=message.type,
                    app_id=message.app_id,
                )
                await channel.default_exchange.publish(replacement, routing_key=queue_name, mandatory=True)
            await message.ack()
            for skipped in pending:
                await skipped.reject(requeue=True)
            pending.clear()
            return True
        for skipped in pending:
            await skipped.reject(requeue=True)
        pending.clear()
        return False
    finally:
        for skipped in pending:
            with suppress(Exception):
                await skipped.reject(requeue=True)
        await connection.close()
