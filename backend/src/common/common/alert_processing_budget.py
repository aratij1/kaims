"""Shared admission budget for queued alert-analysis work across replicas."""
from __future__ import annotations
import asyncio
from contextlib import suppress
from uuid import uuid4
from redis.asyncio import Redis

ANALYSIS_TOPICS = frozenset({'raw-alerts', 'enriched-alerts', 'orchestration-events', 'context-events', 'context-initial-events', 'code-analysis-events', 'resolution-events'})
_CLIENTS = {}
_ACQUIRE = """
local t = redis.call('TIME')
local now = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', now)
redis.call('ZREMRANGEBYSCORE', KEYS[2], '-inf', now)
if redis.call('ZCARD', KEYS[1]) >= tonumber(ARGV[1]) then
 redis.call('ZADD', KEYS[2], now + 30000, ARGV[3])
 return 0
end
redis.call('ZREM', KEYS[2], ARGV[3])
redis.call('ZADD', KEYS[1], now + tonumber(ARGV[2]), ARGV[3])
return 1
"""
_COUNT = """
local t = redis.call('TIME')
local now = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', now)
redis.call('ZREMRANGEBYSCORE', KEYS[2], '-inf', now)
return {redis.call('ZCARD', KEYS[1]), redis.call('ZCARD', KEYS[2])}
"""

def client_for(settings):
    if settings.redis_url not in _CLIENTS:
        _CLIENTS[settings.redis_url] = Redis.from_url(settings.redis_url, decode_responses=True, socket_connect_timeout=2, socket_timeout=2)
    return _CLIENTS[settings.redis_url]

def budget_key(settings):
    return f'{settings.rabbitmq_queue_prefix}:alert-analysis:active'

async def capacity(settings):
    if not settings.alert_processing_limit_enabled:
        return {'status': 'disabled', 'limit': settings.alert_processing_limit, 'active': None}
    try:
        active, waiting = await client_for(settings).eval(_COUNT, 2, budget_key(settings), budget_key(settings) + ':waiting')
        return {'status': 'available', 'limit': settings.alert_processing_limit, 'active': int(active), 'waiting': int(waiting)}
    except Exception:
        return {'status': 'unavailable', 'limit': settings.alert_processing_limit, 'active': None}

async def run_handler(settings, topic, handler, payload, *, timeout_seconds=None):
    """Wait outside the processing timeout. Broker delivery remains unacked.

    Fail closed while Redis is unavailable. Only the actual handler uses the
    processing timeout, so waiting for capacity cannot consume retry/DLQ budget.
    Slots outlive that timeout to recover safely after a worker crash.
    """
    timeout = float(timeout_seconds if timeout_seconds is not None else settings.rabbitmq_handler_timeout_seconds)
    if topic not in ANALYSIS_TOPICS or not settings.alert_processing_limit_enabled:
        return await asyncio.wait_for(handler(payload), timeout=timeout)
    client = client_for(settings)
    token = str(uuid4())
    key = budget_key(settings)
    try:
        while True:
            try:
                acquired = await client.eval(_ACQUIRE, 2, key, key + ':waiting', settings.alert_processing_limit,
                                             int((timeout + 30) * 1000), token)
                if acquired:
                    break
            except Exception:
                # Capacity uncertainty must never admit an extra handler.
                pass
            await asyncio.sleep(1)
        # A delivery may have been cancelled while it waited for capacity.
        from common.message_processing import processing_cancelled
        if await processing_cancelled(settings, payload):
            return None
        return await asyncio.wait_for(handler(payload), timeout=timeout)
    finally:
        with suppress(Exception):
            await client.zrem(key, token)
            await client.zrem(key + ':waiting', token)
