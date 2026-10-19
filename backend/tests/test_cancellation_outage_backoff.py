from unittest.mock import AsyncMock
import pytest
from common.config import Settings
import common.message_processing as module

@pytest.mark.asyncio
async def test_cancellation_outage_is_throttled_and_recovery_is_rechecked(monkeypatch):
    settings = Settings()
    client = AsyncMock()
    client.smembers.side_effect = [ConnectionError("offline"), {"evt-1"}]
    monkeypatch.setattr(module, "_cancellation_clients", {settings.redis_url: client})
    monkeypatch.setattr(module, "_cancelled_cache", {})
    clock = [100.0]
    monkeypatch.setattr(module, "monotonic", lambda: clock[0])
    for _ in range(20):
        assert await module.processing_cancelled(settings, {"event_id": "evt-1"}) is False
    assert client.smembers.await_count == 1
    clock[0] += 2.1
    assert await module.processing_cancelled(settings, {"event_id": "evt-1"}) is True
    assert client.smembers.await_count == 2
