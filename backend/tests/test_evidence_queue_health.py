import importlib.util
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest
from common.database import ContextEnrichmentJobRecord


@pytest.mark.asyncio
async def test_evidence_backlog_includes_durable_jobs_and_is_tenant_scoped(sqlite_session_factory, monkeypatch):
    spec = importlib.util.spec_from_file_location("gateway_evidence_queue_test", Path("backend/src/api-gateway/app.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module.settings, "database_enabled", True)
    module.app.state.session_factory = sqlite_session_factory
    now = datetime.now(UTC)
    async with sqlite_session_factory() as session:
        for tenant, status in [("tenant-a", "scheduled"), ("tenant-a", "retry"),
                               ("tenant-a", "collecting"), ("tenant-a", "collected"),
                               ("tenant-b", "scheduled")]:
            session.add(ContextEnrichmentJobRecord(tenant_id=tenant, incident_id=uuid4(),
                requirement_id=uuid4(), connector_id="discovery-mcp", idempotency_key=uuid4().hex,
                query_payload={}, observation_start=now, observation_end=now, status=status))
        await session.commit()
    report = await module._evidence_queue_health("tenant-a")
    assert report["status"] == "available"
    assert {key: report[key] for key in ("scheduled", "retry", "collecting")} == {
        "scheduled": 1, "retry": 1, "collecting": 1,
    }
    module.app.state.session_factory = None
    assert await module._evidence_queue_health("tenant-a") == {"status": "unavailable"}
