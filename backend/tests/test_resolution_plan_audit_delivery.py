import asyncio
import importlib.util
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest
from common.database import AuditLogRecord, ResolutionOutboxRecord
from sqlalchemy import select


def load_module():
    spec = importlib.util.spec_from_file_location("resolution_audit_test", Path("backend/src/audit-service/app.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.asyncio
@pytest.mark.parametrize("compiled", [False, True])
async def test_durable_plan_delivery_is_idempotent_and_compact(sqlite_session_factory, compiled):
    module = load_module()
    app = SimpleNamespace(state=SimpleNamespace(session_factory=sqlite_session_factory))
    plan_id, incident_id = str(uuid4()), str(uuid4())
    kind = "compiled" if compiled else "selected"
    prefix = "execution-plan-compiled" if compiled else "resolution-plan-selected"
    key = "execution_plan" if compiled else "resolution_selection"
    identity = "plan_id" if compiled else "selection_id"
    event = {"tenant_id": "audit-test", "incident_id": incident_id,
             "event_type": f"incident.resolution.plan.{kind}",
             key: {identity: plan_id, "private_plan_details": "not copied"}}
    async with sqlite_session_factory() as session:
        session.add(ResolutionOutboxRecord(event_id=f"{prefix}:{plan_id}", tenant_id="audit-test",
                    aggregate_id=incident_id, topic="resolution.events", partition_key=incident_id,
                    payload=event, status="retry", attempts=3))
        await session.commit()
    await module.record_resolution_plan_event(app, event)
    await module.record_resolution_plan_event(app, event)
    async with sqlite_session_factory() as session:
        rows = (await session.execute(select(AuditLogRecord))).scalars().all()
        assert len(rows) == 1
        assert rows[0].resource_id == incident_id
        assert rows[0].payload == {"event_id": f"{prefix}:{plan_id}", "plan_id": plan_id,
                                   "delivery_verified": True}
    for change in ({"tenant_id": "other"}, {"incident_id": str(uuid4())},
                   {"unexpected": True}):
        with pytest.raises(ValueError, match="durable source"):
            await module.record_resolution_plan_event(app, {**event, **change})


@pytest.mark.asyncio
async def test_unknown_plan_event_is_rejected(sqlite_session_factory):
    app = SimpleNamespace(state=SimpleNamespace(session_factory=sqlite_session_factory))
    with pytest.raises(ValueError, match="Unsupported"):
        await load_module().record_resolution_plan_event(app, {"event_type": "execute"})


@pytest.mark.asyncio
async def test_startup_registers_control_plane_consumer(monkeypatch):
    module = load_module()
    subscriptions = {}
    monkeypatch.setattr(module, "RabbitMQConsumer", lambda settings, topic: topic)

    async def consume(topic, handler):
        subscriptions[topic] = handler

    monkeypatch.setattr(module, "consume_rabbitmq_forever", consume)
    await module.startup(SimpleNamespace())
    await asyncio.gather(*module.tasks)
    assert "resolution.events" in subscriptions
    assert "closure-events" in subscriptions
    assert "resolution-events" not in subscriptions
