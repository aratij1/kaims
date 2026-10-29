import asyncio
from datetime import datetime, timezone
from uuid import uuid4

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

import importlib.util
from pathlib import Path

from common.database import Base, IncidentProjectionRecord, AuditLogRecord

orch_spec = importlib.util.spec_from_file_location("orchestrator_app", Path("backend/src/orchestrator/app.py"))
orch_mod = importlib.util.module_from_spec(orch_spec)
orch_spec.loader.exec_module(orch_mod)
record_orchestrator_lifecycle_transition = orch_mod.record_orchestrator_lifecycle_transition

audit_spec = importlib.util.spec_from_file_location("audit_service_app", Path("backend/src/audit-service/app.py"))
audit_mod = importlib.util.module_from_spec(audit_spec)
audit_spec.loader.exec_module(audit_mod)
record_human_assignment_event = audit_mod.record_human_assignment_event

@pytest.fixture
async def async_session_factory():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    session_factory = sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    yield session_factory
    await engine.dispose()

class DummyApp:
    def __init__(self, session_factory):
        self.state = type("State", (), {"session_factory": session_factory})()

@pytest.mark.asyncio
async def test_orchestrator_lifecycle_consumer_advances_projection(async_session_factory):
    app = DummyApp(async_session_factory)
    incident_id = uuid4()
    tenant_id = "tenant-lifecycle-test"

    # Setup initial projection
    async with async_session_factory() as session:
        proj = IncidentProjectionRecord(
            incident_id=incident_id,
            tenant_id=tenant_id,
            service="payments",
            environment="prod",
            status="open",
            lifecycle_state="DETECTED",
            lifecycle_version=1,
            latest_event_at=datetime.now(timezone.utc),
            first_seen_at=datetime.now(timezone.utc),
        )
        session.add(proj)
        await session.commit()

    # Step 1: Transition to WAITING_FOR_HUMAN
    payload = {
        "tenant_id": tenant_id,
        "incident_id": str(incident_id),
        "previous_state": "DETECTED",
        "new_state": "WAITING_FOR_HUMAN",
        "version": 2,
        "reason": "Missing runbook requires human input",
        "actor": "context-agent",
    }
    await record_orchestrator_lifecycle_transition(app, payload)

    async with async_session_factory() as session:
        updated = await session.scalar(
            select(IncidentProjectionRecord).where(
                IncidentProjectionRecord.tenant_id == tenant_id,
                IncidentProjectionRecord.incident_id == incident_id,
            )
        )
        assert updated is not None
        assert updated.lifecycle_state == "WAITING_FOR_HUMAN"
        assert updated.status == "waiting_for_human"
        assert updated.lifecycle_version == 2

    # Step 2: Stale transition with older version (e.g. version 1) should be ignored
    stale_payload = {
        "tenant_id": tenant_id,
        "incident_id": str(incident_id),
        "previous_state": "DETECTED",
        "new_state": "COLLECTING",
        "version": 1,
        "reason": "Delayed event",
        "actor": "context-agent",
    }
    await record_orchestrator_lifecycle_transition(app, stale_payload)

    async with async_session_factory() as session:
        recheck = await session.scalar(
            select(IncidentProjectionRecord).where(
                IncidentProjectionRecord.tenant_id == tenant_id,
                IncidentProjectionRecord.incident_id == incident_id,
            )
        )
        assert recheck.lifecycle_state == "WAITING_FOR_HUMAN"
        assert recheck.lifecycle_version == 2

    # Step 3: Advance to CLOSED with recovery proof
    close_payload = {
        "tenant_id": tenant_id,
        "incident_id": str(incident_id),
        "previous_state": "WAITING_FOR_HUMAN",
        "new_state": "CLOSED",
        "version": 3,
        "reason": "Recovery proof verified",
        "actor": "closure-service",
    }
    await record_orchestrator_lifecycle_transition(app, close_payload)

    async with async_session_factory() as session:
        closed = await session.scalar(
            select(IncidentProjectionRecord).where(
                IncidentProjectionRecord.tenant_id == tenant_id,
                IncidentProjectionRecord.incident_id == incident_id,
            )
        )
        assert closed.lifecycle_state == "CLOSED"
        assert closed.status == "closed"
        assert closed.lifecycle_version == 3


@pytest.mark.asyncio
async def test_audit_service_human_assignment_event_recording(async_session_factory):
    app = DummyApp(async_session_factory)
    incident_id = str(uuid4())
    event_id = f"hitl-assignment-blocked:{uuid4()}"
    tenant_id = "tenant-audit-test"

    payload = {
        "schema_version": "kaiops.hitl-assignment.v1",
        "event_id": event_id,
        "tenant_id": tenant_id,
        "incident_id": incident_id,
        "requirement_id": str(uuid4()),
        "status": "ASSIGNMENT_BLOCKED",
        "reason": "NO_AUTHORIZED_RESPONDER",
    }

    # Record first time
    await record_human_assignment_event(app, payload)

    async with async_session_factory() as session:
        audits = (await session.scalars(
            select(AuditLogRecord).where(
                AuditLogRecord.tenant_id == tenant_id,
                AuditLogRecord.resource_id == incident_id,
            )
        )).all()
        assert len(audits) == 1
        assert audits[0].action == "human_evidence.assignment_blocked"
        assert audits[0].actor == "evidence-routing"
        assert audits[0].payload["reason"] == "NO_AUTHORIZED_RESPONDER"

    # Record second time (idempotent duplicate event)
    await record_human_assignment_event(app, payload)

    async with async_session_factory() as session:
        audits_recheck = (await session.scalars(
            select(AuditLogRecord).where(
                AuditLogRecord.tenant_id == tenant_id,
                AuditLogRecord.resource_id == incident_id,
            )
        )).all()
        assert len(audits_recheck) == 1
