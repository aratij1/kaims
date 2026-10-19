import importlib.util
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest
from sqlalchemy import select
from common.database import AuditLogRecord


@pytest.mark.asyncio
async def test_closure_audit_is_idempotent_and_preserves_non_recovery(sqlite_session_factory):
    spec = importlib.util.spec_from_file_location("closure_audit_test", Path("backend/src/audit-service/app.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    app = SimpleNamespace(state=SimpleNamespace(session_factory=sqlite_session_factory))
    incident_id = str(uuid4())
    event = {"event_contract": {"event_id": "closure:test:closed"}, "report": {
        "tenant_id": "closure-test", "incident_id": incident_id,
        "metadata": {"closure_kind": "manual", "technical_recovery_verified": False},
    }}
    await module.record_closure_event(app, event)
    await module.record_closure_event(app, event)
    async with sqlite_session_factory() as session:
        rows = (await session.execute(select(AuditLogRecord).where(AuditLogRecord.tenant_id == "closure-test"))).scalars().all()
        assert len(rows) == 1
        assert rows[0].resource_id == incident_id
        assert rows[0].payload["technical_recovery_verified"] is False


@pytest.mark.asyncio
async def test_closure_audit_rejects_missing_tenant(sqlite_session_factory):
    spec = importlib.util.spec_from_file_location("closure_audit_scope_test", Path("backend/src/audit-service/app.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    app = SimpleNamespace(state=SimpleNamespace(session_factory=sqlite_session_factory))
    with pytest.raises(ValueError, match="tenant"):
        await module.record_closure_event(app, {"event_contract": {"event_id": "test"},
                                               "report": {"incident_id": str(uuid4())}})
