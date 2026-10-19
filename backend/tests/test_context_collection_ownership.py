from contextlib import asynccontextmanager
from types import SimpleNamespace
from unittest.mock import AsyncMock
import pytest
from fastapi import HTTPException
from test_context_knowledge_strategy import load_context_app_module,make_alert,make_incident

@pytest.mark.asyncio
@pytest.mark.parametrize("state",["busy","lock_error","collect_error","success"])
async def test_distributed_context_collection_never_falls_back_to_duplicate_work(monkeypatch,state):
    import common.advisory_lock as locks
    module=load_context_app_module()
    monkeypatch.setattr(module.settings,"database_enabled",True)
    @asynccontextmanager
    async def lease(*args,**kwargs):
        if state=="lock_error": raise RuntimeError("database unavailable")
        yield None if state=="busy" else object()
    monkeypatch.setattr(locks,"advisory_connection",lease)
    collect=AsyncMock(return_value="collected")
    if state=="collect_error": collect.side_effect=ValueError("connector failed")
    monkeypatch.setattr(module,"_collect_context_with_strategy_unlocked",collect)
    app=SimpleNamespace(state=SimpleNamespace(db_engine=SimpleNamespace(dialect=SimpleNamespace(name="mysql"))))
    alert=make_alert();incident=make_incident(alert)
    if state=="success":
        assert await module._collect_context_with_strategy(app,alert,incident,"hybrid")=="collected"
    else:
        with pytest.raises(HTTPException if state=="busy" else RuntimeError if state=="lock_error" else ValueError):
            await module._collect_context_with_strategy(app,alert,incident,"hybrid")
    assert collect.await_count==(0 if state in ("busy","lock_error") else 1)
