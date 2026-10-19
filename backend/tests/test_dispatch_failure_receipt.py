import importlib.util
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest


@pytest.mark.asyncio
@pytest.mark.parametrize("attempt,terminal", [(1, False), (3, True)])
async def test_exhausted_dispatch_retries_persist_failure_instead_of_staying_dispatching(
    monkeypatch, attempt, terminal
):
    path = Path("backend/src/temporal-pilot/temporal_pilot/activities.py")
    spec = importlib.util.spec_from_file_location("dispatch_failure_activities", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module.activity, "info", lambda: SimpleNamespace(attempt=attempt))
    monkeypatch.setattr(module.activity, "heartbeat", lambda *args: None)
    response = httpx.Response(
        500, json={"detail": "Executor unavailable"}, request=httpx.Request("POST", "http://executor/dispatch")
    )
    error = httpx.HTTPStatusError("unavailable", request=response.request, response=response)
    posted = AsyncMock(side_effect=[error, {"status": "failed"}])
    monkeypatch.setattr(module, "_post", posted)
    if terminal:
        assert await module.dispatch_remediation_action({"incident_id": "incident"}) == {"status": "failed"}
        assert posted.await_args_list[-1].args[1] == "/execution-failed"
        assert posted.await_args_list[-1].args[2]["phase"] == "dispatch"
    else:
        with pytest.raises(httpx.HTTPStatusError):
            await module.dispatch_remediation_action({"incident_id": "incident"})
        assert posted.await_count == 1
