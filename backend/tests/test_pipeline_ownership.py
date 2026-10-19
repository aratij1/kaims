import asyncio
from contextlib import asynccontextmanager
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock
import pytest
from common.advisory_lock import advisory_connection
import common.outbox_dispatch as dispatch


def engine_and_connection(results):
    connection=SimpleNamespace(scalar=AsyncMock(side_effect=results),commit=AsyncMock(),rollback=AsyncMock(),invalidate=AsyncMock())
    @asynccontextmanager
    async def connect(): yield connection
    return SimpleNamespace(connect=connect),connection

@pytest.mark.asyncio
@pytest.mark.parametrize("result", [0,None])
async def test_busy_lock_never_releases_another_owner(result):
    engine,connection=engine_and_connection([result])
    async with advisory_connection(engine,"busy") as held:
        assert held is None
    assert connection.scalar.await_count==1
    connection.invalidate.assert_not_awaited()

@pytest.mark.asyncio
async def test_lock_survives_commits_and_releases_on_same_connection():
    engine,connection=engine_and_connection([1,1])
    async with advisory_connection(engine,"owned") as held:
        assert held is connection
        await held.commit()
        await held.commit()
    assert connection.scalar.await_count==2
    assert "GET_LOCK" in str(connection.scalar.await_args_list[0].args[0])
    assert "RELEASE_LOCK" in str(connection.scalar.await_args_list[1].args[0])
    connection.invalidate.assert_not_awaited()

@pytest.mark.asyncio
@pytest.mark.parametrize("failure", [RuntimeError("collection failed"),asyncio.CancelledError()])
async def test_work_failure_releases_ownership_and_propagates(failure):
    engine,connection=engine_and_connection([1,1])
    with pytest.raises(type(failure)):
        async with advisory_connection(engine,"owned"):
            raise failure
    assert connection.scalar.await_count==2

@pytest.mark.asyncio
@pytest.mark.parametrize("results", [[RuntimeError("acquire failed")],[1,0],[1,RuntimeError("release failed")]])
async def test_uncertain_ownership_invalidates_physical_connection(results):
    engine,connection=engine_and_connection(results)
    with pytest.raises(RuntimeError):
        async with advisory_connection(engine,"owned"): pass
    connection.invalidate.assert_awaited_once()

@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["none","publish_error","publish_hang","database_error","commit_error"])
async def test_outbox_commits_published_state_only_after_transport_success(monkeypatch,failure):
    connection=object()
    @asynccontextmanager
    async def owned(*args,**kwargs): yield connection
    monkeypatch.setattr(dispatch,"advisory_connection",owned)
    session=SimpleNamespace(commit=AsyncMock())
    @asynccontextmanager
    async def session_factory(**kwargs):
        assert kwargs["bind"] is connection
        yield session
    monkeypatch.setattr(dispatch,"AsyncSession",session_factory)
    repo=SimpleNamespace(list_pending_resolution_events=AsyncMock(return_value=[SimpleNamespace(topic="context-events",payload={},partition_key="incident",event_id="event")]),mark_resolution_event_published=AsyncMock(),mark_resolution_event_retry=AsyncMock())
    monkeypatch.setattr(dispatch,"IncidentRepository",lambda session:repo)
    async def publish(*args,**kwargs):
        if failure=="publish_error": raise ConnectionError("broker unavailable")
        if failure=="publish_hang": await asyncio.Event().wait()
    producer=SimpleNamespace(publish=AsyncMock(side_effect=publish))
    app=SimpleNamespace(state=SimpleNamespace(db_engine=object(),session_factory=object(),producer=producer))
    settings=SimpleNamespace(database_enabled=True,resolution_outbox_batch_size=5)
    if failure=="database_error": repo.mark_resolution_event_published.side_effect=RuntimeError("DB write failed")
    if failure=="commit_error": session.commit.side_effect=RuntimeError("DB commit failed")
    if failure in ("database_error","commit_error"):
        with pytest.raises(RuntimeError): await dispatch.flush_resolution_outbox(app,settings,publish_timeout_seconds=0.02)
        repo.mark_resolution_event_retry.assert_not_awaited()
    else:
        count=await dispatch.flush_resolution_outbox(app,settings,publish_timeout_seconds=0.02)
        assert count==(1 if failure=="none" else 0)
        assert repo.mark_resolution_event_published.await_count==(1 if failure=="none" else 0)
        assert repo.mark_resolution_event_retry.await_count==(0 if failure=="none" else 1)

@pytest.mark.asyncio
async def test_busy_dispatcher_does_not_publish(monkeypatch):
    @asynccontextmanager
    async def busy(*args,**kwargs): yield None
    monkeypatch.setattr(dispatch,"advisory_connection",busy)
    producer=SimpleNamespace(publish=AsyncMock())
    app=SimpleNamespace(state=SimpleNamespace(db_engine=object(),session_factory=object(),producer=producer))
    assert await dispatch.flush_resolution_outbox(app,SimpleNamespace(database_enabled=True))==0
    producer.publish.assert_not_awaited()
