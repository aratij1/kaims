from unittest.mock import AsyncMock
import pytest
from resolution_agent.snapshot_retry import run_with_snapshot_refresh


@pytest.mark.asyncio
@pytest.mark.parametrize("error", ["parent context snapshot was superseded before investigation persistence", "recommendation context snapshot was superseded before persistence"])
async def test_retries_either_snapshot_race_without_losing_request_identity(error):
    old = {"context": {"snapshot": "old"}, "request_id": "request-a"}
    new = {"context": {"snapshot": "new"}, "request_id": "request-a"}
    run = AsyncMock(side_effect=[ValueError(error), None])
    refresh = AsyncMock(return_value=new)
    await run_with_snapshot_refresh(old, run, refresh)
    assert run.await_args_list[0].args == (old,)
    assert run.await_args_list[1].args == (new,)


@pytest.mark.asyncio
async def test_integrity_errors_are_not_retried():
    run = AsyncMock(side_effect=ValueError("final context snapshot tenant mismatch"))
    refresh = AsyncMock()
    with pytest.raises(ValueError, match="tenant mismatch"):
        await run_with_snapshot_refresh({}, run, refresh)
    refresh.assert_not_awaited()


@pytest.mark.asyncio
async def test_supersession_retries_remain_bounded():
    run = AsyncMock(side_effect=ValueError("context snapshot was superseded"))
    refresh = AsyncMock(return_value={})
    with pytest.raises(ValueError, match="superseded"):
        await run_with_snapshot_refresh({}, run, refresh)
    assert run.await_count == 3


def test_supersession_has_an_actionable_safe_failure_message():
    from common.errors import sanitize_handler_failure_text
    message = sanitize_handler_failure_text("parent context snapshot was superseded before investigation persistence")
    assert message == "Newer context superseded this analysis; rerun against the current evidence snapshot."
