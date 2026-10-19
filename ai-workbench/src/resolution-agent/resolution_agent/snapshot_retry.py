"""Bounded retry of an immutable analysis when newer context wins a race."""
from collections.abc import Awaitable, Callable
from typing import Any


async def run_with_snapshot_refresh(
    payload: dict[str, Any],
    run: Callable[[dict[str, Any]], Awaitable[Any]],
    refresh: Callable[[dict[str, Any]], Awaitable[dict[str, Any] | None]],
    *, max_attempts: int = 3,
) -> Any:
    for attempt in range(max(1, max_attempts)):
        try:
            return await run(payload)
        except ValueError as error:
            # Do not retry schema, tenant, evidence-integrity, or policy errors.
            if "context snapshot was superseded" not in str(error) or attempt + 1 >= max_attempts:
                raise
            replacement = await refresh(payload)
            if replacement is None:
                raise
            payload = replacement
