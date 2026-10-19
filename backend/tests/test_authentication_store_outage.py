from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import HTTPException
from sqlalchemy.exc import OperationalError, TimeoutError

from api_gateway.modules.users.repository import run_in_session


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", [
    OperationalError("SELECT private", {}, Exception(2003, "private connection details")),
    OperationalError("SELECT private", {}, Exception(2013, "lost connection")),
    TimeoutError("private pool details"),
])
async def test_authentication_connection_outage_is_retryable_and_sanitized(failure):
    session = AsyncMock()
    factory = MagicMock()
    factory.return_value.__aenter__ = AsyncMock(return_value=session)
    factory.return_value.__aexit__ = AsyncMock(return_value=False)
    operation = AsyncMock(side_effect=failure)

    with pytest.raises(HTTPException) as result:
        await run_in_session(factory, operation)

    assert result.value.status_code == 503
    assert result.value.detail["code"] == "authentication_store_unavailable"
    assert result.value.detail["retryable"] is True
    assert "private" not in str(result.value.detail)
    assert result.value.headers["Retry-After"] == "5"
    session.rollback.assert_awaited_once()
    session.commit.assert_not_awaited()


@pytest.mark.asyncio
async def test_unrelated_database_failure_is_not_classified_as_connection_outage():
    failure = OperationalError("query", {}, Exception(1054, "unknown column"))
    session = AsyncMock()
    factory = MagicMock()
    factory.return_value.__aenter__ = AsyncMock(return_value=session)
    factory.return_value.__aexit__ = AsyncMock(return_value=False)
    with pytest.raises(OperationalError) as result:
        await run_in_session(factory, AsyncMock(side_effect=failure))
    assert result.value is failure
