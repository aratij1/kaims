from contextlib import asynccontextmanager
from types import SimpleNamespace
from unittest.mock import AsyncMock
import pytest
from sqlalchemy.exc import OperationalError
from common.enrichment_scheduler import persist_collected_evidence, transient_collection_database_error

def test_only_lost_rollback_savepoints_are_transient():
 assert transient_collection_database_error(OperationalError('ROLLBACK TO SAVEPOINT sa_savepoint_1',{},Exception(1305,'SAVEPOINT does not exist')))
 assert not transient_collection_database_error(OperationalError('CALL missing_procedure()',{},Exception(1305,'PROCEDURE does not exist')))

@pytest.mark.asyncio
async def test_savepoint_loss_retries_the_complete_transaction():
 sessions=[]
 @asynccontextmanager
 async def factory():
  session=SimpleNamespace(commit=AsyncMock());sessions.append(session);yield session
 operation=AsyncMock(side_effect=[OperationalError('ROLLBACK TO SAVEPOINT sa_savepoint_1',{},Exception(1305,'SAVEPOINT does not exist')),{'accepted':True}])
 assert await persist_collected_evidence(factory,operation)=={'accepted':True}
 assert len(sessions)==2
 sessions[0].commit.assert_not_awaited()
 sessions[1].commit.assert_awaited_once()
