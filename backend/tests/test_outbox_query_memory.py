from datetime import UTC,datetime,timedelta
import pytest
from sqlalchemy import event
from common.database import ResolutionOutboxRecord
from common.repository import IncidentRepository

@pytest.mark.asyncio
async def test_outbox_sorts_only_ids_and_preserves_due_order(sqlite_session_factory):
    now=datetime.now(UTC)
    async with sqlite_session_factory() as session:
        for name,offset,status,due in [("second",2,"pending",-1),("first",1,"retry",-1),("future",0,"pending",100),("sent",0,"published",-1)]:
            session.add(ResolutionOutboxRecord(event_id=name,tenant_id="tenant-a",aggregate_id="incident",topic="context-events",partition_key="incident",payload={"context":"x"*300000},status=status,attempts=0,created_at=now+timedelta(seconds=offset),next_attempt_at=now+timedelta(seconds=due),published_at=now if status=="published" else None))
        await session.commit()
        queries=[]
        engine=session.bind.sync_engine
        def record(conn,cursor,statement,parameters,context,executemany):queries.append(statement)
        event.listen(engine,"before_cursor_execute",record)
        try:
            rows=await IncidentRepository(session).list_pending_resolution_events(limit=2)
        finally:event.remove(engine,"before_cursor_execute",record)
        assert [row.event_id for row in rows]==["first","second"]
        assert all(len(row.payload["context"])==300000 for row in rows)
        ordered=[q for q in queries if "ORDER BY" in q]
        assert len(ordered)==1
        assert "resolution_outbox.payload" not in ordered[0]
