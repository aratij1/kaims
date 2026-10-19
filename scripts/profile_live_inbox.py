"""Read-only inbox query timings; run inside a KaiMS service runtime."""
import asyncio, time, json
from sqlalchemy import event
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from common.config import Settings
from common.repository import IncidentRepository

async def main():
    engine = create_async_engine(Settings().database_url)
    @event.listens_for(engine.sync_engine, "before_cursor_execute")
    def before(conn, cursor, statement, params, context, many):
        context.started = time.monotonic()
        print("START " + " ".join(statement.split())[:240], flush=True)
    @event.listens_for(engine.sync_engine, "after_cursor_execute")
    def after(conn, cursor, statement, params, context, many):
        print("END %.3f" % (time.monotonic() - context.started), flush=True)
    try:
        async with async_sessionmaker(engine)() as session:
            started = time.monotonic()
            result = await asyncio.wait_for(IncidentRepository(session).list_unified_inbox(
                tenant_id="default", project_id="KaiMS", record_type="all", limit=100, inbox_view="kai_handling"), 100)
            print(json.dumps({"rows": len(result["rows"]), "filtered_count": result["filtered_count"], "seconds": time.monotonic()-started}))
    finally:
        await engine.dispose()
if __name__ == "__main__":
    asyncio.run(main())
