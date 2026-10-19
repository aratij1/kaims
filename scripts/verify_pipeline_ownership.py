"""Read-only MySQL test: unique advisory locks, SELECTs, no business writes."""
import asyncio
import json
from uuid import uuid4
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession,async_sessionmaker,create_async_engine
from common.config import Settings
from common.advisory_lock import advisory_connection,advisory_session

async def main():
    engine=create_async_engine(Settings().database_url,pool_size=3,max_overflow=0)
    factory=async_sessionmaker(engine,expire_on_commit=False)
    name="kaims-review-"+uuid4().hex
    try:
        async with advisory_connection(engine,name) as connection:
            assert connection is not None
            identity=await connection.scalar(text("SELECT CONNECTION_ID()"))
            await connection.commit()
            async with AsyncSession(bind=connection,expire_on_commit=False) as session:
                await session.execute(text("SELECT 1"));await session.commit()
                await session.execute(text("SELECT 1"));await session.commit()
            async with advisory_connection(engine,name) as competing:
                assert competing is None
            assert await connection.scalar(text("SELECT CONNECTION_ID()"))==identity
        async with advisory_session(factory,name) as session:
            assert session is not None
            identity=await session.scalar(text("SELECT CONNECTION_ID()"));await session.commit()
            async with advisory_session(factory,name) as competing:
                assert competing is None
            assert await session.scalar(text("SELECT CONNECTION_ID()"))==identity
        async with advisory_connection(engine,name) as connection:
            assert connection is not None
        print(json.dumps({"same_connection_across_commits":True,"concurrent_owner_blocked":True,"lock_reacquired_after_release":True,"orm_session_ownership_verified":True,"business_writes":0}))
    finally:
        await engine.dispose()

if __name__=="__main__":asyncio.run(main())
