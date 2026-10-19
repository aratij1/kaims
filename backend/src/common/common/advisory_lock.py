"""MySQL advisory ownership pinned to a physical connection across commits."""
from contextlib import asynccontextmanager
from sqlalchemy import text


@asynccontextmanager
async def advisory_connection(engine, name: str, *, wait_seconds: int = 0):
    async with engine.connect() as connection:
        acquired = False
        try:
            acquired = int(await connection.scalar(
                text("SELECT GET_LOCK(:name, :wait_seconds)"),
                {"name": name, "wait_seconds": max(0, wait_seconds)},
            ) or 0) == 1
            # End SQLAlchemy's implicit transaction while retaining the same
            # physical connection (and therefore the MySQL advisory lock).
            await connection.commit()
        except BaseException:
            # Acquisition may have succeeded before the connection was lost.
            # Never return uncertain ownership to the pool.
            await connection.invalidate()
            raise
        try:
            yield connection if acquired else None
        finally:
            if acquired:
                try:
                    await connection.rollback()
                    released = await connection.scalar(text("SELECT RELEASE_LOCK(:name)"), {"name": name})
                    await connection.commit()
                    if int(released or 0) != 1:
                        raise RuntimeError("Advisory lock ownership was lost")
                except BaseException:
                    await connection.invalidate()
                    raise


@asynccontextmanager
async def advisory_session(session_factory, name: str, *, wait_seconds: int = 0):
    # Inspect the bind without checking out a database connection. SQLite
    # keeps the existing process-local serialization used by unit/dev mode.
    async with session_factory() as session:
        engine = session.bind
        if engine is None or engine.dialect.name != "mysql":
            yield session
            return
    async with advisory_connection(engine, name, wait_seconds=wait_seconds) as connection:
        if connection is None:
            yield None
        else:
            async with session_factory(bind=connection) as session:
                yield session
