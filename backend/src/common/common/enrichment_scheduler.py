"""Execute a leased batch without abandoned sibling tasks or expired waiters."""
import asyncio


async def run_leased_collection_batch(jobs, process_job, on_timeout, *, timeout_seconds=90):
    async def run(job):
        try:
            await asyncio.wait_for(process_job(job), timeout=timeout_seconds)
        except asyncio.TimeoutError:
            await on_timeout(job)
    results = await asyncio.gather(*(run(job) for job in jobs), return_exceptions=True)
    # Wait for every sibling before letting the worker start another batch.
    for result in results:
        if isinstance(result, BaseException):
            raise result


class CollectionPersistenceBusy(RuntimeError):
    """Evidence collection succeeded but its database transaction must be retried."""


def transient_collection_database_error(exc):
    from sqlalchemy.exc import OperationalError
    if not isinstance(exc, OperationalError):
        return False
    args = getattr(exc.orig, "args", ())
    if args and args[0] in (1205, 1213):
        return True
    # MySQL rolls back the whole transaction on a deadlock. SQLAlchemy's
    # savepoint cleanup can then mask 1213 with 1305 (savepoint disappeared).
    # Retry the complete transaction; unrelated missing routines stay fatal.
    statement = str(getattr(exc, "statement", "") or "").strip().upper()
    return bool(args and args[0] == 1305 and statement.startswith("ROLLBACK TO SAVEPOINT"))


async def persist_collected_evidence(session_factory, operation, *, maximum_attempts=3):
    """Retry the complete rolled-back transaction without calling the connector again."""
    for attempt in range(maximum_attempts):
        try:
            async with session_factory() as session:
                result = await operation(session)
                await session.commit()
                return result
        except Exception as exc:
            if not transient_collection_database_error(exc):
                raise
            if attempt + 1 == maximum_attempts:
                raise CollectionPersistenceBusy("EVIDENCE_PERSISTENCE_BUSY") from exc
            await asyncio.sleep(0.1 * (2 ** attempt))
