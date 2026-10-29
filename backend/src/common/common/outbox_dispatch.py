"""Shared durable outbox handoff; transport success is recorded only after commit."""
import asyncio
from sqlalchemy.ext.asyncio import AsyncSession
from common.advisory_lock import advisory_connection
from common.repository import IncidentRepository
from common.outbox_context import hydrate_context


async def flush_resolution_outbox(app, settings, *, publish_timeout_seconds=10.0):
    if not settings.database_enabled or getattr(app.state, "session_factory", None) is None:
        return 0
    published = 0
    max_attempts = max(1, int(getattr(settings, "resolution_outbox_max_attempts", 5) or 5))
    batch_size = min(20, max(1, int(getattr(settings, "resolution_outbox_batch_size", 20) or 20)))
    async with advisory_connection(app.state.db_engine, "kaiops_resolution_outbox_dispatch") as connection:
        if connection is None:
            return 0
        async with AsyncSession(bind=connection, expire_on_commit=False) as session:
            repo = IncidentRepository(session)
            if await repo.dead_letter_exhausted_resolution_events(max_attempts=max_attempts):
                await session.commit()
            rows = await repo.list_pending_resolution_events(
                limit=batch_size, max_attempts=max_attempts)
            publishers = getattr(app.state, "message_bus_publishers", {})
            for row in rows:
                provider = str(row.payload.get("transport") or "").strip().lower()
                publisher = publishers.get(provider) or publishers.get("rabbitmq") or app.state.producer
                try:
                    payload = await hydrate_context(session, row)
                    await asyncio.wait_for(publisher.publish(row.topic, payload, key=row.partition_key),
                                           timeout=publish_timeout_seconds)
                except Exception as error:
                    await repo.mark_resolution_event_retry(
                        row.event_id, str(error) or type(error).__name__, max_attempts=max_attempts,
                    )
                    await session.commit()
                else:
                    # A persistence error propagates: the pending row remains
                    # replayable. Do not treat a failed DB transaction as a
                    # broker failure and attempt more writes in that transaction.
                    await repo.mark_resolution_event_published(row.event_id)
                    await session.commit()
                    published += 1
    return published
