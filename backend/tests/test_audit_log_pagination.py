from datetime import UTC, datetime, timedelta
from uuid import uuid4
import pytest
from api_gateway.modules.users.repository import UserRepository
from common.database import AuditLogRecord


@pytest.mark.asyncio
async def test_audit_pages_filter_and_preserve_payload_without_sorting_bodies(sqlite_session_factory):
    now = datetime.now(UTC)
    async with sqlite_session_factory() as session:
        for index in range(4):
            session.add(AuditLogRecord(id=uuid4(), tenant_id="tenant-a", actor="test", action="rca" if index % 2 else "login",
                resource_type="incident", resource_id=str(index), payload={"sequence": index, "body": "evidence" * 10000},
                created_at=now + timedelta(seconds=index)))
        await session.flush()
        repo = UserRepository(session)
        first, total = await repo.list_audit_logs(page=1, page_size=2, action=None)
        second, _ = await repo.list_audit_logs(page=2, page_size=2, action=None)
        assert total == 4
        assert [row.payload["sequence"] for row in first + second] == [3, 2, 1, 0]
        filtered, total = await repo.list_audit_logs(page=1, page_size=2, action="rca")
        assert total == 2
        assert [row.payload["sequence"] for row in filtered] == [3, 1]
