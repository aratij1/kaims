from __future__ import annotations

from uuid import uuid4

import pytest
from common.repository import IncidentRepository


@pytest.mark.asyncio
async def test_runbook_approval_cannot_mutate_another_tenants_version(sqlite_session_factory) -> None:
    runbook_id = str(uuid4())
    async with sqlite_session_factory() as session:
        repository = IncidentRepository(session)
        await repository.approve_runbook_version(
            runbook_id=runbook_id,
            version=1,
            approved_by="reviewer-a@example.test",
            tenant_id="tenant-a",
            payload={
                "title": "Tenant A runbook",
                "markdown": "# Tenant A approved guidance",
                "service": "service-a",
                "reviewed_by": "independent-reviewer@example.test",
            },
        )
        await session.commit()

        with pytest.raises(PermissionError, match="different tenant"):
            await repository.approve_runbook_version(
                runbook_id=runbook_id,
                version=1,
                approved_by="operator-b@example.test",
                tenant_id="tenant-b",
                payload={
                    "title": "Tenant B overwrite",
                    "markdown": "# Unauthorized content",
                    "service": "service-b",
                    "reviewed_by": "independent-operator@example.test",
                },
            )

        tenant_a_governance = await repository.get_runbook_governance(
            runbook_id,
            version=1,
            tenant_id="tenant-a",
        )

    assert tenant_a_governance is not None
    assert tenant_a_governance["payload"]["title"] == "Tenant A runbook"
    assert tenant_a_governance["payload"]["markdown"] == "# Tenant A approved guidance"
