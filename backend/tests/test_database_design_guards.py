from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import uuid4

import pytest
from common.database import (
    ActionRecord,
    ApprovalRecord,
    ContextSnapshotRecord,
    IncidentProjectionRecord,
    ResolutionOutboxRecord,
)
from common.models import Alert, AlertSeverity, Approval, ApprovalDecision, Incident, RemediationAction
from common.outbox_context import compact_context, hydrate_context
from common.repository import IncidentRepository
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["alert", "incident", "approval", "action"])
async def test_upsert_never_reassigns_an_existing_identity_to_another_tenant(sqlite_session_factory, kind):
    incident = Incident(tenant_id="tenant-a", service="api", title="Tenant ownership")
    objects = {
        "alert": Alert(
            tenant_id="tenant-a",
            source="prometheus",
            name="Down",
            service="api",
            description="Unavailable",
            severity=AlertSeverity.HIGH,
        ),
        "incident": incident,
        "approval": Approval(
            tenant_id="tenant-a",
            incident_id=incident.id,
            recommendation_id=uuid4(),
            decision=ApprovalDecision.APPROVED,
            approver="reviewer",
        ),
        "action": RemediationAction(
            tenant_id="tenant-a", incident_id=incident.id, action_type="restart_service", target="api"
        ),
    }
    original = objects[kind]
    async with sqlite_session_factory() as session:
        repo = IncidentRepository(session)
        if kind != "incident":
            await repo.save_incident(incident)
        await getattr(repo, f"save_{kind}")(original)
        await session.commit()
        with pytest.raises(ValueError, match="tenant binding mismatch"):
            await getattr(repo, f"save_{kind}")(original.model_copy(update={"tenant_id": "tenant-b"}))
        await session.rollback()


@pytest.mark.asyncio
async def test_action_cannot_rewrite_another_tenants_projection(sqlite_session_factory):
    incident = Incident(tenant_id="tenant-a", service="api", title="Scoped incident")
    async with sqlite_session_factory() as session:
        repo = IncidentRepository(session)
        await repo.save_incident(incident)
        session.add(
            IncidentProjectionRecord(
                incident_id=incident.id,
                tenant_id="tenant-b",
                service="api",
                environment="prod",
                status="investigating",
                projection_payload={},
            )
        )
        await session.commit()
        with pytest.raises(ValueError, match="tenant binding mismatch"):
            await repo.save_action(
                RemediationAction(
                    tenant_id="tenant-a", incident_id=incident.id, action_type="restart_service", target="api"
                )
            )
        await session.rollback()
        assert (await session.get(IncidentProjectionRecord, incident.id)).status == "investigating"


@pytest.mark.asyncio
@pytest.mark.parametrize("model", [ActionRecord, ApprovalRecord])
async def test_database_rejects_cross_tenant_incident_reference(sqlite_session_factory, model):
    async with sqlite_session_factory() as session:
        await session.execute(text("PRAGMA foreign_keys=ON"))
        incident = Incident(tenant_id="tenant-a", service="api", title="Owned incident")
        await IncidentRepository(session).save_incident(incident)
        await session.commit()
        values = {"id": uuid4(), "tenant_id": "tenant-b", "incident_id": incident.id, "payload": {}}
        if model is ActionRecord:
            values.update(action_type="restart_service", target="api", status="pending")
        else:
            values.update(recommendation_id=uuid4(), decision="approved")
        session.add(model(**values))
        with pytest.raises(IntegrityError):
            await session.flush()
        await session.rollback()


async def seed_snapshot(session):
    incident_id, snapshot_id = uuid4(), uuid4()
    payload = {
        "tenant_id": "tenant-a",
        "incident_id": str(incident_id),
        "metadata": {"context_snapshot_id": str(snapshot_id)},
        "evidence": "x" * 100000,
    }
    session.add(
        ContextSnapshotRecord(
            snapshot_id=snapshot_id,
            tenant_id="tenant-a",
            incident_id=str(incident_id),
            alert_signature="a" * 64,
            subject_fingerprint="b" * 64,
            context_fingerprint="c" * 64,
            payload=payload,
            collected_at=datetime.now(UTC) - timedelta(hours=2),
            expires_at=datetime.now(UTC) - timedelta(hours=1),
        )
    )
    await session.flush()
    return incident_id, snapshot_id, {"context": payload, "transport": "rabbitmq", "decision": {"keep": "original"}}


@pytest.mark.asyncio
async def test_large_context_is_stored_once_and_reconstructed_without_rewriting_outbox(sqlite_session_factory):
    import json

    async with sqlite_session_factory() as session:
        incident, snapshot_id, payload = await seed_snapshot(session)
        compact = await compact_context(
            session, payload=payload, tenant_id="tenant-a", aggregate_id=str(incident), topic="context-initial-events"
        )
        assert len(json.dumps(compact)) < 1000
        assert "context" not in compact
        row = ResolutionOutboxRecord(
            event_id="reference-test",
            tenant_id="tenant-a",
            aggregate_id=str(incident),
            topic="context-initial-events",
            partition_key="api",
            payload=compact,
        )
        session.add(row)
        await session.commit()
        assert await hydrate_context(session, row) == payload
        await session.commit()
        await session.refresh(row)
        assert row.payload == compact
        snapshot = await session.get(ContextSnapshotRecord, snapshot_id)
        assert snapshot.expires_at.replace(tzinfo=UTC) < datetime.now(UTC)


@pytest.mark.asyncio
@pytest.mark.parametrize("tamper", ["tenant", "incident", "checksum", "missing"])
async def test_context_reference_fails_closed_on_binding_or_integrity_errors(sqlite_session_factory, tamper):
    async with sqlite_session_factory() as session:
        incident, _, payload = await seed_snapshot(session)
        compact = await compact_context(
            session, payload=payload, tenant_id="tenant-a", aggregate_id=str(incident), topic="context-events"
        )
        row = SimpleNamespace(payload=compact, tenant_id="tenant-a", aggregate_id=str(incident), topic="context-events")
        if tamper == "tenant":
            row.tenant_id = "tenant-b"
        elif tamper == "incident":
            row.aggregate_id = str(uuid4())
        elif tamper == "missing":
            compact["context_ref"]["snapshot_id"] = str(uuid4())
        else:
            compact["context_ref"]["context_sha256"] = "bad"
        with pytest.raises(ValueError, match="binding or checksum mismatch"):
            await hydrate_context(session, row)


@pytest.mark.asyncio
async def test_nonidentical_snapshot_never_replaces_original_delivery(sqlite_session_factory):
    async with sqlite_session_factory() as session:
        incident, _, payload = await seed_snapshot(session)
        payload = {**payload, "context": {**payload["context"], "extra": "must not be lost"}}
        assert (
            await compact_context(
                session, payload=payload, tenant_id="tenant-a", aggregate_id=str(incident), topic="context-events"
            )
            == payload
        )
        assert await hydrate_context(session, SimpleNamespace(payload=payload)) == payload


@pytest.mark.asyncio
async def test_late_action_writer_cannot_overwrite_newer_persisted_approval(sqlite_session_factory):
    from common.models import RemediationStatus

    incident = Incident(tenant_id="tenant-a", service="api", title="Approval retry race")
    first = Approval(
        tenant_id="tenant-a",
        incident_id=incident.id,
        recommendation_id=uuid4(),
        decision=ApprovalDecision.APPROVED,
        approver="reviewer",
    )
    second = first.model_copy(update={"id": uuid4()})
    action = RemediationAction(
        tenant_id="tenant-a",
        incident_id=incident.id,
        approval_id=first.id,
        action_type="restart_service",
        target="api",
        status=RemediationStatus.FAILED,
    )
    async with sqlite_session_factory() as session:
        repo = IncidentRepository(session)
        await repo.save_incident(incident)
        await repo.save_approval(first)
        await repo.save_approval(second)
        await session.flush()
        original_approval = await session.get(ApprovalRecord, first.id)
        original_approval.created_at = datetime.now(UTC) - timedelta(minutes=1)
        await repo.save_action(action)
        await session.commit()
        await repo.save_action(
            action.model_copy(update={"approval_id": second.id, "status": RemediationStatus.RUNNING})
        )
        await session.commit()
        with pytest.raises(ValueError, match="superseded"):
            await repo.save_action(action.model_copy(update={"status": RemediationStatus.SUCCEEDED}))
        await session.rollback()
        retained = await session.get(ActionRecord, action.id)
        assert retained.approval_id == second.id
        assert retained.status == "running"


@pytest.mark.asyncio
async def test_outbox_writer_uses_references_only_when_enabled(sqlite_session_factory, monkeypatch):
    from common.config import get_settings

    monkeypatch.setenv("OUTBOX_SNAPSHOT_REFERENCES_ENABLED", "true")
    get_settings.cache_clear()
    async with sqlite_session_factory() as session:
        incident, _, payload = await seed_snapshot(session)
        await IncidentRepository(session).enqueue_resolution_event(
            event_id="enabled-reference",
            aggregate_id=str(incident),
            topic="context-events",
            partition_key="api",
            payload=payload,
            tenant_id="tenant-a",
            available_after_seconds=0,
        )
        await session.flush()
        row = await session.get(ResolutionOutboxRecord, "enabled-reference")
        assert "context_ref" in row.payload
        assert await hydrate_context(session, row) == payload
