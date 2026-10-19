from __future__ import annotations

import importlib.util
from datetime import timedelta
from pathlib import Path
import sys

import pytest
from ai_workbench_common.models import Context
from common.database import ContextSnapshotRecord, ResolutionOutboxRecord
from common.repository import IncidentRepository
from common.models import Alert, AlertSeverity, Incident
from context_agent.context_quality import context_subject_fingerprint, govern_context
from sqlalchemy import func, select


def load_context_app_module():
    module_name = "context_agent_snapshot_app"
    if module_name in sys.modules:
        return sys.modules[module_name]
    path = Path("ai-workbench/src/context-agent/app.py")
    spec = importlib.util.spec_from_file_location(module_name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


@pytest.mark.asyncio
@pytest.mark.parametrize("lane", ["background", "initial"])
async def test_context_snapshot_and_outbox_are_committed_once(sqlite_session_factory, lane) -> None:
    module = load_context_app_module()
    module.settings.database_enabled = True
    module.app.state.session_factory = sqlite_session_factory
    alert = Alert(
        tenant_id="tenant-a",
        source="prometheus",
        name="CheckoutErrorRateHigh",
        service="checkout",
        environment="prod",
        severity=AlertSeverity.HIGH,
        description="checkout HTTP 5xx rate is elevated",
        metadata={"tenant_id": "tenant-a", "observability": {"http_5xx_rate": 0.08}},
    )
    incident = Incident(tenant_id=alert.tenant_id, service=alert.service, environment=alert.environment, severity=alert.severity, title=alert.name)
    context = govern_context(
        Context(
            tenant_id=alert.tenant_id,
            incident_id=incident.id,
            alert=alert,
            observability={"http_5xx_rate": 0.08},
            runbook="Inspect checkout errors and verify recovery before making a change.",
            metadata={"context_signature": "a" * 64},
        ),
        tenant_id="tenant-a",
        subject_fingerprint=context_subject_fingerprint(alert, "tenant-a"),
    )
    context.metadata["context_delivery_lane"] = lane
    outgoing = module._build_context_event_payload(
        alert=alert,
        incident=incident,
        context=context,
        decision={"flow_id": str(incident.id)},
        provider_used="rabbitmq",
    )

    first = await module._persist_context_event(
        app=module.app,
        alert=alert,
        incident=incident,
        context=context,
        decision={"flow_id": str(incident.id)},
        provider_used="rabbitmq",
        outgoing_payload=outgoing,
    )
    second = await module._persist_context_event(
        app=module.app,
        alert=alert,
        incident=incident,
        context=context,
        decision={"flow_id": str(incident.id)},
        provider_used="rabbitmq",
        outgoing_payload=outgoing,
    )

    async with sqlite_session_factory() as session:
        snapshots = await session.scalar(select(func.count()).select_from(ContextSnapshotRecord))
        outbox_rows = await session.scalar(select(func.count()).select_from(ResolutionOutboxRecord))
        snapshot = (await session.execute(select(ContextSnapshotRecord))).scalar_one()
        outbox = (await session.execute(select(ResolutionOutboxRecord))).scalar_one()
    assert first is True
    assert second is False
    assert snapshots == 1
    assert outbox_rows == 1
    assert outbox.topic == ("context-initial-events" if lane == "initial" else "context-events")
    assert outgoing["event_contract"]["payload"]["topic"] == outbox.topic
    assert snapshot.context_fingerprint == context.metadata["context_fingerprint"]
    assert snapshot.contract_version == "kaiops.context.v2"
    assert snapshot.expires_at >= snapshot.collected_at + timedelta(
        seconds=module.settings.context_knowledge_ttl_seconds
    )


@pytest.mark.asyncio
async def test_regeneration_preserves_prior_snapshot_and_binds_new_generation(sqlite_session_factory) -> None:
    module = load_context_app_module()
    module.settings.database_enabled = True
    module.app.state.session_factory = sqlite_session_factory
    alert = Alert(
        tenant_id="tenant-a", source="prometheus", name="CheckoutErrors", service="checkout",
        environment="prod", severity=AlertSeverity.HIGH, description="checkout errors",
    )
    incident = Incident(
        tenant_id=alert.tenant_id, service=alert.service, environment=alert.environment,
        severity=alert.severity, title=alert.name,
    )
    base = govern_context(
        Context(tenant_id=alert.tenant_id, incident_id=incident.id, alert=alert),
        tenant_id="tenant-a",
        subject_fingerprint=context_subject_fingerprint(alert, "tenant-a"),
    )
    snapshot_ids: list[str] = []
    for request_id in ("request-v1", "request-v2"):
        context = base.model_copy(update={"metadata": {**base.metadata, "analysis_request_id": request_id}})
        outgoing = module._build_context_event_payload(
            alert=alert, incident=incident, context=context,
            decision={"flow_id": str(incident.id)}, provider_used="rabbitmq",
        )
        assert await module._persist_context_event(
            app=module.app, alert=alert, incident=incident, context=context,
            decision={"flow_id": str(incident.id)}, provider_used="rabbitmq", outgoing_payload=outgoing,
        ) is True
        snapshot_ids.append(outgoing["context"]["metadata"]["context_snapshot_id"])

    async with sqlite_session_factory() as session:
        snapshots = (await session.execute(select(ContextSnapshotRecord))).scalars().all()

    assert len(snapshots) == 2
    assert snapshot_ids[0] != snapshot_ids[1]
    assert {str(row.snapshot_id) for row in snapshots} == set(snapshot_ids)
    snapshots_by_version = sorted(snapshots, key=lambda row: row.snapshot_version)
    assert [row.snapshot_version for row in snapshots_by_version] == [1, 2]
    assert snapshots_by_version[1].parent_snapshot_id == snapshots_by_version[0].snapshot_id


@pytest.mark.asyncio
async def test_snapshot_persists_when_event_publication_is_disabled(sqlite_session_factory) -> None:
    module = load_context_app_module()
    module.settings.database_enabled = True
    module.app.state.session_factory = sqlite_session_factory
    alert = Alert(
        tenant_id="tenant-a", source="prometheus", name="CheckoutErrors", service="checkout",
        environment="prod", severity=AlertSeverity.HIGH, description="checkout errors",
    )
    incident = Incident(
        tenant_id=alert.tenant_id, service=alert.service, environment=alert.environment,
        severity=alert.severity, title=alert.name,
    )
    context = govern_context(
        Context(tenant_id=alert.tenant_id, incident_id=incident.id, alert=alert),
        tenant_id="tenant-a",
        subject_fingerprint=context_subject_fingerprint(alert, "tenant-a"),
    )
    outgoing = module._build_context_event_payload(
        alert=alert, incident=incident, context=context,
        decision={"flow_id": str(incident.id)}, provider_used="rabbitmq",
    )

    enqueued = await module._persist_context_event(
        app=module.app, alert=alert, incident=incident, context=context,
        decision={"flow_id": str(incident.id)}, provider_used="rabbitmq",
        outgoing_payload=outgoing, enqueue_event=False,
    )

    async with sqlite_session_factory() as session:
        snapshots = await session.scalar(select(func.count()).select_from(ContextSnapshotRecord))
        outbox_rows = await session.scalar(select(func.count()).select_from(ResolutionOutboxRecord))
    assert enqueued is False
    assert snapshots == 1
    assert outbox_rows == 0
    assert context.metadata["context_snapshot_id"] == outgoing["context"]["metadata"]["context_snapshot_id"]

    async with sqlite_session_factory() as session:
        repo = IncidentRepository(session)
        exact = await repo.context_snapshot_by_id(
            context.metadata["context_snapshot_id"], tenant_id="tenant-a", incident_id=incident.id,
        )
        wrong_tenant = await repo.context_snapshot_by_id(
            context.metadata["context_snapshot_id"], tenant_id="tenant-b", incident_id=incident.id,
        )
    assert exact is not None
    assert exact["context_fingerprint"] == context.metadata["context_fingerprint"]
    assert wrong_tenant is None


@pytest.mark.asyncio
async def test_final_investigation_snapshot_preserves_context_reusability(sqlite_session_factory) -> None:
    module = load_context_app_module()
    module.settings.database_enabled = True
    module.app.state.session_factory = sqlite_session_factory
    alert = Alert(
        tenant_id="tenant-a", source="prometheus", name="CheckoutLatency", service="checkout",
        environment="prod", severity=AlertSeverity.HIGH, description="checkout latency is above 2s",
    )
    incident = Incident(
        tenant_id=alert.tenant_id, service=alert.service, environment=alert.environment,
        severity=alert.severity, title=alert.name,
    )
    context = govern_context(Context(
        tenant_id=alert.tenant_id,
        incident_id=incident.id,
        alert=alert,
        observability={"query": "checkout_latency_seconds > 2", "series": [{"value": 2.4}]},
        runbook="Inspect checkout latency before selecting a remediation.",
    ), tenant_id="tenant-a", subject_fingerprint=context_subject_fingerprint(alert, "tenant-a"))
    assert context.metadata["context_quality"]["reusable"] is True
    outgoing = module._build_context_event_payload(
        alert=alert, incident=incident, context=context,
        decision={"flow_id": str(incident.id)}, provider_used="rabbitmq",
    )
    await module._persist_context_event(
        app=module.app, alert=alert, incident=incident, context=context,
        decision={"flow_id": str(incident.id)}, provider_used="rabbitmq",
        outgoing_payload=outgoing, enqueue_event=False,
    )

    async with sqlite_session_factory() as session:
        parent = (await session.execute(select(ContextSnapshotRecord))).scalar_one()
        final = await IncidentRepository(session).persist_final_investigation_snapshot(
            context=context,
            report={"status": "insufficient_evidence", "evidence": []},
            parent_snapshot_id=parent.snapshot_id,
        )

        with pytest.raises(ValueError, match="parent context snapshot was superseded"):
            await IncidentRepository(session).persist_final_investigation_snapshot(
                context=context, report={"status": "insufficient_evidence"}, parent_snapshot_id=parent.snapshot_id,
            )

    assert parent.reusable is True
    assert final.reusable is True
    assert final.snapshot_stage == "investigation_complete"
