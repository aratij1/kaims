from __future__ import annotations

import asyncio
import os

from datetime import datetime, timezone
from uuid import UUID

from common.config import get_settings
from common.database import IncidentProjectionRecord
from common.event_publishers import build_event_consumer, build_orchestration_envelope, selected_event_bus_provider
from common.repository import IncidentRepository
from common.logging import get_logger
from common.models import Alert, Incident
from common.rabbitmq import RabbitMQConsumer, consume_forever as consume_rabbitmq_forever
from common.service import create_app
from common.telemetry import EVENTS_PROCESSED
from common.topics import ENRICHED_ALERTS, INCIDENT_LIFECYCLE_EVENTS, ORCHESTRATION_EVENTS
from fastapi import FastAPI, HTTPException
from sqlalchemy import select
from orchestrator.message_bus import publish_orchestration_event
from orchestrator import OrchestratorAgent

settings = get_settings()
settings.service_name = "orchestrator"
agent = OrchestratorAgent()
tasks: list[asyncio.Task] = []
logger = get_logger(__name__)
MESSAGE_BUS_DUAL_CONSUME_ENABLED = str(
    os.getenv("MESSAGE_BUS_DUAL_CONSUME_ENABLED", "false")
).strip().lower() in {"1", "true", "yes", "on"}


async def _persist_orchestration_event(app: FastAPI, envelope: dict) -> None:
    session_factory = getattr(app.state, "session_factory", None)
    if session_factory is None:
        raise RuntimeError("orchestrator database session factory unavailable")

    async with session_factory() as session:
        repo = IncidentRepository(session)
        await repo.save_incident_event(envelope)
        await session.commit()


async def record_orchestrator_lifecycle_transition(app: FastAPI, payload: dict) -> None:
    tenant_id = str(payload.get("tenant_id") or "default").strip()
    incident_id_str = str(payload.get("incident_id") or "").strip()
    new_state = str(payload.get("new_state") or "").strip().upper()
    version = int(payload.get("version") or 0)
    failure_code = payload.get("failure_code")
    reason = payload.get("reason")
    if not incident_id_str or not new_state:
        return
    try:
        incident_uuid = UUID(incident_id_str)
    except ValueError:
        return

    session_factory = getattr(app.state, "session_factory", None)
    if session_factory is None:
        return

    async with session_factory() as session:
        projection = await session.scalar(
            select(IncidentProjectionRecord)
            .where(
                IncidentProjectionRecord.tenant_id == tenant_id,
                IncidentProjectionRecord.incident_id == incident_uuid,
            )
            .with_for_update()
        )
        if projection is not None:
            current_ver = int(projection.lifecycle_version or 1)
            if version >= current_ver:
                projection.lifecycle_state = new_state
                projection.lifecycle_version = version
                if failure_code:
                    projection.lifecycle_failure_code = str(failure_code)
                    projection.lifecycle_failure_reason = str(reason or "")

                state_to_status = {
                    "DETECTED": "open",
                    "REQUIREMENTS_IDENTIFIED": "investigating",
                    "COLLECTING": "collecting",
                    "CONTEXT_READY": "investigating",
                    "INVESTIGATING": "investigating",
                    "WAITING_FOR_HUMAN": "waiting_for_human",
                    "RCA_READY": "rca_ready",
                    "AWAITING_APPROVAL": "awaiting_approval",
                    "PLAN_READY": "approved",
                    "EXECUTING": "remediating",
                    "VALIDATING": "validating",
                    "CLOSED": "closed",
                    "FAILED": "failed",
                    "DEAD_LETTER": "failed",
                }
                mapped_status = state_to_status.get(new_state)
                if mapped_status:
                    projection.status = mapped_status
                projection.updated_at = datetime.now(timezone.utc)
                await session.commit()


def _build_ingress_consumers() -> list[tuple[str, object, object]]:
    workers = max(1, int(getattr(settings, "message_bus_worker_count", 1) or 1))
    consumers: list[tuple[str, object, object]] = []
    for worker in range(workers):
        consumer, loop, provider = build_event_consumer(settings, ENRICHED_ALERTS)
        consumers.append((f"{provider}-w{worker + 1}", consumer, loop))
    return consumers


async def startup(app: FastAPI) -> None:
    app.state.temporal_client = None
    if settings.temporal_pilot_enabled:
        from temporalio.client import Client

        app.state.temporal_client = await Client.connect(
            settings.temporal_address,
            namespace=settings.temporal_namespace,
        )
    app.state.message_bus_provider = selected_event_bus_provider(settings)

    async def handle(payload: dict) -> None:
        alert = Alert.model_validate(payload["alert"])
        incident = Incident.model_validate(payload["incident"])
        decision = await agent.decide_workflow_async_with_runtime(alert, incident)
        transport_provider = app.state.message_bus_provider
        event_envelope = build_orchestration_envelope(
            alert=alert,
            incident=incident,
            decision=decision.__dict__,
            transport_provider=transport_provider,
            channel=ORCHESTRATION_EVENTS,
        )
        try:
            await _persist_orchestration_event(app, event_envelope)
        except Exception:
            logger.exception("orchestrator metadata persistence failed")
            # Let durable delivery retry. Publishing and acknowledging here
            # would advance the workflow without its recorded decision.
            raise
        if settings.temporal_pilot_enabled:
            workflow_id = f"kaiops-incident-{incident.id}"
            try:
                await app.state.temporal_client.start_workflow(
                    "KaiOpsIncidentPilotWorkflow",
                    {
                        "alert": alert.model_dump(mode="json"),
                        "incident": incident.model_dump(mode="json"),
                        "decision": decision.__dict__,
                        "trace_id": str(alert.trace_id or ""),
                        "approval_timeout_hours": settings.temporal_approval_timeout_hours,
                    },
                    id=workflow_id,
                    task_queue=settings.temporal_task_queue,
                )
            except Exception as exc:
                if "already started" not in str(exc).lower():
                    raise
                logger.info("temporal pilot workflow already started", extra={"workflow_id": workflow_id})
            EVENTS_PROCESSED.labels(settings.service_name, f"{ENRICHED_ALERTS}:temporal", "ok").inc()
            return

        provider_used = await publish_orchestration_event(
            producer=app.state.producer,
            publishers={app.state.message_bus_provider: app.state.producer},
            topic=ORCHESTRATION_EVENTS,
            alert=alert,
            incident=incident,
            decision=decision.__dict__,
            deployment_provider=app.state.message_bus_provider,
        )
        EVENTS_PROCESSED.labels(settings.service_name, f"{ENRICHED_ALERTS}:{provider_used}", "ok").inc()

    for source, consumer, consume_forever in _build_ingress_consumers():
        task = asyncio.create_task(consume_forever(consumer, handle), name=f"orchestrator-{source}-consumer")
        tasks.append(task)

    lifecycle_consumer = RabbitMQConsumer(settings, INCIDENT_LIFECYCLE_EVENTS)
    async def handle_lifecycle(payload: dict) -> None:
        await record_orchestrator_lifecycle_transition(app, payload)
    tasks.append(asyncio.create_task(consume_rabbitmq_forever(lifecycle_consumer, handle_lifecycle), name="orchestrator-lifecycle"))


async def shutdown(app: FastAPI) -> None:
    for task in tasks:
        task.cancel()
    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)
    tasks.clear()


app = create_app(title="KaiMS Orchestrator", settings=settings, startup=startup, shutdown=shutdown)


def _temporal_handle(incident_id: str):
    client = getattr(app.state, "temporal_client", None)
    if not settings.temporal_pilot_enabled or client is None:
        raise HTTPException(status_code=503, detail="Temporal pilot is not enabled")
    return client.get_workflow_handle(f"kaiops-incident-{incident_id}")


@app.post("/temporal/workflows/{incident_id}/approval")
async def signal_temporal_approval(incident_id: str, payload: dict) -> dict:
    await _temporal_handle(incident_id).signal("approval", payload)
    return {"signaled": True, "incident_id": incident_id}


@app.post("/temporal/workflows/{incident_id}/cancel")
async def signal_temporal_cancel(incident_id: str, payload: dict | None = None) -> dict:
    await _temporal_handle(incident_id).signal("cancel", str((payload or {}).get("reason") or "operator requested cancellation"))
    return {"signaled": True, "incident_id": incident_id}


@app.get("/temporal/workflows/{incident_id}/status")
async def query_temporal_status(incident_id: str) -> dict:
    return await _temporal_handle(incident_id).query("status")


@app.post("/decide")
async def decide(payload: dict) -> dict:
    alert = Alert.model_validate(payload["alert"])
    incident = Incident.model_validate(payload["incident"])
    return (await agent.decide_workflow_async_with_runtime(alert, incident)).__dict__
