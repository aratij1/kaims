from __future__ import annotations

import asyncio
from time import perf_counter
from uuid import NAMESPACE_URL, UUID, uuid5

from common.config import get_settings
from common.logging import get_logger
from common.models import MonitoringAuditEvent
from common.database import AuditLogRecord, ResolutionOutboxRecord
from common.rabbitmq import RabbitMQConsumer, consume_forever as consume_rabbitmq_forever
from common.repository import IncidentRepository
from common.service import create_app
from common.topics import (
    CLOSURE_EVENTS,
    APPLICATION_DASHBOARD_CREATED,
    APPLICATION_DISCOVERY_COMPLETED,
    APPLICATION_METRICS_VALIDATED,
    APPLICATION_ONBOARD_REQUESTED,
    APPLICATION_PROMETHEUS_UPDATED,
    APPLICATION_RULES_GENERATED,
    APPLICATION_VALIDATION_COMPLETED,
)
from fastapi import FastAPI

settings = get_settings()
settings.service_name = "audit-service"
logger = get_logger(__name__)
tasks: list[asyncio.Task] = []

# Control-plane audit events deliberately use a separate topic from the
# recommendation messages consumed by remediation-engine.
RESOLUTION_PLAN_EVENTS = "resolution.events"


async def record_resolution_plan_event(app: FastAPI, payload: dict) -> None:
    event_type = payload.get("event_type")
    if event_type == "incident.resolution.plan.selected":
        plan = payload.get("resolution_selection") or {}
        prefix = "resolution-plan-selected"
    elif event_type == "incident.resolution.plan.compiled":
        plan = payload.get("execution_plan") or {}
        prefix = "execution-plan-compiled"
    else:
        raise ValueError("Unsupported resolution plan audit event")
    identity_key = "selection_id" if prefix == "resolution-plan-selected" else "plan_id"
    plan_id = str(UUID(str(plan.get(identity_key) or "")))
    incident_id = str(UUID(str(payload.get("incident_id") or "")))
    tenant = str(payload.get("tenant_id") or "").strip()
    if not tenant:
        raise ValueError("Resolution audit requires tenant identity")
    event_id = f"{prefix}:{plan_id}"
    audit_id = uuid5(NAMESPACE_URL, f"resolution-plan-audit:{tenant}:{event_id}")
    async with app.state.session_factory() as session:
        # The producer writes this immutable event in the plan transaction.
        # Locking it also serializes concurrent redeliveries of this receipt.
        source = await session.get(ResolutionOutboxRecord, event_id, with_for_update=True)
        if (source is None or source.tenant_id != tenant
                or source.aggregate_id != incident_id or source.topic != RESOLUTION_PLAN_EVENTS
                or source.payload != payload):
            raise ValueError("Resolution audit does not match its durable source event")
        if await session.get(AuditLogRecord, audit_id) is None:
            session.add(AuditLogRecord(
                id=audit_id, tenant_id=tenant, actor="audit-service",
                action=f"{event_type}.delivered", resource_type="incident",
                resource_id=incident_id,
                payload={"event_id": event_id, "plan_id": plan_id, "delivery_verified": True},
            ))
        await session.commit()


async def record_closure_event(app: FastAPI, payload: dict) -> None:
    report = payload.get("report") or {}
    contract = payload.get("event_contract") or {}
    tenant = str(report.get("tenant_id") or "").strip()
    event_id = str(contract.get("event_id") or "").strip()
    incident_id = str(UUID(str(report.get("incident_id") or "")))
    if not tenant or not event_id:
        raise ValueError("Closure audit requires tenant and event identity")
    audit_id = uuid5(NAMESPACE_URL, f"closure-audit:{tenant}:{event_id}")
    async with app.state.session_factory() as session:
        if await session.get(AuditLogRecord, audit_id) is None:
            metadata = report.get("metadata") or {}
            session.add(AuditLogRecord(
                id=audit_id, tenant_id=tenant, actor="closure-service", action="incident.closure.recorded",
                resource_type="incident", resource_id=incident_id,
                payload={"event_id": event_id, "closure_kind": metadata.get("closure_kind"),
                         "technical_recovery_verified": metadata.get("technical_recovery_verified") is True},
            ))
            await session.commit()


def _resolve_identity(payload: dict) -> tuple[UUID | None, str]:
    application_id = payload.get("application_id") or payload.get("id")
    if application_id:
        try:
            return UUID(str(application_id)), str(payload.get("tenant_id") or "default")
        except ValueError:
            return None, str(payload.get("tenant_id") or "default")
    return None, str(payload.get("tenant_id") or "default")


async def startup(app: FastAPI) -> None:
    plan_consumer = RabbitMQConsumer(settings, RESOLUTION_PLAN_EVENTS)
    async def handle_plan(payload: dict) -> None:
        await record_resolution_plan_event(app, payload)
    tasks.append(asyncio.create_task(consume_rabbitmq_forever(plan_consumer, handle_plan), name="audit-resolution-plans"))
    closure_consumer = RabbitMQConsumer(settings, CLOSURE_EVENTS)
    async def handle_closure(payload: dict) -> None:
        await record_closure_event(app, payload)
    tasks.append(asyncio.create_task(consume_rabbitmq_forever(closure_consumer, handle_closure), name="audit-closure"))
    async def handle_factory(event_type: str):
        async def handle(payload: dict) -> None:
            started = perf_counter()
            application_id, tenant_id = _resolve_identity(payload)
            if application_id is None:
                return
            session_factory = getattr(app.state, "session_factory", None)
            if session_factory is None:
                return
            async with session_factory() as session:
                repo = IncidentRepository(session)
                await repo.save_monitoring_audit(
                    MonitoringAuditEvent(
                        application_id=application_id,
                        tenant_id=tenant_id,
                        event_type=event_type,
                        actor="system",
                        agent="audit-service",
                        decision="recorded",
                        execution_time_ms=(perf_counter() - started) * 1000.0,
                        input=payload,
                        output={"stored": True},
                    )
                )
                await session.commit()
        return handle

    for topic in [
        APPLICATION_ONBOARD_REQUESTED,
        APPLICATION_DISCOVERY_COMPLETED,
        APPLICATION_METRICS_VALIDATED,
        APPLICATION_RULES_GENERATED,
        APPLICATION_PROMETHEUS_UPDATED,
        APPLICATION_VALIDATION_COMPLETED,
        APPLICATION_DASHBOARD_CREATED,
    ]:
        consumer = RabbitMQConsumer(settings, topic)
        tasks.append(asyncio.create_task(consume_rabbitmq_forever(consumer, await handle_factory(topic)), name=f"audit-{topic}"))


async def shutdown(_: FastAPI) -> None:
    for task in tasks:
        task.cancel()


app = create_app(title="KaiOps Audit Service", settings=settings, startup=startup, shutdown=shutdown)
