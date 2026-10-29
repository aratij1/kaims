from __future__ import annotations

import asyncio
import hashlib
import json
import logging
from collections import deque
from contextlib import suppress
from datetime import UTC, datetime, timedelta
from time import perf_counter
from typing import Any
from urllib.parse import quote, unquote, urlencode, urlparse
from uuid import NAMESPACE_URL, UUID, uuid4, uuid5

import aio_pika
import anyio
import httpx
import pymysql
from api_gateway import SafetyAnalyzer
from api_gateway.auth_policy import canonical_route_auth_rule
from api_gateway.control_routes import build_control_router
from api_gateway.modules.triage.router import TriageCorrectionCreate as TriageCorrectionCreate
from api_gateway.modules.triage.router import router as triage_router
from api_gateway.modules.users.models import SystemRole
from api_gateway.modules.users.permissions import AuthContext, current_tenant_id, require_roles
from api_gateway.modules.users.router import router as user_management_router
from api_gateway.modules.users.service import UserService
from common.authorization import OperationalRole, role_is_allowed
from common.config import get_settings
from common.database import (
    ActionRecord,
    AlertRecord,
    ApprovalRecord,
    AuditLogRecord,
    HumanCorrectionRecord,
    IncidentInvestigationBindingRecord,
    IncidentOccurrenceRecord,
    IncidentProjectionRecord,
    IncidentRecord,
    MonitoringConnectionHealthRecord,
    ContextEnrichmentJobRecord,
)
from common.event_publishers import build_agent_event_contract, build_orchestration_envelope
from common.incident_command_contract import build_incident_command_workspace
from common.kafka import normalize_payload
from common.models import Alert, GatewayAuditEvent, Incident, SafetyDecision
from common.repository import IncidentRepository
from common.service import create_app
from common.telemetry import REQUEST_LATENCY
from api_gateway.metric_labels import gateway_metric_operation
from common.topics import ORCHESTRATION_EVENTS
from fastapi import Body, Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse, StreamingResponse
from opentelemetry import trace
from prometheus_client import REGISTRY, Counter, Gauge
from pydantic import ValidationError
from redis.asyncio import Redis
from sqlalchemy import func, select
from sqlalchemy.orm import load_only
from sqlalchemy.exc import SQLAlchemyError
from common.resilience import CircuitOpenError

REQUEST_BODY = Body(default={})

settings = get_settings()
settings.service_name = "api-gateway"
analyzer = SafetyAnalyzer()
AUDIT_EVENTS: deque[GatewayAuditEvent] = deque(maxlen=200)
logger = logging.getLogger("api-gateway")
_GATEWAY_AUDIT_QUEUE_MAXSIZE = 1000


def require_object_payload(payload: Any, label: str = "request body") -> dict[str, Any]:
    if isinstance(payload, dict):
        return payload
    if isinstance(payload, bytes | bytearray):
        payload = payload.decode("utf-8", errors="ignore")
    if isinstance(payload, str):
        try:
            decoded = json.loads(payload)
        except json.JSONDecodeError as exc:
            raise HTTPException(status_code=422, detail=f"{label} must be a JSON object, not a string.") from exc
        if isinstance(decoded, dict):
            return decoded
        if isinstance(decoded, str):
            try:
                nested = json.loads(decoded)
            except json.JSONDecodeError as exc:
                raise HTTPException(status_code=422, detail=f"{label} must be a JSON object, not a string.") from exc
            if isinstance(nested, dict):
                return nested
    raise HTTPException(status_code=422, detail=f"{label} must be a JSON object.")


async def knowledge_pack_payload_from_request(request: Request, payload: Any, label: str) -> dict[str, Any]:
    try:
        return require_object_payload(payload, label)
    except HTTPException:
        raw_body = await request.body()
        if raw_body:
            return require_object_payload(raw_body, label)
        raise


async def _auth_context_from_request(request: Request) -> AuthContext:
    header = str(request.headers.get("authorization") or "").strip()
    scheme, _, token = header.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        raise HTTPException(status_code=401, detail="Bearer access token required")

    user_service = getattr(request.app.state, "user_service", None)
    if user_service is None:
        raise HTTPException(status_code=500, detail="User service is not configured")

    payload = await user_service.decode_access_token(token.strip())
    if str(payload.get("type") or "") != "access":
        raise HTTPException(status_code=401, detail="Access token required")
    external = bool(payload.get("external"))
    session_jti = str(payload.get("sid") or "").strip()
    if not external and not session_jti:
        raise HTTPException(status_code=401, detail="Access token is missing session binding")
    user_id: int | str = str(payload.get("sub")) if external else int(payload.get("sub", "0"))
    if not external:
        await user_service.ensure_active_session(session_jti=session_jti, user_id=int(user_id))
    return AuthContext(
        user_id=user_id,
        role=str(payload.get("role") or ""),
        tenant_id=str(payload.get("tenant_id") or "default"),
        jwt_id=str(payload.get("jti") or ""),
        session_jti=session_jti,
        token_type="access",
        external=external,
        username=str(payload.get("preferred_username") or payload.get("upn") or payload.get("name") or payload.get("sub") or ""),
        email=str(payload.get("email") or payload.get("preferred_username") or "unknown@kaiops.example.com"),
        first_name=str(payload.get("given_name") or payload.get("name") or "External"),
        last_name=str(payload.get("family_name") or "User"),
        acr=str(payload.get("acr") or ""),
        amr=tuple(str(item) for item in (payload.get("amr") or []) if item),
    )


async def _persist_gateway_audit_event(app: FastAPI, event: GatewayAuditEvent) -> None:
    """Persist observability data without breaking the proxied business request.

    Gateway audit storage is secondary telemetry. A database outage or an open
    database circuit must not replace a successful downstream response with a
    gateway HTTP 500.
    """
    session_factory = getattr(app.state, "session_factory", None)
    if not settings.database_enabled or session_factory is None:
        return
    payload = event.model_dump(mode="json")
    try:
        async with session_factory() as session:
            session.add(
                AuditLogRecord(
                    id=event.id,
                    actor="api-gateway",
                    action="gateway.request",
                    resource_type="gateway",
                    resource_id=str(event.trace_id or event.id),
                    payload=payload,
                )
            )
            await session.commit()
    except Exception as exc:
        logger.warning(
            "gateway_audit_persistence_skipped",
            extra={"trace_id": event.trace_id, "error_type": type(exc).__name__},
        )


def _queue_gateway_audit_event(app: FastAPI, event: GatewayAuditEvent) -> None:
    """Queue secondary telemetry without extending business-request latency."""
    queue = getattr(app.state, "gateway_audit_queue", None)
    if queue is None:
        logger.warning("gateway_audit_queue_unavailable", extra={"trace_id": event.trace_id})
        return
    try:
        queue.put_nowait(event)
    except asyncio.QueueFull:
        # The in-memory deque still exposes the most recent diagnostics. A
        # bounded queue prevents a database outage from becoming a memory leak.
        logger.warning("gateway_audit_queue_full", extra={"trace_id": event.trace_id})


async def _gateway_audit_worker(app: FastAPI) -> None:
    queue = app.state.gateway_audit_queue
    while True:
        event = await queue.get()
        try:
            await _persist_gateway_audit_event(app, event)
        finally:
            queue.task_done()


def _gateway_event_from_audit_payload(payload: dict[str, Any]) -> GatewayAuditEvent | None:
    if not isinstance(payload, dict):
        return None
    try:
        return GatewayAuditEvent.model_validate(payload)
    except Exception:
        return None


async def _load_recent_gateway_audit_events(app: FastAPI, limit: int) -> list[GatewayAuditEvent]:
    session_factory = getattr(app.state, "session_factory", None)
    safe_limit = max(1, min(int(limit), 100))
    if not settings.database_enabled or session_factory is None:
        return list(AUDIT_EVENTS)[:safe_limit]
    async with session_factory() as session:
        result = await session.execute(
            select(AuditLogRecord)
            .where(AuditLogRecord.resource_type == "gateway")
            .where(AuditLogRecord.action == "gateway.request")
            .order_by(AuditLogRecord.created_at.desc())
            .limit(safe_limit)
        )
        rows = result.scalars().all()
    events = [_gateway_event_from_audit_payload(row.payload or {}) for row in rows]
    return [event for event in events if event is not None]


async def _load_gateway_audit_summary(app: FastAPI) -> dict[str, Any]:
    session_factory = getattr(app.state, "session_factory", None)
    if not settings.database_enabled or session_factory is None:
        events = list(AUDIT_EVENTS)
        blocked = sum(1 for event in events if event.safety.decision == SafetyDecision.BLOCK)
        review = sum(1 for event in events if event.safety.decision == SafetyDecision.REVIEW)
        allowed = sum(1 for event in events if event.safety.decision == SafetyDecision.ALLOW)
        return {
            "total_events": len(events),
            "allowed": allowed,
            "review": review,
            "blocked": blocked,
            "latest_trace_id": events[0].trace_id if events else None,
        }

    recent_events = await _load_recent_gateway_audit_events(app, 250)
    async with session_factory() as session:
        total = int(
            (
                await session.execute(
                    select(func.count())
                    .select_from(AuditLogRecord)
                    .where(AuditLogRecord.resource_type == "gateway")
                    .where(AuditLogRecord.action == "gateway.request")
                )
            ).scalar_one()
        )
    blocked = sum(1 for event in recent_events if event.safety.decision == SafetyDecision.BLOCK)
    review = sum(1 for event in recent_events if event.safety.decision == SafetyDecision.REVIEW)
    allowed = sum(1 for event in recent_events if event.safety.decision == SafetyDecision.ALLOW)
    latest_event = recent_events[0] if recent_events else None
    return {
        "total_events": total,
        "window_events": len(recent_events),
        "allowed": allowed,
        "review": review,
        "blocked": blocked,
        "latest_trace_id": latest_event.trace_id if latest_event else None,
    }


def _query_alerts_table_row_count() -> float:
    if not settings.database_enabled:
        return 0.0
    connection = None
    try:
        connection = pymysql.connect(
            host=settings.db_host,
            port=int(settings.db_port),
            user=settings.db_user,
            password=settings.db_password,
            database=settings.db_database,
            connect_timeout=3,
            read_timeout=3,
            write_timeout=3,
            cursorclass=pymysql.cursors.Cursor,
            autocommit=True,
        )
        with connection.cursor() as cursor:
            # This is an operational capacity gauge, not a billing count. An
            # exact COUNT(*) repeatedly scans a growing InnoDB table and was a
            # measurable source of database CPU. information_schema provides
            # the inexpensive estimate appropriate for this metric.
            cursor.execute(
                """
                SELECT COALESCE(TABLE_ROWS, 0)
                FROM information_schema.TABLES
                WHERE TABLE_SCHEMA = %s AND TABLE_NAME = 'alerts'
                """,
                (settings.db_database,),
            )
            row = cursor.fetchone()
            return float((row or [0])[0] or 0)
    except Exception as exc:
        logger.warning("alerts_table_row_count_query_failed", extra={"error": str(exc)})
        return 0.0
    finally:
        if connection is not None:
            try:
                connection.close()
            except Exception:
                pass


async def _sample_alerts_table_row_count() -> None:
    """Update the gauge off the event loop; Prometheus scrapes stay read-only and fast."""
    while True:
        count = await asyncio.to_thread(_query_alerts_table_row_count)
        ALERTS_TABLE_ROWS.labels(settings.db_database, "alerts").set(count)
        await asyncio.sleep(max(30.0, settings.alerts_table_metric_interval_seconds))


async def startup(app: FastAPI) -> None:
    app.state.proxy_client = httpx.AsyncClient(
        timeout=httpx.Timeout(settings.gateway_request_timeout_seconds, connect=5.0, pool=5.0),
        limits=httpx.Limits(max_connections=100, max_keepalive_connections=20, keepalive_expiry=30.0),
    )
    if settings.database_enabled:
        app.state.user_service = UserService(settings=settings, session_factory=app.state.session_factory)
        await app.state.user_service.bootstrap_defaults()
    else:
        app.state.user_service = UserService(settings=settings, session_factory=None)

    app.state.gateway_audit_queue = asyncio.Queue(maxsize=_GATEWAY_AUDIT_QUEUE_MAXSIZE)
    app.state.gateway_audit_task = asyncio.create_task(
        _gateway_audit_worker(app),
        name="api-gateway-audit-writer",
    )
    app.state.alerts_table_metric_task = asyncio.create_task(_sample_alerts_table_row_count())


async def shutdown(app: FastAPI) -> None:
    metric_task = getattr(app.state, "alerts_table_metric_task", None)
    if metric_task is not None:
        metric_task.cancel()
        with suppress(asyncio.CancelledError):
            await metric_task
    client = getattr(app.state, "proxy_client", None)
    if client is not None:
        await client.aclose()
    audit_queue = getattr(app.state, "gateway_audit_queue", None)
    if audit_queue is not None:
        try:
            await asyncio.wait_for(audit_queue.join(), timeout=2.0)
        except TimeoutError:
            logger.warning("gateway_audit_shutdown_drain_timed_out", extra={"pending": audit_queue.qsize()})
    audit_task = getattr(app.state, "gateway_audit_task", None)
    if audit_task is not None:
        audit_task.cancel()
        with suppress(asyncio.CancelledError):
            await audit_task


app = create_app(title="KaiMS API Gateway", settings=settings, startup=startup, shutdown=shutdown)


app.include_router(user_management_router)
app.include_router(triage_router)


@app.middleware("http")
async def enforce_operational_auth(request: Request, call_next):
    if settings.environment.strip().lower() in {"local", "demo", "test"}:
        return await call_next(request)

    role_rule = canonical_route_auth_rule(request.method, request.url.path)
    if role_rule is False:
        return await call_next(request)

    try:
        auth = await _auth_context_from_request(request)
    except HTTPException as exc:
        return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})
    if role_rule is not None and not role_is_allowed(auth.role, role_rule):
        return JSONResponse(status_code=403, content={"detail": "Insufficient role permissions"})
    if settings.auth_mode == "oidc" and request.method == "POST" and request.url.path in {"/approval/approve", "/approval/modify", "/remediation/execute"}:
        accepted = {item.strip().lower() for item in settings.oidc_step_up_values.split(",") if item.strip()}
        observed = {auth.acr.lower(), *(item.lower() for item in auth.amr)}
        if not accepted.intersection(observed):
            return JSONResponse(status_code=403, content={"detail": "Step-up authentication is required for this sensitive action"})
    request.state.auth = auth
    return await call_next(request)

def _registered_metric(metric_type, name: str, documentation: str, labelnames: list[str] | None = None):
    """Return an existing process metric when test/module reloads import this app again."""
    lookup_name = name.removesuffix("_total") if metric_type is Counter else name
    existing = REGISTRY._names_to_collectors.get(lookup_name)
    if existing is not None:
        return existing
    return metric_type(name, documentation, labelnames or [])


GATEWAY_REQUESTS = _registered_metric(Counter,
    "kaiops_gateway_requests_total",
    "API gateway requests by path and safety decision",
    ["path", "decision", "status"],
)
GATEWAY_SAFETY_BLOCKS = _registered_metric(Counter,
    "kaiops_gateway_safety_blocks_total",
    "API gateway blocked requests by category",
    ["category"],
)
SSE_CONNECTIONS = _registered_metric(Gauge, "kaiops_sse_connections", "Active authenticated operational SSE connections", ["role"])
SSE_EVENTS = _registered_metric(Counter, "kaiops_sse_events_total", "Operational SSE events emitted", ["event_type"])
ALERTS_TABLE_ROWS = _registered_metric(Gauge,
    "kaiops_mysql_alerts_table_rows",
    "Current number of records in MySQL alerts table",
    ["database", "table"],
)


def trace_id_from_header(value: str | None) -> str:
    return value or uuid4().hex


def _sse_message(event_id: str, event_type: str, payload: dict[str, Any]) -> str:
    return f"id: {event_id}\nevent: {event_type}\ndata: {json.dumps(payload, default=str, separators=(',', ':'))}\n\n"


@app.get("/events/operations")
async def stream_operational_events(request: Request) -> StreamingResponse:
    """Emit tenant-scoped change notifications; clients fetch canonical rows through Query caches."""
    auth = getattr(request.state, "auth", None)
    tenant_id = auth.tenant_id if auth is not None else "default"
    role = auth.role if auth is not None else "local-development"
    last_event_id = str(request.headers.get("last-event-id") or request.query_params.get("last_event_id") or "").strip()
    try:
        cursor_ms = int(last_event_id.split("-", 1)[0])
        cursor = datetime.fromtimestamp(cursor_ms / 1000, UTC)
    except (TypeError, ValueError, OSError):
        cursor = datetime.now(UTC) - timedelta(seconds=5)

    async def events():
        nonlocal cursor
        SSE_CONNECTIONS.labels(role).inc()
        sequence = 0
        try:
            yield "retry: 2000\n\n"
            while not await request.is_disconnected():
                messages: list[str] = []
                session_factory = getattr(app.state, "session_factory", None)
                if settings.database_enabled and session_factory is not None:
                    try:
                        # Starlette cancels disconnected streams repeatedly via an
                        # AnyIO scope. Protect the finite poll AND session cleanup;
                        # a separate deadline still bounds a stalled database poll.
                        with anyio.CancelScope(shield=True):
                            async with asyncio.timeout(10):
                                async with session_factory() as session:
                                    queries = (
                                        ("alert.created", AlertRecord, AlertRecord.id, None),
                                        ("incident.status", IncidentProjectionRecord, IncidentProjectionRecord.incident_id, IncidentProjectionRecord.status),
                                        ("approval.state", ApprovalRecord, ApprovalRecord.id, ApprovalRecord.decision),
                                        ("remediation.progress", ActionRecord, ActionRecord.id, ActionRecord.status),
                                    )
                                    newest = cursor
                                    for event_type, model, identity, state in queries:
                                        stmt = select(model).options(load_only(model.updated_at, identity, *([state] if state is not None else []))).where(model.tenant_id == tenant_id, model.updated_at > cursor).order_by(model.updated_at.asc()).limit(100)
                                        for row in (await session.execute(stmt)).scalars().all():
                                            updated_at = row.updated_at.replace(tzinfo=UTC) if row.updated_at.tzinfo is None else row.updated_at
                                            newest = max(newest, updated_at)
                                            sequence += 1
                                            event_id = f"{int(updated_at.timestamp() * 1000)}-{sequence}"
                                            payload = {"entity_id": str(getattr(row, identity.key)), "changed_at": updated_at.isoformat(), "tenant_id": tenant_id}
                                            if state is not None:
                                                payload["state"] = str(getattr(row, state.key))
                                            messages.append(_sse_message(event_id, event_type, payload))
                                            SSE_EVENTS.labels(event_type).inc()
                                    if role == "Administrator":
                                        stmt = select(MonitoringConnectionHealthRecord).options(load_only(MonitoringConnectionHealthRecord.updated_at, MonitoringConnectionHealthRecord.integration_id, MonitoringConnectionHealthRecord.provider, MonitoringConnectionHealthRecord.status)).where(MonitoringConnectionHealthRecord.updated_at > cursor).order_by(MonitoringConnectionHealthRecord.updated_at.asc()).limit(100)
                                        for row in (await session.execute(stmt)).scalars().all():
                                            updated_at = row.updated_at.replace(tzinfo=UTC) if row.updated_at.tzinfo is None else row.updated_at
                                            newest = max(newest, updated_at)
                                            sequence += 1
                                            event_id = f"{int(updated_at.timestamp() * 1000)}-{sequence}"
                                            messages.append(_sse_message(event_id, "connector.health", {"entity_id": str(row.integration_id), "provider": row.provider, "state": row.status, "changed_at": updated_at.isoformat()}))
                                            SSE_EVENTS.labels("connector.health").inc()
                                    cursor = newest
                    except (SQLAlchemyError, CircuitOpenError, TimeoutError) as exc:
                        logger.warning("operational_event_poll_unavailable", extra={"error_type": type(exc).__name__})
                        # Headers were sent already: close this stream and let the
                        # client's EventSource retry, rather than raise an HTTP error.
                        yield _sse_message("", "dependency.unavailable", {"retryable": True})
                        return
                # Never yield while a session/connection is checked out. Slow
                # or disconnected browsers must not strand pooled DB handles.
                if messages:
                    for message in messages:
                        yield message
                else:
                    sequence += 1
                    now = datetime.now(UTC)
                    yield _sse_message(f"{int(now.timestamp() * 1000)}-{sequence}", "heartbeat", {"at": now.isoformat(), "queue_health": "polling-fallback"})
                await asyncio.sleep(5)
        finally:
            SSE_CONNECTIONS.labels(role).dec()

    return StreamingResponse(events(), media_type="text/event-stream", headers={"Cache-Control": "no-cache, no-transform", "Connection": "keep-alive", "X-Accel-Buffering": "no"})


def preview(payload: Any) -> dict[str, Any]:
    # Collection responses can contain hundreds of nested alert/evidence
    # payloads. Audit their shape and count without deep-normalizing the entire
    # response on the request path; canonical details remain in the source DB.
    if isinstance(payload, dict) and isinstance(payload.get("rows"), list):
        return {"rows_count": len(payload["rows"]), "count": payload.get("count")}
    if isinstance(payload, dict) and isinstance(payload.get("data"), dict) and isinstance(payload["data"].get("rows"), list):
        return {"rows_count": len(payload["data"]["rows"]), "count": payload["data"].get("count")}
    normalized = normalize_payload(payload)
    if not isinstance(normalized, dict):
        return {"value": str(normalized)[:500]}
    return {key: normalized[key] for key in list(normalized)[:10]}


def _normalize_contract_token(value: Any) -> str:
    return "-".join(
        part
        for part in str(value or "").strip().lower().replace("_", "-").replace("/", "-").split("-")
        if part
    )


def _collect_contract_tokens(*values: Any) -> set[str]:
    tokens: set[str] = set()
    for value in values:
        if value is None:
            continue
        if isinstance(value, (list, tuple, set)):
            for item in value:
                tokens.update(_collect_contract_tokens(item))
            continue
        raw = str(value or "").strip()
        if not raw:
            continue
        normalized = _normalize_contract_token(raw)
        if normalized:
            tokens.add(normalized)
        for part in raw.replace(",", " ").replace(";", " ").replace("|", " ").split():
            normalized_part = _normalize_contract_token(part)
            if normalized_part:
                tokens.add(normalized_part)
    return tokens


def _payload_data(payload: dict[str, Any]) -> dict[str, Any]:
    data = payload.get("data") if isinstance(payload, dict) else {}
    return data if isinstance(data, dict) else payload


def _canonical_alert_contract(alert: dict[str, Any]) -> dict[str, Any]:
    labels = alert.get("labels") if isinstance(alert.get("labels"), dict) else {}
    metadata = alert.get("metadata") if isinstance(alert.get("metadata"), dict) else {}
    alert_id = str(alert.get("alert_id") or alert.get("id") or "").strip()
    incident_id = str(alert.get("incident_id") or "").strip()
    service = str(
        alert.get("service")
        or labels.get("service")
        or labels.get("job")
        or metadata.get("service")
        or ""
    ).strip()
    alert_type = str(
        alert.get("alert_type")
        or alert.get("name")
        or alert.get("alert_name")
        or alert.get("alertname")
        or labels.get("alertname")
        or labels.get("alert_type")
        or ""
    ).strip()
    return {
        "schema_version": "kaiops.alert.v1",
        "alert_uid": alert_id or incident_id,
        "alert_id": alert_id,
        "incident_id": incident_id,
        "correlation_id": str(alert.get("correlation_id") or "").strip(),
        "trace_id": str(alert.get("trace_id") or "").strip(),
        "fingerprint": str(alert.get("fingerprint") or labels.get("alert_fingerprint") or "").strip(),
        "alert_type": alert_type,
        "service": service,
        "environment": str(alert.get("environment") or labels.get("environment") or "").strip() or "prod",
        "tenant": str(labels.get("tenant") or metadata.get("tenant") or "default").strip(),
        "severity": str(alert.get("severity") or labels.get("severity") or "").strip().lower(),
        "status": str(alert.get("status") or alert.get("state") or labels.get("alert_status") or "").strip(),
        "project": str(alert.get("project") or labels.get("project") or labels.get("application") or "").strip(),
        "raw_id_fields": {
            "id": alert.get("id"),
            "alert_id": alert.get("alert_id"),
            "incident_id": alert.get("incident_id"),
            "correlation_id": alert.get("correlation_id"),
        },
    }


def _document_match_context(alert: dict[str, Any], canonical: dict[str, Any]) -> dict[str, Any]:
    labels = alert.get("labels") if isinstance(alert.get("labels"), dict) else {}
    metadata = alert.get("metadata") if isinstance(alert.get("metadata"), dict) else {}
    return {
        "ids": _collect_contract_tokens(
            canonical.get("alert_id"),
            canonical.get("incident_id"),
            canonical.get("correlation_id"),
            labels.get("alert_id"),
            metadata.get("alert_id"),
            metadata.get("incident_id"),
        ),
        "alert_types": _collect_contract_tokens(
            canonical.get("alert_type"),
            alert.get("name"),
            alert.get("alert_name"),
            labels.get("alertname"),
            labels.get("alert_type"),
            labels.get("category"),
        ),
        "services": _collect_contract_tokens(
            canonical.get("service"),
            canonical.get("project"),
            alert.get("application"),
            labels.get("service"),
            labels.get("job"),
            labels.get("application"),
            labels.get("project"),
            labels.get("project_name"),
            labels.get("deployment"),
            labels.get("namespace"),
            labels.get("instance"),
            metadata.get("service"),
            metadata.get("application"),
            metadata.get("project"),
        ),
        "generic_service_docs_allowed": alert.get("document_available") is True or bool(metadata.get("runbook_hint")),
    }


def _link_document_to_alert(doc: dict[str, Any], context: dict[str, Any]) -> dict[str, Any] | None:
    doc_ids = _collect_contract_tokens(doc.get("alert_id"), doc.get("id"), (doc.get("metadata") or {}).get("alert_id") if isinstance(doc.get("metadata"), dict) else None)
    doc_types = _collect_contract_tokens(doc.get("alert_type"), doc.get("alert_name"), doc.get("alertname"))
    doc_services = _collect_contract_tokens(doc.get("services"), doc.get("service"))
    doc_kind = _normalize_contract_token(doc.get("kind") or doc.get("document_kind"))
    if context["ids"] & doc_ids:
        reason = "exact-alert-id"
        confidence = 1.0
    elif (context["alert_types"] & doc_types) and (context["services"] & doc_services):
        reason = "alert-type-and-service"
        confidence = 0.9
    elif (
        context["generic_service_docs_allowed"]
        and not doc_ids
        and (context["services"] & doc_services)
        and doc_kind in {"runbook", "incident", "sop", "onboarding"}
    ):
        reason = "service-level-document"
        confidence = 0.72
    else:
        return None
    public_doc = {key: value for key, value in doc.items() if not str(key).startswith("_")}
    public_doc.update(
        {
            "match_reason": reason,
            "match_confidence": confidence,
            "document_scope": "alert-specific" if doc.get("alert_id") else "service-level",
        }
    )
    return public_doc


def _enterprise_contract(canonical: dict[str, Any], trace_id: str) -> dict[str, Any]:
    severity = str(canonical.get("severity") or "").lower()
    risk_tier = "critical" if severity == "critical" else "high" if severity == "high" else "standard"
    return {
        "governance": {
            "agent_contract_version": "kaiops.agent-contract.v1",
            "required_agent_fields": ["input", "output", "confidence", "reasoning", "citations", "fallback_path"],
            "approval_gate_required": severity in {"critical", "high"},
            "allowed_actions": ["triage", "recommend", "request_approval", "dry_run_remediation"],
            "audit_required": True,
        },
        "rbac": {
            "policy_version": "kaiops.rbac.v1",
            "tenant": canonical.get("tenant") or "default",
            "environment": canonical.get("environment") or "prod",
            "risk_tier": risk_tier,
            "action_roles": {
                "view": ["ADMIN", "HITL_APPROVER"],
                "provide_documents": ["ADMIN"],
                "approve": ["ADMIN", "HITL_APPROVER"],
                "execute_remediation": ["ADMIN", "HITL_APPROVER"],
            },
        },
        "observability": {
            "trace_id": canonical.get("trace_id") or trace_id,
            "correlation_id": canonical.get("correlation_id"),
            "required_hops": ["alert-intake", "enrichment", "rag", "llm", "approval", "remediation", "closure", "ui"],
            "quality_gate": "all persisted events should carry trace_id and correlation_id",
        },
        "rag_quality": {
            "contract_version": "kaiops.rag-quality.v1",
            "required_fields": ["kind", "title", "path", "services", "owner", "version", "freshness_score", "embedding_status"],
            "approval_workflow_required": True,
        },
        "llm_reliability": {
            "contract_version": "kaiops.llm-reliability.v1",
            "fallback_required": True,
            "deterministic_fallback": "workflow and alert-stream payload",
            "required_audit_fields": ["prompt_version", "model", "provider", "cost", "token_usage", "validation_result"],
            "cost_guardrail_required": True,
            "required_evaluation_metrics": [
                "confidence_score",
                "grounding_score",
                "hallucination_risk",
                "citation_coverage",
                "evidence_coverage",
                "overall_score",
            ],
        },
        "remediation_safety": {
            "contract_version": "kaiops.remediation-safety.v1",
            "dry_run_required": True,
            "approval_required": severity in {"critical", "high"},
            "required_fields": ["policy_result", "blast_radius", "rollback_plan", "post_checks", "execution_log"],
        },
    }


def _build_gateway_audit_contract(event: GatewayAuditEvent) -> dict[str, Any]:
    status_code = int(event.status_code or 0)
    confidence = 1.0 if status_code < 400 else 0.5
    return build_agent_event_contract(
        flow_id=str(event.trace_id or event.id),
        incident_id=str(event.trace_id or event.id),
        trace_id=str(event.trace_id or ""),
        correlation_id=None,
        agent="api-gateway",
        payload={
            "path": event.path,
            "method": event.method,
            "status_code": status_code,
            "decision": event.safety.decision.value,
        },
        metadata={
            "categories": list(event.safety.categories),
            "latency_ms": event.latency_ms,
            "target_url": event.target_url,
        },
        confidence=confidence,
        reasoning="gateway safety and proxy audit event",
        citations=[f"gateway://{event.path}"],
        evidence_ids=[f"gateway-event:{event.id}"],
    )


async def proxy(
    *,
    method: str,
    path: str,
    target_base: str,
    payload: Any,
    trace_id: str,
    params: dict[str, str] | None = None,
    timeout_seconds: float | None = None,
) -> tuple[int, dict[str, Any]]:
    target_url = f"{target_base.rstrip('/')}/{path.lstrip('/')}"
    headers = {"x-trace-id": trace_id}
    if settings.service_internal_token:
        headers["x-kaiops-internal-token"] = settings.service_internal_token
    client = getattr(app.state, "proxy_client", None)
    if client is None:
        raise httpx.ConnectError("API gateway proxy client is not initialized")

    normalized_method = method.upper()
    is_fast_read = normalized_method == "GET" and path.split("?", 1)[0] in {
        "/alerts/all",
        "/alerts/applications",
        "/alerts/severity-overrides",
        "/incidents/closed",
        "/landing-pad/recent",
        "/onboarding/state",
    }
    if timeout_seconds is not None:
        request_timeout = max(0.5, float(timeout_seconds))
    elif normalized_method == "GET" and path.split("?", 1)[0] == "/landing-pad/recent":
        # Landing-pad scans may include archive + in-memory merge work and can
        # exceed the generic fast-read budget under active ingestion.
        request_timeout = max(45.0, float(settings.gateway_request_timeout_seconds))
    else:
        request_timeout = 12.0 if is_fast_read else settings.gateway_request_timeout_seconds
    timeout = httpx.Timeout(request_timeout, connect=5.0, pool=5.0)
    # A ConnectError/ConnectTimeout occurs before an HTTP response exists.
    # Safe reads get a wider bounded recovery window because Docker can publish
    # a replacement container before uvicorn has bound its socket. Mutations are
    # retried only once: the connection was never established, but keeping that
    # window narrow avoids surprising callers during a prolonged outage.
    max_attempts = 4 if normalized_method == "GET" else 2

    for attempt in range(1, max_attempts + 1):
        try:
            response = await client.request(
                method,
                target_url,
                json=payload or None,
                headers=headers,
                params=params,
                timeout=timeout,
            )
            response.raise_for_status()
            return response.status_code, response.json()
        except httpx.HTTPStatusError:
            raise
        except (httpx.ConnectError, httpx.ConnectTimeout):
            if attempt >= max_attempts:
                raise
            await asyncio.sleep(0.25 * attempt)
        except httpx.HTTPError:
            # A read/pool timeout means the downstream is saturated. Retrying
            # immediately multiplies that load and prolongs the outage.
            raise

    raise httpx.ConnectError(f"Unable to connect to downstream service: {target_url}")


async def guarded_proxy(
    *,
    request: Request,
    method: str,
    path: str,
    target_base: str,
    payload: Any,
    trace_id: str,
    params: dict[str, str] | None = None,
    timeout_seconds: float | None = None,
) -> dict[str, Any]:
    start = perf_counter()
    metric_operation = gateway_metric_operation(request)
    safety = analyzer.analyze({"path": path, "payload": payload})
    target_url = f"{target_base.rstrip('/')}/{path.lstrip('/')}"
    tracer = trace.get_tracer("kaiops.api_gateway")

    with tracer.start_as_current_span("api_gateway.guarded_proxy") as span:
        span.set_attribute("kaiops.trace_id", trace_id)
        span.set_attribute("kaiops.gateway.path", path)
        span.set_attribute("kaiops.gateway.safety_decision", safety.decision.value)
        span.set_attribute("kaiops.gateway.safety_score", safety.score)

        if safety.decision == SafetyDecision.BLOCK:
            for category in safety.categories or ["unknown"]:
                GATEWAY_SAFETY_BLOCKS.labels(category).inc()
            latency_ms = (perf_counter() - start) * 1000
            event = GatewayAuditEvent(
                trace_id=trace_id,
                method=method,
                path=str(request.url.path),
                target_url=target_url,
                status_code=403,
                latency_ms=latency_ms,
                safety=safety,
                request_preview=preview(payload),
            )
            AUDIT_EVENTS.appendleft(event)
            _queue_gateway_audit_event(app, event)
            GATEWAY_REQUESTS.labels(metric_operation, safety.decision.value, "blocked").inc()
            REQUEST_LATENCY.labels(settings.service_name, metric_operation).observe(latency_ms / 1000)
            raise HTTPException(
                status_code=403,
                detail={
                    "message": "Request blocked by API Gateway safety policy",
                    "trace_id": trace_id,
                    "safety": safety.model_dump(mode="json"),
                },
            )

        try:
            status_code, response_payload = await proxy(
                method=method,
                path=path,
                target_base=target_base,
                payload=payload,
                trace_id=trace_id,
                params=params,
                timeout_seconds=timeout_seconds,
            )
            status = "ok"
        except httpx.HTTPStatusError as exc:
            downstream_payload: Any
            try:
                downstream_payload = exc.response.json()
            except Exception:
                downstream_payload = {"message": (exc.response.text or "").strip()}
            status_code = int(exc.response.status_code or 502)
            response_payload = {
                "error": str(exc),
                "trace_id": trace_id,
                "target_url": target_url,
                "downstream": downstream_payload,
                "hint": "Downstream service rejected the request payload.",
            }
            status = "error"
        except httpx.HTTPError as exc:
            status_code = 502
            response_payload = {
                "error": str(exc),
                "trace_id": trace_id,
                "target_url": target_url,
                "hint": "Confirm the downstream service is running and has the requested route.",
            }
            status = "error"

        latency_ms = (perf_counter() - start) * 1000
        wrapped = {
            "trace_id": trace_id,
            "gateway": {
                "path": str(request.url.path),
                "target_url": target_url,
                "safety": safety.model_dump(mode="json"),
                "latency_ms": round(latency_ms, 2),
            },
            "data": response_payload,
        }
        event = GatewayAuditEvent(
            trace_id=trace_id,
            method=method,
            path=str(request.url.path),
            target_url=target_url,
            status_code=status_code,
            latency_ms=latency_ms,
            safety=safety,
            request_preview=preview(payload),
            response_preview=preview(response_payload),
        )
        AUDIT_EVENTS.appendleft(event)
        _queue_gateway_audit_event(app, event)
        GATEWAY_REQUESTS.labels(metric_operation, safety.decision.value, status).inc()
        REQUEST_LATENCY.labels(settings.service_name, metric_operation).observe(latency_ms / 1000)

        if status_code >= 400:
            downstream = response_payload.get("downstream") if isinstance(response_payload, dict) else None
            downstream = downstream if isinstance(downstream, dict) else {}
            downstream_detail = downstream.get("detail") if isinstance(downstream.get("detail"), dict) else {}
            if downstream_detail.get("retryable") is True:
                wrapped.update(
                    {
                        "retryable": True,
                        "code": str(downstream_detail.get("code") or f"http_{status_code}"),
                        "message": str(downstream_detail.get("message") or "The downstream request can be retried."),
                    }
                )
            raise HTTPException(status_code=status_code, detail=wrapped)
        return wrapped


@app.post("/alerts")
async def ingest_alert(
    request: Request,
    payload: dict[str, Any] = REQUEST_BODY,
    x_trace_id: str | None = Header(default=None),
) -> dict[str, Any]:
    return await guarded_proxy(
        request=request,
        method="POST",
        path="/alerts",
        target_base=settings.monitoring_adapter_url,
        payload=payload,
        trace_id=trace_id_from_header(x_trace_id),
    )


@app.post("/evaluations/by-recommendation/{recommendation_id}/feedback")
async def submit_evaluation_feedback(
    recommendation_id: str,
    request: Request,
    payload: dict[str, Any] = REQUEST_BODY,
    x_trace_id: str | None = Header(default=None),
) -> dict[str, Any]:
    """Expose the existing evaluation feedback loop through the authenticated gateway."""
    return await guarded_proxy(
        request=request,
        method="POST",
        path=f"/evaluations/by-recommendation/{recommendation_id}/feedback",
        target_base=settings.evaluation_service_url,
        payload=payload,
        trace_id=trace_id_from_header(x_trace_id),
    )


@app.post("/applications")
async def create_application(
    request: Request,
    payload: dict[str, Any] = REQUEST_BODY,
    x_trace_id: str | None = Header(default=None),
) -> dict[str, Any]:
    return await guarded_proxy(
        request=request,
        method="POST",
        path="/applications",
        target_base=settings.application_onboarding_url,
        payload=payload,
        trace_id=trace_id_from_header(x_trace_id),
    )


@app.get("/applications")
async def list_applications(
    request: Request,
    x_trace_id: str | None = Header(default=None),
) -> dict[str, Any]:
    return await guarded_proxy(
        request=request,
        method="GET",
        path="/applications",
        target_base=settings.application_onboarding_url,
        payload={},
        trace_id=trace_id_from_header(x_trace_id),
    )


@app.get("/applications/{application_id}")
async def get_application(
    application_id: str,
    request: Request,
    x_trace_id: str | None = Header(default=None),
) -> dict[str, Any]:
    return await guarded_proxy(
        request=request,
        method="GET",
        path=f"/applications/{application_id}",
        target_base=settings.application_onboarding_url,
        payload={},
        trace_id=trace_id_from_header(x_trace_id),
    )


@app.put("/applications/{application_id}")
async def update_application(
    application_id: str,
    request: Request,
    payload: dict[str, Any] = REQUEST_BODY,
    x_trace_id: str | None = Header(default=None),
    _: AuthContext = Depends(require_roles(SystemRole.ADMINISTRATOR.value)),  # noqa: B008
) -> dict[str, Any]:
    return await guarded_proxy(
        request=request,
        method="PUT",
        path=f"/applications/{application_id}",
        target_base=settings.application_onboarding_url,
        payload=payload,
        trace_id=trace_id_from_header(x_trace_id),
    )


@app.delete("/applications/{application_id}")
async def delete_application(
    application_id: str,
    request: Request,
    x_trace_id: str | None = Header(default=None),
    _: AuthContext = Depends(require_roles(SystemRole.ADMINISTRATOR.value)),
) -> dict[str, Any]:
    return await guarded_proxy(
        request=request,
        method="DELETE",
        path=f"/applications/{application_id}",
        target_base=settings.application_onboarding_url,
        payload={},
        trace_id=trace_id_from_header(x_trace_id),
    )


@app.get("/applications/{application_id}/history")
async def get_application_history(
    application_id: str,
    request: Request,
    x_trace_id: str | None = Header(default=None),
) -> dict[str, Any]:
    return await guarded_proxy(
        request=request,
        method="GET",
        path=f"/applications/{application_id}/history",
        target_base=settings.application_onboarding_url,
        payload={},
        trace_id=trace_id_from_header(x_trace_id),
    )


@app.get("/applications/{application_id}/validations")
async def get_application_validations(
    application_id: str,
    request: Request,
    x_trace_id: str | None = Header(default=None),
) -> dict[str, Any]:
    return await guarded_proxy(
        request=request,
        method="GET",
        path=f"/applications/{application_id}/validations",
        target_base=settings.application_onboarding_url,
        payload={},
        trace_id=trace_id_from_header(x_trace_id),
    )


@app.get("/applications/{application_id}/dashboards")
async def get_application_dashboards(
    application_id: str,
    request: Request,
    x_trace_id: str | None = Header(default=None),
) -> dict[str, Any]:
    return await guarded_proxy(
        request=request,
        method="GET",
        path=f"/applications/{application_id}/dashboards",
        target_base=settings.application_onboarding_url,
        payload={},
        trace_id=trace_id_from_header(x_trace_id),
    )


@app.get("/alerts")
async def alerts_help() -> dict[str, Any]:
    return {
        "message": "Use POST /alerts to ingest alerts. GET /alerts is informational.",
        "example": {
            "method": "POST",
            "path": "/alerts",
            "payload": {
                "source": "monitoring-adapter",
                "name": "DatabaseReplicaLag",
                "service": "orders-db",
                "severity": "high",
                "description": "Replica lag is above threshold.",
                "labels": {"component": "database"},
                "annotations": {"summary": "Database replica lag spike"},
            },
        },
    }


@app.get("/alerts/recent")
async def get_recent_alerts(
    request: Request,
    limit: int = 50,
    x_trace_id: str | None = Header(default=None),
    tenant_id: str = Depends(current_tenant_id),
) -> dict[str, Any]:
    path = f"/alerts/recent?{urlencode({'limit': str(limit), 'tenant_id': tenant_id})}"
    return await guarded_proxy(
        request=request,
        method="GET",
        path=path,
        target_base=settings.monitoring_adapter_url,
        payload={},
        trace_id=trace_id_from_header(x_trace_id),
    )


@app.post("/evaluations")
async def create_evaluation_record(
    request: Request,
    payload: dict[str, Any] = REQUEST_BODY,
    x_trace_id: str | None = Header(default=None),
    tenant_id: str = Depends(current_tenant_id),
) -> dict[str, Any]:
    return await guarded_proxy(request=request, method="POST", path="/evaluations", target_base=settings.evaluation_service_url, payload={**payload, "tenant_id": tenant_id}, trace_id=trace_id_from_header(x_trace_id))


@app.get("/evaluations")
async def list_evaluation_records(
    request: Request,
    incident_id: str | None = None,
    agent: str | None = None,
    limit: int = 100,
    x_trace_id: str | None = Header(default=None),
    tenant_id: str = Depends(current_tenant_id),
) -> dict[str, Any]:
    query = urlencode({key: value for key, value in {"incident_id": incident_id, "agent": agent, "limit": limit, "tenant_id": tenant_id}.items() if value is not None})
    return await guarded_proxy(request=request, method="GET", path=f"/evaluations?{query}", target_base=settings.evaluation_service_url, payload={}, trace_id=trace_id_from_header(x_trace_id))


@app.get("/evaluations/{evaluation_id}")
async def get_evaluation_record(
    evaluation_id: str,
    request: Request,
    x_trace_id: str | None = Header(default=None),
    tenant_id: str = Depends(current_tenant_id),
) -> dict[str, Any]:
    query = urlencode({"tenant_id": tenant_id})
    return await guarded_proxy(request=request, method="GET", path=f"/evaluations/{evaluation_id}?{query}", target_base=settings.evaluation_service_url, payload={}, trace_id=trace_id_from_header(x_trace_id))


@app.post("/evaluations/autonomy/assess")
async def assess_autonomy_evidence(
    request: Request,
    payload: dict[str, Any] = REQUEST_BODY,
    x_trace_id: str | None = Header(default=None),
    tenant_id: str = Depends(current_tenant_id),
) -> dict[str, Any]:
    return await guarded_proxy(request=request, method="POST", path="/evaluations/autonomy/assess", target_base=settings.evaluation_service_url, payload={**payload, "tenant_id": tenant_id}, trace_id=trace_id_from_header(x_trace_id))


@app.post("/evaluations/retention/sweep")
async def sweep_expired_evaluation_records(
    request: Request,
    payload: dict[str, Any] = REQUEST_BODY,
    x_trace_id: str | None = Header(default=None),
    auth: AuthContext = Depends(require_roles(SystemRole.ADMINISTRATOR.value)),
) -> dict[str, Any]:
    return await guarded_proxy(
        request=request,
        method="POST",
        path="/evaluations/retention/sweep",
        target_base=settings.evaluation_service_url,
        payload={**payload, "tenant_id": auth.tenant_id},
        trace_id=trace_id_from_header(x_trace_id),
    )


@app.get("/alerts/all")
async def get_all_alerts(
    request: Request,
    limit: int = 500,
    compact: bool = False,
    x_trace_id: str | None = Header(default=None),
    tenant_id: str = Depends(current_tenant_id),
) -> dict[str, Any]:
    # tenant_id resolves to "default" for a caller with no/invalid bearer
    # token (this endpoint doesn't otherwise require auth, matching
    # api_gateway.auth_policy's read-routes-open convention) and to the
    # authenticated caller's own tenant otherwise — see current_tenant_id.
    path = f"/alerts/all?{urlencode({'limit': str(limit), 'tenant_id': tenant_id, 'compact': 'true' if compact else 'false'})}"
    return await guarded_proxy(
        request=request,
        method="GET",
        path=path,
        target_base=settings.monitoring_adapter_url,
        payload={},
        trace_id=trace_id_from_header(x_trace_id),
        # Source-balanced alert reads include incident context and can exceed
        # the generic 12-second fast-read budget during active ingestion.
        timeout_seconds=45.0,
    )


@app.get("/alerts/{alert_id}/processed-result")
async def get_alert_processed_result(
    alert_id: str,
    request: Request,
    x_trace_id: str | None = Header(default=None),
    tenant_id: str = Depends(current_tenant_id),
) -> dict[str, Any]:
    path = f"/alerts/{quote(alert_id, safe='')}/processed-result?{urlencode({'tenant_id': tenant_id})}"
    return await guarded_proxy(
        request=request,
        method="GET",
        path=path,
        target_base=settings.monitoring_adapter_url,
        payload={},
        trace_id=trace_id_from_header(x_trace_id),
    )


@app.get("/alerts/applications")
async def get_alert_applications(
    request: Request,
    limit: int = 5000,
    x_trace_id: str | None = Header(default=None),
    tenant_id: str = Depends(current_tenant_id),
) -> dict[str, Any]:
    path = f"/alerts/applications?{urlencode({'limit': str(limit), 'tenant_id': tenant_id})}"
    return await guarded_proxy(
        request=request,
        method="GET",
        path=path,
        target_base=settings.monitoring_adapter_url,
        payload={},
        trace_id=trace_id_from_header(x_trace_id),
    )


@app.get("/alerts/{alert_id}/linked-documents")
async def get_alert_linked_documents(
    alert_id: str,
    request: Request,
    limit: int = 500,
    x_trace_id: str | None = Header(default=None),
    tenant_id: str = Depends(current_tenant_id),
) -> dict[str, Any]:
    trace_id = trace_id_from_header(x_trace_id)
    # Resolve one alert directly. Pulling the entire unified inbox transferred
    # several megabytes and intermittently exhausted this optional view's
    # two-second budget as incident volume grew.
    _ = max(1, min(int(limit), 1000))  # retained for API compatibility
    alerts_path = (
        f"/alerts/{quote(alert_id, safe='')}/processed-result?"
        f"{urlencode({'tenant_id': tenant_id})}"
    )
    alerts_degraded = False
    try:
        _, alerts_payload = await proxy(
            method="GET",
            path=alerts_path,
            target_base=settings.monitoring_adapter_url,
            payload={},
            trace_id=trace_id,
            timeout_seconds=2.0,
        )
    except httpx.HTTPError as exc:
        alerts_degraded = True
        alerts_payload = {"rows": []}
        logger.warning(
            "linked_documents_alert_lookup_degraded alert_id=%s trace_id=%s error_type=%s",
            str(alert_id or "").strip(),
            trace_id,
            type(exc).__name__,
        )
    documents_degraded = alerts_degraded
    documents_warning = ""
    try:
        _, docs_payload = await proxy(
            method="GET",
            path=f"/rag/documents?{urlencode({'tenant_scope': tenant_id})}",
            target_base=settings.context_agent_url,
            payload={},
            trace_id=trace_id,
            # Evidence enrichment is optional and must never hold the
            # incident workspace open behind a saturated context service.
            timeout_seconds=2.0,
        )
    except (httpx.HTTPError, ValueError, TypeError) as exc:
        # Document evidence enriches the RCA view but is not required to show
        # the alert or its stored analysis. Keep the primary experience usable
        # when the context service is saturated or temporarily unavailable.
        documents_degraded = True
        documents_warning = "Document evidence is temporarily unavailable. The stored RCA result is still available."
        docs_payload = {"documents": []}
        logger.warning(
            "linked_documents_degraded alert_id=%s trace_id=%s error_type=%s",
            str(alert_id or "").strip(),
            trace_id,
            type(exc).__name__,
        )
    alerts_data = _payload_data(alerts_payload)
    docs_data = _payload_data(docs_payload)
    rows = alerts_data.get("rows") or alerts_data.get("alerts") or []
    documents = docs_data.get("documents") or []
    if not isinstance(rows, list):
        rows = []
    if not isinstance(documents, list):
        documents = []

    normalized_id = str(alert_id or "").strip()
    exact_alert = alerts_data.get("alert") if isinstance(alerts_data.get("alert"), dict) else None
    selected_alert = exact_alert or next(
        (
            row for row in rows
            if isinstance(row, dict)
            and normalized_id
            in {
                str(row.get("alert_id") or "").strip(),
                str(row.get("id") or "").strip(),
                str(row.get("incident_id") or "").strip(),
                str(row.get("correlation_id") or "").strip(),
            }
        ),
        None,
    )
    if selected_alert is None and alerts_degraded:
        selected_alert = {
            "id": normalized_id,
            "alert_id": normalized_id,
            "name": "Alert details temporarily unavailable",
            "service": "unknown",
            "source": "degraded-alert-lookup",
        }
    elif selected_alert is None:
        raise HTTPException(status_code=404, detail={"message": "alert not found", "alert_id": normalized_id, "trace_id": trace_id})

    canonical = _canonical_alert_contract(selected_alert)
    context = _document_match_context(selected_alert, canonical)
    linked_documents = [
        linked
        for linked in (_link_document_to_alert(doc, context) for doc in documents if isinstance(doc, dict))
        if linked is not None
    ]
    linked_documents.sort(key=lambda doc: (-float(doc.get("match_confidence") or 0), str(doc.get("kind") or ""), str(doc.get("title") or "")))
    contract = _enterprise_contract(canonical, trace_id)
    return {
        "trace_id": trace_id,
        "canonical_alert": canonical,
        "linked_documents": linked_documents,
        "document_link_summary": {
            "count": len(linked_documents),
            "source": "api-gateway.alert-linked-documents",
            "contract_version": "kaiops.alert-document-link.v1",
            "match_reasons": sorted({str(doc.get("match_reason") or "") for doc in linked_documents if doc.get("match_reason")}),
            "degraded": documents_degraded,
            "warning": documents_warning,
        },
        **contract,
    }


@app.get("/alerts/severity-overrides")
async def get_alert_severity_overrides(
    request: Request,
    x_trace_id: str | None = Header(default=None),
) -> dict[str, Any]:
    return await guarded_proxy(
        request=request,
        method="GET",
        path="/alerts/severity-overrides",
        target_base=settings.monitoring_adapter_url,
        payload={},
        trace_id=trace_id_from_header(x_trace_id),
    )


@app.put("/alerts/severity-overrides")
async def put_alert_severity_override(
    request: Request,
    payload: dict[str, Any] = REQUEST_BODY,
    x_trace_id: str | None = Header(default=None),
) -> dict[str, Any]:
    return await guarded_proxy(
        request=request,
        method="PUT",
        path="/alerts/severity-overrides",
        target_base=settings.monitoring_adapter_url,
        payload=payload,
        trace_id=trace_id_from_header(x_trace_id),
    )


@app.delete("/alerts/severity-overrides")
async def delete_alert_severity_override(
    request: Request,
    name: str,
    service: str = "",
    environment: str = "",
    x_trace_id: str | None = Header(default=None),
) -> dict[str, Any]:
    path = f"/alerts/severity-overrides?{urlencode({'name': name, 'service': service, 'environment': environment})}"
    return await guarded_proxy(
        request=request,
        method="DELETE",
        path=path,
        target_base=settings.monitoring_adapter_url,
        payload={},
        trace_id=trace_id_from_header(x_trace_id),
    )


@app.post("/sample/payment-latency")
async def sample_payment_latency(
    request: Request,
    x_trace_id: str | None = Header(default=None),
) -> dict[str, Any]:
    return await guarded_proxy(
        request=request,
        method="POST",
        path="/sample/payment-latency",
        target_base=settings.monitoring_adapter_url,
        payload={},
        trace_id=trace_id_from_header(x_trace_id),
    )


@app.post("/sample/payment-latency/workflow")
async def sample_payment_latency_workflow(
    request: Request,
    fast_mode: bool = False,
    x_trace_id: str | None = Header(default=None),
) -> dict[str, Any]:
    path = "/sample/payment-latency/workflow"
    if fast_mode:
        path = f"{path}?{urlencode({'fast_mode': 'true'})}"
    return await guarded_proxy(
        request=request,
        method="POST",
        path=path,
        target_base=settings.monitoring_adapter_url,
        payload={},
        trace_id=trace_id_from_header(x_trace_id),
    )


@app.get("/sample/flows")
async def sample_flows(
    request: Request,
    x_trace_id: str | None = Header(default=None),
) -> dict[str, Any]:
    return await guarded_proxy(
        request=request,
        method="GET",
        path="/sample/flows",
        target_base=settings.monitoring_adapter_url,
        payload={},
        trace_id=trace_id_from_header(x_trace_id),
    )


@app.get("/onboarding/connectivity")
async def get_onboarding_connectivity(
    request: Request,
    x_trace_id: str | None = Header(default=None),
) -> dict[str, Any]:
    return await guarded_proxy(
        request=request,
        method="GET",
        path="/onboarding/connectivity",
        target_base=settings.monitoring_adapter_url,
        payload={},
        trace_id=trace_id_from_header(x_trace_id),
    )


@app.get("/onboarding/state")
async def get_onboarding_state(
    request: Request,
    x_trace_id: str | None = Header(default=None),
) -> dict[str, Any]:
    return await guarded_proxy(
        request=request,
        method="GET",
        path="/onboarding/state",
        target_base=settings.monitoring_adapter_url,
        payload={},
        trace_id=trace_id_from_header(x_trace_id),
    )


@app.delete("/onboarding/state/{project_name}")
async def delete_onboarding_state(
    project_name: str,
    request: Request,
    provider_name: str | None = None,
    x_trace_id: str | None = Header(default=None),
) -> dict[str, Any]:
    query_suffix = f"?{urlencode({'provider_name': provider_name})}" if provider_name else ""
    return await guarded_proxy(
        request=request,
        method="DELETE",
        path=f"/onboarding/state/{project_name}{query_suffix}",
        target_base=settings.monitoring_adapter_url,
        payload={},
        trace_id=trace_id_from_header(x_trace_id),
    )


@app.get("/onboarding/rules/capabilities")
async def get_onboarding_rule_capabilities(
    request: Request,
    x_trace_id: str | None = Header(default=None),
) -> dict[str, Any]:
    return await guarded_proxy(
        request=request,
        method="GET",
        path="/onboarding/rules/capabilities",
        target_base=settings.monitoring_adapter_url,
        payload={},
        trace_id=trace_id_from_header(x_trace_id),
    )


@app.post("/onboarding/rules/pipeline/existing")
async def post_onboarding_rules_pipeline_existing(
    request: Request,
    payload: dict[str, Any] = REQUEST_BODY,
    x_trace_id: str | None = Header(default=None),
) -> dict[str, Any]:
    return await guarded_proxy(
        request=request,
        method="POST",
        path="/onboarding/rules/pipeline/existing",
        target_base=settings.monitoring_adapter_url,
        payload=payload,
        trace_id=trace_id_from_header(x_trace_id),
    )


@app.post("/onboarding/rules/pipeline/new")
async def post_onboarding_rules_pipeline_new(
    request: Request,
    payload: dict[str, Any] = REQUEST_BODY,
    x_trace_id: str | None = Header(default=None),
) -> dict[str, Any]:
    return await guarded_proxy(
        request=request,
        method="POST",
        path="/onboarding/rules/pipeline/new",
        target_base=settings.monitoring_adapter_url,
        payload=payload,
        trace_id=trace_id_from_header(x_trace_id),
    )


@app.post("/onboarding/rules/pipeline/create")
async def post_onboarding_rules_pipeline_create_alias(
    request: Request,
    payload: dict[str, Any] = REQUEST_BODY,
    x_trace_id: str | None = Header(default=None),
) -> dict[str, Any]:
    # Backward-compatible alias for clients still using older onboarding route names.
    return await guarded_proxy(
        request=request,
        method="POST",
        path="/onboarding/rules/pipeline/new",
        target_base=settings.monitoring_adapter_url,
        payload=payload,
        trace_id=trace_id_from_header(x_trace_id),
    )


@app.get("/onboarding/rules/pipeline/{workflow_id}")
async def get_onboarding_rules_pipeline(
    workflow_id: str,
    request: Request,
    x_trace_id: str | None = Header(default=None),
) -> dict[str, Any]:
    return await guarded_proxy(
        request=request,
        method="GET",
        path=f"/onboarding/rules/pipeline/{workflow_id}",
        target_base=settings.monitoring_adapter_url,
        payload={},
        trace_id=trace_id_from_header(x_trace_id),
    )


@app.put("/onboarding/rules/pipeline/{workflow_id}")
async def put_onboarding_rules_pipeline(
    workflow_id: str,
    request: Request,
    payload: dict[str, Any] = REQUEST_BODY,
    x_trace_id: str | None = Header(default=None),
) -> dict[str, Any]:
    return await guarded_proxy(
        request=request,
        method="PUT",
        path=f"/onboarding/rules/pipeline/{workflow_id}",
        target_base=settings.monitoring_adapter_url,
        payload=payload,
        trace_id=trace_id_from_header(x_trace_id),
    )


@app.delete("/onboarding/rules/pipeline/{workflow_id}")
async def delete_onboarding_rules_pipeline(
    workflow_id: str,
    request: Request,
    x_trace_id: str | None = Header(default=None),
) -> dict[str, Any]:
    return await guarded_proxy(
        request=request,
        method="DELETE",
        path=f"/onboarding/rules/pipeline/{workflow_id}",
        target_base=settings.monitoring_adapter_url,
        payload={},
        trace_id=trace_id_from_header(x_trace_id),
    )


@app.get("/agent-work/items")
async def get_agent_work_items(
    request: Request,
    limit: int = 100,
    x_trace_id: str | None = Header(default=None),
) -> dict[str, Any]:
    path = f"/agent-work/items?{urlencode({'limit': str(limit)})}"
    return await guarded_proxy(
        request=request,
        method="GET",
        path=path,
        target_base=settings.monitoring_adapter_url,
        payload={},
        trace_id=trace_id_from_header(x_trace_id),
    )


@app.get("/incidents/closed")
async def get_closed_incidents(
    request: Request,
    limit: int = 100,
    offset: int = 0,
    x_trace_id: str | None = Header(default=None),
    tenant_id: str = Depends(current_tenant_id),
) -> dict[str, Any]:
    path = f"/incidents/closed?{urlencode({'limit': str(limit), 'tenant_id': tenant_id, 'offset': str(max(0, offset))})}"
    return await guarded_proxy(
        request=request,
        method="GET",
        path=path,
        target_base=settings.monitoring_adapter_url,
        payload={},
        trace_id=trace_id_from_header(x_trace_id),
    )


@app.post("/incidents/{incident_id}/manual-remediation/assign")
async def assign_incident_manual_remediation(
    incident_id: str,
    request: Request,
    payload: dict[str, Any] = REQUEST_BODY,
    x_trace_id: str | None = Header(default=None),
) -> dict[str, Any]:
    return await guarded_proxy(
        request=request,
        method="POST",
        path=f"/incidents/{incident_id}/manual-remediation/assign",
        target_base=settings.monitoring_adapter_url,
        payload=payload,
        trace_id=trace_id_from_header(x_trace_id),
    )


@app.post("/incidents/{incident_id}/manual-remediation/complete")
async def complete_incident_manual_remediation(
    incident_id: str,
    request: Request,
    payload: dict[str, Any] = REQUEST_BODY,
    x_trace_id: str | None = Header(default=None),
) -> dict[str, Any]:
    return await guarded_proxy(
        request=request,
        method="POST",
        path=f"/incidents/{incident_id}/manual-remediation/complete",
        target_base=settings.monitoring_adapter_url,
        payload=payload,
        trace_id=trace_id_from_header(x_trace_id),
    )


@app.get("/incidents/metadata")
async def get_incident_metadata(
    request: Request,
    limit: int = 100,
    include_enrichment: bool = True,
    risk_tier: str | None = None,
    execution_mode: str | None = None,
    transport_provider: str | None = None,
    status: str | None = None,
    service: str | None = None,
    incident_id: str | None = None,
    x_trace_id: str | None = Header(default=None),
    tenant_id: str = Depends(current_tenant_id),
) -> dict[str, Any]:
    params: dict[str, str] = {
        "limit": str(limit),
        "include_enrichment": "true" if include_enrichment else "false",
        "tenant_id": tenant_id,
    }
    if risk_tier:
        params["risk_tier"] = str(risk_tier)
    if execution_mode:
        params["execution_mode"] = str(execution_mode)
    if transport_provider:
        params["transport_provider"] = str(transport_provider)
    if status:
        params["status"] = str(status)
    if service:
        params["service"] = str(service)
    if incident_id:
        params["incident_id"] = str(incident_id)
    path = f"/incidents/metadata?{urlencode(params)}"
    return await guarded_proxy(
        request=request,
        method="GET",
        path=path,
        target_base=settings.monitoring_adapter_url,
        payload={},
        trace_id=trace_id_from_header(x_trace_id),
    )


@app.get("/incidents/{incident_id}/stage-completeness")
async def get_incident_stage_completeness(
    incident_id: str,
    request: Request,
    x_trace_id: str | None = Header(default=None),
    tenant_id: str = Depends(current_tenant_id),
) -> dict[str, Any]:
    path = (
        f"/incidents/{quote(incident_id, safe='')}/stage-completeness?"
        f"{urlencode({'tenant_id': tenant_id})}"
    )
    return await guarded_proxy(
        request=request,
        method="GET",
        path=path,
        target_base=settings.monitoring_adapter_url,
        payload={},
        trace_id=trace_id_from_header(x_trace_id),
    )


def tenant_scoped_analysis_payload(payload: dict[str, Any], tenant_id: str) -> dict[str, Any]:
    """Bind browser-triggered analysis to the authenticated tenant.

    Context and resolution contracts repeat tenant identity at the envelope,
    alert, and incident levels. Never trust any of those browser-supplied
    values when the gateway already owns a verified session identity.
    """
    normalized = dict(payload)
    normalized["tenant_id"] = tenant_id
    if isinstance(normalized.get("alert"), dict):
        normalized["alert"] = {**normalized["alert"], "tenant_id": tenant_id}
    if isinstance(normalized.get("incident"), dict):
        normalized["incident"] = {**normalized["incident"], "tenant_id": tenant_id}
    return normalized


async def _publish_analysis_regeneration_command(
    *,
    request_id: str,
    tenant_id: str,
    alert: Alert,
    incident: Incident,
    decision: dict[str, Any],
    expected_recommendation_id: UUID,
) -> tuple[str, str, bool]:
    """Durably hand an operator-requested analysis rerun to the event pipeline."""
    transport_provider = str(getattr(settings, "event_bus_provider", "rabbitmq") or "rabbitmq")
    event_envelope = build_orchestration_envelope(
        alert=alert,
        incident=incident,
        decision=decision,
        transport_provider=transport_provider,
        channel=ORCHESTRATION_EVENTS,
    )
    event_envelope.update({
        "event_id": request_id,
        "event_type": "incident.analysis.regeneration.requested",
    })
    event_envelope["idempotency"] = {
        "idempotency_key": f"incident.analysis.regeneration.requested:{request_id}",
        "fingerprint": request_id,
    }
    event_contract = build_agent_event_contract(
        flow_id=str(decision.get("flow_id") or incident.id),
        incident_id=str(incident.id),
        trace_id=str(incident.trace_id or alert.trace_id or ""),
        correlation_id=str(alert.correlation_id or "") or None,
        agent="api-gateway",
        payload={
            "analysis_request_id": request_id,
            "analysis_mode": decision.get("analysis_mode"),
            "context_strategy": decision.get("context_strategy"),
            "topic": ORCHESTRATION_EVENTS,
        },
        metadata={"operator_requested": True},
        reasoning="Authenticated operator requested incident analysis regeneration.",
        evidence_ids=[str(alert.id), str(incident.id)],
    )
    command = {
        "alert": alert.model_dump(mode="json"),
        "incident": incident.model_dump(mode="json"),
        "decision": decision,
        "analysis_request": {
            "id": request_id,
            "mode": decision.get("analysis_mode"),
            "requested_at": datetime.now(UTC).isoformat(),
        },
        "transport": transport_provider,
        "event_envelope": event_envelope,
        "event_contract": event_contract,
    }
    outbox_event_id = f"analysis-regeneration:{request_id}"
    stored = False
    session_factory = getattr(app.state, "session_factory", None)
    if settings.database_enabled and session_factory is not None:
        async with session_factory() as session:
            repository = IncidentRepository(session)
            lifecycle, created = await repository.create_or_reuse_analysis_request(
                request_id=UUID(request_id),
                tenant_id=tenant_id,
                incident_id=incident.id,
                alert_id=alert.id,
                expected_recommendation_id=expected_recommendation_id,
                mode=str(decision.get("analysis_mode") or "smart"),
            )
            if not created:
                await session.commit()
                return lifecycle.delivery, str(lifecycle.request_id), False
            stored = await repository.enqueue_resolution_event(
                event_id=outbox_event_id,
                aggregate_id=str(incident.id),
                topic=ORCHESTRATION_EVENTS,
                partition_key=str(alert.service or incident.id),
                payload=command,
                tenant_id=tenant_id,
                available_after_seconds=0,
            )
            await session.commit()

    try:
        await app.state.producer.publish(ORCHESTRATION_EVENTS, command, key=str(alert.service or incident.id))
    except Exception as exc:
        if not stored or session_factory is None:
            raise HTTPException(status_code=503, detail="Analysis command broker is unavailable") from exc
        async with session_factory() as session:
            repository = IncidentRepository(session)
            await repository.mark_resolution_event_retry(outbox_event_id, str(exc))
            lifecycle = await repository.get_analysis_request(UUID(request_id), tenant_id=tenant_id)
            if lifecycle is not None and lifecycle.status in {"accepted", "queued"}:
                lifecycle.status = "queued"
                lifecycle.delivery = "queued"
            await session.commit()
        logger.warning(
            "analysis_regeneration_queued request_id=%s incident_id=%s error_type=%s",
            request_id,
            incident.id,
            type(exc).__name__,
        )
        return "queued", request_id, True

    if stored and session_factory is not None:
        async with session_factory() as session:
            repository = IncidentRepository(session)
            await repository.mark_resolution_event_published(outbox_event_id)
            await session.commit()
    return "published", request_id, True


def _analysis_recommendation_id(*, incident_id: UUID, request_id: UUID) -> UUID:
    """Match the Resolution Agent's stable identity for one analysis request."""
    return uuid5(NAMESPACE_URL, f"kaims:recommendation:{incident_id}:{request_id}:v2")


async def _load_analysis_regeneration_subject(
    *,
    alert_id: str,
    tenant_id: str,
    session_factory: Any,
) -> tuple[Alert, Incident, dict[str, Any], str | None]:
    """Load only the three canonical rows required to enqueue analysis.

    The processed-result projection deliberately hydrates the entire incident
    cockpit and is therefore unsuitable for command acceptance or polling.
    """
    try:
        alert_uuid = UUID(str(alert_id))
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=404, detail="Alert was not found in the authenticated tenant") from exc

    async with session_factory() as session:
        alert_record = (
            await session.execute(
                select(AlertRecord).where(
                    AlertRecord.id == alert_uuid,
                    AlertRecord.tenant_id == tenant_id,
                )
            )
        ).scalar_one_or_none()
        if alert_record is None:
            raise HTTPException(status_code=404, detail="Alert was not found in the authenticated tenant")

        projection_record = (
            await session.execute(
                select(IncidentProjectionRecord)
                .where(
                    IncidentProjectionRecord.alert_id == alert_uuid,
                    IncidentProjectionRecord.tenant_id == tenant_id,
                )
                .order_by(
                    IncidentProjectionRecord.latest_event_at.desc(),
                    IncidentProjectionRecord.updated_at.desc(),
                )
                .limit(1)
            )
        ).scalar_one_or_none()
        if projection_record is None:
            occurrence_record = (
                await session.execute(
                    select(IncidentOccurrenceRecord)
                    .where(
                        IncidentOccurrenceRecord.occurrence_id == alert_uuid,
                        IncidentOccurrenceRecord.tenant_id == tenant_id,
                    )
                    .order_by(IncidentOccurrenceRecord.observed_at.desc())
                    .limit(1)
                )
            ).scalar_one_or_none()
            if occurrence_record is not None:
                projection_record = (
                    await session.execute(
                        select(IncidentProjectionRecord).where(
                            IncidentProjectionRecord.incident_id == occurrence_record.canonical_incident_id,
                            IncidentProjectionRecord.tenant_id == tenant_id,
                        )
                    )
                ).scalar_one_or_none()
        if projection_record is None:
            # Older deduplication records predate incident_occurrences. Their
            # authoritative relation is the canonical incident's alert_ids
            # payload. Processed-result already supports this legacy relation;
            # regeneration must resolve it identically or the cockpit can show
            # an RCA that its own Refresh action is unable to regenerate.
            incident_rows = await session.execute(
                select(IncidentRecord)
                .where(IncidentRecord.tenant_id == tenant_id)
                .order_by(IncidentRecord.updated_at.desc(), IncidentRecord.created_at.desc())
                .limit(300)
            )
            linked_incident = next((
                record
                for record in incident_rows.scalars().all()
                if str(alert_id) in {
                    str(value)
                    for value in (
                        record.payload.get("alert_ids", [])
                        if isinstance(record.payload, dict)
                        and isinstance(record.payload.get("alert_ids"), list)
                        else []
                    )
                }
            ), None)
            if linked_incident is not None:
                projection_record = (
                    await session.execute(
                        select(IncidentProjectionRecord)
                        .where(
                            IncidentProjectionRecord.incident_id == linked_incident.id,
                            IncidentProjectionRecord.tenant_id == tenant_id,
                        )
                        .order_by(
                            IncidentProjectionRecord.latest_event_at.desc(),
                            IncidentProjectionRecord.updated_at.desc(),
                        )
                        .limit(1)
                    )
                ).scalar_one_or_none()
        if projection_record is None:
            raise HTTPException(
                status_code=409,
                detail="The alert does not have a persisted incident yet; refresh after correlation completes",
            )

        incident_record = (
            await session.execute(
                select(IncidentRecord).where(
                    IncidentRecord.id == projection_record.incident_id,
                    IncidentRecord.tenant_id == tenant_id,
                )
            )
        ).scalar_one_or_none()
        if incident_record is None:
            raise HTTPException(
                status_code=409,
                detail="The incident projection is incomplete; refresh after persistence completes",
            )

        # Historical rows contain source-specific keys that are intentionally
        # forbidden by the canonical command models. Reconstruct the command
        # from typed columns and copy only compatible enrichment instead of
        # validating the complete stored source payload as an Alert/Incident.
        stored_alert = dict(alert_record.payload) if isinstance(alert_record.payload, dict) else {}
        stored_incident = dict(incident_record.payload) if isinstance(incident_record.payload, dict) else {}
        valid_severities = {"info", "warning", "high", "critical"}
        alert_severity = str(alert_record.severity or "warning").strip().lower()
        incident_severity = str(incident_record.severity or alert_severity).strip().lower()
        if alert_severity not in valid_severities:
            alert_severity = "warning"
        if incident_severity not in valid_severities:
            incident_severity = alert_severity
        valid_statuses = {
            "open", "investigating", "rca_ready", "awaiting_approval", "approved", "remediating",
            "validating", "resolved", "closed", "failed", "cancelled",
        }
        incident_status = str(incident_record.status or "investigating").strip().lower().replace("-", "_")
        if incident_status not in valid_statuses:
            # Reproduced live: _advance_incident_status_on_grounded_rca (see
            # repository.py) writes "rca_ready" to incident_record.status for
            # every genuinely grounded RCA, but this allow-list never
            # recognized that value -- silently reverting it back to
            # "investigating" here, making a completed, grounded RCA
            # indistinguishable from one that was never looked at.
            incident_status = "investigating"
        stored_annotations = (
            stored_alert.get("annotations") if isinstance(stored_alert.get("annotations"), dict) else {}
        )

        def persisted_alert_time(*keys: str) -> datetime | None:
            for key in keys:
                value = stored_annotations.get(key) or stored_alert.get(key)
                if isinstance(value, datetime):
                    parsed = value
                elif isinstance(value, str) and value.strip():
                    try:
                        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
                    except ValueError:
                        continue
                else:
                    continue
                if parsed.year <= 1:
                    continue
                return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
            return None

        # The source observation time is part of the alert identity.  Never
        # let Alert's default factory replace it with regeneration time, or a
        # historical RCA will query the wrong telemetry and trace window.
        alert_started_at = persisted_alert_time("startsAt", "starts_at", "observed_at", "timestamp")
        alert_started_at = alert_started_at or alert_record.created_at
        alert_ends_at = persisted_alert_time("endsAt", "ends_at")
        alert_payload = {
            "id": str(alert_record.id),
            "created_at": alert_record.created_at,
            "tenant_id": tenant_id,
            "source": alert_record.source,
            "name": alert_record.name,
            "service": alert_record.service,
            "environment": alert_record.environment,
            "severity": alert_severity,
            "description": str(
                stored_alert.get("description") or stored_alert.get("summary") or alert_record.name
            ),
            "starts_at": alert_started_at,
            "ends_at": alert_ends_at,
            "fingerprint": alert_record.fingerprint,
            "correlation_id": alert_record.correlation_id,
            "labels": stored_alert.get("labels") if isinstance(stored_alert.get("labels"), dict) else {},
            "annotations": stored_annotations,
        }
        alert_ids = []
        for candidate in stored_incident.get("alert_ids") or []:
            try:
                alert_ids.append(str(UUID(str(candidate))))
            except (TypeError, ValueError):
                continue
        if str(alert_record.id) not in alert_ids:
            alert_ids.append(str(alert_record.id))
        incident_payload = {
            "id": str(incident_record.id),
            "created_at": incident_record.created_at,
            "tenant_id": tenant_id,
            "alert_ids": alert_ids,
            "service": incident_record.service,
            "environment": incident_record.environment,
            "severity": incident_severity,
            "status": incident_status,
            "title": incident_record.title,
            "summary": str(stored_incident.get("summary") or stored_alert.get("description") or incident_record.title),
            "owner_team": str(stored_incident.get("owner_team") or stored_incident.get("owner") or "") or None,
            "ticket_id": incident_record.ticket_id,
        }
        projection_payload = (
            projection_record.projection_payload
            if isinstance(projection_record.projection_payload, dict)
            else {}
        )
        persisted_decision = (
            projection_payload.get("decision")
            if isinstance(projection_payload.get("decision"), dict)
            else {}
        )
        decision = {
            "requires_approval": projection_record.requires_approval,
            "risk_tier": projection_record.risk_tier,
            "execution_mode": projection_record.execution_mode,
            "policy_version": projection_record.policy_version,
            "policy_reason": projection_record.policy_reason,
            **persisted_decision,
        }
        previous_recommendation_id = (
            str(projection_record.recommendation_id)
            if projection_record.recommendation_id is not None
            else None
        )
        previous_rca_version = 0
        if projection_record.recommendation_id is not None:
            previous_payload = (
                await session.execute(
                    select(AuditLogRecord.payload).where(
                        AuditLogRecord.id == projection_record.recommendation_id,
                        AuditLogRecord.tenant_id == tenant_id,
                        AuditLogRecord.resource_id == str(projection_record.incident_id),
                        AuditLogRecord.action == "recommendation.generated",
                    )
                )
            ).scalar_one_or_none()
            previous_metadata = (
                previous_payload.get("metadata")
                if isinstance(previous_payload, dict) and isinstance(previous_payload.get("metadata"), dict)
                else {}
            )
            try:
                previous_rca_version = max(0, int(previous_metadata.get("rca_version") or 0))
            except (TypeError, ValueError):
                previous_rca_version = 0
        decision["rca_version"] = previous_rca_version + 1

    try:
        return (
            Alert.model_validate(alert_payload),
            Incident.model_validate(incident_payload),
            decision,
            previous_recommendation_id,
        )
    except ValidationError as exc:
        raise HTTPException(
            status_code=409,
            detail="Persisted alert or incident context is incomplete; reload the incident before regenerating analysis",
        ) from exc


@app.post("/analysis/alerts/{alert_id}/regenerate", status_code=202)
async def regenerate_alert_analysis(
    alert_id: str,
    request: Request,
    payload: dict[str, Any] = REQUEST_BODY,
    x_trace_id: str | None = Header(default=None),
    tenant_id: str = Depends(current_tenant_id),
) -> dict[str, Any]:
    """Queue one tenant-scoped RCA regeneration without browser-side orchestration."""
    mode = str(payload.get("mode") or "smart").strip().lower()
    strategies = {"smart": "auto", "fresh": "realtime", "cache": "historical"}
    if mode not in strategies:
        raise HTTPException(status_code=422, detail="mode must be one of: smart, fresh, cache")

    session_factory = getattr(request.app.state, "session_factory", None)
    if session_factory is None:
        raise HTTPException(status_code=503, detail="Database is unavailable for analysis regeneration")
    alert, incident, existing_decision, previous_recommendation_id = await _load_analysis_regeneration_subject(
        alert_id=alert_id,
        tenant_id=tenant_id,
        session_factory=session_factory,
    )
    request_id = str(uuid4())
    decision = {
        "workflow": "guided-remediation",
        "requires_approval": True,
        "risk_tier": "high",
        "execution_mode": "supervised",
        "policy_version": "policy-v1",
        "policy_reason": "Operator-requested analysis follows the governed incident path.",
        **existing_decision,
        "flow_id": str(existing_decision.get("flow_id") or incident.id),
        "analysis_request_id": request_id,
        "analysis_mode": mode,
        "context_strategy": strategies[mode],
        "force_full_analysis": mode == "fresh",
        "regeneration_requested": True,
        "rca_version": max(1, int(existing_decision.get("rca_version") or 1)),
    }
    expected_recommendation_id = _analysis_recommendation_id(
        incident_id=incident.id,
        request_id=UUID(request_id),
    )
    publish_result = await _publish_analysis_regeneration_command(
        request_id=request_id,
        tenant_id=tenant_id,
        alert=alert,
        incident=incident,
        decision=decision,
        expected_recommendation_id=expected_recommendation_id,
    )
    if isinstance(publish_result, tuple):
        delivery, effective_request_id, created = publish_result
    else:  # Compatibility for alternate publishers and focused test doubles.
        delivery, effective_request_id, created = str(publish_result), request_id, True
    if effective_request_id != request_id:
        request_id = effective_request_id
        expected_recommendation_id = _analysis_recommendation_id(
            incident_id=incident.id, request_id=UUID(request_id)
        )
    return {
        "request_id": request_id,
        "status": "accepted" if created else "coalesced",
        "delivery": delivery,
        "alert_id": str(alert.id),
        "incident_id": str(incident.id),
        "previous_recommendation_id": previous_recommendation_id,
        "expected_recommendation_id": str(expected_recommendation_id),
        "analysis_mode": mode,
        "context_strategy": strategies[mode],
        "poll_after_ms": 2500,
    }


@app.post("/incidents/{incident_id}/claims/{claim_id}/amend", status_code=202)
async def amend_incident_claim(
    incident_id: str,
    claim_id: str,
    request: Request,
    payload: dict[str, Any] = REQUEST_BODY,
    auth: AuthContext = Depends(require_roles(  # noqa: B008
        SystemRole.ADMINISTRATOR.value,
        SystemRole.L2_ENGINEER.value,
        SystemRole.L3_ENGINEER.value,
    )),
) -> dict[str, Any]:
    """Record an operator amendment and rerun analysis without treating it as observed evidence."""
    try:
        incident_uuid = UUID(incident_id)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="incident_id must be a UUID") from exc
    corrected_statement = str(payload.get("statement") or "").strip()
    reason = str(payload.get("reason") or "").strip()
    source_reference = str(payload.get("source_reference") or "").strip()
    if len(corrected_statement) < 10:
        raise HTTPException(status_code=422, detail="statement must contain at least 10 characters")
    if len(reason) < 10:
        raise HTTPException(status_code=422, detail="reason must contain at least 10 characters")
    parsed_source = urlparse(source_reference)
    if not source_reference or not parsed_source.scheme:
        raise HTTPException(status_code=422, detail="source_reference must be an absolute source URI")

    factory = getattr(request.app.state, "session_factory", None)
    if not settings.database_enabled or factory is None:
        raise HTTPException(status_code=503, detail="Claim amendment persistence is unavailable")
    actor = str(auth.email or auth.username or auth.user_id).strip()
    async with factory() as session:
        binding = await session.scalar(select(IncidentInvestigationBindingRecord).where(
            IncidentInvestigationBindingRecord.tenant_id == auth.tenant_id,
            IncidentInvestigationBindingRecord.incident_id == incident_uuid,
            IncidentInvestigationBindingRecord.status.notin_(["superseded", "invalidated"]),
        ).order_by(
            IncidentInvestigationBindingRecord.rca_version.desc(),
            IncidentInvestigationBindingRecord.created_at.desc(),
        ).limit(1))
        if binding is None:
            raise HTTPException(status_code=409, detail="No current governed RCA binding is available to amend")
        recommendation = await session.get(AuditLogRecord, binding.recommendation_id)
        recommendation_payload = dict(recommendation.payload or {}) if recommendation else {}
        metadata = recommendation_payload.get("metadata") if isinstance(recommendation_payload.get("metadata"), dict) else {}
        iterative = metadata.get("iterative_investigation") if isinstance(metadata.get("iterative_investigation"), dict) else {}
        rca_result = iterative.get("rca_result") if isinstance(iterative.get("rca_result"), dict) else {}
        claims = [item for item in rca_result.get("claims", []) if isinstance(item, dict)]
        original_claim = next((item for item in claims if str(item.get("claim_id")) == claim_id), None)
        if original_claim is None:
            raise HTTPException(status_code=409, detail="The claim is stale or is not part of the current RCA version")
        prior = await session.scalar(select(func.max(HumanCorrectionRecord.version)).where(
            HumanCorrectionRecord.tenant_id == auth.tenant_id,
            HumanCorrectionRecord.entity_type == "rca",
            HumanCorrectionRecord.entity_id == claim_id,
        ))
        correction = HumanCorrectionRecord(
            id=uuid4(), tenant_id=auth.tenant_id, entity_type="rca", entity_id=claim_id,
            correction_type="rca" if str(original_claim.get("kind") or "").upper() == "CAUSAL" else "impact",
            original_payload=original_claim,
            corrected_payload={
                "statement": corrected_statement,
                "source_reference": source_reference,
                "parent_claim_id": claim_id,
                "rca_version": binding.rca_version,
            },
            reason=reason, actor=actor, actor_role=auth.role,
            status="pending_reanalysis", version=int(prior or 0) + 1,
        )
        session.add(correction)
        binding.status = "invalidated"
        approvals = (await session.execute(select(ApprovalRecord).where(
            ApprovalRecord.tenant_id == auth.tenant_id,
            ApprovalRecord.incident_id == incident_uuid,
            ApprovalRecord.recommendation_id == binding.recommendation_id,
        ))).scalars().all()
        for approval in approvals:
            approval.decision = "stale"
            approval.payload = {**dict(approval.payload or {}), "invalidated_by_claim_amendment_id": str(correction.id)}
        session.add(AuditLogRecord(
            tenant_id=auth.tenant_id, actor=actor, action="incident.claim.amendment.recorded",
            resource_type="incident", resource_id=str(incident_uuid),
            payload={
                "correction_id": str(correction.id), "claim_id": claim_id,
                "rca_version": binding.rca_version, "source_reference": source_reference,
                "actor_role": auth.role, "stale_approvals_invalidated": len(approvals),
            },
        ))
        alert_id = str(binding.alert_id)
        correction_id = str(correction.id)
        await session.commit()

    alert, incident, existing_decision, previous_recommendation_id = await _load_analysis_regeneration_subject(
        alert_id=alert_id, tenant_id=auth.tenant_id, session_factory=factory,
    )
    request_id = str(uuid4())
    decision = {
        "workflow": "guided-remediation", "requires_approval": True,
        "risk_tier": "high", "execution_mode": "supervised",
        "policy_version": "policy-v1", "policy_reason": "Human claim amendments require governed reanalysis.",
        **existing_decision,
        "flow_id": str(existing_decision.get("flow_id") or incident.id),
        "analysis_request_id": request_id, "analysis_mode": "fresh", "context_strategy": "realtime",
        "force_full_analysis": True, "regeneration_requested": True,
        "claim_amendment_id": correction_id,
        "rca_version": max(1, int(existing_decision.get("rca_version") or 1)),
    }
    expected_id = _analysis_recommendation_id(incident_id=incident.id, request_id=UUID(request_id))
    delivery, effective_request_id, _ = await _publish_analysis_regeneration_command(
        request_id=request_id, tenant_id=auth.tenant_id, alert=alert, incident=incident,
        decision=decision, expected_recommendation_id=expected_id,
    )
    return {
        "correction_id": correction_id, "claim_id": claim_id, "status": "pending_reanalysis",
        "request_id": effective_request_id, "delivery": delivery,
        "previous_recommendation_id": previous_recommendation_id,
        "expected_recommendation_id": str(expected_id), "poll_after_ms": 2500,
    }


@app.get("/analysis/requests/{request_id}/status")
async def get_analysis_request_status(
    request_id: str,
    incident_id: str,
    request: Request,
    tenant_id: str = Depends(current_tenant_id),
) -> dict[str, Any]:
    """Check one indexed audit identity instead of rebuilding the incident cockpit."""
    try:
        request_uuid = UUID(request_id)
        incident_uuid = UUID(incident_id)
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=422, detail="request_id and incident_id must be UUIDs") from exc

    expected_recommendation_id = _analysis_recommendation_id(
        incident_id=incident_uuid,
        request_id=request_uuid,
    )
    session_factory = getattr(request.app.state, "session_factory", None)
    if session_factory is None:
        raise HTTPException(status_code=503, detail="Database is unavailable for analysis status")

    async with session_factory() as session:
        repository = IncidentRepository(session)
        lifecycle = await repository.get_analysis_request(request_uuid, tenant_id=tenant_id)
        if lifecycle is not None:
            if lifecycle.incident_id != incident_uuid:
                raise HTTPException(status_code=404, detail="Analysis request was not found for this incident")
            if await repository.expire_analysis_request(lifecycle):
                await session.commit()
            return {
                "request_id": str(lifecycle.request_id),
                "incident_id": str(lifecycle.incident_id),
                "recommendation_id": str(lifecycle.recommendation_id or lifecycle.expected_recommendation_id),
                "status": lifecycle.status,
                "ready": lifecycle.status == "complete",
                "terminal": lifecycle.status in {"complete", "failed", "timed_out", "superseded"},
                "retryable": lifecycle.status in {"failed", "timed_out"},
                "delivery": lifecycle.delivery,
                "terminal_reason": lifecycle.terminal_reason,
                "created_at": lifecycle.created_at,
                "updated_at": lifecycle.updated_at,
                "completed_at": lifecycle.completed_at,
            }
        recommendation_id = (
            await session.execute(
                select(AuditLogRecord.id)
                .where(
                    AuditLogRecord.id == expected_recommendation_id,
                    AuditLogRecord.tenant_id == tenant_id,
                    AuditLogRecord.resource_type == "incident",
                    AuditLogRecord.resource_id == str(incident_uuid),
                    AuditLogRecord.action == "recommendation.generated",
                )
                .limit(1)
            )
        ).scalar_one_or_none()

    ready = recommendation_id is not None
    return {
        "request_id": str(request_uuid),
        "incident_id": str(incident_uuid),
        "recommendation_id": str(expected_recommendation_id),
        "status": "complete" if ready else "running",
        "ready": ready,
    }


@app.post("/analysis/context/collect")
async def collect_analysis_context(
    request: Request,
    payload: dict[str, Any] = REQUEST_BODY,
    publish_events: bool = False,
    x_trace_id: str | None = Header(default=None),
    tenant_id: str = Depends(current_tenant_id),
) -> dict[str, Any]:
    return await guarded_proxy(
        request=request,
        method="POST",
        path="/collect",
        target_base=settings.context_agent_url,
        payload=tenant_scoped_analysis_payload(payload, tenant_id),
        params={"publish_events": "true" if publish_events else "false"},
        trace_id=trace_id_from_header(x_trace_id),
        timeout_seconds=190.0,
    )


@app.post("/analysis/resolution/resolve")
async def resolve_analysis_context(
    request: Request,
    payload: dict[str, Any] = REQUEST_BODY,
    publish_events: bool = True,
    x_trace_id: str | None = Header(default=None),
    tenant_id: str = Depends(current_tenant_id),
) -> dict[str, Any]:
    return await guarded_proxy(
        request=request,
        method="POST",
        path="/resolve",
        target_base=settings.resolution_agent_url,
        payload=tenant_scoped_analysis_payload(payload, tenant_id),
        params={"publish_events": "true" if publish_events else "false"},
        trace_id=trace_id_from_header(x_trace_id),
        timeout_seconds=190.0,
    )


@app.post("/analysis/resolution-catalog/relevant")
async def relevant_analysis_resolutions(
    request: Request,
    payload: dict[str, Any] = REQUEST_BODY,
    x_trace_id: str | None = Header(default=None),
    tenant_id: str = Depends(current_tenant_id),
) -> dict[str, Any]:
    return await guarded_proxy(
        request=request,
        method="POST",
        path="/resolution-catalog/relevant",
        target_base=settings.resolution_agent_url,
        payload={**payload, "tenant_id": tenant_id},
        trace_id=trace_id_from_header(x_trace_id),
    )


@app.post("/analysis/resolution-catalog/select")
async def select_analysis_resolution(
    request: Request,
    payload: dict[str, Any] = REQUEST_BODY,
    x_trace_id: str | None = Header(default=None),
    auth: AuthContext = Depends(require_roles(
        SystemRole.ADMINISTRATOR.value,
        SystemRole.L2_ENGINEER.value,
        SystemRole.L3_ENGINEER.value,
    )),
) -> dict[str, Any]:
    return await guarded_proxy(
        request=request,
        method="POST",
        path="/resolution-catalog/select",
        target_base=settings.resolution_agent_url,
        payload={**payload, "tenant_id": auth.tenant_id, "actor": auth.username or str(auth.user_id)},
        trace_id=trace_id_from_header(x_trace_id),
    )


@app.get("/resolution/investigations/{incident_id}")
async def get_resolution_investigation(
    incident_id: str,
    request: Request,
    x_trace_id: str | None = Header(default=None),
    tenant_id: str = Depends(current_tenant_id),
) -> dict[str, Any]:
    """Return the latest durable iterative investigation for an incident."""
    path = f"/investigations/{quote(incident_id, safe='')}?{urlencode({'tenant_id': tenant_id})}"
    return await guarded_proxy(
        request=request,
        method="GET",
        path=path,
        target_base=settings.resolution_agent_url,
        payload={},
        trace_id=trace_id_from_header(x_trace_id),
    )


@app.get("/landing-pad/recent")
async def get_landing_pad_recent(
    request: Request,
    limit: int = 20,
    include_archive: bool = False,
    x_trace_id: str | None = Header(default=None),
) -> dict[str, Any]:
    path = f"/landing-pad/recent?{urlencode({'limit': str(limit), 'include_archive': str(include_archive).lower()})}"
    return await guarded_proxy(
        request=request,
        method="GET",
        path=path,
        target_base=settings.monitoring_adapter_url,
        payload={},
        trace_id=trace_id_from_header(x_trace_id),
    )


@app.get("/landing-pad/archive")
async def get_landing_pad_archive(
    request: Request,
    limit: int = 100,
    x_trace_id: str | None = Header(default=None),
) -> dict[str, Any]:
    return await guarded_proxy(
        request=request,
        method="GET",
        path=f"/landing-pad/archive?{urlencode({'limit': str(limit)})}",
        target_base=settings.monitoring_adapter_url,
        payload={},
        trace_id=trace_id_from_header(x_trace_id),
    )


@app.get("/landing-pad/objects/{object_id}/access")
async def get_landing_pad_object_access(
    object_id: str,
    request: Request,
    x_trace_id: str | None = Header(default=None),
) -> dict[str, Any]:
    return await guarded_proxy(
        request=request,
        method="GET",
        path=f"/landing-pad/objects/{object_id}/access",
        target_base=settings.monitoring_adapter_url,
        payload={},
        trace_id=trace_id_from_header(x_trace_id),
    )


@app.get("/landing-pad/objects/{object_id}/download")
async def download_landing_pad_object(object_id: str, request: Request) -> StreamingResponse:
    """Stream an authorized object without buffering it in the gateway."""
    target_url = f"{settings.monitoring_adapter_url.rstrip('/')}/landing-pad/objects/{object_id}/download"

    async def content():
        async with httpx.AsyncClient(timeout=httpx.Timeout(60.0, connect=5.0)) as client:
            async with client.stream("GET", target_url, headers={"X-Trace-Id": trace_id_from_header(request.headers.get("x-trace-id"))}) as response:
                if response.status_code >= 400:
                    body = await response.aread()
                    raise HTTPException(status_code=response.status_code, detail=body.decode("utf-8", errors="replace"))
                async for chunk in response.aiter_bytes():
                    yield chunk

    return StreamingResponse(content(), media_type="application/octet-stream", headers={"Content-Disposition": f'attachment; filename="{object_id}"'})


@app.get("/landing-pad/input")
async def get_landing_pad_input(
    request: Request,
    limit: int = 50,
    x_trace_id: str | None = Header(default=None),
) -> dict[str, Any]:
    path = f"/landing-pad/input?{urlencode({'limit': str(limit)})}"
    return await guarded_proxy(
        request=request,
        method="GET",
        path=path,
        target_base=settings.monitoring_adapter_url,
        payload={},
        trace_id=trace_id_from_header(x_trace_id),
    )


@app.post("/landing-pad/input/process")
async def process_landing_pad_input(
    request: Request,
    payload: dict[str, Any] = REQUEST_BODY,
    x_trace_id: str | None = Header(default=None),
) -> dict[str, Any]:
    safe_payload = require_object_payload(payload, "Landing pad input replay payload")
    return await guarded_proxy(
        request=request,
        method="POST",
        path="/landing-pad/input/process",
        target_base=settings.monitoring_adapter_url,
        payload=safe_payload,
        trace_id=trace_id_from_header(x_trace_id),
    )


@app.post("/onboarding/connectivity")
async def post_onboarding_connectivity(
    request: Request,
    payload: dict[str, Any] = REQUEST_BODY,
    x_trace_id: str | None = Header(default=None),
) -> dict[str, Any]:
    return await guarded_proxy(
        request=request,
        method="POST",
        path="/onboarding/connectivity",
        target_base=settings.monitoring_adapter_url,
        payload=payload,
        trace_id=trace_id_from_header(x_trace_id),
    )


@app.post("/onboarding/complete")
async def post_onboarding_complete(
    request: Request,
    payload: dict[str, Any] = REQUEST_BODY,
    x_trace_id: str | None = Header(default=None),
) -> dict[str, Any]:
    return await guarded_proxy(
        request=request,
        method="POST",
        path="/onboarding/complete",
        target_base=settings.monitoring_adapter_url,
        payload=payload,
        trace_id=trace_id_from_header(x_trace_id),
    )


@app.get("/monitoring/providers")
async def get_monitoring_providers(
    request: Request,
    x_trace_id: str | None = Header(default=None),
) -> dict[str, Any]:
    return await guarded_proxy(
        request=request,
        method="GET",
        path="/monitoring/providers",
        target_base=settings.monitoring_adapter_url,
        payload={},
        trace_id=trace_id_from_header(x_trace_id),
    )


@app.get("/monitoring/integrations")
async def get_monitoring_integrations(
    request: Request,
    tenant_id: str = "default",
    x_trace_id: str | None = Header(default=None),
) -> dict[str, Any]:
    path = f"/monitoring/integrations?{urlencode({'tenant_id': tenant_id})}"
    return await guarded_proxy(
        request=request,
        method="GET",
        path=path,
        target_base=settings.monitoring_adapter_url,
        payload={},
        trace_id=trace_id_from_header(x_trace_id),
    )


@app.get("/cloud-ops/connections")
async def list_cloud_connections(
    request: Request,
    project_id: str | None = None,
    x_trace_id: str | None = Header(default=None),
    tenant_id: str = Depends(current_tenant_id),
) -> dict[str, Any]:
    params = {"tenant_id": tenant_id}
    if project_id:
        params["project_id"] = project_id
    return await guarded_proxy(
        request=request,
        method="GET",
        path=f"/connections?{urlencode(params)}",
        target_base=settings.cloud_operations_url,
        payload={},
        trace_id=trace_id_from_header(x_trace_id),
    )


@app.post("/cloud-ops/connections")
async def create_cloud_connection(
    request: Request,
    payload: dict[str, Any] = REQUEST_BODY,
    x_trace_id: str | None = Header(default=None),
    auth: AuthContext = Depends(require_roles(SystemRole.ADMINISTRATOR.value)),
) -> dict[str, Any]:
    return await guarded_proxy(
        request=request,
        method="POST",
        path="/connections",
        target_base=settings.cloud_operations_url,
        payload={**payload, "tenant_id": auth.tenant_id},
        trace_id=trace_id_from_header(x_trace_id),
        timeout_seconds=15.0,
    )


@app.get("/cloud-ops/capabilities")
async def list_cloud_capabilities(
    request: Request,
    provider: str = "simulator",
    x_trace_id: str | None = Header(default=None),
    _: str = Depends(current_tenant_id),
) -> dict[str, Any]:
    return await guarded_proxy(
        request=request,
        method="GET",
        path=f"/capabilities?{urlencode({'provider': provider})}",
        target_base=settings.cloud_operations_url,
        payload={},
        trace_id=trace_id_from_header(x_trace_id),
    )


@app.get("/cloud-ops/onboarding/templates")
async def list_cloud_onboarding_templates(
    request: Request,
    x_trace_id: str | None = Header(default=None),
    _: str = Depends(current_tenant_id),
) -> dict[str, Any]:
    return await guarded_proxy(
        request=request,
        method="GET",
        path="/onboarding/templates",
        target_base=settings.cloud_operations_url,
        payload={},
        trace_id=trace_id_from_header(x_trace_id),
    )


@app.get("/cloud-ops/connectors/catalog")
async def list_connector_catalog(
    request: Request,
    x_trace_id: str | None = Header(default=None),
    _: str = Depends(current_tenant_id),
) -> dict[str, Any]:
    return await guarded_proxy(
        request=request,
        method="GET",
        path="/connectors/catalog",
        target_base=settings.cloud_operations_url,
        payload={},
        trace_id=trace_id_from_header(x_trace_id),
    )


@app.get("/cloud-ops/connections/{connection_id}/knowledge-candidates")
async def cloud_connection_knowledge_candidates(
    connection_id: str,
    request: Request,
    limit: int = 20,
    x_trace_id: str | None = Header(default=None),
    auth: AuthContext = Depends(require_roles(
        SystemRole.ADMINISTRATOR.value, SystemRole.L2_ENGINEER.value, SystemRole.L3_ENGINEER.value,
    )),
) -> dict[str, Any]:
    params = {"tenant_id": auth.tenant_id, "limit": limit}
    return await guarded_proxy(
        request=request,
        method="GET",
        path=f"/connections/{quote(connection_id, safe='')}/knowledge-candidates?{urlencode(params)}",
        target_base=settings.cloud_operations_url,
        payload={},
        trace_id=trace_id_from_header(x_trace_id),
        timeout_seconds=20.0,
    )


@app.post("/cloud-ops/connections/{connection_id}/validate")
async def validate_cloud_connection(
    connection_id: str,
    request: Request,
    payload: dict[str, Any] = REQUEST_BODY,
    x_trace_id: str | None = Header(default=None),
    auth: AuthContext = Depends(require_roles(SystemRole.ADMINISTRATOR.value)),
) -> dict[str, Any]:
    scoped_payload = {**payload, "tenant_id": auth.tenant_id, "actor": auth.username or "admin"}
    return await guarded_proxy(
        request=request,
        method="POST",
        path=f"/connections/{quote(connection_id, safe='')}/validate",
        target_base=settings.cloud_operations_url,
        payload=scoped_payload,
        trace_id=trace_id_from_header(x_trace_id),
        timeout_seconds=15.0,
    )


@app.post("/cloud-ops/connections/{connection_id}/discover")
async def discover_cloud_resources(
    connection_id: str,
    request: Request,
    payload: dict[str, Any] = REQUEST_BODY,
    x_trace_id: str | None = Header(default=None),
    auth: AuthContext = Depends(require_roles(SystemRole.ADMINISTRATOR.value)),
) -> dict[str, Any]:
    scoped_payload = {**payload, "tenant_id": auth.tenant_id, "actor": auth.username or "admin"}
    return await guarded_proxy(
        request=request,
        method="POST",
        path=f"/connections/{quote(connection_id, safe='')}/discover",
        target_base=settings.cloud_operations_url,
        payload=scoped_payload,
        trace_id=trace_id_from_header(x_trace_id),
        timeout_seconds=30.0,
    )


@app.get("/cloud-ops/resources")
async def list_cloud_resources(
    request: Request,
    project_id: str | None = None,
    service_id: str | None = None,
    environment: str | None = None,
    x_trace_id: str | None = Header(default=None),
    tenant_id: str = Depends(current_tenant_id),
) -> dict[str, Any]:
    params = {"tenant_id": tenant_id}
    if project_id:
        params["project_id"] = project_id
    if service_id:
        params["service_id"] = service_id
    if environment:
        params["environment"] = environment
    return await guarded_proxy(
        request=request,
        method="GET",
        path=f"/resources?{urlencode(params)}",
        target_base=settings.cloud_operations_url,
        payload={},
        trace_id=trace_id_from_header(x_trace_id),
    )


@app.get("/cloud-ops/cockpit")
async def cloud_operations_cockpit(
    request: Request,
    project_id: str | None = None,
    environment: str | None = None,
    x_trace_id: str | None = Header(default=None),
    tenant_id: str = Depends(current_tenant_id),
) -> dict[str, Any]:
    params = {"tenant_id": tenant_id}
    if project_id:
        params["project_id"] = project_id
    if environment:
        params["environment"] = environment
    return await guarded_proxy(
        request=request,
        method="GET",
        path=f"/cockpit?{urlencode(params)}",
        target_base=settings.cloud_operations_url,
        payload={},
        trace_id=trace_id_from_header(x_trace_id),
    )


@app.post("/cloud-ops/services/{service_id}/map")
async def map_cloud_service_resources(
    service_id: str,
    request: Request,
    payload: dict[str, Any] = REQUEST_BODY,
    x_trace_id: str | None = Header(default=None),
    auth: AuthContext = Depends(require_roles(SystemRole.ADMINISTRATOR.value)),
) -> dict[str, Any]:
    scoped_payload = {**payload, "tenant_id": auth.tenant_id, "owner": payload.get("owner") or auth.username or "admin"}
    return await guarded_proxy(
        request=request,
        method="POST",
        path=f"/services/{quote(service_id, safe='')}/map",
        target_base=settings.cloud_operations_url,
        payload=scoped_payload,
        trace_id=trace_id_from_header(x_trace_id),
    )


@app.get("/cloud-ops/services/{service_id}/360")
async def cloud_service_360(
    service_id: str,
    request: Request,
    project_id: str,
    environment: str | None = None,
    x_trace_id: str | None = Header(default=None),
    tenant_id: str = Depends(current_tenant_id),
) -> dict[str, Any]:
    params = {"tenant_id": tenant_id, "project_id": project_id}
    if environment:
        params["environment"] = environment
    return await guarded_proxy(
        request=request,
        method="GET",
        path=f"/services/{quote(service_id, safe='')}/360?{urlencode(params)}",
        target_base=settings.cloud_operations_url,
        payload={},
        trace_id=trace_id_from_header(x_trace_id),
    )


@app.get("/cloud-ops/services/{service_id}/topology")
async def cloud_service_topology(
    service_id: str,
    request: Request,
    project_id: str,
    environment: str | None = None,
    x_trace_id: str | None = Header(default=None),
    tenant_id: str = Depends(current_tenant_id),
) -> dict[str, Any]:
    params = {"tenant_id": tenant_id, "project_id": project_id}
    if environment:
        params["environment"] = environment
    return await guarded_proxy(
        request=request,
        method="GET",
        path=f"/services/{quote(service_id, safe='')}/topology?{urlencode(params)}",
        target_base=settings.cloud_operations_url,
        payload={},
        trace_id=trace_id_from_header(x_trace_id),
    )


@app.put("/cloud-ops/services/{service_id}/onboarding")
async def upsert_cloud_service_onboarding(
    service_id: str,
    request: Request,
    payload: dict[str, Any] = REQUEST_BODY,
    x_trace_id: str | None = Header(default=None),
    auth: AuthContext = Depends(require_roles(SystemRole.ADMINISTRATOR.value)),
) -> dict[str, Any]:
    scoped_payload = {**payload, "tenant_id": auth.tenant_id, "actor": auth.username or "admin"}
    return await guarded_proxy(
        request=request,
        method="PUT",
        path=f"/services/{quote(service_id, safe='')}/onboarding",
        target_base=settings.cloud_operations_url,
        payload=scoped_payload,
        trace_id=trace_id_from_header(x_trace_id),
    )


@app.post("/cloud-ops/services/{service_id}/readiness/recalculate")
async def recalculate_cloud_service_readiness(
    service_id: str,
    request: Request,
    payload: dict[str, Any] = REQUEST_BODY,
    x_trace_id: str | None = Header(default=None),
    auth: AuthContext = Depends(require_roles(SystemRole.ADMINISTRATOR.value)),
) -> dict[str, Any]:
    scoped_payload = {**payload, "tenant_id": auth.tenant_id, "actor": auth.username or "admin"}
    return await guarded_proxy(
        request=request,
        method="POST",
        path=f"/services/{quote(service_id, safe='')}/readiness/recalculate",
        target_base=settings.cloud_operations_url,
        payload=scoped_payload,
        trace_id=trace_id_from_header(x_trace_id),
    )


@app.post("/cloud-ops/plans/compile")
async def compile_cloud_plan(
    request: Request,
    payload: dict[str, Any] = REQUEST_BODY,
    x_trace_id: str | None = Header(default=None),
    auth: AuthContext = Depends(require_roles(SystemRole.ADMINISTRATOR.value)),
) -> dict[str, Any]:
    return await guarded_proxy(
        request=request, method="POST", path="/plans/compile", target_base=settings.cloud_operations_url,
        payload={**payload, "tenant_id": auth.tenant_id, "actor": auth.username or "admin"},
        trace_id=trace_id_from_header(x_trace_id), timeout_seconds=15.0,
    )


@app.get("/cloud-ops/plans/{plan_id}")
async def get_cloud_plan(
    plan_id: str, request: Request, x_trace_id: str | None = Header(default=None),
    tenant_id: str = Depends(current_tenant_id),
) -> dict[str, Any]:
    return await guarded_proxy(
        request=request, method="GET",
        path=f"/plans/{quote(plan_id, safe='')}?{urlencode({'tenant_id': tenant_id})}",
        target_base=settings.cloud_operations_url, payload={}, trace_id=trace_id_from_header(x_trace_id),
    )


@app.post("/cloud-ops/plans/{plan_id}/simulate")
async def simulate_cloud_plan(
    plan_id: str, request: Request, payload: dict[str, Any] = REQUEST_BODY,
    x_trace_id: str | None = Header(default=None),
    auth: AuthContext = Depends(require_roles(SystemRole.ADMINISTRATOR.value)),
) -> dict[str, Any]:
    return await guarded_proxy(
        request=request, method="POST", path=f"/plans/{quote(plan_id, safe='')}/simulate",
        target_base=settings.cloud_operations_url,
        payload={**payload, "tenant_id": auth.tenant_id, "actor": auth.username or "admin"},
        trace_id=trace_id_from_header(x_trace_id), timeout_seconds=15.0,
    )


@app.post("/cloud-ops/plans/{plan_id}/approval")
async def approve_cloud_plan(
    plan_id: str, request: Request, payload: dict[str, Any] = REQUEST_BODY,
    x_trace_id: str | None = Header(default=None),
    auth: AuthContext = Depends(require_roles(SystemRole.ADMINISTRATOR.value)),
) -> dict[str, Any]:
    return await guarded_proxy(
        request=request, method="POST", path=f"/plans/{quote(plan_id, safe='')}/approval",
        target_base=settings.cloud_operations_url,
        payload={**payload, "tenant_id": auth.tenant_id, "actor": auth.username or "admin"},
        trace_id=trace_id_from_header(x_trace_id), timeout_seconds=15.0,
    )


@app.post("/cloud-ops/plans/{plan_id}/execute")
async def execute_cloud_plan(
    plan_id: str, request: Request, payload: dict[str, Any] = REQUEST_BODY,
    x_trace_id: str | None = Header(default=None),
    auth: AuthContext = Depends(require_roles(SystemRole.ADMINISTRATOR.value)),
) -> dict[str, Any]:
    return await guarded_proxy(
        request=request, method="POST", path=f"/plans/{quote(plan_id, safe='')}/execute",
        target_base=settings.cloud_operations_url,
        payload={**payload, "tenant_id": auth.tenant_id, "actor": auth.username or "admin"},
        trace_id=trace_id_from_header(x_trace_id), timeout_seconds=60.0,
    )


@app.post("/cloud-ops/executions/{execution_id}/rollback")
async def rollback_cloud_execution(
    execution_id: str, request: Request, payload: dict[str, Any] = REQUEST_BODY,
    x_trace_id: str | None = Header(default=None),
    auth: AuthContext = Depends(require_roles(SystemRole.ADMINISTRATOR.value)),
) -> dict[str, Any]:
    return await guarded_proxy(
        request=request, method="POST", path=f"/executions/{quote(execution_id, safe='')}/rollback",
        target_base=settings.cloud_operations_url,
        payload={**payload, "tenant_id": auth.tenant_id, "actor": auth.username or "admin"},
        trace_id=trace_id_from_header(x_trace_id), timeout_seconds=60.0,
    )


@app.put("/cloud-ops/governance/policy")
async def put_cloud_execution_policy(
    request: Request, payload: dict[str, Any] = REQUEST_BODY,
    x_trace_id: str | None = Header(default=None), auth: AuthContext = Depends(require_roles(SystemRole.ADMINISTRATOR.value)),
) -> dict[str, Any]:
    return await guarded_proxy(request=request, method="PUT", path="/governance/policy", target_base=settings.cloud_operations_url, payload={**payload, "tenant_id": auth.tenant_id, "actor": auth.username or "admin"}, trace_id=trace_id_from_header(x_trace_id))


@app.post("/cloud-ops/governance/maintenance-windows")
async def post_cloud_maintenance_window(
    request: Request, payload: dict[str, Any] = REQUEST_BODY,
    x_trace_id: str | None = Header(default=None), auth: AuthContext = Depends(require_roles(SystemRole.ADMINISTRATOR.value)),
) -> dict[str, Any]:
    return await guarded_proxy(request=request, method="POST", path="/governance/maintenance-windows", target_base=settings.cloud_operations_url, payload={**payload, "tenant_id": auth.tenant_id, "actor": auth.username or "admin"}, trace_id=trace_id_from_header(x_trace_id))


@app.post("/cloud-ops/governance/leases/recover")
async def recover_cloud_execution_leases(
    request: Request, payload: dict[str, Any] = REQUEST_BODY,
    x_trace_id: str | None = Header(default=None), auth: AuthContext = Depends(require_roles(SystemRole.ADMINISTRATOR.value)),
) -> dict[str, Any]:
    return await guarded_proxy(request=request, method="POST", path="/governance/leases/recover", target_base=settings.cloud_operations_url, payload={**payload, "tenant_id": auth.tenant_id}, trace_id=trace_id_from_header(x_trace_id))


@app.get("/cloud-ops/providers/status")
async def get_cloud_provider_status(
    request: Request, x_trace_id: str | None = Header(default=None),
    _: str = Depends(current_tenant_id),
) -> dict[str, Any]:
    return await guarded_proxy(request=request, method="GET", path="/providers/status", target_base=settings.cloud_operations_url, payload={}, trace_id=trace_id_from_header(x_trace_id))


@app.post("/monitoring/integrations")
async def post_monitoring_integrations(
    request: Request,
    payload: dict[str, Any] = REQUEST_BODY,
    x_trace_id: str | None = Header(default=None),
) -> dict[str, Any]:
    return await guarded_proxy(
        request=request,
        method="POST",
        path="/monitoring/integrations",
        target_base=settings.monitoring_adapter_url,
        payload=payload,
        trace_id=trace_id_from_header(x_trace_id),
    )


@app.get("/monitoring/integrations/{integration_id}")
async def get_monitoring_integration(
    integration_id: str,
    request: Request,
    x_trace_id: str | None = Header(default=None),
) -> dict[str, Any]:
    return await guarded_proxy(
        request=request,
        method="GET",
        path=f"/monitoring/integrations/{integration_id}",
        target_base=settings.monitoring_adapter_url,
        payload={},
        trace_id=trace_id_from_header(x_trace_id),
    )


@app.put("/monitoring/integrations/{integration_id}")
async def put_monitoring_integration(
    integration_id: str,
    request: Request,
    payload: dict[str, Any] = REQUEST_BODY,
    x_trace_id: str | None = Header(default=None),
) -> dict[str, Any]:
    return await guarded_proxy(
        request=request,
        method="PUT",
        path=f"/monitoring/integrations/{integration_id}",
        target_base=settings.monitoring_adapter_url,
        payload=payload,
        trace_id=trace_id_from_header(x_trace_id),
    )


@app.delete("/monitoring/integrations/{integration_id}")
async def delete_monitoring_integration(
    integration_id: str,
    request: Request,
    x_trace_id: str | None = Header(default=None),
) -> dict[str, Any]:
    return await guarded_proxy(
        request=request,
        method="DELETE",
        path=f"/monitoring/integrations/{integration_id}",
        target_base=settings.monitoring_adapter_url,
        payload={},
        trace_id=trace_id_from_header(x_trace_id),
    )


@app.post("/monitoring/integrations/{integration_id}/validate")
async def post_monitoring_integration_validate(
    integration_id: str,
    request: Request,
    payload: dict[str, Any] = REQUEST_BODY,
    x_trace_id: str | None = Header(default=None),
) -> dict[str, Any]:
    return await guarded_proxy(
        request=request,
        method="POST",
        path=f"/monitoring/integrations/{integration_id}/validate",
        target_base=settings.monitoring_adapter_url,
        payload=payload,
        trace_id=trace_id_from_header(x_trace_id),
    )


@app.post("/monitoring/integrations/{integration_id}/discover")
async def post_monitoring_integration_discover(
    integration_id: str,
    request: Request,
    payload: dict[str, Any] = REQUEST_BODY,
    x_trace_id: str | None = Header(default=None),
) -> dict[str, Any]:
    return await guarded_proxy(
        request=request,
        method="POST",
        path=f"/monitoring/integrations/{integration_id}/discover",
        target_base=settings.monitoring_adapter_url,
        payload=payload,
        trace_id=trace_id_from_header(x_trace_id),
    )


@app.post("/monitoring/integrations/{integration_id}/register-webhook")
async def post_monitoring_integration_register_webhook(
    integration_id: str,
    request: Request,
    payload: dict[str, Any] = REQUEST_BODY,
    x_trace_id: str | None = Header(default=None),
) -> dict[str, Any]:
    return await guarded_proxy(
        request=request,
        method="POST",
        path=f"/monitoring/integrations/{integration_id}/register-webhook",
        target_base=settings.monitoring_adapter_url,
        payload=payload,
        trace_id=trace_id_from_header(x_trace_id),
    )


@app.get("/monitoring/integrations/{integration_id}/mapping")
async def get_monitoring_integration_mapping(
    integration_id: str,
    request: Request,
    x_trace_id: str | None = Header(default=None),
) -> dict[str, Any]:
    return await guarded_proxy(
        request=request,
        method="GET",
        path=f"/monitoring/integrations/{integration_id}/mapping",
        target_base=settings.monitoring_adapter_url,
        payload={},
        trace_id=trace_id_from_header(x_trace_id),
    )


@app.put("/monitoring/integrations/{integration_id}/mapping")
async def put_monitoring_integration_mapping(
    integration_id: str,
    request: Request,
    payload: dict[str, Any] = REQUEST_BODY,
    x_trace_id: str | None = Header(default=None),
) -> dict[str, Any]:
    return await guarded_proxy(
        request=request,
        method="PUT",
        path=f"/monitoring/integrations/{integration_id}/mapping",
        target_base=settings.monitoring_adapter_url,
        payload=payload,
        trace_id=trace_id_from_header(x_trace_id),
    )


@app.post("/monitoring/integrations/{integration_id}/test-alert")
async def post_monitoring_integration_test_alert(
    integration_id: str,
    request: Request,
    payload: dict[str, Any] = REQUEST_BODY,
    x_trace_id: str | None = Header(default=None),
) -> dict[str, Any]:
    return await guarded_proxy(
        request=request,
        method="POST",
        path=f"/monitoring/integrations/{integration_id}/test-alert",
        target_base=settings.monitoring_adapter_url,
        payload=payload,
        trace_id=trace_id_from_header(x_trace_id),
    )


@app.post("/monitoring/integrations/{integration_id}/activate")
async def post_monitoring_integration_activate(
    integration_id: str,
    request: Request,
    x_trace_id: str | None = Header(default=None),
) -> dict[str, Any]:
    return await guarded_proxy(
        request=request,
        method="POST",
        path=f"/monitoring/integrations/{integration_id}/activate",
        target_base=settings.monitoring_adapter_url,
        payload={},
        trace_id=trace_id_from_header(x_trace_id),
    )


@app.post("/monitoring/integrations/{integration_id}/deactivate")
async def post_monitoring_integration_deactivate(
    integration_id: str,
    request: Request,
    x_trace_id: str | None = Header(default=None),
) -> dict[str, Any]:
    return await guarded_proxy(
        request=request,
        method="POST",
        path=f"/monitoring/integrations/{integration_id}/deactivate",
        target_base=settings.monitoring_adapter_url,
        payload={},
        trace_id=trace_id_from_header(x_trace_id),
    )


@app.get("/monitoring/health")
async def get_monitoring_health(
    request: Request,
    tenant_id: str = "default",
    x_trace_id: str | None = Header(default=None),
) -> dict[str, Any]:
    path = f"/monitoring/health?{urlencode({'tenant_id': tenant_id})}"
    return await guarded_proxy(
        request=request,
        method="GET",
        path=path,
        target_base=settings.monitoring_adapter_url,
        payload={},
        trace_id=trace_id_from_header(x_trace_id),
    )


@app.delete("/alerts/applications/{project_name}")
async def delete_observed_alert_application(
    project_name: str,
    request: Request,
    x_trace_id: str | None = Header(default=None),
    auth: AuthContext = Depends(require_roles(SystemRole.ADMINISTRATOR.value)),
) -> dict[str, Any]:
    return await guarded_proxy(
        request=request,
        method="DELETE",
        path=f"/alerts/applications/{quote(project_name, safe='')}?{urlencode({'tenant_id': auth.tenant_id})}",
        target_base=settings.monitoring_adapter_url,
        payload={},
        trace_id=trace_id_from_header(x_trace_id),
    )


@app.get("/knowledge-development/status")
async def knowledge_development_status(request: Request, x_trace_id: str | None = Header(default=None)) -> dict[str, Any]:
    return await guarded_proxy(request=request, method="GET", path="/status", target_base=settings.knowledge_development_url, payload={}, trace_id=trace_id_from_header(x_trace_id))


@app.get("/knowledge-development/configuration")
async def knowledge_development_configuration(request: Request, x_trace_id: str | None = Header(default=None)) -> dict[str, Any]:
    return await guarded_proxy(request=request, method="GET", path="/configuration", target_base=settings.knowledge_development_url, payload={}, trace_id=trace_id_from_header(x_trace_id))


@app.put("/knowledge-development/configuration")
async def update_knowledge_development_configuration(request: Request, payload: dict[str, Any] = REQUEST_BODY, x_trace_id: str | None = Header(default=None)) -> dict[str, Any]:
    return await guarded_proxy(request=request, method="PUT", path="/configuration", target_base=settings.knowledge_development_url, payload=payload, trace_id=trace_id_from_header(x_trace_id))


@app.post("/knowledge-development/run")
async def run_knowledge_development(
    request: Request,
    payload: dict[str, Any] = REQUEST_BODY,
    x_trace_id: str | None = Header(default=None),
    auth: AuthContext = Depends(require_roles(SystemRole.ADMINISTRATOR.value)),
) -> dict[str, Any]:
    return await guarded_proxy(request=request, method="POST", path="/run", target_base=settings.knowledge_development_url, payload={**payload, "tenant_id": auth.tenant_id}, trace_id=trace_id_from_header(x_trace_id), timeout_seconds=180)


@app.get("/knowledge-development/report")
async def knowledge_development_report(request: Request, x_trace_id: str | None = Header(default=None), auth: AuthContext = Depends(require_roles(SystemRole.ADMINISTRATOR.value))) -> dict[str, Any]:
    return await guarded_proxy(request=request, method="GET", path=f"/report?{urlencode({'tenant_id': auth.tenant_id})}", target_base=settings.knowledge_development_url, payload={}, trace_id=trace_id_from_header(x_trace_id), timeout_seconds=30)


@app.get("/knowledge-development/incidents/{incident_id}/catalog-status")
async def knowledge_development_incident_status(
    incident_id: str,
    request: Request,
    x_trace_id: str | None = Header(default=None),
    auth: AuthContext = Depends(require_roles(SystemRole.ADMINISTRATOR.value)),
) -> dict[str, Any]:
    return await guarded_proxy(
        request=request,
        method="GET",
        path=f"/incidents/{quote(incident_id, safe='')}/catalog-status?{urlencode({'tenant_id': auth.tenant_id})}",
        target_base=settings.knowledge_development_url,
        payload={},
        trace_id=trace_id_from_header(x_trace_id),
        timeout_seconds=15,
    )


@app.post("/knowledge-development/catalog/{runbook_id}/versions/{version}/review")
async def review_knowledge_catalog_candidate(
    runbook_id: str,
    version: int,
    request: Request,
    payload: dict[str, Any] = REQUEST_BODY,
    x_trace_id: str | None = Header(default=None),
    auth: AuthContext = Depends(require_roles(SystemRole.ADMINISTRATOR.value)),
) -> dict[str, Any]:
    return await guarded_proxy(
        request=request,
        method="POST",
        path=f"/catalog/{quote(runbook_id, safe='')}/versions/{version}/review",
        target_base=settings.knowledge_development_url,
        payload={**payload, "tenant_id": auth.tenant_id, "actor": auth.username or str(auth.user_id)},
        trace_id=trace_id_from_header(x_trace_id),
        timeout_seconds=30,
    )


@app.post("/knowledge-development/runbooks/{runbook_id}/approve")
async def approve_knowledge_runbook_draft(
    runbook_id: str,
    request: Request,
    version: int = 1,
    payload: dict[str, Any] = REQUEST_BODY,
    x_trace_id: str | None = Header(default=None),
    auth: AuthContext = Depends(require_roles(SystemRole.ADMINISTRATOR.value, "HITL_APPROVER")),
) -> dict[str, Any]:
    return await guarded_proxy(
        request=request,
        method="POST",
        path=f"/runbooks/{quote(runbook_id, safe='')}/approve?{urlencode({'version': version})}",
        target_base=settings.knowledge_development_url,
        payload={**payload, "tenant_id": auth.tenant_id, "actor": auth.username or str(auth.user_id)},
        trace_id=trace_id_from_header(x_trace_id),
        timeout_seconds=30,
    )


async def _evidence_queue_health(tenant_id: str) -> dict[str, Any]:
    factory = getattr(app.state, "session_factory", None)
    if not settings.database_enabled or factory is None:
        return {"status": "unavailable"}
    try:
        async with asyncio.timeout(2):
            async with factory() as session:
                rows = (await session.execute(select(
                    ContextEnrichmentJobRecord.status, func.count(),
                ).where(
                    ContextEnrichmentJobRecord.tenant_id == tenant_id,
                    ContextEnrichmentJobRecord.status.in_(["scheduled", "retry", "collecting"]),
                ).group_by(ContextEnrichmentJobRecord.status))).all()
        counts = {status: int(count) for status, count in rows}
        return {"status": "available", **{status: counts.get(status, 0)
            for status in ("scheduled", "retry", "collecting")},
            "observed_at": datetime.now(UTC).isoformat()}
    except (TimeoutError, SQLAlchemyError):
        return {"status": "unavailable"}


@app.get("/operations/queue-health")
async def get_queue_health(tenant_id: str = Depends(current_tenant_id)) -> dict[str, Any]:
    """Return live RabbitMQ readiness and backlog data for the command center.

    Broker telemetry is intentionally bounded and read-only. A failed management
    probe returns a useful degraded contract instead of turning dashboard load
    into an HTTP 500.
    """
    from common.alert_processing_budget import ANALYSIS_TOPICS, capacity
    processing = await capacity(settings)
    evidence_collection = await _evidence_queue_health(tenant_id)
    broker_url = urlparse(str(settings.rabbitmq_url or ""))
    if broker_url.scheme not in {"amqp", "amqps"} or not broker_url.hostname:
        return {"status": "not_configured", "provider": "rabbitmq", "healthy": False, "queues": 0, "messages": 0, "ready": 0, "unacknowledged": 0,
                "alert_processing": processing, "evidence_collection": evidence_collection, "analysis_backlog_ready": None}
    scheme = "https" if broker_url.scheme == "amqps" else "http"
    management_url = f"{scheme}://{broker_url.hostname}:15672/api/queues"
    username = unquote(broker_url.username or "guest")
    password = unquote(broker_url.password or "guest")
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(2.0)) as client:
            response = await client.get(management_url, auth=(username, password))
            response.raise_for_status()
        rows = response.json()
        queues = rows if isinstance(rows, list) else []
        queue_rows = [row for row in queues if isinstance(row, dict)]
        primary_rows = [row for row in queue_rows if not str(row.get("name") or "").endswith(".dlq")]
        dead_letter_rows = [row for row in queue_rows if str(row.get("name") or "").endswith(".dlq")]
        messages = sum(int(row.get("messages") or 0) for row in primary_rows)
        ready = sum(int(row.get("messages_ready") or 0) for row in primary_rows)
        unacknowledged = sum(int(row.get("messages_unacknowledged") or 0) for row in primary_rows)
        idle_consumers = sum(
            1 for row in primary_rows
            if int(row.get("consumers") or 0) == 0 and int(row.get("messages_ready") or 0) > 0
        )
        dead_letters = sum(int(row.get("messages") or 0) for row in dead_letter_rows)
        # In-flight deliveries prove that consumers are working; they are not a
        # readiness failure. DLQs are separate operational debt, not primary backlog.
        intake_healthy = idle_consumers == 0
        status = "attention" if not intake_healthy else "degraded" if dead_letters else "healthy"
        readiness_score = 40 if not intake_healthy else 85 if dead_letters else 100
        reason = (
            f"{idle_consumers} primary queue(s) have ready messages but no consumer."
            if not intake_healthy
            else f"Primary event flow is operational; {dead_letters} dead-letter message(s) need review."
            if dead_letters
            else "Primary event flow is operational with no dead-letter backlog."
        )
        return {
            "status": status, "provider": "rabbitmq",
            "alert_processing": processing,
            "evidence_collection": evidence_collection,
            "analysis_backlog_ready": sum(int(row.get("messages_ready") or 0) for row in primary_rows
                if any(str(row.get("name") or "").endswith((f".{topic}", f".{topic}.deferred")) for topic in ANALYSIS_TOPICS)),
            "healthy": intake_healthy and dead_letters == 0,
            "intake_healthy": intake_healthy, "readiness_score": readiness_score, "reason": reason,
            "queues": len(primary_rows), "dead_letter_queues": len(dead_letter_rows),
            "messages": messages, "ready": ready, "unacknowledged": unacknowledged,
            "dead_letters": dead_letters, "queues_without_consumers": idle_consumers,
        }
    except (httpx.HTTPError, ValueError, TypeError) as exc:
        logger.warning("RabbitMQ management health probe failed: %s", exc)
        return {"status": "unreachable", "provider": "rabbitmq", "healthy": False, "queues": 0, "messages": 0, "ready": 0, "unacknowledged": 0,
                "alert_processing": processing, "evidence_collection": evidence_collection, "analysis_backlog_ready": None}


def _rabbit_management() -> tuple[str, tuple[str, str]]:
    broker_url = urlparse(str(settings.rabbitmq_url or ""))
    if broker_url.scheme not in {"amqp", "amqps"} or not broker_url.hostname:
        raise HTTPException(status_code=503, detail="RabbitMQ management is not configured")
    scheme = "https" if broker_url.scheme == "amqps" else "http"
    return f"{scheme}://{broker_url.hostname}:15672/api", (unquote(broker_url.username or "guest"), unquote(broker_url.password or "guest"))


from common.queue_management import (
    broker_vhost, queue_job_id as _queue_job_id,
    mutate_ready_queue_job, sample_ready_messages,
)


async def _mutate_ready_queue_job(**kwargs) -> bool:
    return await mutate_ready_queue_job(broker_url=settings.rabbitmq_url, **kwargs)


async def _queue_audit(request: Request, action: str, resource_id: str, payload: dict[str, Any]) -> None:
    auth = getattr(request.state, "auth", None)
    session_factory = getattr(request.app.state, "session_factory", None)
    if not settings.database_enabled or session_factory is None:
        return
    async with session_factory() as session:
        session.add(AuditLogRecord(tenant_id=getattr(auth, "tenant_id", "default"), actor=getattr(auth, "username", "administrator"), action=action, resource_type="processing_queue", resource_id=resource_id, payload=payload))
        await session.commit()


@app.get("/operations/queues")
async def list_processing_queues(request: Request, _: AuthContext = Depends(require_roles(SystemRole.ADMINISTRATOR.value))) -> dict[str, Any]:
    base, auth = _rabbit_management()
    async with httpx.AsyncClient(timeout=httpx.Timeout(5.0)) as client:
        response = await client.get(f"{base}/queues/{quote(broker_vhost(settings.rabbitmq_url), safe='')}", auth=auth)
        response.raise_for_status()
    prefix = f"{settings.rabbitmq_queue_prefix}."
    rows = []
    for row in response.json() if isinstance(response.json(), list) else []:
        name = str(row.get("name") or "")
        if not name.startswith(prefix):
            continue
        parts = name.split(".")
        rows.append({"name": name, "consumer_service": parts[1] if len(parts) > 2 else "unknown", "stage": ".".join(parts[2:]) if len(parts) > 2 else name, "ready": int(row.get("messages_ready") or 0), "in_flight": int(row.get("messages_unacknowledged") or 0), "total": int(row.get("messages") or 0), "consumers": int(row.get("consumers") or 0), "state": row.get("state") or "unknown", "dead_letter": name.endswith(".dlq"), "deferred": name.endswith(".deferred")})
    rows.sort(key=lambda item: (-item["total"], item["name"]))
    scalable = [
        {
            "queue": row["name"],
            "service": row["consumer_service"],
            "current_consumers": row["consumers"],
            "recommended_consumers": min(16, max(row["consumers"] + 1, (row["ready"] + 4) // 5)),
            "reason": "ready backlog exceeds two messages per active consumer",
        }
        for row in rows
        if not row["dead_letter"] and not row["deferred"]
        and row["ready"] > max(5, row["consumers"] * 2)
    ]
    return {
        "provider": "rabbitmq",
        "queues": rows,
        "summary": {
            "queues": len(rows),
            "ready": sum(row["ready"] for row in rows if not row["dead_letter"] and not row["deferred"]),
            "in_flight": sum(row["in_flight"] for row in rows if not row["dead_letter"] and not row["deferred"]),
            "dead_letter": sum(row["total"] for row in rows if row["dead_letter"]),
            "deferred": sum(row["total"] for row in rows if row["deferred"]),
            "worker_action": "start_workers" if any(not row["dead_letter"] and not row["deferred"] and row["ready"] and not row["consumers"] for row in rows) else "inspect" if scalable else "hold",
            "worker_message": "Ready jobs have no consumer; restore workers before considering scaling." if any(not row["dead_letter"] and not row["deferred"] and row["ready"] and not row["consumers"] for row in rows) else "Backlog needs investigation. Check processing latency and failures before increasing concurrency." if scalable else "No backlog threshold exceeded at this snapshot; throughput has not been established.",
            "scale_recommendations": scalable,
        },
    }


@app.post("/operations/queues/{queue_name}/sample")
async def sample_processing_queue(queue_name: str, request: Request, count: int = 25, _: AuthContext = Depends(require_roles(SystemRole.ADMINISTRATOR.value))) -> dict[str, Any]:
    if not queue_name.startswith(f"{settings.rabbitmq_queue_prefix}."):
        raise HTTPException(status_code=403, detail="Queue is outside the KaiMS namespace")
    messages = await sample_ready_messages(settings.rabbitmq_url, queue_name, count)
    return {"queue": queue_name, "messages": messages, "sampled": len(messages),
            "note": "Ready messages were inspected and requeued. Concurrent consumption can change the sample; requeueing can change delivery order."}



async def _queue_job_action(queue_name: str, job_id: str, request: Request, payload: dict[str, Any], *, rerun: bool) -> dict[str, Any]:
    if not queue_name.startswith(f"{settings.rabbitmq_queue_prefix}."):
        raise HTTPException(status_code=403, detail="Queue is outside the KaiMS namespace")
    verb = "RERUN" if rerun else "REMOVE"
    reason = str(payload.get("reason") or "").strip()
    if not job_id.startswith("job-") or len(reason) < 8 or payload.get("confirmation") != f"{verb} {job_id}":
        raise HTTPException(status_code=422, detail=f"A meaningful reason and exact {verb} confirmation are required")
    found = await _mutate_ready_queue_job(queue_name=queue_name, job_id=job_id, rerun=rerun)
    if not found:
        raise HTTPException(status_code=409, detail="The selected job is no longer ready in the inspected queue window. Refresh before trying again.")
    action = "rerun" if rerun else "removed"
    await _queue_audit(request, f"queue.job.{action}", job_id, {"queue": queue_name, "reason": reason})
    return {"status": action, "queue": queue_name, "job_id": job_id, "effect": "The job was moved to the queue tail for another attempt." if rerun else "Only the selected ready job was removed."}


@app.post("/operations/queues/{queue_name}/jobs/{job_id}/rerun")
async def rerun_processing_queue_job(queue_name: str, job_id: str, request: Request, payload: dict[str, Any] = REQUEST_BODY, _: AuthContext = Depends(require_roles(SystemRole.ADMINISTRATOR.value))) -> dict[str, Any]:
    return await _queue_job_action(queue_name, job_id, request, payload, rerun=True)


@app.delete("/operations/queues/{queue_name}/jobs/{job_id}")
async def remove_processing_queue_job(queue_name: str, job_id: str, request: Request, payload: dict[str, Any] = REQUEST_BODY, _: AuthContext = Depends(require_roles(SystemRole.ADMINISTRATOR.value))) -> dict[str, Any]:
    return await _queue_job_action(queue_name, job_id, request, payload, rerun=False)


@app.post("/operations/queues/cancel-alert")
async def cancel_queued_alert(request: Request, payload: dict[str, Any] = REQUEST_BODY, _: AuthContext = Depends(require_roles(SystemRole.ADMINISTRATOR.value))) -> dict[str, Any]:
    alert_id = str(payload.get("alert_id") or "").strip()
    reason = str(payload.get("reason") or "").strip()
    if not alert_id or len(reason) < 8 or payload.get("confirmation") != f"STOP {alert_id}":
        raise HTTPException(status_code=422, detail="Alert ID, a meaningful reason, and exact STOP confirmation are required")
    client = Redis.from_url(settings.redis_url, decode_responses=True)
    try:
        await client.sadd("kaims:cancelled-processing", alert_id)
        await client.hset(
            "kaims:cancelled-processing:metadata",
            alert_id,
            json.dumps({"reason": reason, "cancelled_at": datetime.now(UTC).isoformat()}),
        )
    finally:
        await client.aclose()
    await _queue_audit(request, "queue.alert.cancelled", alert_id, {"reason": reason})
    return {"status": "cancelled", "alert_id": alert_id, "effect": "Queued stages will acknowledge and quarantine matching work. A currently executing handler may finish its current atomic operation."}


@app.delete("/operations/queues/{queue_name}/messages")
async def purge_processing_queue(queue_name: str, request: Request, payload: dict[str, Any] = REQUEST_BODY, _: AuthContext = Depends(require_roles(SystemRole.ADMINISTRATOR.value))) -> dict[str, Any]:
    if not queue_name.startswith(f"{settings.rabbitmq_queue_prefix}."):
        raise HTTPException(status_code=403, detail="Queue is outside the KaiMS namespace")
    if payload.get("confirmation") != f"PURGE {queue_name}" or len(str(payload.get("reason") or "").strip()) < 8:
        raise HTTPException(status_code=422, detail="A meaningful reason and exact queue purge confirmation are required")
    base, auth = _rabbit_management()
    async with httpx.AsyncClient(timeout=httpx.Timeout(10.0)) as client:
        response = await client.delete(f"{base}/queues/{quote(broker_vhost(settings.rabbitmq_url), safe='')}/{quote(queue_name, safe='')}/contents", auth=auth)
        response.raise_for_status()
    await _queue_audit(request, "queue.messages.purged", queue_name, {"reason": payload["reason"]})
    return {"status": "purged", "queue": queue_name, "effect": "Ready messages were removed. In-flight messages were not interrupted."}


@app.delete("/operations/queues/purge-all/ready-messages")
async def purge_all_processing_queues(request: Request, payload: dict[str, Any] = REQUEST_BODY, _: AuthContext = Depends(require_roles(SystemRole.ADMINISTRATOR.value))) -> dict[str, Any]:
    reason = str(payload.get("reason") or "").strip()
    if payload.get("confirmation") != "PURGE ALL READY JOBS" or len(reason) < 12:
        raise HTTPException(status_code=422, detail="A detailed reason and exact PURGE ALL READY JOBS confirmation are required")
    base, auth = _rabbit_management()
    prefix = f"{settings.rabbitmq_queue_prefix}."
    purged: list[str] = []
    async with httpx.AsyncClient(timeout=httpx.Timeout(30.0)) as client:
        listing = await client.get(f"{base}/queues/{quote(broker_vhost(settings.rabbitmq_url), safe='')}", auth=auth)
        listing.raise_for_status()
        for row in listing.json() if isinstance(listing.json(), list) else []:
            name = str(row.get("name") or "")
            if not name.startswith(prefix) or int(row.get("messages_ready") or 0) <= 0:
                continue
            response = await client.delete(f"{base}/queues/{quote(broker_vhost(settings.rabbitmq_url), safe='')}/{quote(name, safe='')}/contents", auth=auth)
            response.raise_for_status()
            purged.append(name)
    await _queue_audit(request, "queue.all_ready_messages.purged", "all", {"reason": reason, "queues": purged})
    return {"status": "purged", "queues": purged, "queue_count": len(purged), "effect": "All ready KaiMS messages were removed. In-flight messages were not interrupted."}


@app.get("/monitoring/audit")
async def get_monitoring_audit(
    request: Request,
    tenant_id: str = "default",
    limit: int = 100,
    x_trace_id: str | None = Header(default=None),
) -> dict[str, Any]:
    path = f"/monitoring/audit?{urlencode({'tenant_id': tenant_id, 'limit': str(limit)})}"
    return await guarded_proxy(
        request=request,
        method="GET",
        path=path,
        target_base=settings.monitoring_adapter_url,
        payload={},
        trace_id=trace_id_from_header(x_trace_id),
    )


@app.post("/api/v1/alerts/prometheus")
async def post_provider_prometheus_alert(
    request: Request,
    payload: dict[str, Any] = REQUEST_BODY,
    x_trace_id: str | None = Header(default=None),
) -> dict[str, Any]:
    return await guarded_proxy(
        request=request,
        method="POST",
        path="/api/v1/alerts/prometheus",
        target_base=settings.monitoring_adapter_url,
        payload=payload,
        trace_id=trace_id_from_header(x_trace_id),
    )


@app.post("/api/v1/alerts/datadog")
async def post_provider_datadog_alert(
    request: Request,
    payload: dict[str, Any] = REQUEST_BODY,
    x_trace_id: str | None = Header(default=None),
) -> dict[str, Any]:
    return await guarded_proxy(
        request=request,
        method="POST",
        path="/api/v1/alerts/datadog",
        target_base=settings.monitoring_adapter_url,
        payload=payload,
        trace_id=trace_id_from_header(x_trace_id),
    )


@app.post("/api/v1/alerts/newrelic")
async def post_provider_newrelic_alert(
    request: Request,
    payload: dict[str, Any] = REQUEST_BODY,
    x_trace_id: str | None = Header(default=None),
) -> dict[str, Any]:
    return await guarded_proxy(
        request=request,
        method="POST",
        path="/api/v1/alerts/newrelic",
        target_base=settings.monitoring_adapter_url,
        payload=payload,
        trace_id=trace_id_from_header(x_trace_id),
    )


@app.post("/api/v1/alerts/dynatrace")
async def post_provider_dynatrace_alert(
    request: Request,
    payload: dict[str, Any] = REQUEST_BODY,
    x_trace_id: str | None = Header(default=None),
) -> dict[str, Any]:
    return await guarded_proxy(
        request=request,
        method="POST",
        path="/api/v1/alerts/dynatrace",
        target_base=settings.monitoring_adapter_url,
        payload=payload,
        trace_id=trace_id_from_header(x_trace_id),
    )


@app.post("/api/v1/alerts/azure-monitor")
async def post_provider_azure_monitor_alert(
    request: Request,
    payload: dict[str, Any] = REQUEST_BODY,
    x_trace_id: str | None = Header(default=None),
) -> dict[str, Any]:
    return await guarded_proxy(
        request=request,
        method="POST",
        path="/api/v1/alerts/azure-monitor",
        target_base=settings.monitoring_adapter_url,
        payload=payload,
        trace_id=trace_id_from_header(x_trace_id),
    )


@app.post("/api/v1/alerts/splunk")
async def post_provider_splunk_alert(
    request: Request,
    payload: dict[str, Any] = REQUEST_BODY,
    x_trace_id: str | None = Header(default=None),
) -> dict[str, Any]:
    return await guarded_proxy(
        request=request,
        method="POST",
        path="/api/v1/alerts/splunk",
        target_base=settings.monitoring_adapter_url,
        payload=payload,
        trace_id=trace_id_from_header(x_trace_id),
    )


@app.post("/api/v1/alerts/generic")
async def post_provider_generic_alert(
    request: Request,
    provider: str = "prometheus",
    payload: dict[str, Any] = REQUEST_BODY,
    x_trace_id: str | None = Header(default=None),
) -> dict[str, Any]:
    path = f"/api/v1/alerts/generic?{urlencode({'provider': provider})}"
    return await guarded_proxy(
        request=request,
        method="POST",
        path=path,
        target_base=settings.monitoring_adapter_url,
        payload=payload,
        trace_id=trace_id_from_header(x_trace_id),
    )


@app.post("/sample/{flow_id}/workflow")
async def sample_flow_workflow(
    flow_id: str,
    request: Request,
    fast_mode: bool = False,
    x_trace_id: str | None = Header(default=None),
) -> dict[str, Any]:
    path = f"/sample/{flow_id}/workflow"
    if fast_mode:
        path = f"{path}?{urlencode({'fast_mode': 'true'})}"
    return await guarded_proxy(
        request=request,
        method="POST",
        path=path,
        target_base=settings.monitoring_adapter_url,
        payload={},
        trace_id=trace_id_from_header(x_trace_id),
    )


@app.post("/sample/{flow_id}/workflow/continue")
async def continue_sample_flow_workflow(
    flow_id: str,
    request: Request,
    payload: dict[str, Any] = REQUEST_BODY,
    x_trace_id: str | None = Header(default=None),
) -> dict[str, Any]:
    return await guarded_proxy(
        request=request,
        method="POST",
        path=f"/sample/{flow_id}/workflow/continue",
        target_base=settings.monitoring_adapter_url,
        payload=payload,
        trace_id=trace_id_from_header(x_trace_id),
    )


@app.post("/approval/{action}")
async def approval_action(
    action: str,
    request: Request,
    payload: dict[str, Any] = REQUEST_BODY,
    x_trace_id: str | None = Header(default=None),
) -> dict[str, Any]:
    if action not in {"approve", "reject", "modify", "request-evidence", "auto-assign"}:
        raise HTTPException(status_code=404, detail="unknown approval action")
    auth = getattr(request.state, "auth", None)
    if auth is None:
        # Local/demo mode permits anonymous reads, so the global middleware
        # does not populate request.state.auth. Approval mutations still need
        # a validated token because tenant and approver identity must never be
        # accepted from the request body.
        auth = await _auth_context_from_request(request)
    if action == "auto-assign":
        payload = {**payload, "tenant_id": auth.tenant_id}
    else:
        # Approval identity and tenant are security context, never editable
        # request data. Legacy role names remain accepted during migration but
        # are recorded as one of the two supported business roles.
        payload = {
            **payload,
            "tenant_id": auth.tenant_id,
            "approver": auth.email or auth.username or str(auth.user_id),
            "approver_role": "admin"
            if role_is_allowed(auth.role, {OperationalRole.ADMIN.value})
            else "hitl-reviewer",
        }
    return await guarded_proxy(
        request=request,
        method="POST",
        path=f"/{action}",
        target_base=settings.approval_service_url,
        payload=payload,
        trace_id=trace_id_from_header(x_trace_id),
    )


@app.get("/approval/incident/{incident_id}")
async def get_approval_incident_context(
    incident_id: str,
    request: Request,
    x_trace_id: str | None = Header(default=None),
    tenant_id: str = Depends(current_tenant_id),
) -> dict[str, Any]:
    """Expose approval-service's real-time, HMAC-signed approval-readiness
    receipt (`_signed_approval_readiness`) for display before an approval is
    ever attempted.

    Without this proxy the receipt existed only inside approval-service's
    own `GET /incident/{id}` handler - computed fresh on every call, never
    persisted onto the recommendation or execution plan - and nothing in
    api-gateway or the frontend ever called it. `ResolutionPanel.tsx` only
    ever read `metadata.approval_readiness`/`plan.approval_readiness` from
    the recommendation object it already had (via monitoring-adapter's
    processed-result), a key resolution-agent never writes. Net effect:
    the "signed backend approval-readiness receipt" checklist item showed
    "missing" for every incident regardless of true readiness - not a
    safety issue (the real gate at `/approval/approve` recomputes and
    enforces this correctly, independent of what the UI displays), but a
    real, permanently-wrong display bug that eroded trust in the whole
    readiness checklist.
    """
    path = f"/incident/{quote(incident_id, safe='')}?{urlencode({'tenant_id': tenant_id})}"
    return await guarded_proxy(
        request=request,
        method="GET",
        path=path,
        target_base=settings.approval_service_url,
        payload={},
        trace_id=trace_id_from_header(x_trace_id),
    )


@app.get("/incidents/groups")
async def get_incident_groups(
    request: Request,
    limit: int = 25,
    cursor: str | None = None,
    risk_tier: str | None = None,
    execution_mode: str | None = None,
    status: str | None = None,
    service: str | None = None,
    x_trace_id: str | None = Header(default=None),
    tenant_id: str = Depends(current_tenant_id),
) -> dict[str, Any]:
    params: dict[str, str] = {"limit": str(max(1, min(int(limit), 100))), "tenant_id": tenant_id}
    for key, value in {
        "cursor": cursor,
        "risk_tier": risk_tier,
        "execution_mode": execution_mode,
        "status": status,
        "service": service,
    }.items():
        if value:
            params[key] = str(value)
    return await guarded_proxy(
        request=request,
        method="GET",
        path=f"/incidents/groups?{urlencode(params)}",
        target_base=settings.monitoring_adapter_url,
        payload={},
        trace_id=trace_id_from_header(x_trace_id),
    )


@app.get("/incidents/evidence-requests")
async def get_evidence_request_queue(
    request: Request,
    responder: str | None = None,
    limit: int = 100,
    x_trace_id: str | None = Header(default=None),
    tenant_id: str = Depends(current_tenant_id),
) -> dict[str, Any]:
    # Must be registered before the generic /incidents/{incident_id} route
    # below, or Starlette matches "evidence-requests" as an incident_id and
    # this route is never reached.
    params = {"tenant_id": tenant_id, "limit": limit}
    if responder:
        params["responder"] = responder
    return await guarded_proxy(
        request=request, method="GET", path="/incidents/evidence-requests",
        payload=None, target_base=settings.context_agent_url, params=params,
        trace_id=trace_id_from_header(x_trace_id), timeout_seconds=30.0,
    )


@app.get("/incidents/{incident_id}")
async def get_incident_by_id(
    incident_id: str,
    request: Request,
    x_trace_id: str | None = Header(default=None),
    tenant_id: str = Depends(current_tenant_id),
) -> dict[str, Any]:
    return await guarded_proxy(
        request=request,
        method="GET",
        path=f"/incidents/{quote(incident_id, safe='')}?{urlencode({'tenant_id': tenant_id})}",
        target_base=settings.monitoring_adapter_url,
        payload={},
        trace_id=trace_id_from_header(x_trace_id),
    )


@app.get("/incidents/{incident_id}/command")
async def get_incident_command_workspace(
    incident_id: str,
    request: Request,
    include_source_records: bool = True,
    x_trace_id: str | None = Header(default=None),
    tenant_id: str = Depends(current_tenant_id),
) -> dict[str, Any]:
    encoded_incident_id = quote(incident_id, safe="")
    trace_id = trace_id_from_header(x_trace_id)
    for attempt in range(2):
        incident, operations = await asyncio.gather(
            guarded_proxy(
                request=request,
                method="GET",
                path=f"/incidents/{encoded_incident_id}?{urlencode({'tenant_id': tenant_id})}",
                target_base=settings.monitoring_adapter_url,
                payload={},
                trace_id=trace_id,
            ),
            guarded_proxy(
                request=request,
                method="GET",
                path=f"/incidents/{encoded_incident_id}/operations-state",
                target_base=settings.context_agent_url,
                payload=None,
                params={"tenant_id": tenant_id},
                trace_id=trace_id,
                timeout_seconds=30.0,
            ),
        )
        incident_payload = incident.get("data") if isinstance(incident.get("data"), dict) else incident
        operations_payload = operations.get("data") if isinstance(operations.get("data"), dict) else operations
        try:
            return build_incident_command_workspace(
                incident_id=incident_id,
                incident=incident_payload,
                operations=operations_payload,
                include_source_records=include_source_records,
            ).model_dump(mode="json")
        except ValidationError as exc:
            if attempt == 0:
                # A commit between the independent reads is recoverable by
                # re-reading both sides; never mix generations in the UI.
                continue
            logger.error("Incident command workspace identity mismatch for %s: %s", incident_id, exc)
            raise HTTPException(
                status_code=409,
                detail="Incident read models are inconsistent; retry after reconciliation.",
            ) from exc


@app.get("/incidents/inbox/feed")
async def get_unified_incident_inbox(
    request: Request,
    limit: int = 25,
    cursor: str | None = None,
    project_id: str | None = None,
    risk_tier: str | None = None,
    execution_mode: str | None = None,
    transport_provider: str | None = None,
    status: str | None = None,
    service: str | None = None,
    inbox_view: str = "all",
    record_type: str = "incidents",
    severity: str | None = None,
    x_trace_id: str | None = Header(default=None),
    tenant_id: str = Depends(current_tenant_id),
) -> dict[str, Any]:
    params = {
        "tenant_id": tenant_id,
        "limit": str(max(1, min(int(limit), 100))),
        "inbox_view": inbox_view,
        "record_type": record_type,
    }
    effective_project_id = (
        None
        if str(project_id or "").strip().lower() in {"all", "all applications", "all-applications", "unscoped", "all_applications"}
        else project_id
    )
    for key, value in {
        "cursor": cursor,
        "project_id": effective_project_id,
        "risk_tier": risk_tier,
        "execution_mode": execution_mode,
        "transport_provider": transport_provider,
        "status": status,
        "service": service,
        "severity": severity,
    }.items():
        if value:
            params[key] = str(value)
    return await guarded_proxy(
        request=request,
        method="GET",
        path=f"/incidents/inbox/feed?{urlencode(params)}",
        target_base=settings.monitoring_adapter_url,
        payload={},
        trace_id=trace_id_from_header(x_trace_id),
    )


@app.get("/rag/evidence-drafts")
async def list_evidence_rag_drafts(
    request: Request,
    alert_id: str | None = None,
    status: str | None = None,
    document_kind: str | None = None,
    x_trace_id: str | None = Header(default=None),
    tenant_id: str = Depends(current_tenant_id),
) -> dict[str, Any]:
    params = {
        key: value
        for key, value in {"alert_id": alert_id, "status": status, "document_kind": document_kind, "tenant_scope": tenant_id}.items()
        if value
    }
    return await guarded_proxy(
        request=request,
        method="GET",
        path="/rag/evidence-drafts",
        target_base=settings.context_agent_url,
        payload={},
        trace_id=trace_id_from_header(x_trace_id),
        params=params,
    )


@app.post("/rag/evidence-drafts")
async def create_evidence_rag_draft(
    request: Request,
    payload: dict[str, Any] = REQUEST_BODY,
    x_trace_id: str | None = Header(default=None),
    auth: AuthContext = Depends(require_roles(  # noqa: B008
        SystemRole.ADMINISTRATOR.value,
        SystemRole.L2_ENGINEER.value,
        SystemRole.L3_ENGINEER.value,
    )),
) -> dict[str, Any]:
    return await guarded_proxy(
        request=request,
        method="POST",
        path="/rag/evidence-drafts",
        target_base=settings.context_agent_url,
        payload={
            **payload,
            "tenant_scope": auth.tenant_id,
            "created_by": auth.email or auth.username or str(auth.user_id),
        },
        trace_id=trace_id_from_header(x_trace_id),
    )


@app.put("/rag/evidence-drafts/{draft_id}")
async def review_evidence_rag_draft(
    draft_id: str,
    request: Request,
    payload: dict[str, Any] = REQUEST_BODY,
    x_trace_id: str | None = Header(default=None),
    auth: AuthContext = Depends(require_roles(  # noqa: B008
        SystemRole.ADMINISTRATOR.value,
        SystemRole.L2_ENGINEER.value,
        SystemRole.L3_ENGINEER.value,
    )),
) -> dict[str, Any]:
    return await guarded_proxy(
        request=request,
        method="PUT",
        path=f"/rag/evidence-drafts/{quote(draft_id, safe='')}",
        target_base=settings.context_agent_url,
        payload={
            **payload,
            "tenant_scope": auth.tenant_id,
            "reviewed_by": auth.email or auth.username or str(auth.user_id),
        },
        trace_id=trace_id_from_header(x_trace_id),
    )


@app.post("/rag/evidence-drafts/{draft_id}/approve")
async def approve_evidence_rag_draft(
    draft_id: str,
    request: Request,
    payload: dict[str, Any] = REQUEST_BODY,
    x_trace_id: str | None = Header(default=None),
    auth: AuthContext = Depends(require_roles(SystemRole.ADMINISTRATOR.value)),  # noqa: B008
) -> dict[str, Any]:
    return await guarded_proxy(
        request=request,
        method="POST",
        path=f"/rag/evidence-drafts/{quote(draft_id, safe='')}/approve",
        target_base=settings.context_agent_url,
        payload={
            **payload,
            "tenant_scope": auth.tenant_id,
            "approved_by": auth.email or auth.username or str(auth.user_id),
        },
        trace_id=trace_id_from_header(x_trace_id),
    )


@app.post("/rag/evidence-drafts/{draft_id}/revision")
async def revise_evidence_rag_draft(
    draft_id: str,
    request: Request,
    payload: dict[str, Any] = REQUEST_BODY,
    x_trace_id: str | None = Header(default=None),
    auth: AuthContext = Depends(require_roles(  # noqa: B008
        SystemRole.ADMINISTRATOR.value,
        SystemRole.L2_ENGINEER.value,
        SystemRole.L3_ENGINEER.value,
    )),
) -> dict[str, Any]:
    return await guarded_proxy(
        request=request,
        method="POST",
        path=f"/rag/evidence-drafts/{quote(draft_id, safe='')}/revision",
        target_base=settings.context_agent_url,
        payload={
            **payload,
            "tenant_scope": auth.tenant_id,
            "created_by": auth.email or auth.username or str(auth.user_id),
        },
        trace_id=trace_id_from_header(x_trace_id),
    )


@app.get("/incidents/{incident_id}/context-gaps")
async def get_incident_context_gaps(
    incident_id: str,
    request: Request,
    x_trace_id: str | None = Header(default=None),
    tenant_id: str = Depends(current_tenant_id),
) -> dict[str, Any]:
    return await guarded_proxy(
        request=request, method="GET", path=f"/incidents/{incident_id}/context-gaps",
        payload=None,
        target_base=settings.context_agent_url, params={"tenant_id": tenant_id},
        trace_id=trace_id_from_header(x_trace_id), timeout_seconds=30.0,
    )


@app.get("/incidents/{incident_id}/operations-state")
async def get_incident_operations_state(
    incident_id: str,
    request: Request,
    x_trace_id: str | None = Header(default=None),
    tenant_id: str = Depends(current_tenant_id),
) -> dict[str, Any]:
    return await guarded_proxy(
        request=request, method="GET", path=f"/incidents/{quote(incident_id, safe='')}/operations-state",
        payload=None, target_base=settings.context_agent_url, params={"tenant_id": tenant_id},
        trace_id=trace_id_from_header(x_trace_id), timeout_seconds=30.0,
    )


@app.post("/incidents/{incident_id}/context-gaps/{requirement_id}/responses")
async def post_incident_context_gap_response(
    incident_id: str,
    requirement_id: str,
    request: Request,
    payload: dict[str, Any] = REQUEST_BODY,
    x_trace_id: str | None = Header(default=None),
    tenant_id: str = Depends(current_tenant_id),
) -> dict[str, Any]:
    auth = getattr(request.state, "auth", None)
    if auth is None:
        # Local/demo mode bypasses the global operational-auth middleware, but
        # governed evidence mutations still require a validated server-side
        # identity just like approval mutations do.
        auth = await _auth_context_from_request(request)
    responder_id = str(auth.email or auth.username or auth.user_id)
    governed_payload = {
        **payload,
        # These fields are audit evidence and may never be asserted by the browser.
        "responder_id": responder_id,
        "responded_at": datetime.now(UTC).isoformat(),
        "allow_manual_claim": role_is_allowed(
            auth.role, {OperationalRole.ADMIN.value, OperationalRole.HITL_APPROVER.value}
        ),
        "responder_role": auth.role,
    }
    return await guarded_proxy(
        request=request, method="POST",
        path=f"/incidents/{incident_id}/context-gaps/{requirement_id}/responses",
        target_base=settings.context_agent_url, payload=governed_payload, params={"tenant_id": tenant_id},
        trace_id=trace_id_from_header(x_trace_id), timeout_seconds=30.0,
    )


@app.post("/incidents/{incident_id}/hitl/jira")
async def create_incident_hitl_jira_assignment(
    incident_id: str,
    request: Request,
    payload: dict[str, Any] = REQUEST_BODY,
    x_trace_id: str | None = Header(default=None),
    tenant_id: str = Depends(current_tenant_id),
) -> dict[str, Any]:
    scoped_payload = {**payload, "tenant_id": tenant_id, "incident_id": incident_id}
    return await guarded_proxy(
        request=request, method="POST", path="/api/v1/jira/hitl-assignments",
        target_base=settings.monitoring_adapter_url, payload=scoped_payload,
        trace_id=trace_id_from_header(x_trace_id), timeout_seconds=45.0,
    )


@app.get("/rag/knowledge-drafts")
async def list_knowledge_rag_drafts(
    request: Request,
    status: str | None = None,
    x_trace_id: str | None = Header(default=None),
    tenant_id: str = Depends(current_tenant_id),
) -> dict[str, Any]:
    return await guarded_proxy(
        request=request, method="GET", path="/rag/knowledge-drafts",
        target_base=settings.context_agent_url, payload={},
        params={"tenant_scope": tenant_id, **({"status": status} if status else {})},
        trace_id=trace_id_from_header(x_trace_id),
    )


@app.post("/rag/knowledge-drafts")
async def create_knowledge_rag_draft(
    request: Request,
    payload: dict[str, Any] = REQUEST_BODY,
    x_trace_id: str | None = Header(default=None),
    auth: AuthContext = Depends(require_roles(  # noqa: B008
        SystemRole.ADMINISTRATOR.value, SystemRole.L2_ENGINEER.value, SystemRole.L3_ENGINEER.value,
    )),
) -> dict[str, Any]:
    actor = auth.email or auth.username or str(auth.user_id)
    clean = {key: value for key, value in payload.items() if key not in {
        "tenant_id", "tenant_scope", "created_by", "reviewed_by", "approved_by", "review_status",
    }}
    source_ref = str(clean.get("source_ref") or "").strip()
    if not source_ref:
        source_system = str(clean.get("source_system") or "kaims-knowledge").strip()
        source_identity = str(
            clean.get("alert_id") or clean.get("application_id") or clean.get("title") or "document"
        )
        source_ref = f"{source_system}://{source_identity}"
    metadata = clean.get("metadata") if isinstance(clean.get("metadata"), dict) else {}
    normalized = {
        "kind": str(clean.get("kind") or "application").strip().lower(),
        "source_ref": source_ref,
        "title": str(clean.get("title") or clean.get("alert_type") or "Operational knowledge").strip(),
        "content": str(clean.get("content") or clean.get("summary") or "").strip(),
        "metadata": {**metadata, **{
            key: value for key, value in clean.items()
            if key not in {"kind", "source_ref", "title", "content", "metadata"}
        }},
    }
    return await guarded_proxy(
        request=request, method="POST", path="/rag/knowledge-drafts",
        target_base=settings.context_agent_url,
        payload={**normalized, "tenant_scope": auth.tenant_id, "created_by": actor},
        trace_id=trace_id_from_header(x_trace_id),
    )


@app.put("/rag/knowledge-drafts/{draft_id}")
async def review_knowledge_rag_draft(
    draft_id: str, request: Request, payload: dict[str, Any] = REQUEST_BODY,
    x_trace_id: str | None = Header(default=None),
    auth: AuthContext = Depends(require_roles(  # noqa: B008
        SystemRole.ADMINISTRATOR.value, SystemRole.L2_ENGINEER.value, SystemRole.L3_ENGINEER.value,
    )),
) -> dict[str, Any]:
    actor = auth.email or auth.username or str(auth.user_id)
    return await guarded_proxy(
        request=request, method="PUT", path=f"/rag/knowledge-drafts/{quote(draft_id, safe='')}",
        target_base=settings.context_agent_url,
        payload={**payload, "tenant_scope": auth.tenant_id, "reviewed_by": actor},
        trace_id=trace_id_from_header(x_trace_id),
    )


@app.post("/rag/knowledge-drafts/{draft_id}/approve")
async def approve_knowledge_rag_draft(
    draft_id: str, request: Request, payload: dict[str, Any] = REQUEST_BODY,
    x_trace_id: str | None = Header(default=None),
    auth: AuthContext = Depends(require_roles(SystemRole.ADMINISTRATOR.value)),  # noqa: B008
) -> dict[str, Any]:
    actor = auth.email or auth.username or str(auth.user_id)
    return await guarded_proxy(
        request=request, method="POST",
        path=f"/rag/knowledge-drafts/{quote(draft_id, safe='')}/approve",
        target_base=settings.context_agent_url,
        payload={"expected_row_version": payload.get("expected_row_version"),
                 "tenant_scope": auth.tenant_id, "approved_by": actor},
        trace_id=trace_id_from_header(x_trace_id),
    )


@app.post("/rag/governed-documents/{document_id}/retry-index")
async def retry_governed_rag_index(
    document_id: str,
    request: Request,
    x_trace_id: str | None = Header(default=None),
    auth: AuthContext = Depends(require_roles(SystemRole.ADMINISTRATOR.value)),  # noqa: B008
) -> dict[str, Any]:
    return await guarded_proxy(
        request=request,
        method="POST",
        path=f"/rag/governed-documents/{quote(document_id, safe='')}/retry-index",
        target_base=settings.context_agent_url,
        payload={
            "tenant_scope": auth.tenant_id,
            "requested_by": auth.email or auth.username or str(auth.user_id),
        },
        trace_id=trace_id_from_header(x_trace_id),
    )


@app.post("/knowledge-pack/draft")
async def draft_knowledge_pack(
    request: Request,
    payload: Any = REQUEST_BODY,
    x_trace_id: str | None = Header(default=None),
) -> dict[str, Any]:
    payload = await knowledge_pack_payload_from_request(request, payload, "Knowledge Pack draft payload")
    return await guarded_proxy(
        request=request,
        method="POST",
        path="/knowledge-pack/draft",
        target_base=settings.context_agent_url,
        payload=payload,
        trace_id=trace_id_from_header(x_trace_id),
    )


@app.post("/knowledge-pack/validate")
async def validate_knowledge_pack(
    request: Request,
    payload: Any = REQUEST_BODY,
    x_trace_id: str | None = Header(default=None),
) -> dict[str, Any]:
    payload = await knowledge_pack_payload_from_request(request, payload, "Knowledge Pack validation payload")
    return await guarded_proxy(
        request=request,
        method="POST",
        path="/knowledge-pack/validate",
        target_base=settings.context_agent_url,
        payload=payload,
        trace_id=trace_id_from_header(x_trace_id),
    )


@app.post("/knowledge-pack/approve")
async def approve_knowledge_pack(
    request: Request,
    payload: Any = REQUEST_BODY,
    x_trace_id: str | None = Header(default=None),
    auth: AuthContext = Depends(require_roles(SystemRole.ADMINISTRATOR.value)),  # noqa: B008
) -> dict[str, Any]:
    payload = await knowledge_pack_payload_from_request(request, payload, "Knowledge Pack approval payload")
    payload = {
        **payload,
        "tenant_id": auth.tenant_id,
        "approved_by": auth.email or auth.username or str(auth.user_id),
    }
    return await guarded_proxy(
        request=request,
        method="POST",
        path="/knowledge-pack/approve",
        target_base=settings.context_agent_url,
        payload=payload,
        trace_id=trace_id_from_header(x_trace_id),
    )


@app.get("/rag/documents")
async def list_rag_documents(
    request: Request,
    x_trace_id: str | None = Header(default=None),
    tenant_id: str = Depends(current_tenant_id),
) -> dict[str, Any]:
    trace_id = trace_id_from_header(x_trace_id)
    try:
        return await guarded_proxy(
            request=request,
            method="GET",
            path=f"/rag/documents?{urlencode({'tenant_scope': tenant_id})}",
            target_base=settings.context_agent_url,
            payload={},
            trace_id=trace_id,
            # Knowledge inventory enriches Copilot but must never hold the
            # application open while the context agent rebuilds its index.
            timeout_seconds=5.0,
        )
    except HTTPException as exc:
        if exc.status_code != 502:
            raise
        logger.warning("rag_documents_degraded trace_id=%s", trace_id)
        return {
            "trace_id": trace_id,
            "data": {
                "documents": [],
                "degraded": True,
                "warning": "Knowledge inventory is temporarily unavailable. Other Copilot workflows remain available.",
            },
        }


@app.get("/rag/documents/content")
async def get_rag_document_content(
    request: Request,
    path: str,
    x_trace_id: str | None = Header(default=None),
    tenant_id: str = Depends(current_tenant_id),
) -> dict[str, Any]:
    return await guarded_proxy(
        request=request,
        method="GET",
        path="/rag/documents/content",
        target_base=settings.context_agent_url,
        payload={},
        trace_id=trace_id_from_header(x_trace_id),
        params={"path": path, "tenant_scope": tenant_id},
    )


@app.post("/rag/reload")
async def reload_rag(
    request: Request,
    x_trace_id: str | None = Header(default=None),
) -> dict[str, Any]:
    return await guarded_proxy(
        request=request,
        method="POST",
        path="/rag/reload",
        target_base=settings.context_agent_url,
        payload={},
        trace_id=trace_id_from_header(x_trace_id),
    )


@app.get("/rag/index")
async def get_rag_index(
    request: Request,
    x_trace_id: str | None = Header(default=None),
) -> dict[str, Any]:
    return await guarded_proxy(
        request=request,
        method="GET",
        path="/rag/index",
        target_base=settings.context_agent_url,
        payload={},
        trace_id=trace_id_from_header(x_trace_id),
    )


@app.post("/rag/index/sync")
async def sync_rag_index(
    request: Request,
    x_trace_id: str | None = Header(default=None),
) -> dict[str, Any]:
    return await guarded_proxy(
        request=request,
        method="POST",
        path="/rag/index/sync",
        target_base=settings.context_agent_url,
        payload={},
        trace_id=trace_id_from_header(x_trace_id),
    )


@app.get("/rag/search")
async def search_rag(
    query: str,
    request: Request,
    limit: int = 8,
    tenant_id: str = Depends(current_tenant_id),
    x_trace_id: str | None = Header(default=None),
) -> dict[str, Any]:
    query_string = urlencode({"query": query, "limit": limit, "tenant_id": tenant_id})
    return await guarded_proxy(
        request=request,
        method="GET",
        path=f"/rag/search?{query_string}",
        target_base=settings.context_agent_url,
        payload={},
        trace_id=trace_id_from_header(x_trace_id),
    )


@app.get("/rag/flow-catalog")
async def flow_catalog(
    request: Request,
    x_trace_id: str | None = Header(default=None),
) -> dict[str, Any]:
    return await guarded_proxy(
        request=request,
        method="GET",
        path="/rag/flow-catalog",
        target_base=settings.context_agent_url,
        payload={},
        trace_id=trace_id_from_header(x_trace_id),
    )


app.include_router(
    build_control_router(
        settings=settings,
        guarded_proxy=guarded_proxy,
        raw_proxy=proxy,
        trace_id_from_header=trace_id_from_header,
        analyzer=analyzer,
        load_recent_events=lambda limit: _load_recent_gateway_audit_events(app, limit),
        build_audit_contract=_build_gateway_audit_contract,
        load_audit_summary=lambda: _load_gateway_audit_summary(app),
        auth_context_from_request=_auth_context_from_request,
    )
)
