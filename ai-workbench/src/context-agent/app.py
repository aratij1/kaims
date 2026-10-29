from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import os
import re
import shlex
from datetime import UTC, datetime, timedelta
from pathlib import Path
from time import perf_counter
from typing import Any
from urllib.parse import urlparse
from uuid import NAMESPACE_URL, UUID, uuid5

import httpx
from ai_workbench_common.models import Context
from common.config import get_settings
from common.context_enrichment_contract import (
    EvidenceRequirement,
    HumanEvidenceResponse,
    authorized_enrichment_connectors,
    discovery_evidence_requirements as build_evidence_requirements,
    next_authorized_enrichment_connector,
    normalize_connector_response,
)
from common.database import AuditLogRecord, ContextEnrichmentJobRecord, GovernedRagDocumentRecord
from common.event_publishers import EventPublisher, RabbitMQPublisher, build_agent_event_contract, build_event_envelope
from common.kafka import KafkaConsumer
from common.kafka import consume_forever as consume_kafka_forever
from common.models import Alert, Incident
from common.investigation_gaps import unattempted_requirement_connector, collection_attempt_limit, requirement_reconciliation_needed
from common.rabbitmq import RabbitMQConsumer
from common.rabbitmq import consume_forever as consume_rabbitmq_forever
from common.rag_governance import content_checksum, retrieval_allowed
from common.repository import ContextEnrichmentRepository, IncidentRepository
from common.service import create_app
from common.telemetry import (
    CONTEXT_KNOWLEDGE_OPERATIONS,
    CONTEXT_KNOWLEDGE_REUSE_COUNT,
    CONTEXT_QUALITY_SCORE,
    CONTEXT_REUSE_DECISIONS,
    CONTEXT_SOURCE_RESULTS,
    CONTEXT_STRATEGY_DURATION,
    CONTEXT_STRATEGY_REQUESTS,
    EVENTS_PROCESSED,
)
from common.tenant_identity import require_tenant_id
from common.topics import CONTEXT_EVENTS, ORCHESTRATION_EVENTS, context_delivery_topic
from context_agent import ContextIntelligenceAgent
from context_agent.connectors import VectorDBConnector
from context_agent.context_quality import (
    SOURCE_POLICIES,
    assess_context,
    context_subject_fingerprint,
    govern_context,
)
from context_agent.knowledge_graph import KnowledgeGraph
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select, text

settings = get_settings()
settings.service_name = "context-agent"
logger = logging.getLogger("context-agent")
agent = ContextIntelligenceAgent()
tasks: list[asyncio.Task] = []
MESSAGE_BUS_DUAL_CONSUME_ENABLED = str(
    os.getenv("MESSAGE_BUS_DUAL_CONSUME_ENABLED", "false")
).strip().lower() in {"1", "true", "yes", "on"}
_CONTEXT_COLLECTION_LOCKS: dict[str, asyncio.Lock] = {}
GOVERNED_RAG_APPROVED_TOPIC = "rag.document.approved"


def _incident_from_workflow_payload(payload: dict[str, Any]) -> Incident:
    """Hydrate the strict domain incident from an enriched read projection.

    Incident projections acquire lifecycle and approval annotations after the
    canonical event is created. Those read-model fields are useful to callers
    but are not part of the strict Incident contract consumed by this agent.
    """
    return Incident.model_validate({
        key: value for key, value in payload.items() if key in Incident.model_fields
    })


def _context_strategy(override: str | None = None) -> str:
    strategy = str(override or getattr(settings, "context_strategy", "auto") or "auto").strip().lower()
    aliases = {"continuous": "auto", "immediate": "realtime"}
    strategy = aliases.get(strategy, strategy)
    return strategy if strategy in {"auto", "realtime", "historical"} else "auto"


def _context_completeness(context: Context) -> tuple[bool, list[str]]:
    quality = assess_context(
        context,
        threshold=float(getattr(settings, "context_min_quality_score", 0.70) or 0.70),
    )
    return not bool(quality["missing_required"]), list(quality["missing_context"])


def _record_context_quality(context: Context, decision: str, reason: str) -> None:
    metadata = context.metadata if isinstance(context.metadata, dict) else {}
    quality = metadata.get("context_quality") if isinstance(metadata.get("context_quality"), dict) else {}
    for dimension, key in (
        ("overall", "quality_score"),
        ("coverage", "coverage_score"),
        ("freshness", "freshness_score"),
        ("provenance", "provenance_score"),
        ("relevance", "relevance_score"),
    ):
        try:
            CONTEXT_QUALITY_SCORE.labels(dimension).observe(float(quality.get(key, 0.0) or 0.0))
        except (TypeError, ValueError):
            continue
    bounded_reason = re.sub(r"[^a-z0-9_]+", "_", str(reason or "unknown").lower()).strip("_")[:64] or "unknown"
    CONTEXT_REUSE_DECISIONS.labels(decision, bounded_reason).inc()
    sources = metadata.get("context_sources") if isinstance(metadata.get("context_sources"), dict) else {}
    for source, status in sources.items():
        status_value = str(status.get("status") if isinstance(status, dict) else status or "unknown").lower()
        CONTEXT_SOURCE_RESULTS.labels(str(source)[:40], status_value[:40]).inc()


def _has_code_evidence(context: Context) -> bool:
    metadata = context.metadata if isinstance(context.metadata, dict) else {}
    discovery = metadata.get("discovery_report") if isinstance(metadata.get("discovery_report"), dict) else {}
    evidence = discovery.get("evidence") if isinstance(discovery.get("evidence"), list) else []
    return any(
        isinstance(row, dict) and str(row.get("source") or "").strip().lower() == "code"
        for row in evidence
    )


def _context_identity(alert: Alert) -> tuple[str, str, str, str]:
    labels = alert.labels if isinstance(alert.labels, dict) else {}
    tenant_id = require_tenant_id(alert.tenant_id, source="context alert identity")
    service = str(alert.service or "unknown").strip().lower() or "unknown"
    environment = str(alert.environment or labels.get("environment") or "prod").strip().lower() or "prod"
    # Alert type identity must not include deployment-specific labels. A pod,
    # namespace, project, or application change is another occurrence of the
    # same alert type and should reuse validated knowledge. Service and
    # environment retain the safety boundary between distinct workloads.
    stable_labels = {
        key: str(labels.get(key) or "").strip().lower()
        for key in ("category", "alert_family")
        if str(labels.get(key) or "").strip()
    }
    signature_input = {
        "source": str(alert.source or "").strip().lower(),
        "name": str(alert.name or "").strip().lower(),
        "service": service,
        "environment": environment,
        "labels": stable_labels,
    }
    signature = hashlib.sha256(
        json.dumps(signature_input, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return tenant_id, service, environment, signature


def _resolution_quality_score(payload: Any) -> float:
    if not isinstance(payload, dict) or not payload:
        return 0.0
    metadata = payload.get("metadata") if isinstance(payload.get("metadata"), dict) else {}
    evaluation = metadata.get("evaluation") if isinstance(metadata.get("evaluation"), dict) else {}
    raw = evaluation.get("overall_score")
    if raw is None:
        raw = payload.get("confidence")
    try:
        score = float(raw or 0.0)
    except (TypeError, ValueError):
        return 0.0
    return max(0.0, min(score / 100.0 if score > 1.0 else score, 1.0))


def _qualified_resolution_cache(payload: Any) -> bool:
    if not bool(getattr(settings, "context_resolution_reuse_enabled", True)):
        return False
    threshold = float(getattr(settings, "context_resolution_reuse_min_score", 0.7) or 0.7)
    return _resolution_quality_score(payload) > max(0.0, min(threshold, 1.0))


async def _collect_context_with_strategy_unlocked(
    app: FastAPI,
    alert: Alert,
    incident: Incident,
    strategy_override: str | None = None,
    supplied_context: dict[str, Any] | None = None,
) -> Context:
    started = perf_counter()
    strategy = _context_strategy(strategy_override)
    tenant_id, service, environment, signature = _context_identity(alert)
    subject_fingerprint = context_subject_fingerprint(alert, tenant_id)
    quality_threshold = float(getattr(settings, "context_min_quality_score", 0.70) or 0.70)
    max_evidence = int(getattr(settings, "context_max_evidence_per_source", 20) or 20)
    session_factory = getattr(app.state, "session_factory", None)
    database_available = bool(settings.database_enabled and session_factory is not None)
    if database_available:
        metadata = alert.metadata if isinstance(alert.metadata, dict) else {}
        candidates = [
            metadata.get("project_id"), metadata.get("project"), metadata.get("application_id"),
            metadata.get("application"), metadata.get("application_name"), alert.service,
        ]
        try:
            async with session_factory() as session:
                resolved_connectors = await IncidentRepository(session).resolve_context_integrations(
                    tenant_id=tenant_id,
                    project_candidates=[str(value) for value in candidates if str(value or "").strip()],
                )
            alert.metadata = {
                **metadata,
                "resolved_context_connectors": resolved_connectors,
                "connector_resolution": {
                    "status": "completed" if resolved_connectors else "misconfigured",
                    "tenant_id": tenant_id,
                    "project_candidates": [str(value) for value in candidates if str(value or "").strip()],
                    "resolved_count": len(resolved_connectors),
                },
            }
        except Exception as exc:
            logger.exception("failed to resolve onboarded context connectors")
            alert.metadata = {
                **metadata,
                "resolved_context_connectors": [],
                "connector_resolution": {
                    "status": "unavailable",
                    "tenant_id": tenant_id,
                    "error": str(exc)[:300],
                },
            }

    if isinstance(supplied_context, dict):
        try:
            provided = Context.model_validate(supplied_context).model_copy(
                update={"incident_id": incident.id, "alert": alert}
            )
        except Exception:
            logger.warning("supplied context is invalid; evaluating cache policy instead")
        else:
            provided_metadata = provided.metadata if isinstance(provided.metadata, dict) else {}
            supplied_subject = str(provided_metadata.get("context_subject_fingerprint") or "")
            supplied_scope_matches = not supplied_subject or supplied_subject == subject_fingerprint
            if strategy != "realtime" and supplied_scope_matches:
                provided.metadata = {
                    **(provided.metadata if isinstance(provided.metadata, dict) else {}),
                    "context_strategy": strategy,
                    "context_source": "ticket_payload",
                    "context_reused": True,
                    "realtime_collection_performed": False,
                }
                provided = govern_context(
                    provided,
                    tenant_id=tenant_id,
                    subject_fingerprint=subject_fingerprint,
                    threshold=quality_threshold,
                    max_evidence_per_source=max_evidence,
                )
                if bool(provided.metadata["context_quality"]["reusable"]):
                    CONTEXT_STRATEGY_REQUESTS.labels(strategy, "complete_payload").inc()
                    _record_context_quality(provided, "reuse", "validated_ticket_payload")
                    return provided
                _record_context_quality(provided, "refresh", "ticket_payload_below_quality")
            elif not supplied_scope_matches:
                CONTEXT_REUSE_DECISIONS.labels("refresh", "ticket_payload_scope_changed").inc()

    if strategy in {"auto", "historical"} and database_available:
        configured_ttl = int(getattr(settings, "context_knowledge_ttl_seconds", 0) or 0)
        historical_ttl = int(os.getenv("CONTEXT_HISTORICAL_MAX_AGE_SECONDS", "0") or 0)
        ttl_seconds = historical_ttl if strategy == "historical" else configured_ttl
        not_before = (
            datetime.now(UTC) - timedelta(seconds=max(60, ttl_seconds))
            if ttl_seconds > 0
            else datetime.min.replace(tzinfo=UTC)
        )
        try:
            async with session_factory() as session:
                repo = IncidentRepository(session)
                cached = await repo.find_context_knowledge(
                    tenant_id=tenant_id,
                    service=service,
                    environment=environment,
                    alert_name=str(alert.name or "unknown"),
                    alert_signature=signature,
                    not_before=not_before,
                )
                CONTEXT_KNOWLEDGE_OPERATIONS.labels("lookup", "hit" if cached else "miss").inc()
                if cached:
                    try:
                        context = Context.model_validate(cached.get("payload", {})).model_copy(
                            update={"incident_id": incident.id, "alert": alert}
                        )
                    except Exception:
                        CONTEXT_KNOWLEDGE_OPERATIONS.labels("lookup", "invalid").inc()
                        logger.exception("invalid cached context knowledge id=%s; refreshing", cached.get("id"))
                    else:
                        cached_metadata = dict(context.metadata if isinstance(context.metadata, dict) else {})
                        learned_runbooks = await repo.find_learned_runbooks(
                            tenant_id=tenant_id,
                            service=service,
                            alert_name=str(alert.name or "unknown"),
                            alert_signature=signature,
                            limit=5,
                        )
                        if learned_runbooks:
                            if not str(context.runbook or "").strip():
                                context.runbook = str(learned_runbooks[0].get("markdown") or "")
                            cached_metadata["matched_learned_runbook"] = learned_runbooks[0]
                            cached_metadata["learned_runbooks"] = learned_runbooks
                            cached_metadata["document_available"] = True
                        alert_meta = alert.metadata if isinstance(alert.metadata, dict) else {}
                        if isinstance(alert_meta.get("observability"), dict) and alert_meta.get("observability"):
                            context.observability = {**dict(context.observability or {}), **dict(alert_meta["observability"])}
                        if isinstance(alert_meta.get("discovery_report"), dict):
                            cached_metadata["discovery_report"] = dict(alert_meta["discovery_report"])
                        if isinstance(alert_meta.get("current_evidence"), dict):
                            merged_ev = dict(cached_metadata.get("context_evidence") or {})
                            for k, v in alert_meta["current_evidence"].items():
                                if isinstance(v, list):
                                    merged_ev[k] = list(v)
                            cached_metadata["context_evidence"] = merged_ev
                        if supplied_context is not None:
                            if supplied_context.observability:
                                context.observability = {**dict(context.observability or {}), **dict(supplied_context.observability)}
                            sup_meta = supplied_context.metadata if isinstance(supplied_context.metadata, dict) else {}
                            if isinstance(sup_meta.get("discovery_report"), dict):
                                cached_metadata["discovery_report"] = dict(sup_meta["discovery_report"])
                        cached_subject = str(cached_metadata.get("context_subject_fingerprint") or "")
                        scope_matches = bool(not cached_subject or cached_subject == subject_fingerprint)
                        cached_resolution = cached.get("resolution_payload", {})
                        resolution_reusable = _qualified_resolution_cache(cached_resolution)
                        context.metadata = {
                            **cached_metadata,
                            "context_strategy": strategy,
                            "context_source": "periodic_knowledge",
                            "context_reused": True,
                            "realtime_collection_performed": False,
                            "context_collected_at": cached.get("collected_at"),
                        }
                        context = govern_context(
                            context,
                            tenant_id=tenant_id,
                            subject_fingerprint=subject_fingerprint,
                            threshold=quality_threshold,
                            max_evidence_per_source=max_evidence,
                        )
                        quality = context.metadata["context_quality"]
                        runbook_now_available = False
                        if not str(context.runbook or "").strip():
                            try:
                                vc = vector_connector()
                                rb_matches = vc.search(
                                    f"{alert.name} {service}",
                                    limit=1,
                                    preferred_kind="runbook",
                                    service=service,
                                    tenant_id=tenant_id,
                                )
                                runbook_now_available = any(
                                    str(m.get("kind", "")).lower() == "runbook"
                                    and vc.context_match_relevant(m, service)
                                    for m in rb_matches
                                )
                            except Exception:
                                runbook_now_available = False
                        continue_with_refresh = (
                            not scope_matches
                            or runbook_now_available
                            or (strategy == "auto" and not bool(quality.get("reusable")))
                        )
                        if continue_with_refresh:
                            reason = (
                                "subject_scope_changed"
                                if not scope_matches
                                else ("runbook_now_available" if runbook_now_available else "cached_context_below_quality")
                            )
                            CONTEXT_KNOWLEDGE_OPERATIONS.labels("lookup", reason).inc()
                            _record_context_quality(context, "refresh", reason)
                            logger.info(
                                "cached context rejected signature=%s reason=%s quality=%s",
                                signature,
                                reason,
                                quality.get("quality_score"),
                            )
                        else:
                            reuse_count = int(cached.get("reuse_count", 1) or 1)
                            context.metadata = {
                                **context.metadata,
                                "alert_type_known": True,
                                "knowledge_route": "reuse_validated_context_snapshot",
                                "knowledge_match_type": cached.get("match_type", "signature"),
                                "context_knowledge_id": cached.get("id"),
                                "context_source_alert_id": cached.get("source_alert_id"),
                                "context_source_incident_id": cached.get("source_incident_id"),
                                "context_collected_at": cached.get("collected_at"),
                                "context_reuse_count": reuse_count,
                                "context_signature": signature,
                                "prior_resolution": cached_resolution if resolution_reusable else {},
                                "prior_resolution_score": _resolution_quality_score(cached.get("resolution_payload", {})),
                                "prior_resolution_reusable": resolution_reusable,
                                "resolution_reuse_threshold": float(
                                    getattr(settings, "context_resolution_reuse_min_score", 0.7) or 0.7
                                ),
                            }
                            await session.commit()
                            CONTEXT_KNOWLEDGE_REUSE_COUNT.observe(reuse_count)
                            CONTEXT_STRATEGY_REQUESTS.labels(strategy, "cache_hit").inc()
                            _record_context_quality(context, "reuse", "quality_and_scope_passed")
                            CONTEXT_STRATEGY_DURATION.labels(strategy, "reused").observe(
                                max(0.0, perf_counter() - started)
                            )
                            return context
        except Exception:
            CONTEXT_KNOWLEDGE_OPERATIONS.labels("lookup", "error").inc()
            logger.exception("context knowledge lookup failed; continuing with fresh discovery")

    if strategy in {"auto", "historical"} and not database_available:
        CONTEXT_KNOWLEDGE_OPERATIONS.labels("lookup", "unavailable").inc()

    if strategy == "historical":
        context = Context(tenant_id=tenant_id, incident_id=incident.id, alert=alert)
        context.metadata = {
            "context_strategy": "historical",
            "context_source": "historical_cache_miss",
            "context_reused": False,
            "context_complete": False,
            "context_missing_sections": ["historical_context"],
            "realtime_collection_performed": False,
        }
        context = govern_context(
            context,
            tenant_id=tenant_id,
            subject_fingerprint=subject_fingerprint,
            threshold=quality_threshold,
            max_evidence_per_source=max_evidence,
        )
        _record_context_quality(context, "miss", "historical_cache_miss")
        CONTEXT_STRATEGY_REQUESTS.labels("historical", "cache_miss").inc()
        return context

    # Generate/reuse scoped diagnostic guidance before the first collection.
    # This draft is never placed in context.runbook (trusted remediation).
    diagnostic_plan = None
    diagnostic_error = None
    if database_available:
        try:
            from common.diagnostic_runbooks import ensure_diagnostic_runbook
            async with session_factory() as session:
                diagnostic_plan = await ensure_diagnostic_runbook(session, tenant_id=tenant_id,
                    application=str(alert.metadata.get("application") or alert.labels.get("application") or service),
                    service=service, environment=environment, alert_family=alert.name)
                await session.commit()
        except Exception:
            diagnostic_error = "diagnostic_runbook_persistence_unavailable"
            logger.exception("diagnostic runbook bootstrap failed; continuing bounded discovery")
    alert.metadata = {**alert.metadata, "diagnostic_runbook": diagnostic_plan,
                      "diagnostic_runbook_error": diagnostic_error}
    try:
        context = await agent.collect_with_runtime(alert, incident)
    except Exception:
        CONTEXT_STRATEGY_REQUESTS.labels(strategy, "discovery_error").inc()
        CONTEXT_STRATEGY_DURATION.labels(strategy, "error").observe(max(0.0, perf_counter() - started))
        raise
    collected_at = datetime.now(UTC)
    if database_available:
        try:
            async with session_factory() as session:
                repo = IncidentRepository(session)
                learned_runbooks = await repo.find_learned_runbooks(
                    tenant_id=tenant_id,
                    service=service,
                    alert_name=str(alert.name or "unknown"),
                    alert_signature=signature,
                    limit=5,
                )
                if learned_runbooks:
                    if not str(context.runbook or "").strip():
                        context.runbook = str(learned_runbooks[0].get("markdown") or "")
                    meta_dict = dict(context.metadata if isinstance(context.metadata, dict) else {})
                    meta_dict["matched_learned_runbook"] = learned_runbooks[0]
                    meta_dict["learned_runbooks"] = learned_runbooks
                    meta_dict["document_available"] = True
                    context.metadata = meta_dict
        except Exception:
            logger.exception("learned runbook lookup failed during fresh context collection")
    context.metadata = {
        **(context.metadata if isinstance(context.metadata, dict) else {}),
        "context_strategy": strategy,
        "context_reused": False,
        "context_source": "realtime_collection",
        "diagnostic_runbook": diagnostic_plan,
        "diagnostic_runbook_error": diagnostic_error,
        "alert_type_known": False,
        "knowledge_route": "full_context_then_learn",
        "realtime_collection_performed": True,
        "context_signature": signature,
        "context_collected_at": collected_at.isoformat(),
    }
    context = govern_context(
        context,
        tenant_id=tenant_id,
        subject_fingerprint=subject_fingerprint,
        now=collected_at,
        threshold=quality_threshold,
        max_evidence_per_source=max_evidence,
    )
    if database_available:
        try:
            async with session_factory() as session:
                repo = IncidentRepository(session)
                knowledge_id = await repo.save_context_knowledge(
                    tenant_id=tenant_id,
                    service=service,
                    environment=environment,
                    alert_name=str(alert.name or "unknown"),
                    alert_signature=signature,
                    source_alert_id=alert.id,
                    source_incident_id=incident.id,
                    payload=context.model_dump(mode="json"),
                )
                context.metadata["context_knowledge_id"] = knowledge_id
                await session.commit()
            CONTEXT_KNOWLEDGE_OPERATIONS.labels("store", "success").inc()
        except Exception:
            CONTEXT_KNOWLEDGE_OPERATIONS.labels("store", "error").inc()
            logger.exception("context knowledge persistence failed; returning freshly collected context")
    outcome = "fresh" if strategy == "realtime" else "cache_miss"
    CONTEXT_STRATEGY_REQUESTS.labels(strategy, outcome).inc()
    _record_context_quality(context, "collect", "fresh_discovery")
    CONTEXT_STRATEGY_DURATION.labels(strategy, "fresh_discovery").observe(max(0.0, perf_counter() - started))
    return context


async def _collect_context_with_strategy(
    app: FastAPI,
    alert: Alert,
    incident: Incident,
    strategy_override: str | None = None,
    supplied_context: dict[str, Any] | None = None,
) -> Context:
    """Coalesce identical collection work in-process and across MySQL replicas."""

    strategy = _context_strategy(strategy_override)
    if strategy == "realtime":
        return await _collect_context_with_strategy_unlocked(
            app, alert, incident, strategy_override, supplied_context
        )

    tenant_id, _, _, signature = _context_identity(alert)
    lock_digest = hashlib.sha256(f"{tenant_id}:{signature}".encode("utf-8")).hexdigest()[:40]
    local_key = f"{tenant_id}:{signature}"
    local_lock = _CONTEXT_COLLECTION_LOCKS.setdefault(local_key, asyncio.Lock())
    if len(_CONTEXT_COLLECTION_LOCKS) > 2048:
        for key, candidate in list(_CONTEXT_COLLECTION_LOCKS.items()):
            if key != local_key and not candidate.locked():
                _CONTEXT_COLLECTION_LOCKS.pop(key, None)
            if len(_CONTEXT_COLLECTION_LOCKS) <= 1536:
                break

    async with local_lock:
        engine = getattr(app.state, "db_engine", None)
        if settings.database_enabled and engine is not None and engine.dialect.name == "mysql":
            lock_name = f"kaiops:context:{lock_digest}"
            wait_seconds = int(getattr(settings, "context_collection_lease_wait_seconds", 30) or 0)
            from common.advisory_lock import advisory_connection
            async with advisory_connection(engine, lock_name, wait_seconds=wait_seconds) as connection:
                if connection is None:
                    CONTEXT_REUSE_DECISIONS.labels("collect", "distributed_lease_timeout").inc()
                    raise HTTPException(status_code=503, detail="Context collection is already in progress; retry shortly.", headers={"Retry-After": "5"})
                # Collection exceptions must propagate once. They must never
                # be mistaken for lock failures and trigger a second collection.
                return await _collect_context_with_strategy_unlocked(
                    app, alert, incident, strategy_override, supplied_context
                )
        return await _collect_context_with_strategy_unlocked(
            app, alert, incident, strategy_override, supplied_context
        )


def _extract_message_bus_provider(payload: dict[str, Any]) -> str:
    decision = payload.get("decision")
    if isinstance(decision, dict):
        provider = str(decision.get("message_bus_provider", "rabbitmq")).strip().lower()
        if provider in {"kafka", "rabbitmq", "azure-service-bus", "servicebus", "azure"}:
            return provider
    transport = str(payload.get("transport", "")).strip().lower()
    if transport in {"kafka", "rabbitmq", "azure-service-bus", "servicebus", "azure"}:
        return transport
    return "rabbitmq"


async def _publish_context_event(
    *,
    app: FastAPI,
    provider: str,
    alert: Alert,
    incident: Incident,
    context: Context,
    decision: dict[str, Any] | None,
    payload: dict[str, Any] | None = None,
) -> str:
    publishers: dict[str, EventPublisher] = getattr(app.state, "message_bus_publishers", {})
    selected = publishers.get(provider)
    provider_used = provider
    if selected is None:
        provider_used = "rabbitmq"
        selected = publishers.get("rabbitmq", app.state.producer)

    outgoing = payload or _build_context_event_payload(
        alert=alert, incident=incident, context=context, decision=decision, provider_used=provider_used
    )
    event_id = str((outgoing.get("event_contract") or {}).get("event_id") or "")
    try:
        await selected.publish(context_delivery_topic(context.metadata), outgoing, key=alert.service)
    except Exception as exc:
        if event_id and settings.database_enabled and getattr(app.state, "session_factory", None) is not None:
            async with app.state.session_factory() as session:
                await IncidentRepository(session).mark_resolution_event_retry(event_id, str(exc))
                await session.commit()
        raise
    if event_id and settings.database_enabled and getattr(app.state, "session_factory", None) is not None:
        async with app.state.session_factory() as session:
            await IncidentRepository(session).mark_resolution_event_published(event_id)
            await session.commit()
    return provider_used


async def _persist_context_event(
    *,
    app: FastAPI,
    alert: Alert,
    incident: Incident,
    context: Context,
    decision: dict[str, Any] | None,
    provider_used: str,
    outgoing_payload: dict[str, Any],
    enqueue_event: bool = True,
) -> bool:
    if not settings.database_enabled or getattr(app.state, "session_factory", None) is None:
        return True
    decision_payload = decision if isinstance(decision, dict) else {}
    tenant_id, _, _, alert_signature = _context_identity(alert)
    quality = context.metadata.get("context_quality") if isinstance(context.metadata.get("context_quality"), dict) else {}
    context_fingerprint = str(context.metadata.get("context_fingerprint") or "")
    subject_fingerprint = str(context.metadata.get("context_subject_fingerprint") or "")
    analysis_request_id = str(context.metadata.get("analysis_request_id") or "").strip()
    snapshot_identity = analysis_request_id or context_fingerprint
    snapshot_id = uuid5(
        NAMESPACE_URL,
        f"kaims:context-snapshot:{tenant_id}:{incident.id}:{snapshot_identity}",
    )
    context.metadata["context_snapshot_id"] = str(snapshot_id)
    context.metadata["context_snapshot_identity"] = snapshot_identity
    outgoing_context = outgoing_payload.get("context")
    if isinstance(outgoing_context, dict):
        outgoing_metadata = outgoing_context.get("metadata")
        outgoing_metadata = outgoing_metadata if isinstance(outgoing_metadata, dict) else {}
        outgoing_context["metadata"] = {
            **outgoing_metadata,
            "context_snapshot_id": str(snapshot_id),
            "context_snapshot_identity": snapshot_identity,
        }
    event_id = str((outgoing_payload.get("event_contract") or {}).get("event_id") or "")
    collected_at_raw = str(context.metadata.get("context_collected_at") or "")
    try:
        collected_at = datetime.fromisoformat(collected_at_raw.replace("Z", "+00:00"))
    except ValueError:
        collected_at = datetime.now(UTC)
    if collected_at.tzinfo is None:
        collected_at = collected_at.replace(tzinfo=UTC)
    assessed_at_raw = str(quality.get("assessed_at") or "")
    try:
        assessed_at = datetime.fromisoformat(assessed_at_raw.replace("Z", "+00:00"))
    except ValueError:
        assessed_at = datetime.now(UTC)
    if assessed_at.tzinfo is None:
        assessed_at = assessed_at.replace(tzinfo=UTC)
    # Snapshot expiry protects the immutable handoff, while context quality
    # separately controls whether individual evidence is usable. The outer
    # lease must cover a normal operator review session; using only the
    # five-minute processing floor caused correctly persisted contracts to
    # expire while an operator was still reading the RCA. Per-source freshness,
    # quality blockers, and execution gates remain independently authoritative.
    processing_lease_seconds = 300
    operator_review_lease_seconds = int(
        getattr(settings, "context_knowledge_ttl_seconds", 14400) or 14400
    )
    expires_at = assessed_at + timedelta(
        seconds=max(
            processing_lease_seconds,
            operator_review_lease_seconds,
            int(quality.get("valid_for_seconds") or 0),
        )
    )
    async with app.state.session_factory() as session:
        repo = IncidentRepository(session)
        incident_event = build_event_envelope(
                event_type="incident.context.collected",
                identity={
                    "incident_id": str(incident.id),
                    "alert_id": str(alert.id),
                    "trace_id": str(incident.trace_id or alert.trace_id or ""),
                    "correlation_id": str(alert.correlation_id or "") or None,
                    "causation_id": None,
                    "parent_event_id": None,
                },
                scope={
                    "tenant_id": tenant_id,
                    "service": str(alert.service or "unknown"),
                    "environment": str(alert.environment or "prod"),
                    "region": None,
                    "team": str(alert.metadata.get("owner_team") or "") or None,
                },
                state={
                    "severity": str(getattr(alert.severity, "value", alert.severity) or "warning").lower(),
                    "status": "investigating",
                    "owner": None,
                },
                policy={
                    "risk_tier": str(decision_payload.get("risk_tier") or "unknown"),
                    "execution_mode": str(decision_payload.get("execution_mode") or "unknown"),
                    "requires_approval": decision_payload.get("requires_approval"),
                    "policy_version": decision_payload.get("policy_version"),
                    "policy_reason": decision_payload.get("policy_reason"),
                },
                transport={
                    "provider": provider_used,
                    "channel": context_delivery_topic(context.metadata),
                    "partition": None,
                    "offset": None,
                    "delivery_tag": None,
                },
                payload={
                    "workflow": decision_payload.get("workflow"),
                    "context": context.model_dump(mode="json"),
                    "deployment": context.deployment,
                    "related_incidents": context.related_incidents,
                    "dependency_services": context.dependency_services,
                    "document_available": bool(context.metadata.get("rag_service_tagged_match", False)),
                    "discovery_report": context.metadata.get("discovery_report", {}),
                    "discovery_evidence": context.metadata.get("discovery_evidence", {}),
                    "context_sources": context.metadata.get("context_sources", {}),
                    "context_evidence": context.metadata.get("context_evidence", {}),
                    "context_quality": quality,
                    "context_fingerprint": context_fingerprint,
                    "context_snapshot_id": str(snapshot_id),
                    "analysis_request_id": analysis_request_id or None,
                    "subject_fingerprint": subject_fingerprint,
                },
            )
        audit_identity = analysis_request_id or context_fingerprint
        incident_event["event_id"] = str(
            uuid5(NAMESPACE_URL, f"kaims:context-audit:{incident.id}:{audit_identity}")
        )
        await repo.save_incident_event(incident_event)
        await repo.save_context_snapshot(
            snapshot_id=snapshot_id,
            tenant_id=tenant_id,
            incident_id=str(incident.id),
            source_incident_id=str(context.metadata.get("context_source_incident_id") or "") or None,
            alert_signature=alert_signature,
            subject_fingerprint=subject_fingerprint,
            context_fingerprint=context_fingerprint,
            contract_version=str(context.metadata.get("context_contract_version") or "kaiops.context.v2"),
            quality_score=float(quality.get("quality_score") or 0.0),
            reusable=bool(quality.get("reusable")),
            source_manifest=context.metadata.get("context_sources", {}),
            payload=outgoing_context if isinstance(outgoing_context, dict) else context.model_dump(mode="json"),
            collected_at=collected_at,
            expires_at=expires_at,
        )
        enqueued = False
        if enqueue_event:
            enqueued = await repo.enqueue_resolution_event(
                event_id=event_id,
                aggregate_id=str(incident.id),
                topic=context_delivery_topic(context.metadata),
                partition_key=str(alert.service or incident.id),
                payload=outgoing_payload,
                tenant_id=tenant_id,
                available_after_seconds=float(
                    getattr(settings, "resolution_outbox_initial_delay_seconds", 60.0) or 60.0
                ),
            )
        await session.commit()
        return enqueued


async def _context_enrichment_worker(app: FastAPI, lane: str = "fair") -> None:
    """Execute durable read-only gap jobs and hand fresh context back to RCA."""
    connector_aliases = {"opensearch": "discovery-mcp", "jaeger": "discovery-mcp", "jira": "discovery-mcp"}
    worker_id = f"{settings.service_name}:{os.getenv('HOSTNAME', 'local')}:{os.getpid()}:{lane}"
    async def execute_one(_payload):
        if not settings.database_enabled or getattr(app.state, "session_factory", None) is None:
            await asyncio.sleep(5)
            return
        async def claim_jobs(session):
            return await ContextEnrichmentRepository(session).claim_context_enrichment_jobs(
                worker_id=worker_id, limit=1, lease_seconds=120, lane=lane,
            )
        from common.enrichment_scheduler import persist_collected_evidence
        # MySQL can deadlock when independent workers update queue indexes.
        # Retry the rolled-back claim transaction before any connector runs.
        jobs = await persist_collected_evidence(app.state.session_factory, claim_jobs)
        if not jobs:
            await asyncio.sleep(3)
            return
        async def process_job(job):
            failure = "connector returned no attributable evidence"
            try:
                query = job.get("query_payload") if isinstance(job.get("query_payload"), dict) else {}
                alert = Alert.model_validate(query.get("alert"))
                incident = Incident.model_validate(query.get("incident"))
                async with app.state.session_factory() as session:
                    repository = ContextEnrichmentRepository(session)
                    requirement_payload = await repository.context_evidence_requirement(
                        tenant_id=job["tenant_id"], requirement_id=job["requirement_id"],
                    )
                    if requirement_payload is None:
                        await repository.finish_context_enrichment_job(
                            job_id=job["job_id"], worker_id=worker_id,
                            collected=False, error="ORPHANED_EVIDENCE_REQUIREMENT",
                            maximum_attempts=1,
                        )
                        await session.commit()
                if requirement_payload is None:
                    logger.warning(
                        "orphaned context enrichment job dead-lettered job_id=%s requirement_id=%s",
                        job["job_id"], job["requirement_id"],
                    )
                    return
                requirement = EvidenceRequirement.model_validate(requirement_payload)
                connector_name = connector_aliases.get(job["connector_id"], job["connector_id"])
                connector = next((item for item in agent.connectors if item.name == connector_name), None)
                if connector is None:
                    raise RuntimeError(f"connector {job['connector_id']} is not installed")
                targeted_metadata = dict(alert.metadata)
                targeted_metadata["context_requirement_category"] = requirement.category
                targeted_metadata["context_requirement_question"] = requirement.question
                targeted_metadata["context_collection_tool"] = (
                    "resource-health.search"
                    if requirement.category == "metrics" and "resource telemetry" in requirement.question.lower()
                    else "dependency-health.search"
                    if requirement.category == "topology" and "dependency health" in requirement.question.lower()
                    else "topology.search"
                    if requirement.category == "topology"
                    else ""
                )
                for field, key in (("context_observation_start", "observation_start"),
                                   ("context_observation_end", "observation_end")):
                    observed = job.get(key)
                    # MySQL DATETIME stores UTC without tzinfo.
                    if isinstance(observed, datetime):
                        observed = (observed if observed.tzinfo else observed.replace(tzinfo=UTC)).isoformat()
                    targeted_metadata[field] = observed
                targeted_alert = alert.model_copy(update={"metadata": targeted_metadata})
                raw_response = await connector.fetch(targeted_alert, incident)
                normalization = normalize_connector_response(
                    raw_response=raw_response, requirement=requirement, incident=incident,
                    connector=job["connector_id"], collected_at=datetime.now(UTC),
                )
                async def persist_result(session):
                    nonlocal failure
                    repository = ContextEnrichmentRepository(session)
                    persisted = await repository.persist_enrichment_result_atomically(
                        job_id=job["job_id"], worker_id=worker_id,
                        accepted_records=normalization.records,
                        rejected_records=normalization.rejected,
                        source_response_metadata=normalization.metadata,
                    )
                    if not persisted["accepted"]:
                        explicit_gap = str(raw_response.get("evidence_gap") or "").strip()
                        failure = explicit_gap or "; ".join(dict.fromkeys(
                            str(item.get("code") or "EVIDENCE_REJECTED")
                            for item in normalization.rejected
                        )) or failure
                        final_status = await repository.finish_context_enrichment_job(
                            job_id=job["job_id"], worker_id=worker_id,
                            collected=False, error=failure,
                            retry_after_seconds=min(300, 15 * (2 ** max(0, int(job["attempt_count"]) - 1))),
                            maximum_attempts=collection_attempt_limit(explicit_gap, normalization.rejected),
                        )
                        fallback_connector = None
                        if final_status == "dead_letter":
                            authorized = set(query.get("authorized_connectors") or [])
                            if not authorized:
                                authorized = authorized_enrichment_connectors(
                                    alert_metadata=alert.metadata, context_payload={},
                                )
                            attempted = {
                                *query.get("attempted_connectors", []),
                                str(job["connector_id"]),
                            }
                            fallback_connector = next_authorized_enrichment_connector(
                                candidate_connectors=requirement.candidate_connectors,
                                authorized_connectors=authorized,
                                attempted_connectors=attempted,
                            )
                            if fallback_connector:
                                await repository.schedule_context_enrichment_job(
                                    tenant_id=job["tenant_id"], incident_id=job["incident_id"],
                                    requirement_id=job["requirement_id"], connector_id=fallback_connector,
                                    query_payload={
                                        **query,
                                        "authorized_connectors": sorted(authorized),
                                        "attempted_connectors": sorted(attempted),
                                    },
                                    observation_start=job["observation_start"],
                                    observation_end=job["observation_end"],
                                )
                        if final_status == "dead_letter" and fallback_connector is None:
                            assignment = await repository.resolve_human_evidence_responder(
                                tenant_id=job["tenant_id"], incident_id=job["incident_id"],
                            )
                            await repository.create_human_evidence_request(
                                automatic_fallback=True,
                                tenant_id=job["tenant_id"], incident_id=job["incident_id"],
                                requirement_id=job["requirement_id"],
                                expected_responder=assignment["identity"] if assignment else None,
                                assignment_source=assignment["source"] if assignment else None,
                                assignment_failure_reason=None if assignment else "NO_AUTHORIZED_RESPONDER",
                                due_at=datetime.now(UTC) + timedelta(hours=1),
                                acceptable_format="A source reference and a concise factual observation.",
                                evidence_already_checked=requirement.candidate_connectors,
                                hypothesis_impact=requirement.reason,
                                investigation_can_continue=True,
                            )
                    return persisted
                from common.enrichment_scheduler import persist_collected_evidence
                persisted = await persist_collected_evidence(app.state.session_factory, persist_result)
                if persisted["accepted"]:
                    logger.info(
                        "context enrichment persisted for outbox delivery job_id=%s event_id=%s",
                        job["job_id"], persisted["outbox_event_id"],
                    )
            except Exception as exc:
                failure = str(exc)[:1000]
                logger.exception("context enrichment job failed job_id=%s", job.get("job_id"))
                async with app.state.session_factory() as session:
                    repository = ContextEnrichmentRepository(session)
                    current = await session.get(ContextEnrichmentJobRecord, UUID(job["job_id"]))
                    if current is not None and current.status == "collecting" and current.lease_owner == worker_id:
                        from common.enrichment_scheduler import CollectionPersistenceBusy, transient_collection_database_error
                        if isinstance(exc, CollectionPersistenceBusy) or transient_collection_database_error(exc):
                            # Contention is infrastructure failure, not a failed evidence source.
                            # Return the lease without exhausting connector attempts or requesting a human.
                            current.attempt_count = max(0, current.attempt_count - 1)
                            current.status = "retry"
                            current.available_at = datetime.now(UTC) + timedelta(seconds=15)
                            current.lease_owner = None
                            current.lease_expires_at = None
                            current.last_error = "EVIDENCE_PERSISTENCE_BUSY"
                            await session.commit()
                            return
                        await repository.finish_context_enrichment_job(
                            job_id=job["job_id"], worker_id=worker_id,
                            collected=False, error=failure,
                            retry_after_seconds=min(300, 15 * (2 ** max(0, int(job["attempt_count"]) - 1))),
                            maximum_attempts=1 if failure == "STALE_EVIDENCE_REQUIREMENT" else 4,
                        )
                    await session.commit()
        async def on_collection_timeout(job):
            async with app.state.session_factory() as session:
                current = await session.get(ContextEnrichmentJobRecord, UUID(job["job_id"]))
                if current is not None and current.status == "collecting" and current.lease_owner == worker_id:
                    await ContextEnrichmentRepository(session).finish_context_enrichment_job(
                        job_id=job["job_id"], worker_id=worker_id,
                        collected=False, error="COLLECTION_DEADLINE_EXCEEDED",
                        retry_after_seconds=60, maximum_attempts=4,
                    )
                await session.commit()

        from common.enrichment_scheduler import run_leased_collection_batch
        # Bound each job below its 120-second lease, and start the leased
        # batch together instead of spending leases waiting on siblings.
        await run_leased_collection_batch(jobs, process_job, on_collection_timeout)

    while True:
        try:
            from common.alert_processing_budget import run_handler
            # Admission precedes claiming the job: waiting must not consume its
            # lease or count as a failed collection attempt. Each claim is one job.
            await run_handler(settings, "context-events", execute_one, {}, timeout_seconds=120)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("context enrichment worker loop failed")
            await asyncio.sleep(5)


def _build_context_event_payload(
    *,
    alert: Alert,
    incident: Incident,
    context: Context,
    decision: dict[str, Any] | None,
    provider_used: str,
) -> dict[str, Any]:
    decision_payload = decision if isinstance(decision, dict) else {}
    flow_id = str(decision_payload.get("flow_id") or incident.id)
    discovery = context.metadata.get("discovery_report", {})
    if not isinstance(discovery, dict):
        discovery = {}
    report = discovery.get("report") if isinstance(discovery.get("report"), dict) else {}
    evidence = discovery.get("evidence") if isinstance(discovery.get("evidence"), list) else []
    evidence_ids = [
        str(row.get("evidence_id"))
        for row in evidence
        if isinstance(row, dict) and str(row.get("evidence_id") or "").strip()
    ]
    citations = [
        str(row.get("uri"))
        for row in evidence
        if isinstance(row, dict) and str(row.get("uri") or "").strip()
    ]
    event_contract = build_agent_event_contract(
        flow_id=flow_id,
        incident_id=str(incident.id),
        trace_id=str(incident.trace_id or alert.trace_id or ""),
        correlation_id=str(alert.correlation_id or "") or None,
        agent="context-agent",
        payload={
            "service": alert.service,
            "transport_provider": provider_used,
            "topic": context_delivery_topic(context.metadata),
            "rag_document_count": context.metadata.get("rag_documents", 0),
            "context_sources": context.metadata.get("context_sources", {}),
            "discovery": {
                "protocol": discovery.get("protocol"),
                "summary": report.get("summary"),
                "hypotheses": report.get("hypotheses", []),
                "retrieval_stages": discovery.get("retrieval_stages", []),
                "evidence": evidence,
                "model_usage": discovery.get("model_usage", {}),
                "model_interaction": discovery.get("model_interaction", {}),
                "insufficient_evidence": report.get("insufficient_evidence", False),
                "external_knowledge_eligible": report.get("external_knowledge_eligible", False),
                "external_knowledge_used": report.get("external_knowledge_used", False),
                "external_tools_used": report.get("external_tools_used", []),
                "external_knowledge_error": report.get("external_knowledge_error"),
            },
        },
        metadata={
            "workflow": decision_payload.get("workflow"),
            "requires_approval": decision_payload.get("requires_approval"),
            "message_bus_provider": decision_payload.get("message_bus_provider"),
        },
        confidence=float(
            (context.metadata.get("context_quality") or {}).get("quality_score", 0.0)
            if isinstance(context.metadata.get("context_quality"), dict)
            else 0.0
        ),
        reasoning=str(
            report.get("summary")
            or "Quality-scored context was assembled from the sources that returned grounded evidence; missing sources remain explicit."
        ),
        citations=citations or [f"alert://{alert.id}"],
        evidence_ids=evidence_ids or [f"alert:{alert.id}", f"incident:{incident.id}"],
    )
    context_fingerprint = str(context.metadata.get("context_fingerprint") or "")
    analysis_request_id = str(context.metadata.get("analysis_request_id") or "").strip()
    event_identity = analysis_request_id or context_fingerprint[:24]
    event_contract["event_id"] = f"context:{incident.id}:{event_identity}"
    return {
        "context": context.model_dump(mode="json"),
        "incident": incident.model_dump(mode="json"),
        "decision": decision if isinstance(decision, dict) else {},
        "transport": provider_used,
        "event_contract": event_contract,
    }


def _attach_analysis_request_metadata(
    context: Context,
    *,
    decision: dict[str, Any] | None = None,
    analysis_request: dict[str, Any] | None = None,
) -> Context:
    """Carry regeneration identity through the asynchronous RCA pipeline."""
    routing = decision if isinstance(decision, dict) else {}
    request_payload = analysis_request if isinstance(analysis_request, dict) else {}
    request_id = str(routing.get("analysis_request_id") or request_payload.get("id") or "").strip()
    if not request_id:
        metadata = context.metadata if isinstance(context.metadata, dict) else {}
        request_id = str(uuid5(
            NAMESPACE_URL,
            f"kaims:analysis-request:{context.incident_id}:{context.alert.id}:"
            f"{metadata.get('context_fingerprint') or context.alert.fingerprint or 'initial'}",
        ))
    mode = str(routing.get("analysis_mode") or request_payload.get("mode") or "smart").strip().lower()
    metadata = context.metadata if isinstance(context.metadata, dict) else {}
    return context.model_copy(update={
        "metadata": {
            **metadata,
            "analysis_request_id": request_id,
            "analysis_mode": mode,
            "rca_version": max(1, int(routing.get("rca_version") or 1)),
            "force_full_analysis": bool(routing.get("force_full_analysis")) or mode == "fresh",
            "regeneration_requested": True,
            "regenerated_from_alert_id": str(context.alert.id),
            "regenerate_requested_at": str(request_payload.get("requested_at") or ""),
        }
    })


async def _flush_context_outbox(app: FastAPI) -> int:
    from common.outbox_dispatch import flush_resolution_outbox
    return await flush_resolution_outbox(app, settings)


async def _context_outbox_dispatch_loop(app: FastAPI) -> None:
    interval = max(1.0, float(getattr(settings, "resolution_outbox_poll_seconds", 5.0) or 5.0))
    while True:
        try:
            await _flush_context_outbox(app)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("context event outbox dispatch failed")
        await asyncio.sleep(interval)


def _build_ingress_consumers() -> list[tuple[str, object, object]]:
    workers = max(1, int(getattr(settings, "message_bus_worker_count", 1) or 1))
    consumers: list[tuple[str, object, object]] = []
    for worker in range(workers):
        consumers.append(
            (f"rabbitmq-w{worker + 1}", RabbitMQConsumer(settings, ORCHESTRATION_EVENTS), consume_rabbitmq_forever)
        )
    if settings.kafka_enabled and MESSAGE_BUS_DUAL_CONSUME_ENABLED:
        for worker in range(workers):
            consumers.insert(
                worker,
                (f"kafka-w{worker + 1}", KafkaConsumer(settings, ORCHESTRATION_EVENTS), consume_kafka_forever),
            )
    return consumers


def _validate_governed_index_event(payload: dict[str, Any]) -> tuple[str, UUID]:
    tenant_id = require_tenant_id(payload.get("tenant_id"), source="governed RAG index event")
    try:
        document_id = UUID(str(payload.get("document_id") or ""))
    except ValueError as exc:
        raise ValueError("rag.document.approved requires a valid document_id") from exc
    if not str(payload.get("content_checksum") or "").startswith("sha256:"):
        raise ValueError("rag.document.approved requires a content checksum")
    return tenant_id, document_id


async def _index_governed_document(
    app: FastAPI,
    payload: dict[str, Any],
    *,
    stale_indexing_seconds: float = 60.0,
) -> None:
    tenant_id, document_id = _validate_governed_index_event(payload)
    retry_limit = max(1, int(getattr(settings, "rag_index_retry_limit", 5) or 5))
    async with app.state.session_factory() as session:
        repo = IncidentRepository(session)
        document = await repo.claim_governed_rag_document_for_indexing(
            tenant_id=tenant_id,
            document_id=document_id,
            stale_indexing_seconds=stale_indexing_seconds,
        )
        if document is None:
            await session.rollback()
            return
        await session.commit()
        try:
            expected = f"sha256:{hashlib.sha256(document.content.encode('utf-8')).hexdigest()}"
            if expected != document.content_checksum or expected != payload.get("content_checksum"):
                raise RuntimeError("authoritative governed document checksum mismatch")
            connector = vector_connector()
            receipt = await connector.index_governed_document(document)
            await connector.verify_index_receipt(receipt, expected_checksum=expected)
            await repo.mark_governed_rag_document_indexed(
                tenant_id=tenant_id, document_id=document_id, index_receipt=receipt,
            )
            await session.commit()
        except Exception as exc:
            retry_seconds = max(1.0, float(getattr(settings, "rag_index_retry_seconds", 30.0) or 30.0))
            retry_at = datetime.now(UTC) + timedelta(seconds=retry_seconds * max(1, document.index_attempts))
            await repo.mark_governed_rag_document_index_failed(
                tenant_id=tenant_id, document_id=document_id, error=str(exc), retry_at=retry_at,
                retry_limit=retry_limit,
            )
            await session.commit()
            raise


async def _run_governed_rag_retry_pass(
    app: FastAPI,
    *,
    stale_indexing_seconds: float = 60.0,
) -> int:
    retry_limit = max(1, int(getattr(settings, "rag_index_retry_limit", 5) or 5))
    async with app.state.session_factory() as session:
        due = await IncidentRepository(session).list_due_governed_rag_index_retries(
            retry_limit=retry_limit,
            stale_indexing_seconds=stale_indexing_seconds,
        )
    processed = 0
    for document in due:
        payload = {
            "tenant_id": document.tenant_id,
            "document_id": str(document.document_id),
            "content_checksum": document.content_checksum,
        }
        try:
            await _index_governed_document(
                app,
                payload,
                stale_indexing_seconds=stale_indexing_seconds,
            )
            processed += 1
        except Exception:
            logger.exception(
                "governed RAG index retry failed",
                extra={"document_id": str(document.document_id)},
            )
    return processed


async def _governed_rag_retry_loop(app: FastAPI) -> None:
    while True:
        try:
            await _run_governed_rag_retry_pass(app)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("governed RAG retry scan failed")
        await asyncio.sleep(max(5.0, float(getattr(settings, "rag_index_retry_seconds", 30.0) or 30.0)))


async def _maintain_context_queue(app: FastAPI, tenant_id: str) -> None:
    from common.alert_processing_budget import client_for
    from common.queue_lifecycle import maintain_context_queue
    try:
        async with asyncio.timeout(15):
            cursor_key = f"{settings.rabbitmq_queue_prefix}:context-maintenance:{tenant_id}"
            cursor = await client_for(settings).get(cursor_key) or ""
            maintenance = await maintain_context_queue(
                app.state.session_factory, tenant_id=tenant_id, cursor=cursor, incident_limit=20,
                progress=lambda value: client_for(settings).set(cursor_key, value),
            )
            await client_for(settings).set(cursor_key, maintenance["next_cursor"])
        logger.info("context queue maintenance tenant=%s scanned=%s changed=%s",
            tenant_id, maintenance["incidents_scanned"], maintenance["jobs_changed"])
    except asyncio.CancelledError:
        raise
    except TimeoutError:
        logger.info("context queue maintenance yielded at time budget tenant=%s; committed cursor retained", tenant_id)
    except Exception:
        # Maintenance failure must not suppress ordinary evidence reconciliation.
        logger.exception("context queue maintenance failed tenant=%s", tenant_id)


async def _context_reconciliation_loop(app: FastAPI) -> None:
    """Continuously reconcile all enabled tenants under a durable global lease."""
    owner = f"{settings.service_name}:{os.getenv('HOSTNAME', 'local')}:{os.getpid()}"
    lease_key = "active-incident-evidence"
    interval = max(5.0, float(settings.context_reconciliation_interval_seconds or 30.0))
    lease_seconds = max(30, int(settings.context_reconciliation_lease_seconds or 120))
    batch_size = max(1, min(int(settings.context_reconciliation_batch_size or 100), 500))
    while True:
        acquired = False
        try:
            async with app.state.session_factory() as session:
                repository = ContextEnrichmentRepository(session)
                acquired = await repository.claim_reconciliation_lease(
                    lease_key=lease_key, owner=owner, lease_seconds=lease_seconds,
                )
                tenants = await repository.enabled_reconciliation_tenants() if acquired else []
                await session.commit()
            for tenant_id in tenants:
                async with app.state.session_factory() as session:
                    repository = ContextEnrichmentRepository(session)
                    if not await repository.claim_reconciliation_lease(
                        lease_key=lease_key, owner=owner, lease_seconds=lease_seconds,
                    ):
                        await session.rollback()
                        break
                    run = await repository.start_reconciliation_run(owner=owner, tenant_id=tenant_id)
                    run_id = run.run_id
                    await session.commit()
                summary: dict[str, Any]
                try:
                    await _maintain_context_queue(app, tenant_id)
                    summary = await _reconcile_context_enrichment_tenant(ContextEnrichmentReconcileRequest(
                        tenant_id=tenant_id, limit=batch_size, dry_run=False,
                    ))
                    run_status = "completed_with_errors" if summary.get("errors") else "completed"
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    logger.exception("context reconciliation failed tenant=%s", tenant_id)
                    summary = {"errors": [{"code": "RECONCILIATION_FAILED", "detail": str(exc)[:500]}]}
                    run_status = "failed"
                async with app.state.session_factory() as session:
                    await ContextEnrichmentRepository(session).finish_reconciliation_run(
                        run_id=run_id, summary=summary, status=run_status,
                    )
                    await session.commit()
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("context reconciliation scheduler iteration failed")
        finally:
            if acquired:
                try:
                    async with app.state.session_factory() as session:
                        await ContextEnrichmentRepository(session).release_reconciliation_lease(
                            lease_key=lease_key, owner=owner,
                        )
                        await session.commit()
                except Exception:
                    logger.exception("context reconciliation lease release failed")
        await asyncio.sleep(interval)


async def _human_evidence_jira_sync_loop(app: FastAPI) -> None:
    """Deliver durable assigned evidence requests to the Jira integration."""
    endpoint = f"{str(settings.monitoring_adapter_url).rstrip('/')}/api/v1/jira/evidence-requests"
    ui_base = os.getenv("KAIMS_UI_BASE_URL", "http://localhost").rstrip("/")
    failure_cooldown_seconds = max(
        30.0, min(float(os.getenv("CONTEXT_JIRA_FAILURE_COOLDOWN_SECONDS", "300")), 1800.0)
    )
    while True:
        upstream_failed = False
        try:
            async with app.state.session_factory() as session:
                rows = await ContextEnrichmentRepository(session).claim_human_evidence_jira_requests(limit=20)
                await session.commit()
            async with httpx.AsyncClient(timeout=30.0) as client:
                for index, row in enumerate(rows):
                    try:
                        response = await client.post(endpoint, json={
                            **row,
                            "due_at": row["due_at"].isoformat(),
                            "kaims_deep_link": f"{ui_base}/incidents/{row['incident_id']}",
                        })
                        response.raise_for_status()
                    except asyncio.CancelledError:
                        raise
                    except Exception as exc:
                        logger.warning("human evidence Jira synchronization failed request_id=%s", row["request_id"])
                        async with app.state.session_factory() as session:
                            repository = ContextEnrichmentRepository(session)
                            # A transport/upstream failure applies to the batch.
                            # Do not hammer the same unavailable integration once
                            # per pending request or leave the claimed remainder
                            # stranded in "syncing" until lease recovery.
                            for pending in rows[index:]:
                                await repository.fail_human_evidence_jira_sync(
                                    request_id=pending["request_id"], error=type(exc).__name__,
                                )
                            await session.commit()
                        upstream_failed = True
                        break
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("human evidence Jira synchronization scan failed")
        await asyncio.sleep(failure_cooldown_seconds if upstream_failed else 10.0)


async def startup(app: FastAPI) -> None:
    if settings.database_enabled:
        try:
            async with app.state.session_factory() as session:
                await session.execute(text(
                    "SELECT lease_owner, lease_expires_at FROM context_enrichment_jobs LIMIT 0"
                ))
                await session.execute(text(
                    "SELECT lease_owner, lease_expires_at FROM context_reconciliation_leases LIMIT 0"
                ))
        except Exception as exc:
            raise RuntimeError(
                "context enrichment schema is incompatible; run pending migrations before startup"
            ) from exc
        try:
            async with app.state.session_factory() as session:
                gov_rows = (await session.execute(
                    select(GovernedRagDocumentRecord).where(
                        GovernedRagDocumentRecord.review_status == "approved",
                        GovernedRagDocumentRecord.index_status.in_(("indexed", "pending")),
                    )
                )).scalars().all()
            vc = vector_connector()
            for gov_doc in gov_rows:
                try:
                    if gov_doc.index_status == "indexed":
                        await vc.index_governed_document(gov_doc)
                    elif gov_doc.index_status == "pending":
                        await _index_governed_document(app, {
                            "tenant_id": gov_doc.tenant_id,
                            "document_id": str(gov_doc.document_id),
                            "content_checksum": gov_doc.content_checksum,
                        })
                except Exception:
                    logger.exception(
                        "governed RAG startup hydration failed for document; retry loop will recover",
                        extra={"document_id": str(gov_doc.document_id)},
                    )
        except Exception:
            logger.exception("governed RAG startup hydration failed; retry loop will recover")
    provider = str(getattr(settings, "event_bus_provider", "rabbitmq") or "rabbitmq").strip().lower()
    app.state.message_bus_publishers = {provider: app.state.producer, "rabbitmq": app.state.producer}

    if settings.kafka_enabled:
        app.state.message_bus_publishers["kafka"] = app.state.producer

    if settings.kafka_enabled:
        rabbitmq_publisher = RabbitMQPublisher(settings)
        try:
            await rabbitmq_publisher.start()
            app.state.message_bus_publishers["rabbitmq"] = rabbitmq_publisher
        except Exception:
            app.state.rabbitmq_publisher = None
        else:
            app.state.rabbitmq_publisher = rabbitmq_publisher
    else:
        app.state.rabbitmq_publisher = None

    tasks.append(asyncio.create_task(_context_outbox_dispatch_loop(app), name="context-agent-event-outbox"))
    for lane in ("fair", "recovery", "retry", "priority"):
        tasks.append(asyncio.create_task(_context_enrichment_worker(app, lane), name=f"context-agent-enrichment-{lane}"))
    from common.queue_backpressure import backlog_loop, controller_enabled
    if controller_enabled(settings.queue_backlog_enabled, provider, app.state.rabbitmq_publisher is not None):
        tasks.append(asyncio.create_task(backlog_loop(settings), name="context-agent-backlog-controller"))
    if settings.context_reconciliation_enabled:
        tasks.append(asyncio.create_task(
            _context_reconciliation_loop(app), name="context-agent-enrichment-reconciler",
        ))
    if settings.jira_polling_enabled:
        tasks.append(asyncio.create_task(
            _human_evidence_jira_sync_loop(app), name="context-agent-human-evidence-jira-sync",
        ))

    index_consumer = RabbitMQConsumer(settings, GOVERNED_RAG_APPROVED_TOPIC)
    tasks.append(asyncio.create_task(
        consume_rabbitmq_forever(index_consumer, lambda payload: _index_governed_document(app, payload)),
        name="context-agent-governed-rag-indexer",
    ))
    tasks.append(asyncio.create_task(_governed_rag_retry_loop(app), name="context-agent-rag-index-retries"))

    async def handle(payload: dict) -> None:
        alert = Alert.model_validate(payload["alert"])
        incident = _incident_from_workflow_payload(payload["incident"])
        decision = payload.get("decision") if isinstance(payload.get("decision"), dict) else {}
        if settings.database_enabled:
            from common.analysis_admission import retire_ineligible_analysis
            async with app.state.session_factory() as session:
                retired = await retire_ineligible_analysis(session, alert, incident, decision.get("analysis_request_id"))
                await session.commit()
            if retired:
                logger.info("Queued analysis retired before collection", extra={"incident_id": str(incident.id), "reason": retired})
                return
        context = await _collect_context_with_strategy(
            app, alert, incident, decision.get("context_strategy"), payload.get("context")
        )
        context = _attach_analysis_request_metadata(
            context,
            decision=decision,
            analysis_request=payload.get("analysis_request"),
        )
        context = context.model_copy(update={"metadata": {
            **context.metadata, "context_delivery_lane": "initial",
        }})
        # Evidence drafts are created only after the recommendation and its
        # normalized investigation binding have committed.
        provider = _extract_message_bus_provider(payload)
        publishers: dict[str, EventPublisher] = getattr(app.state, "message_bus_publishers", {})
        provider_used = provider if publishers.get(provider) is not None else "rabbitmq"
        outgoing_payload = _build_context_event_payload(
            alert=alert,
            incident=incident,
            context=context,
            decision=payload.get("decision") if isinstance(payload.get("decision"), dict) else None,
            provider_used=provider_used,
        )
        enqueued = await _persist_context_event(
            app=app,
            alert=alert,
            incident=incident,
            context=context,
            decision=payload.get("decision") if isinstance(payload.get("decision"), dict) else None,
            provider_used=provider_used,
            outgoing_payload=outgoing_payload,
        )
        if enqueued:
            await _publish_context_event(
                app=app,
                provider=provider_used,
                alert=alert,
                incident=incident,
                context=context,
                decision=payload.get("decision") if isinstance(payload.get("decision"), dict) else None,
                payload=outgoing_payload,
            )
        else:
            CONTEXT_REUSE_DECISIONS.labels("publish", "duplicate_event_suppressed").inc()
        EVENTS_PROCESSED.labels(settings.service_name, f"{ORCHESTRATION_EVENTS}:{provider_used}", "ok").inc()

    async def record_terminal_failure(payload: dict[str, Any], error: str) -> None:
        decision = payload.get("decision") if isinstance(payload.get("decision"), dict) else {}
        incident = payload.get("incident") if isinstance(payload.get("incident"), dict) else {}
        alert = payload.get("alert") if isinstance(payload.get("alert"), dict) else {}
        request_id = str(decision.get("analysis_request_id") or "").strip()
        tenant_id = str(incident.get("tenant_id") or alert.get("tenant_id") or "").strip()
        if not request_id or not tenant_id or not settings.database_enabled:
            return
        async with app.state.session_factory() as session:
            await IncidentRepository(session).fail_analysis_request(
                request_id, tenant_id=tenant_id, reason=error,
            )
            await session.commit()

    for source, consumer, consume_forever in _build_ingress_consumers():
        runner = (
            consume_forever(consumer, handle, record_terminal_failure)
            if source.startswith("rabbitmq")
            else consume_forever(consumer, handle)
        )
        task = asyncio.create_task(runner, name=f"context-agent-{source}-consumer")
        tasks.append(task)


async def shutdown(app: FastAPI) -> None:
    for task in tasks:
        task.cancel()
    rabbitmq_publisher = getattr(app.state, "rabbitmq_publisher", None)
    if rabbitmq_publisher is not None:
        await rabbitmq_publisher.stop()


app = create_app(title="KaiMS Context Intelligence Agent", settings=settings, startup=startup, shutdown=shutdown)


class RagDocumentRequest(BaseModel):
    kind: str = Field(pattern="^(runbook|incident|deployment|change|dependency|remediation)$")
    alert_id: str | None = Field(default=None, max_length=80)
    alert_type: str | None = Field(default=None, max_length=80)
    severity: str | None = Field(default=None, max_length=32)
    title: str = Field(min_length=3, max_length=160)
    summary: str | None = Field(default=None, min_length=0)
    content: str = Field(min_length=20)
    services: list[str] = Field(default_factory=list)
    deployment: str | None = None
    dependencies: list[str] = Field(default_factory=list)
    change_id: str | None = None
    root_cause: str | None = None
    impact: str | None = None
    execution_plan: str | None = None
    commands: list[str] = Field(default_factory=list)
    scripts: list[str] = Field(default_factory=list)
    queries: list[str] = Field(default_factory=list)
    recommended_action: str | None = None
    source_system: str | None = None
    source_ref: str | None = None
    resolved_by: str | None = None
    closed_at: str | None = None
    metadata: dict[str, str] = Field(default_factory=dict)
    tenant_scope: str = Field(default="", max_length=128)
    owner_team: str = Field(default="", max_length=160)
    review_status: str = Field(default="pending_review", pattern="^(draft|pending_review|approved|rejected)$")
    corpus_classification: str = Field(
        default="GENERATED_UNVERIFIED",
        pattern="^(PRODUCTION_CURATED|TENANT_CURATED|GENERATED_UNVERIFIED|DEMO_ONLY|MALFORMED|OBSOLETE)$",
    )
    content_version: int = Field(default=1, ge=1)
    created_at: str | None = None
    updated_at: str | None = None
    last_reviewed: str | None = None
    reviewed_by: str | None = Field(default=None, max_length=160)
    approved_by: str | None = Field(default=None, max_length=160)
    approved_at: str | None = None


class RagDocumentUpdateRequest(RagDocumentRequest):
    path: str = Field(min_length=3)


class RagDocumentApproveRequest(BaseModel):
    tenant_scope: str = Field(min_length=1, max_length=128)
    approved_by: str = Field(min_length=1, max_length=160)
    owner_team: str = Field(min_length=2, max_length=160)


class EvidenceRagDraftReviewRequest(BaseModel):
    tenant_scope: str = Field(min_length=1, max_length=128)
    expected_row_version: int = Field(ge=1)
    title: str = Field(min_length=3, max_length=160)
    content: str = Field(min_length=20)
    reviewed_by: str = Field(min_length=2, max_length=120)
    review_notes: str | None = Field(default=None, max_length=2000)


class EvidenceRagDraftApproveRequest(BaseModel):
    tenant_scope: str = Field(min_length=1, max_length=128)
    expected_row_version: int = Field(ge=1)
    approved_by: str = Field(min_length=2, max_length=120)
    owner_team: str | None = Field(default=None, min_length=2, max_length=160)


class EvidenceRagDraftRevisionRequest(BaseModel):
    tenant_scope: str = Field(min_length=1, max_length=128)
    created_by: str = Field(min_length=2, max_length=160)


class GovernedRagIndexRetryRequest(BaseModel):
    tenant_scope: str = Field(min_length=1, max_length=128)
    requested_by: str = Field(min_length=2, max_length=160)


class KnowledgeRagDraftCreateRequest(BaseModel):
    tenant_scope: str = Field(min_length=1, max_length=128)
    created_by: str = Field(min_length=2, max_length=160)
    kind: str = Field(pattern="^(runbook|incident|deployment|change|dependency|remediation|application|monitoring)$")
    source_ref: str = Field(min_length=3, max_length=512)
    title: str = Field(min_length=3, max_length=160)
    content: str = Field(min_length=20)
    metadata: dict[str, Any] = Field(default_factory=dict)


class KnowledgeRagDraftReviewRequest(BaseModel):
    tenant_scope: str = Field(min_length=1, max_length=128)
    reviewed_by: str = Field(min_length=2, max_length=160)
    expected_row_version: int = Field(ge=1)
    title: str = Field(min_length=3, max_length=160)
    content: str = Field(min_length=20)
    review_notes: str | None = Field(default=None, max_length=2000)


class KnowledgeRagDraftApproveRequest(BaseModel):
    tenant_scope: str = Field(min_length=1, max_length=128)
    approved_by: str = Field(min_length=2, max_length=160)
    expected_row_version: int = Field(ge=1)


class EvidenceRagDraftCreateRequest(BaseModel):
    tenant_scope: str = Field(min_length=1, max_length=128)
    created_by: str = Field(min_length=2, max_length=160)
    incident_id: UUID
    alert_id: UUID
    analysis_request_id: UUID
    context_snapshot_id: UUID
    context_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    recommendation_id: UUID
    rca_version: int = Field(ge=1)
    evidence_ids: list[str] = Field(min_length=1)
    source_uris: list[str] = Field(min_length=1)
    content: str = Field(min_length=20)
    alert_type: str = Field(default="Alert", max_length=255)
    severity: str = Field(default="unknown", max_length=32)
    environment: str = Field(default="unknown", max_length=64)
    services: list[str] = Field(default_factory=list)


def _metadata_value(metadata: dict[str, str], *keys: str, default: str = "") -> str:
    for key in keys:
        value = str(metadata.get(key) or "").strip()
        if value:
            return value
    return default


def _http_url_or_default(value: str, default: str) -> str:
    candidate = str(value or "").strip()
    parsed = urlparse(candidate)
    return candidate if parsed.scheme in {"http", "https"} and parsed.netloc else default


def _single_remediation_script(request: RagDocumentRequest) -> str:
    service = (request.services[0] if request.services else request.alert_type or "kaiops-service").strip()
    environment = _metadata_value(request.metadata, "environment", default="prod")
    api_gateway_url = _http_url_or_default(_metadata_value(
        request.metadata,
        "api_gateway_url",
        "apiGatewayUrl",
        "gateway_url",
        default="http://api-gateway:8000",
    ), "http://api-gateway:8000")
    prometheus_url = _http_url_or_default(_metadata_value(
        request.metadata,
        "prometheus_url",
        "monitoring_url",
        "metrics_endpoint",
        default="http://prometheus:9090",
    ), "http://prometheus:9090")
    mysql_host = _metadata_value(request.metadata, "mysql_host", "database_host", default="mysql")
    mysql_database = _metadata_value(request.metadata, "mysql_database", "database_name", default="kaiops")
    mysql_user = _metadata_value(request.metadata, "mysql_user", "database_user", default="kaiops")
    return (
        "bash scripts/remediation/kaiops_alert_health_triage.sh "
        f"--service {shlex.quote(service or 'kaiops-service')} "
        f"--environment {shlex.quote(environment or 'prod')} "
        f"--api-gateway-url {shlex.quote(api_gateway_url)} "
        f"--prometheus-url {shlex.quote(prometheus_url)} "
        f"--mysql-host {shlex.quote(mysql_host)} "
        f"--mysql-database {shlex.quote(mysql_database)} "
        f"--mysql-user {shlex.quote(mysql_user)} "
        "--dry-run true"
    )


def _execution_script_lines(request: RagDocumentRequest) -> list[str]:
    scripts = [str(item).strip() for item in request.scripts if str(item).strip()]
    has_fragments = any(str(item).strip() for item in [*request.commands, *request.queries])
    if scripts:
        return scripts
    if has_fragments:
        return [_single_remediation_script(request)]
    return []


class KnowledgePackSourceDocument(BaseModel):
    name: str = Field(default="uploaded-document", max_length=240)
    category: str | None = Field(default=None, max_length=80)
    text: str = Field(default="", max_length=200_000)
    excerpt: str | None = Field(default=None, max_length=1000)


class KnowledgePackRequest(BaseModel):
    service: str | None = Field(default=None, max_length=128)
    environment: str | None = Field(default=None, max_length=64)
    owner_team: str | None = Field(default=None, max_length=160)
    documents: list[KnowledgePackSourceDocument] = Field(default_factory=list)


class KnowledgePackApproveRequest(KnowledgePackRequest):
    accepted_facts: dict[str, Any] = Field(default_factory=dict)
    tenant_id: str = Field(min_length=1, max_length=128)
    approved_by: str = Field(min_length=1, max_length=160)
    approval_expires_at: datetime


def vector_connector() -> VectorDBConnector:
    for connector in agent.connectors:
        if isinstance(connector, VectorDBConnector):
            return connector
    raise RuntimeError("VectorDBConnector is not configured")


def knowledge_graph() -> KnowledgeGraph:
    connector = vector_connector()
    if not connector.documents:
        connector.documents = connector.load_documents()
    if connector._knowledge_graph is None:
        connector._knowledge_graph = KnowledgeGraph.from_documents(connector.documents)
    return connector._knowledge_graph


def slugify(value: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9]+", "-", value.strip().lower()).strip("-")
    return slug or "document"


def kind_directory(kind: str) -> str:
    return {
        "runbook": "runbooks",
        "incident": "incidents",
        "deployment": "deployments",
        "change": "changes",
        "dependency": "dependencies",
        "remediation": "remediations",
    }[kind]


def _first_match(patterns: list[str], text: str) -> str:
    for pattern in patterns:
        match = re.search(pattern, text, flags=re.IGNORECASE | re.MULTILINE)
        if match:
            return str(match.group(1) if match.groups() else match.group(0)).strip(" :-\t\r\n")
    return ""


def _unique_tokens(values: list[str], *, limit: int = 12) -> list[str]:
    rows: list[str] = []
    seen: set[str] = set()
    for value in values:
        token = re.sub(r"\s+", " ", str(value or "").strip(" ,.;:-\n\r\t"))
        key = token.lower()
        if not token or key in seen:
            continue
        seen.add(key)
        rows.append(token)
        if len(rows) >= limit:
            break
    return rows


def _fact(value: Any, confidence: float, sources: list[str], status: str | None = None) -> dict[str, Any]:
    present = bool(value if not isinstance(value, list) else len(value))
    return {
        "value": value,
        "confidence": round(float(confidence if present else 0.0), 3),
        "sources": _unique_tokens(sources, limit=8),
        "status": status or ("accepted" if present and confidence >= 0.78 else "needs_review"),
    }


def _compute_knowledge_pack_validation(facts: dict[str, Any]) -> dict[str, Any]:
    required = ["service", "environment", "owner_team", "alert_patterns"]
    recommended = ["dependencies", "commands", "rollback_plan", "validation_checks"]
    missing_required = [key for key in required if not facts[key]["value"]]
    missing_recommended = [key for key in recommended if not facts[key]["value"]]
    low_confidence = [key for key, value in facts.items() if float(value.get("confidence") or 0.0) < 0.7]
    overall_confidence = round(
        sum(float(value.get("confidence") or 0.0) for value in facts.values()) / max(1, len(facts)),
        3,
    )
    return {
        "missing_required": missing_required,
        "missing_recommended": missing_recommended,
        "low_confidence": low_confidence,
        "overall_confidence": overall_confidence,
    }


def _classify_pack_document(name: str, text: str, category: str | None = None) -> str:
    haystack = f"{category or ''} {name} {text}".lower()
    if re.search(r"\b(rca|postmortem|root cause)\b", haystack):
        return "incident"
    if re.search(r"\b(dependency|topology|upstream|downstream|service map)\b", haystack):
        return "dependency"
    if re.search(r"\b(change|deployment|release|rollback)\b", haystack):
        return "change"
    if re.search(r"\b(remediation|restart|failover|scale|script|command|query)\b", haystack):
        return "remediation"
    return "runbook"


def build_knowledge_pack(request: KnowledgePackRequest) -> dict[str, Any]:
    docs = [doc for doc in request.documents if str(doc.text or "").strip()]
    combined = "\n\n".join(f"# {doc.name}\n{doc.text}" for doc in docs)
    source_names = [doc.name for doc in docs]
    service = str(request.service or "").strip() or _first_match(
        [r"\bservice\s*[:=-]\s*([a-zA-Z0-9_.-]+)", r"\bapplication\s*[:=-]\s*([a-zA-Z0-9_.-]+)"],
        combined,
    )
    environment = str(request.environment or "").strip() or _first_match(
        [r"\benvironment\s*[:=-]\s*(prod|production|stage|staging|dev|test)", r"\benv\s*[:=-]\s*(prod|production|stage|staging|dev|test)"],
        combined,
    )
    owner = str(request.owner_team or "").strip() or _first_match(
        [r"\bowner(?:_team|\s+team)?\s*[:=-]\s*([a-zA-Z0-9_.@ -]+)", r"\bteam\s*[:=-]\s*([a-zA-Z0-9_.@ -]+)"],
        combined,
    )
    dependencies = _unique_tokens(
        re.findall(r"(?:depends on|dependency|upstream|downstream)\s*[:=-]\s*([a-zA-Z0-9_.-]+)", combined, flags=re.IGNORECASE)
        + re.findall(r"\b(redis|mysql|postgres|kafka|rabbitmq|servicebus|ledger|fraud|checkout|prometheus|grafana)\b", combined, flags=re.IGNORECASE),
        limit=12,
    )
    alert_patterns = _unique_tokens(
        re.findall(r"(?:alert|monitor|rule)\s*[:=-]\s*([^\n]{8,160})", combined, flags=re.IGNORECASE)
        + re.findall(r"([^\n]*(?:latency|availability|error rate|5xx|cpu|memory|queue|replication|timeout)[^\n]{0,140})", combined, flags=re.IGNORECASE),
        limit=10,
    )
    commands = _unique_tokens(
        re.findall(r"^\s*(?:cmd|command|script|query)?\s*:?\s*((?:kubectl|helm|terraform|ansible-playbook|mysql|redis-cli|curl|powershell|scripts/|\./)[^\n`]+)", combined, flags=re.IGNORECASE | re.MULTILINE),
        limit=10,
    )
    rollback = _unique_tokens(
        re.findall(r"(rollback[^\n]{6,180}|failback[^\n]{6,180}|restore[^\n]{6,180})", combined, flags=re.IGNORECASE),
        limit=6,
    )
    validation_checks = _unique_tokens(
        re.findall(r"(validate[^\n]{6,180}|verify[^\n]{6,180}|check[^\n]{6,180})", combined, flags=re.IGNORECASE),
        limit=8,
    )
    detected_docs = [
        {
            "name": doc.name,
            "category": doc.category or _classify_pack_document(doc.name, doc.text),
            "detected_kind": _classify_pack_document(doc.name, doc.text, doc.category),
            "excerpt": (doc.excerpt or re.sub(r"\s+", " ", doc.text).strip()[:220]),
        }
        for doc in docs
    ]
    facts = {
        "service": _fact(service, 0.96 if request.service else 0.78, source_names),
        "environment": _fact(environment or "prod", 0.92 if request.environment else 0.68, source_names, status="accepted" if environment else "needs_review"),
        "owner_team": _fact(owner, 0.92 if request.owner_team else 0.7, source_names),
        "dependencies": _fact(dependencies, 0.82 if dependencies else 0.0, source_names),
        "alert_patterns": _fact(alert_patterns, 0.84 if alert_patterns else 0.0, source_names),
        "commands": _fact(commands, 0.8 if commands else 0.0, source_names),
        "rollback_plan": _fact(rollback, 0.78 if rollback else 0.0, source_names),
        "validation_checks": _fact(validation_checks, 0.8 if validation_checks else 0.0, source_names),
    }
    validation = _compute_knowledge_pack_validation(facts)
    missing_required = validation["missing_required"]
    missing_recommended = validation["missing_recommended"]
    low_confidence = validation["low_confidence"]
    return {
        "contract_version": "kaiops.knowledge-pack.v1",
        "status": "ready" if not missing_required and not low_confidence[:1] else "needs_review",
        "document_count": len(docs),
        "detected_documents": detected_docs,
        "facts": facts,
        "validation": validation,
        "next_questions": [
            question
            for key, question in {
                "service": "Which service/application is this knowledge pack for?",
                "owner_team": "Who owns this service?",
                "alert_patterns": "Which alert pattern or monitor should KaiOps use for this service?",
                "rollback_plan": "What rollback or failback plan should be used if remediation fails?",
                "validation_checks": "How should KaiOps verify recovery after remediation?",
            }.items()
            if key in missing_required or key in missing_recommended or key in low_confidence
        ][:5],
    }


def _knowledge_pack_to_rag_request(
    pack: dict[str, Any], approved_by: str, tenant_scope: str
) -> RagDocumentRequest:
    facts = pack.get("facts") if isinstance(pack.get("facts"), dict) else {}

    def fact_value(key: str, default: Any = "") -> Any:
        row = facts.get(key) if isinstance(facts.get(key), dict) else {}
        value = row.get("value", default)
        return value if value not in (None, "") else default

    service = str(fact_value("service", "unknown-service")).strip() or "unknown-service"
    environment = str(fact_value("environment", "prod")).strip() or "prod"
    owner = str(fact_value("owner_team", "")).strip()
    if not owner:
        raise HTTPException(status_code=422, detail="owner_team must be explicitly approved")
    dependencies = fact_value("dependencies", [])
    commands = fact_value("commands", [])
    validation = fact_value("validation_checks", [])
    rollback = fact_value("rollback_plan", [])
    alert_patterns = fact_value("alert_patterns", [])
    content = "\n".join(
        [
            f"Knowledge pack for {service} in {environment}.",
            "",
            "Alert patterns:",
            *[f"- {item}" for item in (alert_patterns if isinstance(alert_patterns, list) else [alert_patterns]) if str(item).strip()],
            "",
            "Dependencies:",
            *[f"- {item}" for item in (dependencies if isinstance(dependencies, list) else [dependencies]) if str(item).strip()],
            "",
            "Validation checks:",
            *[f"- {item}" for item in (validation if isinstance(validation, list) else [validation]) if str(item).strip()],
            "",
            "Rollback plan:",
            *[f"- {item}" for item in (rollback if isinstance(rollback, list) else [rollback]) if str(item).strip()],
        ]
    ).strip()
    return RagDocumentRequest(
        kind="runbook",
        title=f"{service} Knowledge Pack",
        summary=f"Approved KaiOps knowledge pack for {service}.",
        content=content or f"Approved KaiOps knowledge pack for {service}.",
        services=[service],
        dependencies=dependencies if isinstance(dependencies, list) else [],
        commands=commands if isinstance(commands, list) else [],
        queries=validation if isinstance(validation, list) else [],
        source_system="knowledge-pack",
        source_ref=f"knowledge-pack://{service}/{environment}",
        resolved_by=owner,
        tenant_scope=tenant_scope,
        owner_team=owner,
        review_status="approved",
        corpus_classification="TENANT_CURATED",
        reviewed_by=approved_by,
        approved_by=approved_by,
        approved_at=datetime.now(UTC).isoformat(),
        last_reviewed=datetime.now(UTC).isoformat(),
        metadata={
            "environment": environment,
            "knowledge_pack_status": str(pack.get("status") or "approved"),
            "knowledge_pack_confidence": str((pack.get("validation") or {}).get("overall_confidence", "")),
        },
    )


def render_document(request: RagDocumentRequest) -> str:
    now = datetime.now(UTC).isoformat()
    metadata: dict[str, Any] = {
        "kind": request.kind,
        "title": request.title,
        "tenant_scope": request.tenant_scope,
        "services": ", ".join(request.services),
        "owner_team": request.owner_team,
        "source_system": request.source_system or "",
        "source_ref": request.source_ref or "",
        "review_status": request.review_status,
        "corpus_classification": request.corpus_classification,
        "content_version": request.content_version,
        "created_at": request.created_at or now,
        "updated_at": request.updated_at or now,
        "last_reviewed": request.last_reviewed or "",
        "reviewed_by": request.reviewed_by or "",
        "approved_by": request.approved_by or "",
        "approved_at": request.approved_at or "",
        "content_checksum": content_checksum(request.content),
    }
    if request.alert_id:
        metadata["alert_id"] = request.alert_id
    if request.alert_type:
        metadata["alert_type"] = request.alert_type
    if request.severity:
        metadata["severity"] = request.severity.lower()
    if request.deployment:
        metadata["deployment"] = request.deployment
    if request.dependencies:
        metadata["dependencies"] = ", ".join(request.dependencies)
    if request.change_id:
        metadata["change_id"] = request.change_id
    if request.source_system:
        metadata["source_system"] = request.source_system
    if request.source_ref:
        metadata["source_ref"] = request.source_ref
    if request.resolved_by:
        metadata["resolved_by"] = request.resolved_by
    if request.closed_at:
        metadata["closed_at"] = request.closed_at
    if request.root_cause:
        metadata["root_cause"] = request.root_cause
    if request.impact:
        metadata["impact"] = request.impact
    if request.execution_plan:
        metadata["execution_plan"] = request.execution_plan
    if request.recommended_action:
        metadata["recommended_action"] = request.recommended_action
    metadata.update(request.metadata)
    header = "\n".join(f"{key}: {value}" for key, value in metadata.items())
    body_lines = [f"# {request.title}"]
    if request.summary:
        body_lines.extend(["", "## Summary", request.summary.strip()])
    if request.content.strip():
        body_lines.extend(["", "## Description", request.content.strip()])
    if request.root_cause:
        body_lines.extend(["", "## Root Cause", request.root_cause.strip()])
    if request.impact:
        body_lines.extend(["", "## Impact", request.impact.strip()])
    if request.execution_plan:
        body_lines.extend(["", "## Execution Plan", request.execution_plan.strip()])
    script_lines = _execution_script_lines(request)
    if script_lines:
        body_lines.extend(["", "## Remediation Script"])
        for item in script_lines:
            body_lines.extend(["```bash", item, "```"])
    elif request.commands:
        body_lines.extend(["", "## Commands", *[f"- {item}" for item in request.commands if str(item).strip()]])
    return f"{header}\n\n" + "\n".join(body_lines).rstrip() + "\n"


def write_rag_document(request: RagDocumentRequest) -> dict[str, Any]:
    connector = vector_connector()
    root = connector.root_path()
    target_dir = root / kind_directory(request.kind)
    try:
        target_dir.mkdir(parents=True, exist_ok=True)
    except FileExistsError:
        if not (target_dir.exists() and target_dir.is_dir()):
            fallback_root = Path("/tmp/kaiops/rag")
            target_dir = fallback_root / kind_directory(request.kind)
            target_dir.mkdir(parents=True, exist_ok=True)
    base_name = slugify(request.alert_id or request.title)
    target = target_dir / f"{base_name}.md"
    if not request.alert_id:
        counter = 2
        while target.exists():
            target = target_dir / f"{base_name}-{counter}.md"
            counter += 1
    target.write_text(render_document(request), encoding="utf-8")
    count = connector.reload()
    return {"path": str(target), "document_count": count, "index": connector.index_info()}


def write_rag_document_to_path(request: RagDocumentRequest, path: str) -> dict[str, Any]:
    connector = vector_connector()
    root = connector.root_path().resolve()
    target = Path(path).expanduser().resolve()
    if root not in target.parents:
        raise HTTPException(status_code=400, detail="Document path is outside the RAG directory")
    if target.suffix.lower() != ".md":
        raise HTTPException(status_code=400, detail="Document path must end with .md")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(render_document(request), encoding="utf-8")
    count = connector.reload()
    return {"path": str(target), "document_count": count, "index": connector.index_info()}


def _evidence_draft_dir() -> Path:
    # JSON drafts deliberately live outside the Markdown index. They cannot
    # participate in grounding until an explicit approval promotes them.
    target = vector_connector().root_path() / "_review"
    target.mkdir(parents=True, exist_ok=True)
    return target


def _draft_path(draft_id: str) -> Path:
    safe_id = slugify(draft_id)
    target = (_evidence_draft_dir() / f"{safe_id}.json").resolve()
    if _evidence_draft_dir().resolve() not in target.parents:
        raise HTTPException(status_code=400, detail="invalid draft id")
    return target


def _read_evidence_draft(draft_id: str) -> dict[str, Any]:
    path = _draft_path(draft_id)
    if not path.exists():
        raise HTTPException(status_code=404, detail="evidence RAG draft not found")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise HTTPException(status_code=500, detail="evidence RAG draft is unreadable") from exc
    if not isinstance(payload, dict):
        raise HTTPException(status_code=500, detail="evidence RAG draft is invalid")
    return payload


def _write_evidence_draft(payload: dict[str, Any]) -> dict[str, Any]:
    draft_id = str(payload.get("draft_id") or "").strip()
    if not draft_id:
        raise ValueError("draft_id is required")
    _draft_path(draft_id).write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return payload


_GENERIC_EVIDENCE_TERMS = {
    "alert", "application", "critical", "error", "failed", "failure",
    "high", "incident", "monitor", "monitoring", "prod", "production",
    "service", "validation", "warning",
}

INCIDENT_DOCUMENT_KINDS = ("incident", "jira", "runbook", "deployment", "change", "dependency", "remediation")


def _typed_incident_document_content(kind: str, *, alert_name: str, service: str, environment: str, base: str) -> str:
    headings = {
        "incident": ("Incident record", "Timeline and impact", "Current lifecycle state"),
        "jira": ("Jira ticket draft", "Problem statement", "Acceptance and verification criteria"),
        "runbook": ("Runbook draft", "Safe diagnostic procedure", "Escalation and stop conditions"),
        "deployment": ("Deployment record", "Version and rollout context", "Validation and rollback"),
        "change": ("Change record", "Observed change window", "Risk, approval, and rollback"),
        "dependency": ("Dependency record", "Upstream and downstream services", "Health and ownership checks"),
        "remediation": ("Remediation plan draft", "Proposed governed action", "Preflight, validation, and rollback"),
    }
    title, section, controls = headings[kind]
    return "\n".join([
        f"# {title}: {alert_name}", "", f"Service: {service}", f"Environment: {environment}",
        "Status: Draft — operator verification required", "", f"## {section}", base,
        "",
        f"## {controls}",
        "Not established by verified evidence. Review and complete this section before publication.",
        "", "## Evidence and provenance", "Only the cited evidence in this draft may be treated as observed fact.",
    ])


def _crawled_incident_document_bundle(
    *, alert_name: str, service: str, environment: str,
    evidence_rows: list[dict[str, Any]],
) -> list[dict[str, str]]:
    facts: list[str] = []
    for row in evidence_rows[:50]:
        evidence_id = str(row.get("evidence_id") or row.get("id") or "").strip()
        source_uri = str(
            row.get("source_reference") or row.get("source_uri") or row.get("uri")
            or row.get("path") or row.get("citation") or ""
        ).strip()
        content = row.get("content") if isinstance(row.get("content"), dict) else {}
        observation = (
            row.get("snippet") or row.get("message") or row.get("summary")
            or (json.dumps(content, sort_keys=True, default=str) if content else "")
        )
        if evidence_id and source_uri and str(observation).strip():
            facts.append(f"- [{evidence_id}] {str(observation).strip()[:1000]} (source: {source_uri})")
    base = "\n".join(facts) or "No attributable crawler evidence was available."
    return [{
        "document_kind": kind,
        "title": f"{kind.replace('_', ' ').title()} draft: {alert_name}",
        "content": _typed_incident_document_content(
            kind, alert_name=alert_name, service=service, environment=environment, base=base,
        ),
    } for kind in INCIDENT_DOCUMENT_KINDS]


async def _create_crawled_evidence_drafts(
    repository: IncidentRepository, *, tenant_id: str, candidate: dict[str, Any],
    alert: Alert, incident: Incident,
) -> int:
    evidence_rows = [
        row for row in (
            candidate.get("accepted_evidence") or candidate.get("snapshot_evidence") or []
        )
        if isinstance(row, dict)
    ]
    evidence_ids = list(dict.fromkeys(
        str(row.get("evidence_id") or row.get("id") or "").strip()
        for row in evidence_rows
        if str(row.get("evidence_id") or row.get("id") or "").strip()
    ))
    source_uris = list(dict.fromkeys(
        str(
            row.get("source_reference") or row.get("source_uri") or row.get("uri")
            or row.get("path") or row.get("citation") or ""
        ).strip()
        for row in evidence_rows
        if str(
            row.get("source_reference") or row.get("source_uri") or row.get("uri")
            or row.get("path") or row.get("citation") or ""
        ).strip()
    ))
    if not evidence_ids or not source_uris:
        return 0
    existing = await repository.list_evidence_rag_drafts(
        tenant_id=tenant_id, alert_id=candidate["alert_id"],
    )
    existing_kinds = {str(row.get("document_kind") or "").lower() for row in existing}
    if set(INCIDENT_DOCUMENT_KINDS).issubset(existing_kinds):
        return 0
    documents = [
        row for row in _crawled_incident_document_bundle(
            alert_name=str(alert.name or incident.title or "Incident"),
            service=str(alert.service or incident.service or "unknown"),
            environment=str(alert.environment or incident.environment or "unknown"),
            evidence_rows=evidence_rows,
        )
        if row["document_kind"] not in existing_kinds
    ]
    if not documents:
        return 0
    drafts = await repository.create_evidence_rag_drafts(
        tenant_id=tenant_id, created_by="context-enrichment-crawler",
        binding=dict(candidate["binding"]), documents=documents,
        evidence_ids=evidence_ids, source_uris=source_uris,
        allow_snapshot_evidence=True,
    )
    return len(drafts)


def _write_incident_document_bundle(common: dict[str, Any], base_content: str) -> list[dict[str, Any]]:
    now = datetime.now(UTC).isoformat()
    drafts: list[dict[str, Any]] = []
    for kind in INCIDENT_DOCUMENT_KINDS:
        draft_id = f"evidence-{slugify(str(common['tenant_scope']))}-{common['alert_id']}-{kind}"
        path = _draft_path(draft_id)
        if path.exists():
            drafts.append(_read_evidence_draft(draft_id))
            continue
        title = f"{kind.replace('_', ' ').title()} draft: {common.get('alert_type') or common['alert_id']}"
        drafts.append(_write_evidence_draft({
            **common,
            "draft_id": draft_id,
            "document_kind": kind,
            "title": title,
            "content": _typed_incident_document_content(
                kind,
                alert_name=str(common.get("alert_type") or common["alert_id"]),
                service=str((common.get("services") or ["unknown"])[0]),
                environment=str(common.get("environment") or "unknown"),
                base=base_content,
            ),
            "status": "draft", "created_at": now, "updated_at": now,
            "reviewed_by": None, "review_notes": None, "approved_by": None,
            "approved_at": None, "rag_document_path": None,
        }))
    return drafts


def _alert_identity_terms(alert: Alert) -> set[str]:
    raw_labels = getattr(alert, "labels", {})
    labels = raw_labels if isinstance(raw_labels, dict) else {}
    values = [
        alert.service,
        alert.name,
        labels.get("application"),
        labels.get("project"),
        labels.get("project_name"),
        labels.get("monitor_id"),
    ]
    terms: set[str] = set()
    for value in values:
        for token in re.findall(r"[a-z0-9][a-z0-9_.-]{2,}", str(value or "").lower()):
            if token not in _GENERIC_EVIDENCE_TERMS:
                terms.add(token)
    return terms


def _evidence_matches_alert(row: dict[str, Any], identity_terms: set[str]) -> bool:
    if not identity_terms:
        return False
    haystack = " ".join(
        str(row.get(key) or "")
        for key in ("source", "snippet", "summary", "uri", "path", "title")
    ).lower()
    return any(term in haystack for term in identity_terms)


def create_evidence_rag_draft(*, alert: Alert, incident: Incident, context: Context) -> dict[str, Any] | None:
    metadata = context.metadata if isinstance(context.metadata, dict) else {}
    discovery = metadata.get("discovery_report") if isinstance(metadata.get("discovery_report"), dict) else {}
    report = discovery.get("report") if isinstance(discovery.get("report"), dict) else {}
    evidence = discovery.get("evidence") if isinstance(discovery.get("evidence"), list) else []
    identity_terms = _alert_identity_terms(alert)
    grounded = [
        row for row in evidence
        if isinstance(row, dict)
        and str(row.get("evidence_id") or "").strip()
        and _evidence_matches_alert(row, identity_terms)
    ]
    if not grounded:
        return None
    evidence_lines = [
        f"- [{row.get('evidence_id')}] {row.get('source', 'evidence')}: "
        f"{str(row.get('snippet') or row.get('summary') or '').strip()[:1200]} "
        f"({row.get('uri') or row.get('path') or 'source unavailable'})"
        for row in grounded[:40]
    ]
    hypotheses = report.get("hypotheses") if isinstance(report.get("hypotheses"), list) else []
    hypothesis_lines = [
        f"- {str(item.get('cause') or '').strip()} (confidence {item.get('confidence', 0)})"
        for item in hypotheses[:8]
        if isinstance(item, dict) and str(item.get("cause") or "").strip()
    ]
    content = "\n".join(
        [
            "## Alert",
            f"{alert.name} on {alert.service} ({alert.environment})",
            "",
            "## Evidence-backed summary",
            str(report.get("summary") or "Evidence collected; user review is required before grounding."),
            "",
            "## Hypotheses",
            *(hypothesis_lines or ["- No grounded hypothesis was produced."]),
            "",
            "## Collected evidence",
            *evidence_lines,
        ]
    )
    drafts = _write_incident_document_bundle(
        {
            "tenant_scope": alert.tenant_id,
            "alert_id": str(alert.id),
            "incident_id": str(incident.id),
            "alert_type": alert.name,
            "severity": str(getattr(alert.severity, "value", alert.severity)),
            "environment": alert.environment,
            "services": [alert.service],
            "evidence_ids": [str(row["evidence_id"]) for row in grounded],
            "source_uris": [str(row.get("uri") or row.get("path") or "") for row in grounded if row.get("uri") or row.get("path")],
            "evidence_relevance": {
                "verified": True,
                "identity_terms": sorted(identity_terms),
                "relevant_count": len(grounded),
                "retrieved_count": len(evidence),
            },
        }, content
    )
    return next(item for item in drafts if item["document_kind"] == "incident")


def _normalize_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    return []


def _first_content_line(content: str, fallback: str) -> str:
    for line in content.splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            return stripped
    return fallback


def rebuild_flow_catalog_from_rag(connector: VectorDBConnector) -> None:
    catalog_path = connector.root_path() / "flows.json"
    entries: list[dict[str, Any]] = []
    for doc in connector.documents:
        if str(doc.get("kind", "")).strip().lower() != "incident":
            continue
        full_doc = connector._load_full_document(str(doc.get("path", "")))
        alert_id = str(full_doc.get("alert_id") or full_doc.get("id") or "").strip()
        alert_name = str(full_doc.get("alert_name") or full_doc.get("title") or "Incident").strip() or "Incident"
        flow_id = slugify(alert_id or alert_name)
        services = _normalize_list(full_doc.get("services", []))
        service = services[0] if services else str(full_doc.get("service", "unknown")).strip() or "unknown"
        severity = str(full_doc.get("severity", "HIGH")).upper().strip()
        if severity not in {"CRITICAL", "HIGH", "WARNING"}:
            severity = "HIGH"
        recommended_action = str(full_doc.get("recommended_action") or full_doc.get("remediation_comment") or "Investigate issue")
        content = str(full_doc.get("content", "")).strip()
        summary = str(full_doc.get("summary") or _first_content_line(content, alert_name)).strip()
        execution_plan = str(full_doc.get("execution_plan") or "").strip()
        alert_type = str(full_doc.get("alert_type", "")).strip()
        entry = {
            "id": flow_id,
            "alert_id": alert_id or flow_id.upper(),
            "alert_name": alert_name,
            "alert_type": alert_type,
            "title": alert_name,
            "service": service,
            "severity": severity,
            "summary": summary[:220],
            "recommended_action": recommended_action,
            "description": summary[:220],
            "execution_plan": execution_plan[:220] or None,
            "deployment": str(full_doc.get("deployment", "")).strip() or None,
            "change_id": str(full_doc.get("change_id", "")).strip() or None,
            "root_cause": str(full_doc.get("root_cause", "")).strip() or None,
            "impact": str(full_doc.get("impact", "")).strip() or None,
            "source": "rag-incident",
        }
        entries.append({k: v for k, v in entry.items() if v not in (None, "")})

    by_id = {str(item.get("id")): item for item in entries if item.get("id")}
    merged = list(by_id.values())
    merged.sort(key=lambda item: str(item.get("title", "")).lower())
    catalog_path.write_text(json.dumps(merged, indent=2), encoding="utf-8")
    markdown_path = connector.root_path() / "flows.md"
    markdown_path.write_text(render_flow_catalog_markdown(merged), encoding="utf-8")


def render_flow_catalog_markdown(entries: list[dict[str, Any]]) -> str:
    field_labels = [
        ("service", "Service"),
        ("severity", "Severity"),
        ("alert_type", "Alert Type"),
        ("alert_id", "Alert ID"),
        ("summary", "Summary"),
        ("recommended_action", "Recommended Action"),
        ("root_cause", "Root Cause"),
        ("impact", "Impact"),
        ("deployment", "Deployment"),
        ("change_id", "Change ID"),
        ("execution_plan", "Execution Plan"),
    ]
    lines = [
        "# Alert Flow Catalog",
        "",
        "_Auto-generated from RAG incident documents whenever flows.json is rebuilt. "
        "Edit the source incident docs and resubmit them — this file is overwritten "
        "on every rebuild and excluded from RAG document matching._",
        "",
    ]
    if not entries:
        lines.append("_No incident-kind RAG documents are currently onboarded._")
    for entry in entries:
        title = str(entry.get("title") or entry.get("alert_name") or "Untitled Alert")
        lines.append(f"## {title}")
        for key, label in field_labels:
            value = entry.get(key)
            if value not in (None, ""):
                lines.append(f"- **{label}:** {value}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def read_flow_catalog(connector: VectorDBConnector) -> list[dict[str, Any]]:
    catalog_path = connector.root_path() / "flows.json"
    if not catalog_path.exists():
        return []
    try:
        data = json.loads(catalog_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    if not isinstance(data, list):
        return []
    return [item for item in data if isinstance(item, dict)]


@app.post("/collect", response_model=Context)
async def collect(payload: dict, publish_events: bool = True) -> Context:
    alert = Alert.model_validate(payload["alert"])
    incident = _incident_from_workflow_payload(payload["incident"])
    context = await _collect_context_with_strategy(
        app, alert, incident, payload.get("context_strategy"), payload.get("context")
    )
    context = _attach_analysis_request_metadata(
        context,
        decision=payload.get("decision"),
        analysis_request=payload.get("analysis_request"),
    )
    context = context.model_copy(update={"metadata": {
        **context.metadata, "context_delivery_lane": "initial",
    }})
    provider = _extract_message_bus_provider(payload)
    publishers: dict[str, EventPublisher] = getattr(app.state, "message_bus_publishers", {})
    provider_used = provider if publishers.get(provider) is not None else "rabbitmq"
    outgoing_payload = _build_context_event_payload(
        alert=alert,
        incident=incident,
        context=context,
        decision=payload.get("decision") if isinstance(payload.get("decision"), dict) else None,
        provider_used=provider_used,
    )
    enqueued = await _persist_context_event(
        app=app,
        alert=alert,
        incident=incident,
        context=context,
        decision=payload.get("decision") if isinstance(payload.get("decision"), dict) else None,
        provider_used=provider_used,
        outgoing_payload=outgoing_payload,
        enqueue_event=publish_events,
    )
    if publish_events and enqueued:
        await _publish_context_event(
            app=app,
            provider=provider_used,
            alert=alert,
            incident=incident,
            context=context,
            decision=payload.get("decision") if isinstance(payload.get("decision"), dict) else None,
            payload=outgoing_payload,
        )
    return context


@app.get("/context/strategy")
async def context_strategy_status() -> dict[str, Any]:
    return {
        "default": _context_strategy(),
        "supported": ["auto", "realtime", "historical"],
        "auto": {
            "cache_aside": True,
            "ttl_seconds": int(getattr(settings, "context_knowledge_ttl_seconds", 14400) or 14400),
            "refresh_policy": "quality_freshness_scope_or_conflict_failure",
            "match_scope": ["tenant", "service", "environment", "alert-family", "subject-fingerprint"],
            "quality_threshold": float(getattr(settings, "context_min_quality_score", 0.70) or 0.70),
            "per_source_ttl_seconds": {
                source: int(policy["ttl_seconds"]) for source, policy in SOURCE_POLICIES.items()
            },
            "adaptive_connector_planning": True,
            "single_flight": {"process": True, "mysql_replica_lease": True},
            "resolution_reuse_enabled": bool(getattr(settings, "context_resolution_reuse_enabled", True)),
            "resolution_reuse_min_score": float(getattr(settings, "context_resolution_reuse_min_score", 0.7) or 0.7),
        },
        "realtime": {"always_refresh": True},
        "historical": {"always_refresh": False, "cache_miss_collects_realtime": False},
    }


@app.get("/context/snapshots/{incident_id}")
async def latest_context_snapshot(incident_id: str, tenant_id: str = "default") -> dict[str, Any]:
    if not settings.database_enabled or getattr(app.state, "session_factory", None) is None:
        raise HTTPException(status_code=503, detail="context snapshot database is unavailable")
    async with app.state.session_factory() as session:
        snapshot = await IncidentRepository(session).latest_context_snapshot(
            incident_id,
            tenant_id=tenant_id,
        )
    if snapshot is None:
        raise HTTPException(status_code=404, detail="context snapshot not found")
    return snapshot


@app.get("/incidents/{incident_id}/context-gaps")
async def list_context_gaps(incident_id: str, tenant_id: str) -> dict[str, Any]:
    tenant = require_tenant_id(tenant_id, source="context gap inventory")
    if not settings.database_enabled or getattr(app.state, "session_factory", None) is None:
        raise HTTPException(status_code=503, detail="context enrichment database is unavailable")
    async with app.state.session_factory() as session:
        repository = ContextEnrichmentRepository(session)
        rows = await repository.list_context_evidence_requirements(
            tenant_id=tenant, incident_id=incident_id,
        )
        activity = await repository.list_context_enrichment_activity(
            tenant_id=tenant, incident_id=incident_id,
        )
    return {
        "schema_version": "kaiops.context-enrichment.v1",
        "incident_id": incident_id, "tenant_id": tenant,
        "requirements": rows, "count": len(rows), **activity,
    }


@app.get("/incidents/evidence-requests")
async def list_evidence_request_queue(
    tenant_id: str, responder: str | None = None, limit: int = 100,
) -> dict[str, Any]:
    """Cross-incident queue of unanswered human evidence requests, so an
    operator (or the fallback default_responder) can work through the backlog
    without opening every incident individually first."""
    tenant = require_tenant_id(tenant_id, source="human evidence request queue")
    if not settings.database_enabled or getattr(app.state, "session_factory", None) is None:
        raise HTTPException(status_code=503, detail="context enrichment database is unavailable")
    async with app.state.session_factory() as session:
        rows = await ContextEnrichmentRepository(session).list_human_evidence_request_queue(
            tenant_id=tenant, responder=responder, limit=limit,
        )
    return {"schema_version": "kaiops.human-evidence-queue.v1", "requests": rows, "count": len(rows)}


@app.get("/incidents/{incident_id}/operations-state")
async def incident_operations_state(incident_id: str, tenant_id: str) -> dict[str, Any]:
    tenant = require_tenant_id(tenant_id, source="incident operations state")
    if not settings.database_enabled or getattr(app.state, "session_factory", None) is None:
        raise HTTPException(status_code=503, detail={
            "code": "operations_state_unavailable",
            "message": "Incident operations state is temporarily unavailable.",
        })
    try:
        async with app.state.session_factory() as session:
            state = await ContextEnrichmentRepository(session).incident_operations_state(
                tenant_id=tenant, incident_id=incident_id,
            )
    except (TypeError, ValueError):
        state = None
    if state is None:
        raise HTTPException(status_code=404, detail={
            "code": "incident_not_found", "message": "The incident was not found.",
        })
    return {
        **state,
        "release": {
            "release_sha": os.getenv("KAIMS_RELEASE_SHA", "dev"),
            "schema_version": "20260923_schema_migration_checksums",
            "contract_version": "kaiops.incident-operations.v1",
            "build_time": os.getenv("KAIMS_BUILD_TIME", "unknown"),
        },
    }


class ContextEnrichmentReconcileRequest(BaseModel):
    tenant_id: str = Field(min_length=1, max_length=128)
    limit: int = Field(default=100, ge=1, le=500)
    dry_run: bool = True


class CollectionPriorityRequest(BaseModel):
    tenant_id: str = Field(min_length=1, max_length=128)
    actor_id: str = Field(min_length=1, max_length=255)
    reason: str = Field(min_length=10, max_length=4000)


@app.post("/internal/incidents/{incident_id}/context-collection/prioritize")
async def prioritize_context_collection(incident_id: str, request: CollectionPriorityRequest,
                                       x_kaiops_internal_token: str = Header(default="")):
    if not settings.service_internal_token or not hmac.compare_digest(x_kaiops_internal_token, settings.service_internal_token):
        raise HTTPException(status_code=403, detail="Service authentication is required")
    async with app.state.session_factory() as session:
        try:
            result = await ContextEnrichmentRepository(session).prioritize_context_collection(
                tenant_id=request.tenant_id, incident_id=incident_id, actor=request.actor_id, reason=request.reason)
            await session.commit()
            return result
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc


class IncidentLifecycleTransitionRequest(BaseModel):
    tenant_id: str = Field(min_length=1, max_length=128)
    target_state: str = Field(min_length=1, max_length=64)
    expected_version: int = Field(ge=1)
    actor: str = Field(min_length=1, max_length=160)
    reason: str = Field(min_length=1, max_length=4000)
    idempotency_key: str = Field(min_length=1, max_length=160)
    failure_code: str | None = Field(default=None, max_length=128)


@app.post("/internal/incidents/{incident_id}/lifecycle/transition")
async def transition_incident_lifecycle(
    incident_id: str,
    payload: IncidentLifecycleTransitionRequest,
    x_kaiops_internal_token: str = Header(default=""),
) -> dict[str, Any]:
    expected = str(settings.service_internal_token or "")
    if not expected or not hmac.compare_digest(x_kaiops_internal_token, expected):
        raise HTTPException(status_code=403, detail={
            "code": "internal_auth_required", "message": "Service authentication is required.",
        })
    try:
        async with app.state.session_factory() as session:
            result = await ContextEnrichmentRepository(session).transition_incident_lifecycle(
                tenant_id=payload.tenant_id, incident_id=incident_id,
                target_state=payload.target_state, expected_version=payload.expected_version,
                actor=payload.actor, reason=payload.reason,
                idempotency_key=payload.idempotency_key, failure_code=payload.failure_code,
            )
            await session.commit()
        return {"schema_version": "kaiops.incident-lifecycle.v1", **result}
    except LookupError as exc:
        raise HTTPException(status_code=404, detail={
            "code": "incident_not_found", "message": "The incident was not found.",
        }) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail={
            "code": "stale_lifecycle_version", "message": "The incident lifecycle changed; reload and retry.",
        }) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail={
            "code": "lifecycle_transition_rejected", "message": str(exc),
        }) from exc


async def _reconcile_context_enrichment_tenant(
    request: ContextEnrichmentReconcileRequest,
) -> dict[str, Any]:
    summary: dict[str, Any] = {
        "incidents_scanned": 0, "gaps_found": 0, "requirements_created": 0,
        "jobs_scheduled": 0, "human_requests_created": 0, "skipped_incidents": 0,
        "document_drafts_created": 0, "errors": [], "dry_run": request.dry_run,
    }
    async with app.state.session_factory() as session:
        repository = ContextEnrichmentRepository(session)
        draft_repository = IncidentRepository(session)
        summary["terminal_collection_cleanup"] = await repository.retire_closed_incident_collection_jobs(
            tenant_id=request.tenant_id, actor="context-enrichment-reconciler", dry_run=request.dry_run,
        )
        if not request.dry_run:
            await session.commit()
        candidates = await repository.active_incident_gap_candidates(
            tenant_id=request.tenant_id, limit=request.limit,
        )
        summary["incidents_scanned"] = len(candidates)
        for candidate in candidates:
            try:
                existing = await repository.list_context_evidence_requirements(
                    tenant_id=request.tenant_id, incident_id=candidate["incident_id"],
                )
                requirements = build_evidence_requirements(
                    tenant_id=request.tenant_id, incident_id=candidate["incident_id"],
                    rca_version=candidate["rca_version"], missing_evidence=candidate["gaps"],
                    now=datetime.now(UTC), previous_requirements=existing,
                    reviewed_sources=candidate.get("reviewed_sources") or {},
                )
                summary["gaps_found"] += len(requirements)
                activity = await repository.list_context_enrichment_activity(
                    tenant_id=request.tenant_id, incident_id=candidate["incident_id"],
                )
                dead_letter_requirement_ids = {
                    str(row["requirement_id"])
                    for row in activity["jobs"]
                    if str(row.get("status") or "").lower() == "dead_letter"
                }
                ledger_coverage = await repository.reconcile_requirement_coverage_from_ledger(
                    tenant_id=request.tenant_id, incident_id=candidate["incident_id"],
                    apply=not request.dry_run,
                )
                existing_keys = {
                    (int(row["rca_version"]), str(row["category"]), str(row["question"]))
                    for row in existing
                }
                missing = [
                    row for row in requirements
                    if (row.rca_version, row.category, row.question) not in existing_keys
                ]
                existing_by_key = {
                    (int(row["rca_version"]), str(row["category"]), str(row["question"])): row
                    for row in existing
                }
                work = [
                    row for row in requirements
                    if str(row.requirement_id) not in ledger_coverage
                    if str((existing_by_key.get((row.rca_version, row.category, row.question)) or {}).get("status") or "identified").lower()
                    not in {"collected", "answered", "satisfied", "scheduled", "collecting"}
                ]
                settled_prior_keys = {
                    (str(row["category"]), str(row["question"]).strip().casefold())
                    for row in existing
                    if int(row.get("rca_version") or 0) < int(candidate["rca_version"])
                    and str(row.get("status") or "").lower() in {
                        "collected", "answered", "satisfied", "blocked", "human_requested", "assignment_blocked",
                    }
                }
                settled_prior_categories = {
                    str(row["category"])
                    for row in existing
                    if int(row.get("rca_version") or 0) < int(candidate["rca_version"])
                    and str(row.get("status") or "").lower() in {
                        "collected", "answered", "satisfied", "blocked", "human_requested", "assignment_blocked",
                    }
                }
                if int(candidate["rca_version"]) > 1 and (settled_prior_keys or settled_prior_categories):
                    requirements = [
                        row for row in requirements
                        if (row.category, row.question.strip().casefold()) not in settled_prior_keys
                        and row.category not in settled_prior_categories
                    ]
                    missing = [
                        row for row in missing
                        if (row.category, row.question.strip().casefold()) not in settled_prior_keys
                        and row.category not in settled_prior_categories
                    ]
                    work = [
                        row for row in work
                        if (row.category, row.question.strip().casefold()) not in settled_prior_keys
                        and row.category not in settled_prior_categories
                    ]
                summary["requirements_created"] += len(missing)
                context_payload = candidate["context"] if isinstance(candidate["context"], dict) else {}
                alert_payload = context_payload.get("alert") if isinstance(context_payload.get("alert"), dict) else {}
                incident_payload = candidate["incident"] if isinstance(candidate["incident"], dict) else {}
                alert = Alert.model_validate(alert_payload)
                # Refresh onboarding sources: a historical snapshot must not keep
                # a newly connected, tenant-scoped source invisible forever.
                source_metadata = dict(alert.metadata)
                source_candidates = [source_metadata.get(key) for key in
                    ("project_id", "project", "application_id", "application", "application_name")]
                resolved = await draft_repository.resolve_context_integrations(
                    tenant_id=request.tenant_id,
                    project_candidates=[str(value) for value in [*source_candidates, alert.service] if value],
                )
                alert.metadata = {**source_metadata, "resolved_context_connectors": resolved}
                incident = _incident_from_workflow_payload({
                    **incident_payload, "id": candidate["incident_id"],
                    "tenant_id": request.tenant_id, "alert_ids": [candidate["alert_id"]],
                })
                authorized = authorized_enrichment_connectors(
                    alert_metadata=alert.metadata,
                    context_payload=context_payload,
                )
                attempted_by_requirement: dict[str, set[str]] = {}
                for activity_job in activity["jobs"]:
                    attempted_by_requirement.setdefault(str(activity_job["requirement_id"]), set()).add(
                        str(activity_job.get("connector_id") or "").strip().lower()
                    )
                dead_requirements = [
                    requirement for requirement in requirements
                    if str(requirement.requirement_id) not in ledger_coverage
                    and str(requirement.requirement_id) in dead_letter_requirement_ids
                ]
                planned: list[tuple[EvidenceRequirement, str | None]] = [
                    (requirement, unattempted_requirement_connector(requirement, authorized, activity["jobs"]))
                    for requirement in work
                    if str(requirement.requirement_id) not in dead_letter_requirement_ids
                    and requirement_reconciliation_needed(
                        requirement, authorized, activity["jobs"],
                        str((existing_by_key.get((requirement.rca_version, requirement.category, requirement.question)) or {}).get("status")),
                    )
                ]
                recovered_plans = [
                    (
                        requirement,
                        unattempted_requirement_connector(requirement, authorized, activity["jobs"]),
                    )
                    for requirement in dead_requirements
                ]
                planned.extend((requirement, connector) for requirement, connector in recovered_plans if connector)
                recoverable_ids = {
                    str(requirement.requirement_id)
                    for requirement, connector in recovered_plans
                    if connector
                }
                active_job_requirement_ids = {
                    str(job["requirement_id"]) for job in activity["jobs"]
                    if job.get("status") in {"scheduled", "collecting", "retry", "collected"}
                }
                dead_letter_fallbacks = [
                    row for row in existing
                    if int(row["rca_version"]) == int(candidate["rca_version"])
                    and str(row["requirement_id"]) in dead_letter_requirement_ids
                    and str(row["requirement_id"]) not in recoverable_ids
                    and str(row["requirement_id"]) not in active_job_requirement_ids
                    and str(row.get("status")) not in {"human_requested", "assignment_blocked", "collected", "satisfied", "answered", "blocked", "cancelled"}
                ]
                summary["jobs_scheduled"] += sum(1 for _, connector in planned if connector)
                summary["human_requests_created"] += (
                    sum(1 for _, connector in planned if not connector)
                    + len(dead_letter_fallbacks)
                )
                if not request.dry_run and (planned or dead_letter_fallbacks):
                    await repository.upsert_context_evidence_requirements(requirements)
                    now = datetime.now(UTC).replace(microsecond=0)
                    alert_start = alert.starts_at.astimezone(UTC).replace(microsecond=0)
                    alert_end = (
                        alert.ends_at.astimezone(UTC).replace(microsecond=0)
                        if alert.ends_at is not None
                        else alert_start + timedelta(minutes=15)
                    )
                    window_start = alert_start - timedelta(minutes=15)
                    window_end = min(now, max(alert_start, alert_end) + timedelta(minutes=15))
                    for requirement, connector in planned:
                        if connector:
                            await repository.schedule_context_enrichment_job(
                                tenant_id=request.tenant_id, incident_id=incident.id,
                                requirement_id=requirement.requirement_id, connector_id=connector,
                                query_payload={
                                    "schema_version": "kaiops.context-enrichment-query.v1",
                                    "category": requirement.category, "question": requirement.question,
                                    "alert": alert.model_dump(mode="json"),
                                    "incident": incident.model_dump(mode="json"),
                                    "decision": {"reconciled": True},
                                    "authorized_connectors": sorted(authorized),
                                    "attempted_connectors": sorted(attempted_by_requirement.get(str(requirement.requirement_id), set())),
                                },
                                observation_start=window_start,
                                observation_end=window_end,
                            )
                        else:
                            assignment = await repository.resolve_human_evidence_responder(
                                tenant_id=request.tenant_id, incident_id=incident.id,
                            )
                            await repository.create_human_evidence_request(
                                automatic_fallback=True,
                                tenant_id=request.tenant_id, incident_id=incident.id,
                                requirement_id=requirement.requirement_id,
                                expected_responder=assignment["identity"] if assignment else None,
                                assignment_source=assignment["source"] if assignment else None,
                                assignment_failure_reason=None if assignment else "NO_AUTHORIZED_RESPONDER",
                                due_at=datetime.now(UTC) + timedelta(hours=1),
                                acceptable_format="A source reference and a concise factual observation.",
                                evidence_already_checked=requirement.candidate_connectors,
                                hypothesis_impact=requirement.reason,
                                investigation_can_continue=True,
                            )
                            if assignment is None:
                                event_id = f"hitl-assignment-blocked:{requirement.requirement_id}"
                                await repository.enqueue_resolution_event(
                                    event_id=event_id, tenant_id=request.tenant_id,
                                    aggregate_id=str(incident.id), topic="human-evidence-assignment-events",
                                    partition_key=str(incident.id), available_after_seconds=0,
                                    payload={
                                        "schema_version": "kaiops.hitl-assignment.v1",
                                        "event_id": event_id, "tenant_id": request.tenant_id,
                                        "incident_id": str(incident.id),
                                        "requirement_id": str(requirement.requirement_id),
                                        "status": "ASSIGNMENT_BLOCKED",
                                        "reason": "NO_AUTHORIZED_RESPONDER",
                                    },
                                )
                    for row in dead_letter_fallbacks:
                        assignment = await repository.resolve_human_evidence_responder(
                            tenant_id=request.tenant_id, incident_id=incident.id,
                        )
                        await repository.create_human_evidence_request(
                                automatic_fallback=True,
                            tenant_id=request.tenant_id, incident_id=incident.id,
                            requirement_id=row["requirement_id"],
                            expected_responder=assignment["identity"] if assignment else None,
                            assignment_source=assignment["source"] if assignment else None,
                            assignment_failure_reason=None if assignment else "NO_AUTHORIZED_RESPONDER",
                            due_at=datetime.now(UTC) + timedelta(hours=1),
                            acceptable_format="A source reference and a concise factual observation.",
                            evidence_already_checked=list(row.get("candidate_connectors") or []),
                            hypothesis_impact=str(row.get("reason") or "Required evidence was unavailable."),
                            investigation_can_continue=True,
                        )
                if not request.dry_run:
                    summary["document_drafts_created"] += await _create_crawled_evidence_drafts(
                        draft_repository, tenant_id=request.tenant_id, candidate=candidate,
                        alert=alert, incident=incident,
                    )
            except Exception as exc:
                summary["errors"].append({"incident_id": candidate["incident_id"], "error": str(exc)[:500]})
        if request.dry_run:
            await session.rollback()
        else:
            session.add(AuditLogRecord(
                tenant_id=request.tenant_id, actor="context-enrichment-reconciler",
                action="context.enrichment.reconciled", resource_type="tenant",
                resource_id=request.tenant_id, payload=summary,
            ))
            await session.commit()
    return summary


@app.post("/internal/context-enrichment/reconcile")
async def reconcile_context_enrichment(
    request: ContextEnrichmentReconcileRequest,
    x_kaiops_internal_token: str = Header(default=""),
) -> dict[str, Any]:
    expected = str(settings.service_internal_token or "")
    if not expected or not hmac.compare_digest(x_kaiops_internal_token, expected):
        raise HTTPException(status_code=403, detail="service authentication is required")
    return await _reconcile_context_enrichment_tenant(request)


@app.post("/incidents/{incident_id}/context-gaps/{requirement_id}/responses")
async def respond_to_context_gap(
    incident_id: str,
    requirement_id: str,
    request: HumanEvidenceResponse,
    tenant_id: str,
) -> dict[str, Any]:
    tenant = require_tenant_id(tenant_id, source="context gap response")
    if not settings.database_enabled or getattr(app.state, "session_factory", None) is None:
        raise HTTPException(status_code=503, detail="context enrichment database is unavailable")
    async with app.state.session_factory() as session:
        try:
            result = await ContextEnrichmentRepository(session).record_human_evidence_response(
                tenant_id=tenant, incident_id=incident_id, requirement_id=requirement_id,
                response=request.model_dump(mode="json", exclude_unset=True),
            )
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail={
                "code": "responder_not_authorized", "message": str(exc),
            }) from exc
        except ValueError as exc:
            raise HTTPException(status_code=409, detail={
                "code": "human_evidence_rejected", "message": str(exc),
            }) from exc
        await session.commit()
    gov_doc = result.get("governed_document")
    if isinstance(gov_doc, dict) and gov_doc.get("document_id"):
        try:
            await _index_governed_document(app, {
                "tenant_id": tenant,
                "document_id": gov_doc["document_id"],
                "content_checksum": gov_doc["content_checksum"],
            })
            result["indexing_status"] = "indexed"
            result["runbook_status"] = "indexed"
            result["learning_complete"] = bool(result.get("reusable", True))
        except Exception as exc:
            logger.exception("immediate governed RAG indexing failed after human evidence response; retry loop will recover")
            result["indexing_status"] = "failed"
            result["indexing_error"] = str(exc)
            result["learning_complete"] = False
    else:
        result["indexing_status"] = "pending_approval" if result.get("knowledge_draft_id") else "not_applicable"
        result["learning_complete"] = False
    return result


@app.get("/rag/knowledge-drafts")
async def list_knowledge_rag_drafts(tenant_scope: str, status: str | None = None) -> dict[str, Any]:
    tenant = require_tenant_id(tenant_scope, source="knowledge draft inventory")
    async with app.state.session_factory() as session:
        drafts = await IncidentRepository(session).list_knowledge_rag_drafts(
            tenant_id=tenant, status=status,
        )
    return {"drafts": drafts, "count": len(drafts)}


@app.post("/rag/knowledge-drafts")
async def create_knowledge_rag_draft(request: KnowledgeRagDraftCreateRequest) -> dict[str, Any]:
    tenant = require_tenant_id(request.tenant_scope, source="knowledge draft creation")
    async with app.state.session_factory() as session:
        try:
            draft = await IncidentRepository(session).create_knowledge_rag_draft(
                tenant_id=tenant, created_by=request.created_by, document_kind=request.kind,
                source_ref=request.source_ref, title=request.title, content=request.content,
                metadata=request.metadata,
            )
            await session.commit()
        except RuntimeError as exc:
            await session.rollback()
            raise HTTPException(status_code=409, detail=str(exc)) from exc
    return {"status": draft["status"], "draft": draft}


@app.put("/rag/knowledge-drafts/{draft_id}")
async def review_knowledge_rag_draft(
    draft_id: str,
    request: KnowledgeRagDraftReviewRequest,
    x_operational_role: str | None = Header(default=None, alias="X-Operational-Role"),
    x_actor_id: str | None = Header(default=None, alias="X-Actor-Id"),
) -> dict[str, Any]:
    tenant = require_tenant_id(request.tenant_scope, source="knowledge draft review")
    if isinstance(x_operational_role, str) and x_operational_role.strip():
        if x_operational_role.strip().lower() not in {"admin", "hitl_approver", "operator"}:
            raise HTTPException(status_code=403, detail="knowledge draft review requires OPERATOR, HITL_APPROVER, or ADMIN role")
    if isinstance(x_actor_id, str) and x_actor_id.strip():
        if x_actor_id.strip().casefold() != request.reviewed_by.strip().casefold():
            raise HTTPException(status_code=403, detail="authenticated actor does not match reviewed_by")
    async with app.state.session_factory() as session:
        draft = await IncidentRepository(session).review_knowledge_rag_draft(
            tenant_id=tenant, draft_id=draft_id,
            expected_row_version=request.expected_row_version, title=request.title,
            content=request.content, review_notes=request.review_notes,
            reviewed_by=request.reviewed_by,
        )
        if draft is None:
            raise HTTPException(status_code=409, detail="knowledge draft is stale or unavailable")
        await session.commit()
    return {"status": "reviewed", "draft": draft}


@app.post("/rag/knowledge-drafts/{draft_id}/approve")
async def approve_knowledge_rag_draft(
    draft_id: str,
    request: KnowledgeRagDraftApproveRequest,
    x_operational_role: str | None = Header(default=None, alias="X-Operational-Role"),
    x_actor_id: str | None = Header(default=None, alias="X-Actor-Id"),
) -> dict[str, Any]:
    tenant = require_tenant_id(request.tenant_scope, source="knowledge draft approval")
    if isinstance(x_operational_role, str) and x_operational_role.strip():
        if x_operational_role.strip().lower() not in {"admin", "hitl_approver"}:
            raise HTTPException(status_code=403, detail="knowledge draft approval requires HITL_APPROVER or ADMIN role")
    if isinstance(x_actor_id, str) and x_actor_id.strip():
        if x_actor_id.strip().casefold() != request.approved_by.strip().casefold():
            raise HTTPException(status_code=403, detail="authenticated actor does not match approved_by")
    async with app.state.session_factory() as session:
        try:
            approved = await IncidentRepository(session).approve_knowledge_rag_draft(
                tenant_id=tenant, draft_id=draft_id,
                expected_row_version=request.expected_row_version,
                approved_by=request.approved_by,
            )
            if approved is None:
                raise HTTPException(status_code=404, detail="knowledge draft not found")
            await session.commit()
        except RuntimeError as exc:
            await session.rollback()
            raise HTTPException(status_code=409, detail=str(exc)) from exc
    draft, document = approved
    indexed = False
    index_error: str | None = None
    try:
        await _index_governed_document(app, {
            "tenant_id": tenant,
            "document_id": document["document_id"],
            "content_checksum": document["content_checksum"],
        })
        indexed = True
    except Exception as exc:
        index_error = str(exc)
        logger.exception("immediate governed RAG indexing failed; retry loop will recover")
    return {
        "status": "approved_pending_index",
        "indexing_status": "indexed" if indexed else "failed",
        "learning_complete": indexed,
        "indexing_error": index_error,
        "draft": draft,
        "document": document,
    }


def _list_evidence_rag_drafts_sync(
    alert_id: str | None, status: str | None, tenant_scope: str, document_kind: str | None = None
) -> list[dict[str, Any]]:
    if alert_id:
        return [
            payload
            for payload in _list_evidence_rag_drafts_sync(None, status, tenant_scope, document_kind)
            if str(payload.get("alert_id") or "") == alert_id
        ]

    drafts: list[dict[str, Any]] = []
    for path in sorted(_evidence_draft_dir().glob("*.json"), key=lambda item: item.stat().st_mtime, reverse=True):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if not isinstance(payload, dict):
            continue
        if str(payload.get("tenant_scope") or "") != tenant_scope:
            continue
        if status and str(payload.get("status") or "").lower() != status.lower():
            continue
        if document_kind and str(payload.get("document_kind") or "incident").lower() != document_kind.lower():
            continue
        drafts.append(payload)
    return drafts


@app.get("/rag/evidence-drafts")
async def list_evidence_rag_drafts(
    alert_id: str | None = None,
    status: str | None = None,
    document_kind: str | None = None,
    tenant_scope: str = "",
) -> dict[str, Any]:
    tenant = require_tenant_id(tenant_scope, source="evidence draft listing")
    if not settings.database_enabled or getattr(app.state, "session_factory", None) is None:
        raise HTTPException(status_code=503, detail="durable evidence draft storage is unavailable")
    async with app.state.session_factory() as session:
        try:
            drafts = await IncidentRepository(session).list_evidence_rag_drafts(
                tenant_id=tenant, alert_id=alert_id, status=status, document_kind=document_kind,
            )
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
    return {"count": len(drafts), "drafts": drafts}


@app.post("/rag/evidence-drafts")
async def create_evidence_rag_draft_from_rca(request: EvidenceRagDraftCreateRequest) -> dict[str, Any]:
    """Create the reviewable alert document when the RCA pipeline has no draft."""
    tenant = require_tenant_id(request.tenant_scope, source="evidence draft creation")
    if not settings.database_enabled or getattr(app.state, "session_factory", None) is None:
        raise HTTPException(status_code=503, detail="durable evidence draft storage is unavailable")
    documents = []
    for kind in INCIDENT_DOCUMENT_KINDS:
        documents.append({
            "document_kind": kind,
            "title": f"{kind.replace('_', ' ').title()} draft: {request.alert_type}",
            "content": _typed_incident_document_content(
                kind, alert_name=request.alert_type,
                service=request.services[0] if request.services else "unknown",
                environment=request.environment, base=request.content,
            ),
        })
    binding = {
        "incident_id": request.incident_id, "alert_id": request.alert_id,
        "analysis_request_id": request.analysis_request_id,
        "context_snapshot_id": request.context_snapshot_id,
        "context_fingerprint": request.context_fingerprint,
        "recommendation_id": request.recommendation_id, "rca_version": request.rca_version,
    }
    async with app.state.session_factory() as session:
        try:
            drafts = await IncidentRepository(session).create_evidence_rag_drafts(
                tenant_id=tenant, created_by=request.created_by, binding=binding,
                documents=documents, evidence_ids=request.evidence_ids,
                source_uris=request.source_uris,
            )
            await session.commit()
        except RuntimeError as exc:
            await session.rollback()
            raise HTTPException(status_code=409, detail=str(exc)) from exc
    return {"status": "created", "draft": drafts[0], "drafts": drafts}


@app.put("/rag/evidence-drafts/{draft_id}")
async def review_evidence_rag_draft(
    draft_id: str,
    request: EvidenceRagDraftReviewRequest,
) -> dict[str, Any]:
    tenant = require_tenant_id(request.tenant_scope, source="evidence draft review")
    if not settings.database_enabled or getattr(app.state, "session_factory", None) is None:
        raise HTTPException(status_code=503, detail="durable evidence draft storage is unavailable")
    async with app.state.session_factory() as session:
        draft = await IncidentRepository(session).review_evidence_rag_draft(
            tenant_id=tenant, draft_id=draft_id,
            expected_row_version=request.expected_row_version, title=request.title.strip(),
            content=request.content.strip(), review_notes=str(request.review_notes or "").strip() or None,
            reviewed_by=request.reviewed_by.strip(),
        )
        if draft is None:
            exists_for_tenant = await IncidentRepository(session).list_evidence_rag_drafts(tenant_id=tenant)
            if not any(item["draft_id"] == draft_id for item in exists_for_tenant):
                raise HTTPException(status_code=404, detail="evidence RAG draft not found")
            raise HTTPException(status_code=409, detail={
                "code": "stale_evidence_draft",
                "message": "The evidence draft was changed by another reviewer.",
            })
        await session.commit()
    return {"status": "reviewed", "draft": draft}


@app.post("/rag/evidence-drafts/{draft_id}/approve")
async def approve_evidence_rag_draft(
    draft_id: str,
    request: EvidenceRagDraftApproveRequest,
) -> dict[str, Any]:
    tenant = require_tenant_id(request.tenant_scope, source="evidence approval")
    if not settings.database_enabled or getattr(app.state, "session_factory", None) is None:
        raise HTTPException(status_code=503, detail="durable evidence draft storage is unavailable")
    async with app.state.session_factory() as session:
        try:
            approved = await IncidentRepository(session).approve_evidence_rag_draft(
                tenant_id=tenant, draft_id=draft_id,
                expected_row_version=request.expected_row_version,
                approved_by=request.approved_by.strip(), owner_team=request.owner_team,
            )
            if approved is None:
                raise HTTPException(status_code=404, detail="evidence RAG draft not found")
            await session.commit()
        except RuntimeError as exc:
            await session.rollback()
            raise HTTPException(status_code=409, detail=str(exc)) from exc
    draft, document = approved
    indexed = False
    index_error: str | None = None
    try:
        await _index_governed_document(app, {
            "tenant_id": tenant,
            "document_id": document["document_id"],
            "content_checksum": document["content_checksum"],
        })
        indexed = True
    except Exception as exc:
        index_error = str(exc)
        logger.exception("immediate governed RAG indexing failed; retry loop will recover")
    return {
        "status": "approved_pending_index",
        "indexing_status": "indexed" if indexed else "failed",
        "learning_complete": indexed,
        "indexing_error": index_error,
        "draft": draft,
        "document": document,
    }


@app.post("/rag/evidence-drafts/{draft_id}/revision")
async def revise_evidence_rag_draft(
    draft_id: str, request: EvidenceRagDraftRevisionRequest,
) -> dict[str, Any]:
    tenant = require_tenant_id(request.tenant_scope, source="evidence revision")
    if not settings.database_enabled or getattr(app.state, "session_factory", None) is None:
        raise HTTPException(status_code=503, detail="durable evidence draft storage is unavailable")
    async with app.state.session_factory() as session:
        try:
            draft = await IncidentRepository(session).revise_evidence_rag_draft(
                tenant_id=tenant, draft_id=draft_id, created_by=request.created_by.strip(),
            )
            if draft is None:
                raise HTTPException(status_code=404, detail="evidence RAG draft not found")
            await session.commit()
        except RuntimeError as exc:
            await session.rollback()
            raise HTTPException(status_code=409, detail=str(exc)) from exc
    return {"status": "draft", "draft": draft}


@app.post("/rag/governed-documents/{document_id}/retry-index")
async def retry_governed_rag_index(
    document_id: str, request: GovernedRagIndexRetryRequest,
) -> dict[str, Any]:
    tenant = require_tenant_id(request.tenant_scope, source="governed RAG index retry")
    async with app.state.session_factory() as session:
        repo = IncidentRepository(session)
        retry = await repo.retry_failed_governed_rag_document(
            tenant_id=tenant, document_id=document_id,
        )
        if retry is None:
            raise HTTPException(status_code=404, detail="failed governed document was not found")
        await session.commit()
    indexed = False
    index_error: str | None = None
    try:
        await _index_governed_document(app, {
            "tenant_id": tenant,
            "document_id": document_id,
            "content_checksum": retry["content_checksum"],
        })
        indexed = True
    except Exception as exc:
        index_error = str(exc)
        logger.exception("manual governed RAG index retry failed; retry loop will recover")
    return {
        "status": "retry_requested",
        "document_id": document_id,
        "indexing_status": "indexed" if indexed else "failed",
        "indexing_error": index_error,
    }


@app.post("/knowledge-pack/draft")
async def draft_knowledge_pack(request: KnowledgePackRequest) -> dict[str, Any]:
    pack = build_knowledge_pack(request)
    return {"status": "drafted", "knowledge_pack": pack}


@app.post("/knowledge-pack/validate")
async def validate_knowledge_pack(request: KnowledgePackRequest) -> dict[str, Any]:
    pack = build_knowledge_pack(request)
    return {
        "status": pack.get("status", "needs_review"),
        "knowledge_pack": pack,
        "validation": pack.get("validation", {}),
        "next_questions": pack.get("next_questions", []),
    }


@app.post("/knowledge-pack/approve")
async def approve_knowledge_pack(request: KnowledgePackApproveRequest) -> dict[str, Any]:
    pack = build_knowledge_pack(request)
    facts = pack.get("facts") if isinstance(pack.get("facts"), dict) else {}
    for key, value in request.accepted_facts.items():
        fact = facts.get(key) if isinstance(facts.get(key), dict) else None
        if fact is None:
            facts[key] = _fact(value, 0.9, ["manual-review"], status="accepted")
            continue
        fact["value"] = value
        fact["status"] = "accepted"
        fact["confidence"] = max(float(fact.get("confidence") or 0.0), 0.9)
        sources = fact.get("sources") if isinstance(fact.get("sources"), list) else []
        fact["sources"] = _unique_tokens([*sources, "manual-review"], limit=8)
    pack["facts"] = facts
    # accepted_facts overrides above change confidence/status per field, so
    # validation stats (esp. overall_confidence) must be recomputed here —
    # otherwise the persisted knowledge_pack_confidence reflects the stale
    # pre-override extraction average instead of what was actually approved.
    pack["validation"] = _compute_knowledge_pack_validation(facts)
    pack["status"] = "reviewed_pending_governance"
    rag_request = _knowledge_pack_to_rag_request(
        pack,
        request.approved_by,
        require_tenant_id(request.tenant_id, source="knowledge pack approval"),
    )
    runbook_id = str(uuid5(NAMESPACE_URL, rag_request.content))
    checksum = f"sha256:{hashlib.sha256(rag_request.content.encode('utf-8')).hexdigest()}"
    governance = {"runbook_id": runbook_id, "version": 1, "status": "draft"}
    draft: dict[str, Any] | None = None
    if settings.database_enabled and getattr(app.state, "session_factory", None) is not None:
        async with app.state.session_factory() as session:
            tenant = require_tenant_id(request.tenant_id, source="knowledge pack approval")
            draft = await IncidentRepository(session).create_knowledge_rag_draft(
                tenant_id=tenant, created_by=request.approved_by, document_kind=rag_request.kind,
                source_ref=rag_request.source_ref or f"knowledge-pack://{runbook_id}",
                title=rag_request.title, content=rag_request.content,
                metadata={
                    "knowledge_pack": pack, "checksum_sha256": checksum,
                    "approval_expires_at": request.approval_expires_at.isoformat(),
                },
            )
            await session.commit()
    return {
        "status": "pending_review", "knowledge_pack": pack,
        "knowledge_draft": draft, "runbook_governance": governance,
    }


_RAG_DOCUMENT_INTERNAL_FIELDS = {"_embedding", "_metadata_embedding", "_synthetic"}


def _public_rag_document(doc: dict[str, Any], connector: VectorDBConnector) -> dict[str, Any]:
    public = {key: value for key, value in doc.items() if key not in _RAG_DOCUMENT_INTERNAL_FIELDS}
    full_doc = connector._load_full_document(str(doc.get("path", "")))
    embedding_status = "embedded" if isinstance(doc.get("_metadata_embedding"), list) else "pending"
    if full_doc and not isinstance(full_doc.get("_embedding"), list):
        embedding_status = "metadata-only"
    public.setdefault("owner", str(public.get("resolved_by") or public.get("source_system") or "unassigned"))
    public.setdefault("version", str(public.get("version") or "v1"))
    public.setdefault("freshness_score", 1.0 if public.get("closed_at") or public.get("source_ref") else 0.75)
    public["embedding_status"] = embedding_status
    public["embedding_model"] = connector.embedding_info()
    public["vector_store"] = connector.vector_store_info()
    return public


@app.get("/rag/documents")
def list_rag_documents(tenant_scope: str) -> dict[str, Any]:
    """Build the potentially large catalog on FastAPI's worker pool.

    Connector metadata and document projection are synchronous and can take
    seconds for a large RAG corpus. A synchronous route keeps that work off
    the event loop so health checks and incident consumers stay responsive.
    """
    connector = vector_connector()
    tenant = require_tenant_id(tenant_scope, source="RAG inventory")
    documents = [
        doc for doc in connector.documents
        if not doc.get("_synthetic") and retrieval_allowed(doc, tenant)
    ]
    return {
        "document_count": len(documents),
        "index": connector.index_info(),
        "documents": [_public_rag_document(doc, connector) for doc in documents],
    }


@app.get("/rag/documents/content")
async def get_rag_document_content(path: str, tenant_scope: str) -> dict[str, Any]:
    connector = vector_connector()
    tenant = require_tenant_id(tenant_scope, source="RAG content lookup")
    known_paths = {str(doc.get("path", "")) for doc in connector.documents}
    if path not in known_paths:
        raise HTTPException(status_code=404, detail="document not found")
    full_doc = connector._load_full_document(path)
    if not full_doc or not retrieval_allowed(full_doc, tenant):
        raise HTTPException(status_code=404, detail="document not found")
    return {key: value for key, value in full_doc.items() if key not in _RAG_DOCUMENT_INTERNAL_FIELDS}


@app.post("/rag/reload")
async def reload_rag() -> dict[str, Any]:
    connector = vector_connector()
    count = await asyncio.to_thread(connector.reload)
    rebuild_flow_catalog_from_rag(connector)
    return {"status": "reloaded", "document_count": count, "index": connector.index_info()}


@app.get("/rag/index")
async def get_rag_index() -> dict[str, Any]:
    connector = vector_connector()
    return connector.index_info()


@app.get("/knowledge-graph")
async def get_knowledge_graph() -> dict[str, Any]:
    graph = knowledge_graph()
    return {"status": "ready", "summary": graph.summary(), "nodes": list(graph.nodes.values()), "edges": graph.edges}


@app.get("/knowledge-graph/context")
async def get_knowledge_graph_context(service: str, depth: int = 2, limit: int = 80) -> dict[str, Any]:
    return knowledge_graph().context(service, depth=max(0, min(depth, 4)), limit=max(1, min(limit, 250)))


@app.post("/rag/index/sync")
async def sync_rag_index() -> dict[str, Any]:
    connector = vector_connector()
    result = connector.sync_remote_index()
    return {"status": "synced" if result.get("indexed", 0) else "skipped", "result": result, "index": connector.index_info()}


@app.get("/rag/search")
async def search_rag(
    query: str,
    tenant_id: str,
    limit: int = 8,
    kind: str | None = None,
    service: str | None = None,
) -> dict[str, Any]:
    tenant_id = require_tenant_id(tenant_id, source="RAG search identity")
    matches = vector_connector().search(
        query,
        limit=max(1, min(limit, 20)),
        preferred_kind=kind,
        service=service,
        tenant_id=tenant_id,
    )
    return {
        "query": query,
        "index": vector_connector().index_info(),
        "matches": [
            {
                "kind": match.get("kind"),
                "title": match.get("title"),
                "services": match.get("services", []),
                "deployment": match.get("deployment"),
                "path": match.get("path"),
                "tenant_scope": match.get("tenant_scope"),
                "source_system": match.get("source_system"),
                "source_ref": match.get("source_ref"),
                "content_version": match.get("content_version"),
                "review_status": match.get("review_status"),
                "score": match.get("_similarity", 0.0),
                "semantic_score": match.get("_semantic_score", 0.0),
                "metadata_match_score": match.get("_metadata_match_score", 0.0),
                "context_relevant": vector_connector().context_match_relevant(match, service or "") if service else None,
                "embedding_model": vector_connector().embedding_info(),
                "vector_store": vector_connector().vector_store_info(),
                "preview": str(match.get("content", ""))[:300],
            }
            for match in matches
        ],
    }


@app.get("/rag/flow-catalog")
async def flow_catalog() -> dict[str, Any]:
    connector = vector_connector()
    entries = read_flow_catalog(connector)
    return {
        "count": len(entries),
        "entries": entries,
        "path": str(connector.root_path() / "flows.json"),
    }
