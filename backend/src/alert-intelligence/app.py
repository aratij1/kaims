from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import re
from collections.abc import Awaitable, Callable, Coroutine
from datetime import UTC
from typing import Any

from alert_intelligence import AlertIntelligenceAgent
from common.config import get_settings
from common.ai_layer_client import AiLayerClient
from common.event_publishers import build_event_envelope
from common.kafka import KafkaConsumer, consume_forever as consume_kafka_forever
from common.models import Alert, Incident
from common.rabbitmq import RabbitMQConsumer, consume_forever as consume_rabbitmq_forever
from common.repository import IncidentRepository
from common.servicebus import AzureServiceBusConsumer, consume_forever as consume_service_bus_forever
from common.repository_interfaces import SqlAlertHistoryRepository
from common.service import create_app
from common.telemetry import EVENTS_PROCESSED
from common.topics import ENRICHED_ALERTS, JIRA_INVESTIGATIONS, RAW_ALERTS
from fastapi import FastAPI
import httpx
from pydantic import BaseModel, Field

settings = get_settings()
settings.service_name = "alert-intelligence"
agent = AlertIntelligenceAgent()
tasks: list[asyncio.Task] = []
ai_client = AiLayerClient(settings)
DISCOVERY_LLM_ENABLED = str(os.getenv("DISCOVERY_LLM_ENABLED", "true")).strip().lower() in {"1", "true", "yes", "on"}
DISCOVERY_MIN_CONFIDENCE = max(0.0, min(1.0, float(os.getenv("DISCOVERY_MIN_CONFIDENCE", "0.65") or 0.65)))
DISCOVERY_WARNING_MIN_CONFIDENCE = max(
    DISCOVERY_MIN_CONFIDENCE,
    min(1.0, float(os.getenv("DISCOVERY_WARNING_MIN_CONFIDENCE", "0.80") or 0.80)),
)
MESSAGE_BUS_DUAL_CONSUME_ENABLED = str(
    os.getenv("MESSAGE_BUS_DUAL_CONSUME_ENABLED", "false")
).strip().lower() in {"1", "true", "yes", "on"}
logger = logging.getLogger("alert-intelligence")

ConsumeRunner = Callable[[Any, Callable[[dict], Awaitable[None]]], Coroutine[Any, Any, None]]


def _json_object(value: str) -> dict[str, Any]:
    text = str(value or "").strip()
    fenced = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", text, re.IGNORECASE)
    candidate = fenced.group(1).strip() if fenced else text
    start = candidate.find("{")
    end = candidate.rfind("}")
    if start >= 0 and end > start:
        candidate = candidate[start : end + 1] if start >= 0 and end > start else candidate
    try:
        parsed = json.loads(candidate)
        return parsed if isinstance(parsed, dict) else {}
    except ValueError:
        return {}


async def _llm_discovery(alert: Alert) -> dict[str, Any]:
    if not DISCOVERY_LLM_ENABLED:
        return {}
    prompt = (
        "Act as an SRE discovery agent. Return one strict JSON object only. Required keys: "
        "title, description, service, environment, "
        "category, initial_hypothesis, technical_impact, business_impact, affected_users, scope, urgency, "
        "actionable, actionability_reason, recommended_severity, confidence, reasoning, evidence_used, "
        "missing_evidence, alternative_hypotheses, impact_basis. Set actionable=true only when "
        "operator intervention or investigation is required; routine cleanup, retry noise, test signals, and KaiOps' "
        "own integration errors are not actionable. confidence must be 0..1. Treat the supplied alert as an observation, "
        "not proof of root cause or customer impact. evidence_used must contain only identifiers or fields present in the "
        "payload. Separate observed impact from possible risk, list unknowns in missing_evidence, and never invent evidence."
    )
    try:
        response = await ai_client.route_model(
            severity=alert.severity,
            task="general",
            prompt=prompt,
            payload={"alert": alert.model_dump(mode="json")},
        )
        parsed = _json_object(str(response.get("content") or ""))
        if parsed:
            usage = response.get("usage") if isinstance(response.get("usage"), dict) else {}
            parsed["model_provider"] = str(usage.get("provider") or "model-router")
            parsed["model_name"] = str(response.get("model") or usage.get("model") or "unknown")
            try:
                confidence = float(parsed.get("confidence"))
                if 1.0 < confidence <= 100.0:
                    parsed["confidence"] = confidence / 100.0
            except (TypeError, ValueError):
                pass
            logger.info(
                "incident_pipeline stage=llm_discovery outcome=parsed provider=%s model=%s",
                parsed["model_provider"],
                parsed["model_name"],
            )
        else:
            usage = response.get("usage") if isinstance(response.get("usage"), dict) else {}
            logger.warning(
                "incident_pipeline stage=llm_discovery outcome=fallback provider=%s model=%s reason=non-json-response",
                usage.get("provider"),
                response.get("model") or usage.get("model"),
            )
        return parsed
    except Exception:
        return {}


def _qualify_candidate_for_jira(candidate: dict[str, Any]) -> tuple[bool, str]:
    if not bool(candidate.get("actionable")):
        return False, str(candidate.get("actionability_reason") or "Discovery classified signal as non-actionable")
    confidence = float(candidate.get("confidence") or 0.0)
    severity = str(candidate.get("final_severity") or candidate.get("recommended_severity") or "").lower()
    threshold = DISCOVERY_WARNING_MIN_CONFIDENCE if severity == "warning" else DISCOVERY_MIN_CONFIDENCE
    evidence_rows = candidate.get("evidence") if isinstance(candidate.get("evidence"), list) else []
    occurrence_count = 1
    for row in evidence_rows:
        attributes = row.get("attributes") if isinstance(row, dict) and isinstance(row.get("attributes"), dict) else {}
        try:
            occurrence_count = max(occurrence_count, int(str(attributes.get("occurrence_count") or "1")))
        except ValueError:
            continue
    if severity == "critical" and evidence_rows:
        threshold = min(threshold, 0.45)
    elif severity == "high" and occurrence_count >= 3:
        threshold = min(threshold, 0.60)
    if severity not in {"warning", "high", "critical"}:
        return False, f"final severity {severity or 'unknown'} is below Jira threshold"
    if confidence < threshold:
        return False, f"confidence {confidence:.2f} is below {threshold:.2f}"
    if not evidence_rows:
        return False, "candidate has no evidence references"
    return True, "qualified by actionability, severity, confidence, and evidence policy"


async def _sync_candidate_to_jira(incident: Any) -> str | None:
    candidate = incident.metadata.get("incident_candidate") if isinstance(incident.metadata, dict) else {}
    if not isinstance(candidate, dict):
        return None
    qualified, qualification_reason = _qualify_candidate_for_jira(candidate)
    incident.metadata["jira_qualification"] = {
        "qualified": True,
        "discovery_qualified": qualified,
        "reason": "mandatory ticket after alert deduplication",
        "discovery_reason": qualification_reason,
        "policy_version": "jira-for-every-deduplicated-alert-v1",
    }
    jira_key = str(getattr(incident, "ticket_id", "") or candidate.get("jira_key") or "")
    base_url = str(os.getenv("JIRA_API_BASE_URL", "") or "").rstrip("/")
    email = str(os.getenv("JIRA_API_EMAIL", "") or "")
    token = str(os.getenv("JIRA_API_TOKEN", "") or "")
    project_key = str(os.getenv("JIRA_PROJECT_KEY", "") or "")
    if not (base_url and email and token and project_key):
        return None
    idempotency_key = str(candidate.get("idempotency_key") or "")
    fingerprint_label = f"kaiops-candidate-{idempotency_key[:32]}"
    async with httpx.AsyncClient(auth=(email, token), timeout=15.0) as client:
        if not jira_key:
            jql = (
                f'project = "{project_key}" AND labels = "{fingerprint_label}" '
                "AND statusCategory != Done ORDER BY updated DESC"
            )
            search = await client.get(
                f"{base_url}/rest/api/3/search/jql",
                params={"jql": jql, "fields": "key,status", "maxResults": 1},
            )
            search.raise_for_status()
            issues = search.json().get("issues", []) if isinstance(search.json(), dict) else []
            if issues and isinstance(issues[0], dict):
                jira_key = str(issues[0].get("key") or "")
            else:
                severity = str(candidate.get("final_severity") or "warning").lower()
                description = (
                    "h2. AI-discovered incident\n"
                    f"* Service: {candidate.get('service')}\n"
                    f"* Environment: {candidate.get('environment')}\n"
                    f"* Category: {candidate.get('category')}\n"
                    f"* Final severity: {severity}\n"
                    f"* Confidence: {candidate.get('confidence')}\n\n"
                    "h2. Initial hypothesis\n"
                    f"{candidate.get('initial_hypothesis')}\n\n"
                    "h2. Business impact\n"
                    f"{candidate.get('business_impact')}\n\n"
                    "h2. Evidence\n"
                    f"{json.dumps(candidate.get('evidence', []), default=str)[:5000]}"
                )
                created = await client.post(
                    f"{base_url}/rest/api/2/issue",
                    json={
                        "fields": {
                            "project": {"key": project_key},
                            "summary": str(candidate.get("title") or "KaiOps incident")[:255],
                            "description": description,
                            "issuetype": {"name": "Bug"},
                            "labels": [
                                "managed_by_kaiops",
                                fingerprint_label,
                                f"kaiops-severity-{severity}",
                            ],
                        }
                    },
                )
                created.raise_for_status()
                jira_key = str(created.json().get("key") or "")
                if not jira_key:
                    raise RuntimeError("Jira create response did not include an issue key")
        incident.ticket_id = jira_key
        candidate["jira_key"] = jira_key
        candidate["jira_url"] = f"{base_url}/browse/{jira_key}"
        incident.metadata["incident_candidate"] = candidate
        incident.metadata["jira"] = {"key": jira_key, "url": candidate["jira_url"]}
    property_key = f"kaiops-candidate-{idempotency_key[:32]}"
    property_url = f"{base_url}/rest/api/2/issue/{jira_key}/properties/{property_key}"
    async with httpx.AsyncClient(auth=(email, token), timeout=15.0) as client:
        existing = await client.get(property_url)
        if existing.status_code == 200:
            return jira_key
        markers = {
            "managed_by_kaiops": True,
            "kaiops_incident_id": str(incident.id),
            "event_origin": "kaiops",
            "idempotency_key": idempotency_key,
        }
        await client.put(
            property_url,
            json={
                **markers,
                "incident_candidate": candidate,
                "severity_policy": incident.metadata.get("severity_policy", {}),
            },
        )
        await client.put(
            f"{base_url}/rest/api/2/issue/{jira_key}",
            json={
                "update": {
                    "labels": [
                        {"add": "managed_by_kaiops"},
                        {"add": f"kaiops_incident_{str(incident.id).replace('-', '_')}"},
                    ]
                }
            },
        )
        body = (
            "[kaiops-managed-update]\n"
            "h2. AI Discovery and Severity Policy\n"
            f"* KaiOps incident ID: {incident.id}\n"
            f"* Category: {candidate.get('category')}\n"
            f"* Final severity: {candidate.get('final_severity')}\n"
            f"* Confidence: {candidate.get('confidence')}\n"
            f"* Initial hypothesis: {candidate.get('initial_hypothesis')}\n"
            f"* Business impact: {candidate.get('business_impact')}\n"
            f"* Evidence: {', '.join(str(row.get('uri')) for row in candidate.get('evidence', []) if isinstance(row, dict))}\n"
            f"* Similar incidents: {json.dumps(candidate.get('similar_incidents', []), default=str)[:1500]}"
        )
        await client.post(f"{base_url}/rest/api/2/issue/{jira_key}/comment", json={"body": body})
    logger.info(
        "incident_pipeline stage=jira outcome=synchronized incident=%s issue=%s",
        incident.id,
        jira_key,
    )
    return jira_key


async def _reuse_correlated_jira(incident: Any) -> str | None:
    if not settings.database_enabled or getattr(app.state, "session_factory", None) is None:
        return None
    metadata = incident.metadata if isinstance(incident.metadata, dict) else {}
    candidate = metadata.get("incident_candidate") if isinstance(metadata.get("incident_candidate"), dict) else {}
    correlation_key = str(candidate.get("correlation_key") or "").strip()
    canonical = metadata.get("canonical_correlation") if isinstance(metadata.get("canonical_correlation"), dict) else {}
    project_id = str(canonical.get("project_id") or "").strip()
    tenant_id = str(incident.tenant_id or "").strip()
    environment = str(incident.environment or "").strip()
    service = str(incident.service or "").strip()
    if not all((correlation_key, tenant_id, project_id, environment, service)):
        return None
    async with app.state.session_factory() as session:
        jira_key = await IncidentRepository(session).find_open_jira_by_correlation_key(
            correlation_key,
            tenant_id=tenant_id,
            project_id=project_id,
            environment=environment,
            service=service,
        )
    if jira_key:
        incident.ticket_id = jira_key
        candidate["jira_key"] = jira_key
        metadata["incident_candidate"] = candidate
        incident.metadata = metadata
        logger.info(
            "incident_pipeline stage=jira_match outcome=reused incident=%s issue=%s correlation_key=%s",
            incident.id,
            jira_key,
            correlation_key,
        )
    return jira_key


def _incident_from_persisted_payload(payload: dict[str, Any], incident_type: type[Incident] = Incident) -> Incident:
    """Hydrate a strict Incident from its enriched persistence/read payload."""
    return incident_type.model_validate({
        key: value for key, value in payload.items() if key in incident_type.model_fields
    })


def _occurrence_idempotency_key(source_event_id: str, alert: Alert) -> str:
    onset = alert.starts_at
    if onset is not None:
        onset = onset.replace(tzinfo=UTC) if onset.tzinfo is None else onset.astimezone(UTC)
    # Prometheus fingerprints identify a rule/label set, not an outage episode.
    # Bound delivery retries to the same onset without collapsing later outages.
    material = json.dumps([alert.tenant_id, source_event_id, onset.isoformat() if onset else None])
    return "alert-occurrence:" + hashlib.sha256(material.encode()).hexdigest()


async def _merge_duplicate_into_canonical(alert: Alert, incident: Any) -> Any | None:
    deduplication = alert.metadata.get("deduplication") if isinstance(alert.metadata, dict) else {}
    if not settings.database_enabled or getattr(app.state, "session_factory", None) is None:
        return None
    candidate = incident.metadata.get("incident_candidate") if isinstance(incident.metadata, dict) else {}
    correlation_key = str(
        candidate.get("correlation_key") or alert.fingerprint or alert.correlation_id or alert.id
    ).strip()
    project_id = str(
        alert.labels.get("project_id")
        or alert.labels.get("project")
        or alert.labels.get("project_name")
        or alert.metadata.get("project_id")
        or candidate.get("application")
        or alert.service
    ).strip()
    source_event_ids = candidate.get("source_event_ids") if isinstance(candidate, dict) else None
    source_event_id = (
        str(source_event_ids[0]).strip()
        if isinstance(source_event_ids, list) and source_event_ids and str(source_event_ids[0]).strip()
        else str(alert.id)
    )
    # Candidate idempotency identifies a correlation family; occurrence
    # idempotency must identify the immutable source event within that family.
    idempotency_key = _occurrence_idempotency_key(source_event_id, alert)
    window_minutes = int(
        (deduplication.get("window_minutes") if isinstance(deduplication, dict) else None)
        or agent.deduplication_window_minutes
        or 60
    )
    async with app.state.session_factory() as session:
        repo = IncidentRepository(session)
        ownership = await repo.acquire_canonical_incident(
            incident=incident,
            occurrence_id=alert.id,
            correlation_key=correlation_key,
            project_id=project_id,
            idempotency_key=idempotency_key,
            causation_id=str(candidate.get("idempotency_key") or alert.correlation_id or "") or None,
            correlation_window_minutes=window_minutes,
            observed_at=alert.starts_at,
        )
        canonical_incident_id = ownership["canonical_incident_id"]
        correlation_metadata = {
            "correlation_family_id": str(ownership["correlation_family_id"]),
            "canonical_incident_id": str(canonical_incident_id),
            "correlation_generation": int(ownership["correlation_generation"]),
            "correlation_key": correlation_key,
            "project_id": project_id,
        }
        incident.metadata["canonical_correlation"] = correlation_metadata
        alert.metadata["canonical_correlation"] = correlation_metadata
        alert.labels["kaiops_incident_id"] = str(canonical_incident_id)
        if canonical_incident_id == incident.id:
            await repo.save_alert(alert)
            await repo.save_incident(incident)
            await repo.save_incident_event(_build_alert_enriched_envelope(alert, incident))
            await session.commit()
            return None
        payload = await repo.get_incident(
            str(canonical_incident_id), tenant_id=str(alert.tenant_id or "default")
        )
        if not payload:
            raise RuntimeError("Canonical correlation ownership references a missing incident")
        # Persistence payloads intentionally include read-model annotations
        # such as approval_status/state. The strict domain model forbids those
        # extras, so hydrate only its declared fields. This keeps a delayed
        # duplicate from failing merely because the canonical incident has
        # already advanced to an approval or terminal lifecycle state.
        canonical = _incident_from_persisted_payload(payload, type(incident))
        if alert.id not in canonical.alert_ids:
            canonical.alert_ids.append(alert.id)
        canonical_metadata = canonical.metadata if isinstance(canonical.metadata, dict) else {}
        canonical_metadata["deduplication"] = {
            "occurrence_count": len(canonical.alert_ids),
            "latest_duplicate_alert_id": str(alert.id),
            "window_minutes": deduplication.get("window_minutes"),
        }
        canonical.metadata = canonical_metadata
        canonical.metadata["canonical_correlation"] = correlation_metadata
        if isinstance(deduplication, dict):
            deduplication.update(
                {
                    "canonical_incident_id": str(canonical.id),
                    "canonical_jira_key": str(canonical.ticket_id or ""),
                    "processing_stopped": True,
                    "reason": "Duplicate occurrence linked to canonical incident",
                }
            )
        if canonical.ticket_id:
            alert.labels["ticket_id"] = str(canonical.ticket_id)
            alert.labels["jira_issue_key"] = str(canonical.ticket_id)
        await repo.save_alert(alert)
        await repo.save_incident(canonical)
        await repo.save_incident_event(_build_alert_enriched_envelope(alert, canonical))
        from common.stalled_investigation import recover_stalled_investigation
        await recover_stalled_investigation(repo, alert, canonical)
        await session.commit()
    logger.info(
        "incident_pipeline stage=deduplicate outcome=linked_duplicate alert=%s canonical_incident=%s issue=%s",
        alert.id,
        canonical.id,
        canonical.ticket_id,
    )
    return canonical


def _connect_jira_context(alert: Alert, incident: Any) -> None:
    """Keep the external work item attached to every downstream code path."""
    jira_key = str(getattr(incident, "ticket_id", "") or "").strip()
    if not jira_key:
        return
    candidate = incident.metadata.get("incident_candidate", {}) if isinstance(incident.metadata, dict) else {}
    jira_url = str(candidate.get("jira_url") or "").strip() if isinstance(candidate, dict) else ""
    alert.labels["ticket_id"] = jira_key
    alert.labels["jira_issue_key"] = jira_key
    alert.metadata["jira"] = {"key": jira_key, "url": jira_url}
    alert.metadata["ticket_id"] = jira_key


def _build_alert_enriched_envelope(alert: Alert, incident: Any) -> dict[str, Any]:
    severity = str(getattr(alert.severity, "value", alert.severity) or "warning").strip().lower() or "warning"
    return build_event_envelope(
        event_type="incident.alert.enriched",
        identity={
            "incident_id": str(incident.id),
            "alert_id": str(alert.id),
            "trace_id": str(incident.trace_id or alert.trace_id or ""),
            "correlation_id": str(alert.correlation_id or "") or None,
            "causation_id": None,
            "parent_event_id": None,
        },
        scope={
            "tenant_id": str(alert.tenant_id or "default"),
            "service": str(alert.service or "unknown"),
            "environment": str(alert.environment or "prod"),
            "region": None,
            "team": str(alert.metadata.get("owner_team") or "") or None,
        },
        state={
            "severity": severity,
            "status": "investigating",
            "owner": None,
        },
        policy={
            "risk_tier": "unknown",
            "execution_mode": "unknown",
            "requires_approval": None,
            "policy_version": None,
            "policy_reason": "alert enriched and incident opened",
        },
        transport={
            "provider": "unknown",
            "channel": ENRICHED_ALERTS,
            "partition": None,
            "offset": None,
            "delivery_tag": None,
        },
        payload={
            "alert_name": alert.name,
            "alert_source": alert.source,
            "incident_title": incident.title,
            "service": alert.service,
            "jira_key": str(getattr(incident, "ticket_id", "") or "") or None,
            "incident_candidate": incident.metadata.get("incident_candidate", {}),
            "severity_policy": incident.metadata.get("severity_policy", {}),
            "managed_by_kaiops": True,
            "kaiops_incident_id": str(incident.id),
            "event_origin": "kaiops",
        },
    )


def _noise_classification(alert: Alert, incident: Any) -> tuple[bool, str]:
    candidate = incident.metadata.get("incident_candidate", {}) if isinstance(incident.metadata, dict) else {}
    noise = bool(
        candidate.get("noise")
        or candidate.get("false_positive")
        or candidate.get("actionable") is False
    )
    rationale = candidate.get("audit_metadata", {}).get("rationale") if isinstance(candidate.get("audit_metadata"), dict) else None
    reason = str(
        rationale
        or candidate.get("actionability_reason")
        or candidate.get("description")
        or "Classified as non-actionable monitoring noise."
    ).strip()
    if noise:
        deduplication = alert.metadata.setdefault("deduplication", {})
        if isinstance(deduplication, dict):
            deduplication.update({"disposition": "noise", "processing_stopped": True, "reason": reason})
        alert.metadata["noise"] = {"classified": True, "processing_stopped": True, "reason": reason}
    return noise, reason

async def startup(app: FastAPI) -> None:
    if settings.database_enabled and getattr(app.state, "session_factory", None) is not None:
        agent.alert_history_repository = SqlAlertHistoryRepository(
            session_factory=app.state.session_factory,
            max_items=max(25, min(int(settings.alert_correlation_candidate_limit), 1000)),
            max_age_minutes=max(1, int(agent.deduplication_window_minutes or 60)),
        )

    workers = max(1, int(getattr(settings, "message_bus_worker_count", 1) or 1))
    consumers: list[tuple[str, Any, ConsumeRunner, str]] = []
    for worker in range(workers):
        consumers.append((f"rabbitmq-w{worker + 1}", RabbitMQConsumer(settings, RAW_ALERTS), consume_rabbitmq_forever, "alerts"))
        consumers.append(
            (
                f"rabbitmq-jira-w{worker + 1}",
                RabbitMQConsumer(settings, JIRA_INVESTIGATIONS),
                consume_rabbitmq_forever,
                "jira",
            )
        )
    # Producers may mirror an event to RabbitMQ and Kafka for durability.
    # Consuming both copies in the same service executes LLM/Jira side effects
    # twice, so RabbitMQ is primary unless dual consumption is explicitly
    # requested for a migration.
    if settings.kafka_enabled and MESSAGE_BUS_DUAL_CONSUME_ENABLED:
        for worker in range(workers):
            consumers.insert(worker, (f"kafka-w{worker + 1}", KafkaConsumer(settings, RAW_ALERTS), consume_kafka_forever, "alerts"))
            consumers.insert(
                worker,
                (
                    f"kafka-jira-w{worker + 1}",
                    KafkaConsumer(settings, JIRA_INVESTIGATIONS),
                    consume_kafka_forever,
                    "jira",
                ),
            )
    if settings.azure_service_bus_enabled:
        for worker in range(workers):
            consumers.append(
                (
                    f"servicebus-w{worker + 1}",
                    AzureServiceBusConsumer(settings, RAW_ALERTS),
                    consume_service_bus_forever,
                    "alerts",
                )
            )

    async def handle_alert(payload: dict) -> None:
        raw_alert_payload = payload.get("alert") if isinstance(payload.get("alert"), dict) else payload
        alert_input = Alert.model_validate(raw_alert_payload)
        # Older deliveries may already be queued when admission policy changes.
        if alert_input.severity.value == "warning":
            alert_input.labels = {**alert_input.labels, "pipeline_outcome": "live_alert_only"}
            if settings.database_enabled:
                async with app.state.session_factory() as session:
                    await IncidentRepository(session).save_alert(alert_input)
                    await session.commit()
            return
        llm_discovery = await _llm_discovery(alert_input)
        alert, incident = await agent.process(alert_input, llm_discovery)
        noise, noise_reason = _noise_classification(alert, incident)
        if noise:
            if settings.database_enabled:
                async with app.state.session_factory() as session:
                    repo = IncidentRepository(session)
                    await repo.save_alert(alert)
                    await session.commit()
            logger.info("alert_pipeline outcome=noise alert=%s reason=%s", alert.id, noise_reason)
            EVENTS_PROCESSED.labels(settings.service_name, RAW_ALERTS, "noise").inc()
            return
        canonical = await _merge_duplicate_into_canonical(alert, incident)
        if canonical is not None:
            EVENTS_PROCESSED.labels(settings.service_name, RAW_ALERTS, "duplicate").inc()
            return
        # Investigation must not be gated on Jira ticket creation succeeding —
        # see the matching fix in process() below for the full rationale.
        # This handle() function is the real message-bus consumer for every
        # live alert (RAW_ALERTS); process() is a manual-test-only HTTP
        # endpoint. Only this path actually mattered for the bug.
        await app.state.producer.publish(
            ENRICHED_ALERTS,
            {"alert": alert, "incident": incident},
            key=str(alert.correlation_id or alert.service),
        )
        # Jira is an external, rate-limited side effect. Keep it off the raw
        # alert hot path so a slow Atlassian API cannot hold RabbitMQ delivery
        # credits and stop correlation/context for every other alert.
        await app.state.producer.publish(
            JIRA_INVESTIGATIONS,
            {"alert": alert, "incident": incident},
            key=str(alert.correlation_id or alert.service),
        )
        EVENTS_PROCESSED.labels(settings.service_name, RAW_ALERTS, "ok").inc()

    async def handle_jira(payload: dict) -> None:
        incident_payload = payload.get("incident") if isinstance(payload.get("incident"), dict) else None
        if incident_payload is None:
            raise ValueError("jira investigation payload is missing incident")
        incident = Incident.model_validate(incident_payload)
        await _reuse_correlated_jira(incident)
        jira_key = await _sync_candidate_to_jira(incident)
        if not jira_key:
            logger.info(
                "incident_pipeline stage=jira outcome=no_ticket incident=%s reason=Jira is not configured",
                incident.id,
            )
            return
        if settings.database_enabled:
            async with app.state.session_factory() as session:
                await IncidentRepository(session).save_incident(incident)
                await session.commit()

    for source, consumer, consume_forever, handler_kind in consumers:
        handler = handle_jira if handler_kind == "jira" else handle_alert
        task = asyncio.create_task(consume_forever(consumer, handler), name=f"alert-intelligence-{source}-consumer")
        tasks.append(task)


async def shutdown(_: FastAPI) -> None:
    for task in tasks:
        task.cancel()


app = create_app(title="KaiMS Alert Intelligence", settings=settings, startup=startup, shutdown=shutdown)


class DeduplicationConfigUpdate(BaseModel):
    enabled: bool | None = None
    window_minutes: int | None = Field(default=None, ge=1, le=1440)


@app.get("/deduplication/config")
async def get_deduplication_config() -> dict[str, Any]:
    return {
        "enabled": bool(agent.deduplication_enabled),
        "window_minutes": int(agent.deduplication_window_minutes or 60),
        "similarity_threshold": float(agent.correlation_threshold or 0.72),
        "algorithm": "exact-or-weighted-similarity-v1",
    }


@app.put("/deduplication/config")
async def update_deduplication_config(update: DeduplicationConfigUpdate) -> dict[str, Any]:
    if update.enabled is not None:
        agent.deduplication_enabled = update.enabled
    if update.window_minutes is not None:
        agent.deduplication_window_minutes = update.window_minutes
        agent.retention_minutes = max(int(agent.retention_minutes or 0), update.window_minutes)
    return await get_deduplication_config()


@app.post("/process")
async def process(alert: Alert) -> dict:
    enriched, incident = await agent.process(alert, await _llm_discovery(alert))
    noise, noise_reason = _noise_classification(enriched, incident)
    if noise:
        if settings.database_enabled:
            async with app.state.session_factory() as session:
                repo = IncidentRepository(session)
                await repo.save_alert(enriched)
                await session.commit()
        return {"alert": enriched, "incident": None, "disposition": "noise", "processing_stopped": True, "reason": noise_reason, "jira_qualified": False}
    canonical = await _merge_duplicate_into_canonical(enriched, incident)
    if canonical is not None:
        return {
            "alert": enriched,
            "incident": canonical,
            "disposition": "duplicate",
            "processing_stopped": True,
            "reason": "Duplicate occurrence linked to canonical incident",
            "jira_qualified": bool(canonical.ticket_id),
        }
    jira_key: str | None = None
    try:
        await _reuse_correlated_jira(incident)
        jira_key = await _sync_candidate_to_jira(incident)
    except Exception:
        logger.exception("failed to synchronize incident candidate to Jira incident=%s", incident.id)
    _connect_jira_context(enriched, incident)
    if settings.database_enabled:
        async with app.state.session_factory() as session:
            repo = IncidentRepository(session)
            await repo.save_alert(enriched)
            await repo.save_incident(incident)
            await session.commit()
    # Investigation (context-agent -> resolution-agent RCA/impact/fix) must not
    # be gated on Jira ticket creation succeeding. Previously this only fired
    # `if jira_key:`, so any alert the actionability/confidence qualification
    # judged not worth a ticket (test signals, low-confidence noise, or a rate
    # limit) got zero investigation and permanently showed an empty RCA in the
    # UI with no indication why. Ticket-worthiness and investigation-worthiness
    # are different questions — every alert that reaches this point already
    # passed LLM discovery and deserves an explanation, even when it doesn't
    # deserve a ticket.
    await app.state.producer.publish(ENRICHED_ALERTS, {"alert": enriched, "incident": incident}, key=alert.service)
    return {"alert": enriched, "incident": incident, "jira_qualified": bool(jira_key)}
