from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import os
from collections.abc import Awaitable, Callable, Coroutine
from datetime import UTC, datetime, timedelta
from time import monotonic
from typing import Any
from uuid import NAMESPACE_URL, UUID, uuid4, uuid5

import httpx
from ai_workbench_common.models import Context
from common.investigation_gaps import investigation_gaps, blocking_investigation_gaps, requirement_blocks_recollection, incident_collection_window
from common.capability_registry import default_capability_registry
from common.config import get_settings
from common.context_enrichment_contract import (
    authorized_enrichment_connectors,
    discovery_evidence_requirements as build_evidence_requirements,
    evidence_category_reviewed,
    initial_causal_collection_gaps,
    next_authorized_enrichment_connector,
)
from common.database import RunbookVersionRecord
from common.event_publishers import build_agent_event_contract, build_event_envelope
from common.kafka import KafkaConsumer
from common.kafka import consume_forever as consume_kafka_forever
from common.models import Alert, Incident, Recommendation
from common.orchestration.execution_plan import resolve_execution_plan
from common.orchestration.execution_plan_contract import (
    ExecutionPlanV2,
    verify_plan_fingerprint,
)
from common.rabbitmq import RabbitMQConsumer
from common.rabbitmq import consume_forever as consume_rabbitmq_forever
from common.remediation_plan import (
    AutonomyRecommendation,
    RemediationPlan,
    assess_remediation_plan,
)
from common.repository import ContextEnrichmentRepository, IncidentRepository
from common.resolution_lifecycle import ResolutionState, create_lifecycle, decide_resolution_control
from common.service import create_app
from common.telemetry import CONTEXT_KNOWLEDGE_OPERATIONS, EVENTS_PROCESSED
from common.tenant_identity import require_tenant_id
from common.topics import CONTEXT_EVENTS, INITIAL_CONTEXT_EVENTS, RESOLUTION_EVENTS
from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel, Field
from sqlalchemy import select
from resolution_agent import ResolutionIntelligenceAgent
from resolution_agent.catalog import (
    RESOLUTION_CATALOG,
    prepare_resolution_plan,
    register_global_knowledge,
    register_learned_runbooks,
    relevant_resolutions,
)
from resolution_agent.contracts import ResolutionOption
from resolution_agent.investigation import IterativeInvestigator
from resolution_agent.metrics import HITL_TOTAL, HOTL_TOTAL, PLAN_BLOCKED_TOTAL
from resolution_agent.policy import ResolutionPolicyDecision, ResolutionPolicyInput, evaluate_resolution_policy
from resolution_agent.workflow import ResolutionWorkflowState, transition_idempotency_key

settings = get_settings()
settings.service_name = "resolution-agent"
logger = logging.getLogger("kaiops.resolution_agent.app")
agent = ResolutionIntelligenceAgent()
investigator = IterativeInvestigator()
tasks: list[asyncio.Task] = []
_GLOBAL_KNOWLEDGE_CACHE: dict[str, tuple[float, list[dict[str, Any]]]] = {}
_GLOBAL_KNOWLEDGE_CACHE_TTL_SECONDS = 300.0
_GLOBAL_KNOWLEDGE_CACHE_MAX_ENTRIES = 256
MESSAGE_BUS_DUAL_CONSUME_ENABLED = str(os.getenv("MESSAGE_BUS_DUAL_CONSUME_ENABLED", "false")).strip().lower() in {
    "1",
    "true",
    "yes",
    "on",
}

ConsumeRunner = Callable[[Any, Callable[[dict], Awaitable[None]]], Coroutine[Any, Any, None]]


class RcaReuseDecision(BaseModel):
    reusable: bool
    reasons: list[str] = Field(default_factory=list)


def _utc_aware(value: datetime | str) -> datetime:
    parsed = value if isinstance(value, datetime) else datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)


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


def validate_rca_reuse(
    prior_recommendation: Recommendation | dict[str, Any], final_snapshot: Any,
) -> RcaReuseDecision:
    prior = (
        prior_recommendation.model_dump(mode="json")
        if isinstance(prior_recommendation, Recommendation) else dict(prior_recommendation)
    )
    metadata = prior.get("metadata") if isinstance(prior.get("metadata"), dict) else {}
    def snapshot_value(name: str, default: Any = None) -> Any:
        return final_snapshot.get(name, default) if isinstance(final_snapshot, dict) else getattr(final_snapshot, name, default)

    snapshot_payload = snapshot_value("payload", snapshot_value("context", {}))
    snapshot_metadata = (
        snapshot_payload.get("metadata") if isinstance(snapshot_payload.get("metadata"), dict) else {}
    )
    alert = snapshot_payload.get("alert") if isinstance(snapshot_payload.get("alert"), dict) else {}
    reasons: list[str] = []
    expected_pairs = (
        (str(prior.get("tenant_id") or metadata.get("tenant_id") or ""), str(snapshot_value("tenant_id")), "tenant"),
        (str(metadata.get("context_subject_fingerprint") or ""), str(snapshot_value("subject_fingerprint")), "subject"),
        (str(metadata.get("context_fingerprint") or ""), str(snapshot_value("context_fingerprint")), "context"),
        (str(metadata.get("service") or ""), str(alert.get("service") or ""), "service"),
        (str(metadata.get("environment") or ""), str(alert.get("environment") or ""), "environment"),
        (str(metadata.get("deployment_id") or ""), str(snapshot_metadata.get("deployment_id") or ""), "deployment"),
        (str(metadata.get("change_id") or ""), str(snapshot_metadata.get("change_id") or ""), "change"),
    )
    for prior_value, current_value, label in expected_pairs:
        required = label in {"tenant", "subject", "context", "service", "environment"}
        if (required and not prior_value) or prior_value != current_value:
            reasons.append(f"{label}_mismatch")
    prior_ids = {str(value) for value in metadata.get("evidence_ids") or []}
    if not prior_ids or prior_ids != set(snapshot_value("evidence_ids", []) or []):
        reasons.append("evidence_ids_mismatch")
    prior_checksums = metadata.get("evidence_content_checksums")
    if not isinstance(prior_checksums, dict) or prior_checksums != dict(snapshot_value("evidence_checksums", {}) or {}):
        reasons.append("evidence_checksums_mismatch")
    prior_contradictions = set(metadata.get("contradicting_evidence_ids") or [])
    current_report = snapshot_metadata.get("investigation_report")
    conclusion = current_report.get("conclusion") if isinstance(current_report, dict) else {}
    current_contradictions = set(
        conclusion.get("contradicting_evidence_ids") if isinstance(conclusion, dict) else []
    )
    if prior_contradictions != current_contradictions:
        reasons.append("contradiction_state_mismatch")
    if _utc_aware(snapshot_value("expires_at")) <= datetime.now(UTC):
        reasons.append("snapshot_expired")
    return RcaReuseDecision(reusable=not reasons, reasons=reasons)


def _resolution_reuse_threshold() -> float:
    configured = float(getattr(settings, "context_resolution_reuse_min_score", 0.7) or 0.7)
    return max(0.0, min(configured, 1.0))


def _deterministic_recommendation_id(context: Context) -> UUID:
    metadata = context.metadata if isinstance(context.metadata, dict) else {}
    # A manual regeneration is a distinct governed analysis generation even
    # when the underlying evidence fingerprint is unchanged. Without this
    # request identity, polling cannot distinguish the new result from the
    # recommendation that existed before the operator clicked regenerate.
    identity = str(metadata.get("analysis_request_id") or "").strip()
    try:
        UUID(identity)
    except (TypeError, ValueError):
        raise HTTPException(
            status_code=409,
            detail="a durable UUID analysis_request_id is required before RCA generation",
        ) from None
    return uuid5(NAMESPACE_URL, f"kaims:recommendation:{context.incident_id}:{identity}:v2")


def _attach_rca_governance_binding(recommendation: Recommendation, context: Context) -> None:
    """Bind one immutable RCA generation to the context snapshot it evaluated."""

    context_metadata = context.metadata if isinstance(context.metadata, dict) else {}
    runtime = recommendation.metadata if isinstance(recommendation.metadata, dict) else {}
    snapshot_evidence_ids = {
        str(value) for value in context_metadata.get("evidence_ids") or [] if str(value).strip()
    }
    rca_analysis = runtime.get("rca_analysis") if isinstance(runtime.get("rca_analysis"), dict) else {}
    referenced_evidence = (
        rca_analysis.get("evidence_used")
        if isinstance(rca_analysis.get("evidence_used"), list)
        else []
    )
    # The immutable binding records evidence actually referenced by this RCA,
    # not every record available in its context snapshot. The snapshot identity
    # already preserves the complete evidence universe.
    evidence_ids = sorted({
        str(value) for value in referenced_evidence
        if str(value).strip() and str(value) in snapshot_evidence_ids
    })
    model_usage = runtime.get("model_usage") if isinstance(runtime.get("model_usage"), list) else []
    model_versions = sorted({
        str(item.get("model") or item.get("provider") or "").strip()
        for item in model_usage if isinstance(item, dict) and str(item.get("model") or item.get("provider") or "").strip()
    })
    tool_names = {
        str(value).strip() for value in runtime.get("external_tools_used") or [] if str(value).strip()
    }
    iterative = runtime.get("iterative_investigation")
    if isinstance(iterative, dict):
        tool_names.update(str(value).strip() for value in iterative.get("tools_used") or [] if str(value).strip())
    evidence_set_digest = "sha256:" + hashlib.sha256(
        json.dumps(evidence_ids, separators=(",", ":")).encode()
    ).hexdigest()
    recommendation.metadata = {
        **runtime,
        "diagnostic_runbook": context_metadata.get("diagnostic_runbook"),
        "analysis_request_id": str(context_metadata.get("analysis_request_id") or "") or None,
        "project_id": str(context_metadata.get("project_id") or context.alert.labels.get("project_id") or "default"),
        "alert_id": str(context.alert.id),
        "context_snapshot_id": str(context_metadata.get("context_snapshot_id") or "") or None,
        "context_fingerprint": str(context_metadata.get("context_fingerprint") or "") or None,
        "context_subject_fingerprint": str(context_metadata.get("context_subject_fingerprint") or "") or None,
        "evidence_ids": evidence_ids,
        "evidence_set_digest": evidence_set_digest,
        "evidence_content_checksums": dict(context_metadata.get("evidence_content_checksums") or {}),
        "service": str(context.alert.service or ""),
        "environment": str(context.alert.environment or ""),
        "deployment_id": str(context_metadata.get("deployment_id") or ""),
        "change_id": str(context_metadata.get("change_id") or ""),
        "rca_version": max(1, int(context_metadata.get("rca_version") or 1)),
        "recommendation_version": str(recommendation.id),
        "investigation_id": runtime.get("investigation_id"),
        "model_version": ",".join(model_versions) or "deterministic-fallback-v1",
        "prompt_version": str(runtime.get("prompt_version") or "resolution-graph-v2"),
        "tool_versions": {
            **{name: "contract-v1" for name in sorted(tool_names)},
            **dict(runtime.get("tool_versions") or {}),
        },
        "generated_at": recommendation.created_at.isoformat(),
    }


async def _require_context_snapshot_binding(context: Context) -> dict[str, Any]:
    """Fail closed before persisting an RCA against orphaned or stale context."""
    if not settings.database_enabled or getattr(app.state, "session_factory", None) is None:
        raise HTTPException(status_code=503, detail="durable context snapshot storage is unavailable")
    metadata = context.metadata if isinstance(context.metadata, dict) else {}
    snapshot_id = str(metadata.get("context_snapshot_id") or "").strip()
    if not snapshot_id:
        raise HTTPException(status_code=409, detail="context_snapshot_id is required before RCA persistence")
    async with app.state.session_factory() as session:
        snapshot = await IncidentRepository(session).context_snapshot_by_id(
            snapshot_id, tenant_id=context.tenant_id, incident_id=context.incident_id,
        )
    if snapshot is None:
        raise HTTPException(
            status_code=409,
            detail="the bound context snapshot does not exist for this tenant and incident",
        )
    persisted = snapshot.get("context") if isinstance(snapshot.get("context"), dict) else {}
    persisted_alert = persisted.get("alert") if isinstance(persisted.get("alert"), dict) else {}
    if str(persisted_alert.get("id") or "") != str(context.alert.id):
        raise HTTPException(status_code=409, detail="the bound context snapshot belongs to a different alert")
    if str(snapshot.get("context_fingerprint") or "") != str(metadata.get("context_fingerprint") or ""):
        raise HTTPException(status_code=409, detail="the bound context snapshot fingerprint does not match")
    freshness_mandatory = bool(metadata.get("force_full_analysis")) or str(
        metadata.get("analysis_mode") or metadata.get("context_strategy") or ""
    ).lower() in {"fresh", "realtime"}
    # MySQL may return DATETIME values without tzinfo. Normalize at the
    # service boundary before comparing them with an aware UTC clock.
    expires_at = _utc_aware(snapshot["expires_at"])
    if freshness_mandatory and expires_at <= datetime.now(UTC):
        raise HTTPException(status_code=409, detail="the bound context snapshot has expired")
    return snapshot


def _attach_resolution_options(
    recommendation: Recommendation,
    context: Context,
    investigation_report: dict[str, Any],
) -> None:
    """Project governed catalog matches into typed, non-executable options."""
    if investigation_report.get("conclusive") is not True:
        recommendation.metadata["resolution_options"] = []
        recommendation.metadata["resolution_options_status"] = str(
            investigation_report.get("outcome") or "INSUFFICIENT_EVIDENCE"
        )
        return
    conclusion = investigation_report.get("conclusion") if isinstance(investigation_report.get("conclusion"), dict) else {}
    evidence_ids = [str(value) for value in conclusion.get("evidence_ids") or [] if str(value).strip()]
    confidence = max(0.0, min(float(conclusion.get("confidence") or recommendation.confidence or 0.0), 1.0))
    matches = relevant_resolutions(
        issue=str(recommendation.root_cause or context.alert.description or context.alert.name),
        service=context.alert.service,
        recommended_action=str(recommendation.recommended_action or ""),
        limit=3,
    )
    options: list[dict[str, Any]] = []
    for rank, match in enumerate(matches, start=1):
        risk = str(match.get("risk") or "high").upper()
        option = ResolutionOption(
            option_id=str(match["id"]),
            incident_id=context.incident_id,
            correlation_id=str(context.trace_id or context.incident_id),
            title=str(match.get("title") or match["id"]),
            objective=str(match.get("applicability") or "Restore the affected service safely."),
            action_type=str(match.get("strategy") or "diagnose"),
            target={"platform": match.get("platform"), "service": context.alert.service},
            reasoning=(
                f"Rank {rank}: governed catalog match based on the evidence-supported RCA; "
                f"match reasons={', '.join(str(value) for value in match.get('match_reasons') or []) or 'catalog taxonomy'}."
            ),
            supporting_evidence_ids=evidence_ids,
            confidence=confidence,
            estimated_success_probability=min(confidence, float(match.get("relevance") or 0.0)),
            risk_level=risk,
            estimated_recovery_time=None,
            blast_radius={"affected_services": [context.alert.service], "verified": False},
            preconditions=[{"description": str(value), "required": True} for value in match.get("prerequisites") or []],
            validation_plan=[{"description": str(value), "source": "registered-validator-required"} for value in match.get("validation") or []],
            rollback_plan={"steps": list(match.get("rollback") or [])} if match.get("rollback") else None,
            automation_eligibility="HITL" if risk in {"LOW", "MEDIUM"} else "MANUAL_ONLY",
        )
        options.append(option.model_dump(mode="json"))
    recommendation.metadata["resolution_options"] = options
    recommendation.metadata["resolution_options_status"] = "RANKED" if options else "UNSUPPORTED_ACTION"
    typed_investigation = recommendation.metadata.get("iterative_investigation")
    if isinstance(typed_investigation, dict):
        rca_result = typed_investigation.get("rca_result")
        if isinstance(rca_result, dict):
            rca_result["resolution_options"] = options


async def investigate_context(context: Context) -> tuple[Context, dict[str, Any]]:
    """Collect investigator evidence before the immutable RCA snapshot is finalized."""
    enabled = str(os.getenv("RESOLUTION_ITERATIVE_INVESTIGATION_ENABLED", "true")).strip().lower() in {
        "1", "true", "yes", "on",
    }
    if not enabled:
        return context, {}
    report: dict[str, Any] = {}

    async def persist(event: str, payload: dict[str, Any]) -> None:
        if not settings.database_enabled or getattr(app.state, "session_factory", None) is None:
            return
        async with app.state.session_factory() as session:
            repo = IncidentRepository(session)
            if event == "started":
                await repo.create_resolution_investigation(payload)
            elif event == "step":
                await repo.append_resolution_investigation_step(payload)
            elif event == "completed":
                await repo.complete_resolution_investigation(payload)
            await session.commit()

    try:
        report = await investigator.investigate(context, persist=persist)
    except Exception as exc:
        logger.exception("iterative investigation failed")
        report = {"status": "failed", "conclusive": False, "persistence_errors": [str(exc)[:300]]}
    metadata = dict(context.metadata if isinstance(context.metadata, dict) else {})
    context_evidence = dict(
        metadata.get("context_evidence") if isinstance(metadata.get("context_evidence"), dict) else {}
    )
    for row in report.get("evidence", []):
        if not isinstance(row, dict):
            continue
        source = investigator._source(row)
        bucket = {"history": "tickets", "data": "database", "alert": "telemetry"}.get(source, source)
        rows = list(context_evidence.get(bucket) if isinstance(context_evidence.get(bucket), list) else [])
        known = {str(item.get("evidence_id") or item.get("uri") or "") for item in rows if isinstance(item, dict)}
        identity = str(row.get("evidence_id") or row.get("uri") or "")
        if identity and identity not in known:
            rows.append(row)
        context_evidence[bucket] = rows
    metadata["context_evidence"] = context_evidence
    metadata["iterative_investigation"] = {key: value for key, value in report.items() if key != "evidence"}
    metadata["_final_investigation_report"] = report
    return context.model_copy(update={"metadata": metadata}), report


async def persist_final_investigation_snapshot(
    context: Context, report: dict[str, Any], parent_snapshot_id: UUID | str,
) -> Any:
    async with app.state.session_factory() as session:
        row = await IncidentRepository(session).persist_final_investigation_snapshot(
            context=context, report=report, parent_snapshot_id=parent_snapshot_id,
        )
        await session.commit()
        return row


def bind_context_to_snapshot(context: Context, *, snapshot: Any) -> Context:
    metadata = dict(context.metadata if isinstance(context.metadata, dict) else {})
    metadata.update({
        "context_snapshot_id": str(snapshot.snapshot_id),
        "context_fingerprint": snapshot.context_fingerprint,
        "snapshot_stage": "investigation_complete",
        "context_subject_fingerprint": snapshot.subject_fingerprint,
        "evidence_ids": list(snapshot.evidence_ids or []),
        "evidence_content_checksums": dict(snapshot.evidence_checksums or {}),
        "context_expires_at": snapshot.expires_at.isoformat(),
        "service": str(context.alert.service or ""),
        "environment": str(context.alert.environment or ""),
    })
    return context.model_copy(update={"metadata": metadata})


async def _commit_investigation_recommendation(
    context: Context, report: dict[str, Any], parent_snapshot_id: UUID | str,
    recommendation: Recommendation, decision_payload: dict[str, Any] | None = None,
) -> Context:
    """Commit the frozen evidence and its recommendation in one short transaction.

    Tool and model calls must finish before entering this function. The parent
    freshness guard still rejects evidence that changed during investigation;
    no intermediate final snapshot is published while synthesis is running.
    """
    async with app.state.session_factory() as session:
        repo = IncidentRepository(session)
        snapshot = await repo.persist_final_investigation_snapshot(
            context=context, report=report, parent_snapshot_id=parent_snapshot_id,
        )
        bound = bind_context_to_snapshot(context, snapshot=snapshot)
        _attach_rca_governance_binding(recommendation, bound)
        _validate_recommendation_snapshot_evidence(recommendation, snapshot)
        plan = _apply_catalog_plan(recommendation, bound, decision_payload)
        orchestration = recommendation.metadata.get("orchestration_decision")
        if isinstance(orchestration, dict):
            orchestration["execution_plan_fingerprint"] = plan.get("plan_fingerprint") if isinstance(plan, dict) else None
        await repo.save_recommendation_as_audit(recommendation, tenant_id=bound.tenant_id)
        await session.commit()
    return bound


async def _bind_next_rca_version(context: Context) -> Context:
    """Bind regeneration to the next version in durable incident history."""
    if not settings.database_enabled or getattr(app.state, "session_factory", None) is None:
        return context
    async with app.state.session_factory() as session:
        version = await IncidentRepository(session).reserve_incident_rca_version(
            tenant_id=context.tenant_id, incident_id=context.incident_id,
            recommendation_id=_deterministic_recommendation_id(context),
        )
        await session.commit()
    metadata = dict(context.metadata) if isinstance(context.metadata, dict) else {}
    metadata["rca_version"] = version
    return context.model_copy(update={"metadata": metadata})


def _validate_recommendation_snapshot_evidence(recommendation: Recommendation, snapshot: Any) -> None:
    metadata = recommendation.metadata if isinstance(recommendation.metadata, dict) else {}
    evidence_ids = metadata.get("evidence_ids")
    if not isinstance(evidence_ids, list):
        analysis = metadata.get("rca_analysis") if isinstance(metadata.get("rca_analysis"), dict) else {}
        evidence_ids = analysis.get("evidence_used", [])
    outside = sorted({str(value) for value in evidence_ids or []} - set(snapshot.evidence_ids or []))
    if outside:
        raise HTTPException(status_code=409, detail={
            "code": "evidence_snapshot_mismatch",
            "message": "RCA evidence is not contained in the final investigation snapshot",
            "evidence_ids": outside,
        })
    ordered = sorted({str(value) for value in evidence_ids or [] if str(value).strip()})
    expected_digest = "sha256:" + hashlib.sha256(
        json.dumps(ordered, separators=(",", ":")).encode()
    ).hexdigest()
    if metadata.get("evidence_set_digest") != expected_digest:
        raise HTTPException(status_code=409, detail={
            "code": "evidence_digest_mismatch",
            "message": "RCA evidence digest does not resolve to its cited evidence IDs",
        })


async def _resolve_context(context: Context) -> Recommendation:
    metadata = context.metadata if isinstance(context.metadata, dict) else {}
    prior = metadata.get("prior_resolution") if isinstance(metadata.get("prior_resolution"), dict) else {}
    score = _resolution_quality_score(prior)
    reuse_decision = validate_rca_reuse(prior, {
        "payload": context.model_dump(mode="json"), "tenant_id": context.tenant_id,
        "subject_fingerprint": metadata.get("context_subject_fingerprint"),
        "context_fingerprint": metadata.get("context_fingerprint"),
        "evidence_ids": metadata.get("evidence_ids", []),
        "evidence_checksums": metadata.get("evidence_content_checksums", {}),
        "expires_at": metadata.get("context_expires_at"),
    }) if prior else RcaReuseDecision(reusable=False, reasons=["no_prior_recommendation"])
    may_reuse = (
        bool(getattr(settings, "context_resolution_reuse_enabled", True))
        and bool(metadata.get("context_reused"))
        and not bool(metadata.get("force_full_analysis"))
        and score > _resolution_reuse_threshold()
        and reuse_decision.reusable
    )
    if prior and not reuse_decision.reusable:
        metadata = {
            **metadata,
            "prior_resolution": {},
            "historical_precedents": [
                *list(metadata.get("historical_precedents") or []),
                {"recommendation": prior, "reuse_rejected_reasons": reuse_decision.reasons},
            ][-5:],
        }
        context = context.model_copy(update={"metadata": metadata})
    if not may_reuse:
        investigation_report = (
            dict(metadata.get("_final_investigation_report"))
            if isinstance(metadata.get("_final_investigation_report"), dict) else {}
        )
        investigation_enabled = str(os.getenv("RESOLUTION_ITERATIVE_INVESTIGATION_ENABLED", "true")).strip().lower() in {
            "1", "true", "yes", "on",
        }
        if investigation_enabled and not investigation_report:
            async def persist_investigation(event: str, payload: dict[str, Any]) -> None:
                if not settings.database_enabled or getattr(app.state, "session_factory", None) is None:
                    return
                try:
                    async with app.state.session_factory() as session:
                        repo = IncidentRepository(session)
                        if event == "started":
                            await repo.create_resolution_investigation(payload)
                        elif event == "step":
                            await repo.append_resolution_investigation_step(payload)
                        elif event == "completed":
                            await repo.complete_resolution_investigation(payload)
                        await session.commit()
                except Exception as exc:
                    # Investigation remains useful in-memory when persistence is
                    # temporarily unavailable; expose degradation in the report.
                    logger.exception("failed to persist resolution investigation event=%s", event)
                    investigation_report.setdefault("persistence_errors", []).append(str(exc)[:300])

            investigation_report = await investigator.investigate(context, persist=persist_investigation)
            metadata = dict(context.metadata if isinstance(context.metadata, dict) else {})
            context_evidence = dict(
                metadata.get("context_evidence") if isinstance(metadata.get("context_evidence"), dict) else {}
            )
            for row in investigation_report.get("evidence", []):
                if not isinstance(row, dict):
                    continue
                source = investigator._source(row)
                bucket = {
                    "history": "tickets", "data": "database", "alert": "telemetry",
                }.get(source, source)
                rows = list(context_evidence.get(bucket) if isinstance(context_evidence.get(bucket), list) else [])
                known = {str(item.get("evidence_id") or item.get("uri") or "") for item in rows if isinstance(item, dict)}
                identity = str(row.get("evidence_id") or row.get("uri") or "")
                if identity and identity not in known:
                    rows.append(row)
                context_evidence[bucket] = rows
            metadata["context_evidence"] = context_evidence
            metadata["iterative_investigation"] = {
                key: value for key, value in investigation_report.items() if key != "evidence"
            }
            context = context.model_copy(update={"metadata": metadata})
        from resolution_agent.runtime_recovery import stopped_workload_recommendation
        recommendation = stopped_workload_recommendation(context, investigation_report)
        if recommendation is None:
            recommendation = await agent.resolve_with_runtime(context)
        if investigation_report:
            recommendation.metadata["iterative_investigation"] = {
                key: value for key, value in investigation_report.items() if key != "evidence"
            }
            recommendation.metadata["investigation_id"] = investigation_report.get("investigation_id")
            recommendation.metadata["investigation_status"] = investigation_report.get("status")
            if not investigation_report.get("conclusive"):
                next_evidence = [
                    item for item in investigation_report.get("next_evidence", [])
                    if isinstance(item, dict) and str(item.get("source") or "").strip()
                ]
                missing = ", ".join(str(item["source"]) for item in next_evidence)
                conclusion = (
                    investigation_report.get("conclusion")
                    if isinstance(investigation_report.get("conclusion"), dict)
                    else {}
                )
                # Name the actual reason an investigation stayed inconclusive instead of
                # one generic message regardless of cause - "no hypothesis at all",
                # "confidence fell short", and "not enough independent corroboration"
                # each call for a different next action from an operator.
                if conclusion.get("hypothesis_id") is None:
                    inconclusive_reason = "no falsifiable causal hypothesis could be formed from the collected evidence."
                elif not conclusion.get("causally_eligible", True):
                    inconclusive_reason = "the leading signal is a symptom summary, not a causal mechanism."
                else:
                    leading_confidence = float(conclusion.get("confidence") or 0.0)
                    threshold = float(conclusion.get("conclusive_threshold") or 0.65)
                    source_count = int(conclusion.get("independent_source_count") or 0)
                    minimum_sources = int(conclusion.get("minimum_independent_sources") or 2)
                    if leading_confidence < threshold:
                        inconclusive_reason = (
                            f"the leading hypothesis reached {leading_confidence:.0%} confidence, "
                            f"below the {threshold:.0%} required to confirm a root cause."
                        )
                    elif source_count < minimum_sources:
                        inconclusive_reason = (
                            f"only {source_count} independent evidence source{'s' if source_count != 1 else ''} "
                            f"corroborate{'s' if source_count == 1 else ''} it, short of the {minimum_sources} required."
                        )
                    else:
                        inconclusive_reason = "the collected evidence does not independently corroborate a causal hypothesis."
                recommendation.root_cause = f"Investigation inconclusive: {inconclusive_reason}"
                recommendation.recommended_action = (
                    f"Collect the next required read-only evidence ({missing}) and rerun resolution."
                    if missing
                    else "Review the collected evidence, run the highest-value targeted diagnostic, and rerun resolution."
                )
                diagnostic_confidence = max(
                    0.0, min(float(conclusion.get("confidence") or recommendation.confidence or 0.0), 0.99)
                )
                recommendation.confidence = diagnostic_confidence
                available_evidence_ids = {
                    str(item.get("evidence_id"))
                    for item in investigation_report.get("evidence", [])
                    if isinstance(item, dict) and str(item.get("evidence_id") or "").strip()
                }
                diagnostic_evidence_ids = [
                    str(value) for value in conclusion.get("evidence_ids", [])
                    if str(value) in available_evidence_ids
                ]
                evidence_by_id = {
                    str(item.get("evidence_id")): item
                    for item in investigation_report.get("evidence", [])
                    if isinstance(item, dict) and str(item.get("evidence_id") or "").strip()
                }
                hypotheses = [
                    item for item in investigation_report.get("hypotheses", [])
                    if isinstance(item, dict)
                ]
                leading = next(
                    (
                        item for item in hypotheses
                        if str(item.get("hypothesis_id") or "") == str(conclusion.get("hypothesis_id") or "")
                    ),
                    hypotheses[0] if hypotheses else {},
                )
                rca_analysis = dict(
                    recommendation.metadata.get("rca_analysis")
                    if isinstance(recommendation.metadata.get("rca_analysis"), dict)
                    else {}
                )
                rca_analysis.update({
                    "root_cause": recommendation.root_cause,
                    "grounding_notes": f"RCA remains unconfirmed: {inconclusive_reason}",
                    "confidence_score": diagnostic_confidence,
                    "confidence_kind": "leading_hypothesis",
                    "evidence_used": diagnostic_evidence_ids,
                    "supporting_signals": (
                        [str(leading.get("reasoning_summary") or "").strip()]
                        if str(leading.get("reasoning_summary") or "").strip()
                        else [
                            "The diagnostic candidate references "
                            f"{investigator._source(evidence_by_id[evidence_id])} evidence {evidence_id}."
                            for evidence_id in diagnostic_evidence_ids
                            if evidence_id in evidence_by_id
                        ]
                    ),
                    "contradictions": list(leading.get("contradicting_evidence_ids") or []),
                    "missing_evidence": investigation_gaps(rca_analysis, investigation_report),
                })
                recommendation.metadata["rca_analysis"] = rca_analysis
                recommendation.rationale = (
                    f"The leading diagnostic hypothesis is supported by {len(diagnostic_evidence_ids)} "
                    f"validated evidence citation(s); confidence={diagnostic_confidence:.2f}. "
                    "It remains non-actionable until the conclusive evidence gate passes."
                )
                recommendation.metadata["resolution_outcome"] = "inconclusive"
                recommendation.metadata["confidence_kind"] = "leading_hypothesis"
                recommendation.metadata["confidence_actionable"] = False
            analysis = dict(recommendation.metadata.get("rca_analysis") or {})
            analysis["missing_evidence"] = blocking_investigation_gaps(analysis, investigation_report)
            recommendation.metadata["rca_analysis"] = analysis
            _attach_resolution_options(recommendation, context, investigation_report)
            # The impact graph runs after the iterative investigator. Replace
            # its provisional NOT_ESTABLISHED placeholder with that assessment.
            from resolution_agent.impact_claim import evaluated_impact_claim, measured_latency_impact
            typed = recommendation.metadata.get("iterative_investigation", {})
            result = typed.get("rca_result") if isinstance(typed, dict) else None
            if isinstance(result, dict):
                claim = evaluated_impact_claim(
                    recommendation.metadata.get("impact_analysis") or {},
                    recommendation.impact,
                    investigation_report.get("evidence") or [],
                )
                if claim["status"] == "NOT_ESTABLISHED":
                    measured = measured_latency_impact(context.alert, investigation_report.get("evidence") or [])
                    if measured is not None:
                        claim = measured
                        recommendation.impact = measured["statement"]
                        recommendation.metadata.setdefault("impact_analysis", {})["technical_observation"] = measured
                result["claims"] = [row for row in result.get("claims", []) if row.get("kind") != "IMPACT"] + [claim]
        recommendation.metadata = {
            **(recommendation.metadata if isinstance(recommendation.metadata, dict) else {}),
            "analysis_reused": False,
            "analysis_source": "fresh_evidence_analysis",
        }
        recommendation.id = _deterministic_recommendation_id(context)
        return recommendation
    try:
        cached_recommendation = Recommendation.model_validate(prior)
    except Exception:
        CONTEXT_KNOWLEDGE_OPERATIONS.labels("reuse_resolution", "invalid").inc()
        return await agent.resolve_with_runtime(context)
    recommendation = cached_recommendation.model_copy(
        update={
            "tenant_id": context.tenant_id,
            "id": _deterministic_recommendation_id(context),
            "created_at": datetime.now(UTC),
            "incident_id": context.incident_id,
            "trace_id": str(context.alert.trace_id or "") or None,
        }
    )
    recommendation.metadata = {
        **(recommendation.metadata if isinstance(recommendation.metadata, dict) else {}),
        "analysis_reused": True,
        "analysis_source": "qualified_context_resolution_cache",
        "analysis_source_incident_id": metadata.get("context_source_incident_id"),
        "analysis_source_alert_id": metadata.get("context_source_alert_id"),
        "analysis_reuse_score": score,
        "analysis_reuse_threshold": _resolution_reuse_threshold(),
        "analysis_reused_at": datetime.now(UTC).isoformat(),
    }
    CONTEXT_KNOWLEDGE_OPERATIONS.labels("reuse_resolution", "success").inc()
    return recommendation


def _catalog_plan_for(
    context: Context,
    decision: dict[str, Any] | None = None,
    recommendation: Recommendation | None = None,
) -> dict[str, Any]:
    routing = decision if isinstance(decision, dict) else {}
    supplied = routing.get("execution_plan")
    supplied_values = []
    if isinstance(supplied, dict):
        for key in ("commands", "preflight_commands", "validation_commands", "rollback_commands"):
            values = supplied.get(key, [])
            supplied_values.extend(str(value) for value in (values if isinstance(values, list) else [values]))
    legacy_compose_binding = any(
        "docker-socket-proxy:2375/containers/" in value
        and "/containers/$container_id/" not in value
        and "/containers/json?" not in value
        for value in supplied_values
    )
    if (
        isinstance(supplied, dict)
        and supplied.get("schema_version") == "kaims.execution-plan.v2"
        and not legacy_compose_binding
    ):
        try:
            validated = ExecutionPlanV2.model_validate(supplied)
        except ValueError:
            pass
        else:
            if verify_plan_fingerprint(supplied):
                return validated.model_dump(mode="json")
    return resolve_execution_plan(
        alert=context.alert,
        workflow_name=str(routing.get("workflow") or "resolution-rerun"),
        requires_approval=bool(routing.get("requires_approval", True)),
        risk_tier=str(routing.get("risk_tier") or "medium"),
        execution_mode=str(routing.get("execution_mode") or "human-approval"),
        resolution_hints=" ".join(
            filter(
                None,
                (
                    str(recommendation.root_cause or "") if recommendation else "",
                    str(recommendation.recommended_action or "") if recommendation else "",
                    " ".join(
                        str(item.get("cause") or "")
                        for item in (
                            recommendation.metadata.get("hypothesis_analysis", {}).get("ranked", [])
                            if recommendation and isinstance(recommendation.metadata, dict)
                            else []
                        )
                        if isinstance(item, dict)
                    ),
                ),
            )
        )[:4000],
        evidence_basis=(
            [
                str(evidence_id)
                for evidence_ids in recommendation.metadata.get("investigation_report", {}).get("source_evidence_ids", {}).values()
                for evidence_id in (evidence_ids if isinstance(evidence_ids, list) else [])
                if str(evidence_id).strip()
            ]
            if recommendation
            and isinstance(recommendation.metadata, dict)
            and isinstance(recommendation.metadata.get("investigation_report"), dict)
            else []
        ),
        incident_id=recommendation.incident_id if recommendation else None,
        root_cause=str(recommendation.root_cause or "RCA not yet established") if recommendation else "RCA not yet established",
        confidence=float(recommendation.confidence or 0.0) if recommendation else 0.0,
    )


def _apply_catalog_plan(recommendation: Recommendation, context: Context, decision: dict[str, Any] | None = None) -> dict[str, Any]:
    metadata = recommendation.metadata if isinstance(recommendation.metadata, dict) else {}
    analysis = metadata.get("rca_analysis") if isinstance(metadata.get("rca_analysis"), dict) else {}
    # The model's grounded label cannot outrank its own outstanding causal
    # gaps. Reconcile before plan construction and immutable binding persistence.
    if str(metadata.get("rca_status") or "").lower() == "grounded" and (
        analysis.get("missing_evidence") or analysis.get("conflicting_evidence")
    ):
        metadata["rca_status"] = "insufficient_evidence"
        metadata["rca_handoff_blockers"] = [
            *(["declared evidence gaps remain"] if analysis.get("missing_evidence") else []),
            *(["conflicting evidence remains unresolved"] if analysis.get("conflicting_evidence") else []),
        ]
        recommendation.metadata = metadata
    plan = dict(_catalog_plan_for(context, decision, recommendation))
    model_plan = metadata.get("execution_plan") if isinstance(metadata.get("execution_plan"), dict) else {}
    metadata["model_proposed_execution_plan"] = model_plan
    rca_analysis = metadata.get("rca_analysis") if isinstance(metadata.get("rca_analysis"), dict) else {}
    context_readiness = (
        rca_analysis.get("context_readiness")
        if isinstance(rca_analysis.get("context_readiness"), dict)
        else {}
    )
    evidence_gate_prefixes = (
        "Context evidence is only ",
        "The causal hypothesis is not independently corroborated",
        "No application runtime, log, telemetry, or code evidence supports",
        "Discovery evidence is degraded or unavailable",
    )
    evidence_gate_blocks = [
        str(reason)
        for reason in model_plan.get("readiness_blocks", [])
        if str(reason).startswith(evidence_gate_prefixes)
    ]
    if context_readiness and context_readiness.get("ready") is not True:
        readiness_score = float(context_readiness.get("score") or 0.0)
        evidence_gate_blocks.append(
            f"Context evidence is only {readiness_score:.0%} RCA-ready; collect independent direct and causal evidence."
        )
    if evidence_gate_blocks:
        plan["execution_ready"] = False
        plan["readiness_blocks"] = list(dict.fromkeys([
            *(plan.get("readiness_blocks") or []),
            *evidence_gate_blocks,
        ]))
    # The normalized investigation contract uses an integer generation, while
    # ExecutionPlanV2 carries the immutable version as a string.  Normalize at
    # this boundary so a fresh, bound RCA cannot fail after analysis merely
    # because Pydantic does not coerce numbers in strict string fields.
    try:
        plan["rca_version"] = int(metadata.get("rca_version") or 0) or None
    except (TypeError, ValueError):
        plan["rca_version"] = None
    plan["evidence_snapshot_id"] = metadata.get("context_snapshot_id")
    plan["recommendation_id"] = recommendation.id
    plan["recommendation_version"] = str(recommendation.id)
    investigation = metadata.get("investigation_report") if isinstance(metadata.get("investigation_report"), dict) else {}
    plan["evidence_basis"] = list(rca_analysis.get("evidence_used") or [])
    plan["investigation_report"] = investigation
    plan["historical_precedents"] = list(
        metadata.get("hypothesis_analysis", {}).get("ranked", [])
        if isinstance(metadata.get("hypothesis_analysis"), dict)
        else []
    )[:5]
    iterative = metadata.get("iterative_investigation") if isinstance(metadata.get("iterative_investigation"), dict) else {}
    if iterative and iterative.get("conclusive") is not True:
        candidate_plan = dict(plan)
        plan = {
            **plan,
            "plan_kind": "diagnostic",
            "diagnostic_only": True,
            "mutating": False,
            "execution_ready": False,
            "commands": [],
            "scripts": [],
            "rollback_commands": [],
            "readiness_blocks": list(dict.fromkeys([
                *(plan.get("readiness_blocks") or []),
                "Iterative investigation is inconclusive; corrective execution is not authorized.",
                *(
                    f"Missing evidence source: {source}"
                    for source in iterative.get("missing_sources", [])[:5]
                ),
            ])),
            "investigation_status": iterative.get("status"),
            "investigation_id": iterative.get("investigation_id"),
            "next_evidence": iterative.get("next_evidence", []),
        }
        metadata["candidate_execution_plan"] = candidate_plan
    confidence = float(
        (iterative.get("conclusion") or {}).get("confidence")
        or recommendation.confidence
        or 0.0
    )
    connector = plan.get("connection", {}).get("connector", {}) if isinstance(plan.get("connection"), dict) else {}
    policy_risk = str(plan.get("risk_tier") or "medium").lower()
    if policy_risk not in {"low", "medium", "high", "critical"}:
        policy_risk = "medium"
    policy = evaluate_resolution_policy(ResolutionPolicyInput(
        environment=str(context.alert.environment or "unknown").lower(),
        risk=policy_risk,
        confidence=max(0.0, min(confidence, 1.0)),
        runbook_status=str(plan.get("runbook_status") or "unregistered"),
        runbook_success_rate=float(plan.get("runbook_success_rate") or 0.0),
        mutating=bool(plan.get("mutating")),
        # Genuinely reversible only when a real rollback command exists. An
        # acknowledged non-reversible-but-approved recovery strategy (see
        # execution_plan.py's recovery_strategy_acknowledged) makes the plan
        # execution-eligible but must never be reported as reversible=True -
        # policy.py's action_not_reversible HITL reason must still fire.
        reversible=bool(plan.get("rollback_commands")),
        canary_supported=bool(plan.get("canary_supported")),
        blast_radius=str(plan.get("blast_radius") or "single-service"),
        target_verified=bool(str(plan.get("remediation_target") or "").strip()),
        validation_available=bool(plan.get("validation_commands")),
        rollback_available=bool(plan.get("rollback_commands")) or (
            plan.get("rollback_mode") == "not_applicable" and bool(plan.get("recovery_strategy_acknowledged"))
        ),
        contradiction_count=len((iterative.get("conclusion") or {}).get("contradicting_evidence_ids") or []),
        database_change=str(connector.get("type") or "").lower() in {"database", "mysql"},
        rca_conclusive=bool(iterative.get("conclusive")),
    ))
    plan["policy_decision"] = policy.model_dump(mode="json")
    if policy.decision == "hitl":
        HITL_TOTAL.inc()
    elif policy.decision == "hotl":
        HOTL_TOTAL.inc()
    elif policy.decision == "block":
        PLAN_BLOCKED_TOTAL.inc()
    if policy.decision in {"block", "investigate"} and plan.get("mutating"):
        metadata["candidate_execution_plan"] = dict(plan)
        plan["plan_kind"] = "diagnostic"
        plan["diagnostic_only"] = True
        plan["mutating"] = False
        plan["execution_ready"] = False
        plan["commands"] = []
        plan["rollback_commands"] = []
        plan["readiness_blocks"] = list(dict.fromkeys([
            *(plan.get("readiness_blocks") or []),
            *(f"policy:{reason}" for reason in policy.reason_codes),
        ]))
    plan["requires_approval"] = policy.decision == "hitl"
    plan["approval_required"] = policy.decision == "hitl"
    if not plan.get("commands"):
        plan["actions"] = []
    plan["preflight"] = list(plan.get("preflight_commands") or [])
    plan["validation"] = list(plan.get("validation_commands") or [])
    plan["rollback"] = list(plan.get("rollback_commands") or [])
    plan["evidence_references"] = list(plan.get("evidence_basis") or [])
    plan["approval_policy"] = {
        "decision": (
            "hitl_required"
            if policy.decision == "hitl"
            else "denied"
            if policy.decision == "block"
            else "recommend_only"
        ),
        "required_approver_role": "hitl-reviewer",
        "reason_codes": list(policy.reason_codes),
        "approval_expiry_seconds": 900,
    }
    plan = ExecutionPlanV2.model_validate(plan).finalized().model_dump(mode="json")
    _attach_typed_remediation_plan(recommendation, context, plan)
    metadata["execution_plan"] = plan
    metadata["remediation_target"] = str(plan.get("remediation_target") or context.alert.service or "")
    metadata["recommended_commands"] = list(plan.get("commands") or [])
    metadata["runbook_id"] = str(plan.get("runbook_governance_id") or "")
    metadata["runbook_slug"] = str(plan.get("playbook_id") or "")
    metadata["runbook_version"] = plan.get("playbook_version")
    metadata["runbook_status"] = str(plan.get("runbook_status") or "")
    metadata["runbook_checksum"] = str(plan.get("runbook_checksum") or "")
    routing = decision if isinstance(decision, dict) else {}
    # An earlier intake route cannot waive a requirement imposed by the
    # evaluated, target-bound execution policy.
    requires_approval = bool(routing.get("requires_approval") or plan.get("requires_approval", True))
    control = decide_resolution_control(
        plan,
        requires_approval=requires_approval,
        sources=(routing, metadata, context.alert.metadata if isinstance(context.alert.metadata, dict) else {}),
    )
    metadata["resolution_control"] = control
    analysis_reused = metadata.get("analysis_reused") is True
    disposition = str(control.get("disposition") or "investigate")
    if disposition in {"watch_only", "investigate"}:
        path_id, path_label = "diagnostic", "Diagnostic completion"
        skipped = ["approval", "execution"]
    elif analysis_reused and disposition == "execution_ready":
        path_id, path_label = "verified_fast_path", "Verified context fast path"
        skipped = ["context_collection", "rca_generation", "approval"]
    elif analysis_reused:
        path_id, path_label = "guided_reuse", "Reused analysis with approval"
        skipped = ["context_collection", "rca_generation"]
    elif disposition == "execution_ready":
        path_id, path_label = "autonomous", "Fresh analysis autonomous path"
        skipped = ["approval"]
    else:
        path_id, path_label = "guided", "Fresh analysis guided path"
        skipped = []
    metadata["orchestration_path"] = {
        "schema_version": "kaims.orchestration-path.v1",
        "id": path_id,
        "label": path_label,
        "context_reused": bool(context.metadata.get("context_reused")),
        "analysis_reused": analysis_reused,
        "disposition": disposition,
        "skipped_stages": skipped,
    }
    metadata["resolution_lifecycle"] = create_lifecycle(
        tenant_id=context.tenant_id,
        incident_id=recommendation.incident_id,
        recommendation_id=recommendation.id,
        plan=plan,
        state=ResolutionState(control["initial_state"]),
        reason_code=str(control["reason_code"]),
        control=control,
    )
    recommendation.metadata = metadata
    recommendation.commands = list(plan.get("commands") or [])
    return plan


_CAPABILITY_BINDINGS: dict[tuple[str, str], str] = {
    ("kubernetes", "restart_pod"): "kubernetes.restart_workload",
    ("kubernetes", "restart_service"): "kubernetes.restart_workload",
    ("kubernetes", "rollback_deployment"): "kubernetes.rollback_deployment",
    ("kubernetes", "scale_workload"): "kubernetes.scale_workload",
    ("mysql", "read_status"): "database.collect_diagnostics",
    ("mysql", "collect_diagnostics"): "database.collect_diagnostics",
    ("mysql", "failover_database"): "database.failover",
    ("api", "restart_service"): "application.restart_service",
}


def _attach_typed_remediation_plan(
    recommendation: Recommendation,
    context: Context,
    execution_plan: dict[str, Any],
) -> None:
    """Project only registered, typed catalog actions into the Resolution contract."""
    metadata = recommendation.metadata if isinstance(recommendation.metadata, dict) else {}
    actions = execution_plan.get("actions") if isinstance(execution_plan.get("actions"), list) else []
    if len(actions) != 1 or not isinstance(actions[0], dict):
        metadata["remediation_plan_status"] = {
            "valid": False,
            "execution_eligible": False,
            "reason_codes": ["single_registered_capability_required"],
        }
        recommendation.remediation_plan = None
        recommendation.metadata = metadata
        return
    action = actions[0]
    binding = action.get("safety_binding") if isinstance(action.get("safety_binding"), dict) else {}
    capability = binding.get("capability") if isinstance(binding.get("capability"), dict) else {}
    operation = str(capability.get("operation") or "").strip()
    connection = execution_plan.get("connection") if isinstance(execution_plan.get("connection"), dict) else {}
    connector = connection.get("connector") if isinstance(connection.get("connector"), dict) else {}
    connector_type = str(connector.get("type") or "").strip().lower()
    capability_id = _CAPABILITY_BINDINGS.get((connector_type, operation))
    if not capability_id:
        metadata["remediation_plan_status"] = {
            "valid": False,
            "execution_eligible": False,
            "reason_codes": ["unregistered_capability_binding"],
            "catalog_operation": operation,
            "connector_type": connector_type,
        }
        recommendation.remediation_plan = None
        recommendation.metadata = metadata
        return
    blast = binding.get("blast_radius") if isinstance(binding.get("blast_radius"), dict) else {}
    target = str(action.get("target_resource_id") or "").strip()
    affected = [str(item) for item in blast.get("affected_resource_ids", []) if str(item).strip()]
    stable_target_identity = target.startswith(("dt://", "urn:", "arn:", "k8s://", "/subscriptions/"))
    evidence = [str(item) for item in execution_plan.get("evidence_references", []) if str(item).strip()]
    registry = default_capability_registry()
    definition = registry.get(capability_id)
    raw_inputs = action.get("inputs") if isinstance(action.get("inputs"), dict) else {}
    parameters = {
        str(key): value
        for key, value in raw_inputs.items()
        if str(key).lower() not in {"catalog_command", "command", "commands", "script", "scripts"}
    }
    risk_scores = {"low": 20, "medium": 45, "high": 75, "critical": 95}
    typed_plan = RemediationPlan(
        incident_id=recommendation.incident_id,
        tenant_id=recommendation.tenant_id,
        root_cause=recommendation.root_cause,
        root_cause_confidence=recommendation.confidence,
        supporting_evidence=evidence,
        affected_resources=affected or ([target] if target else []),
        blast_radius=blast.get("scope") or "unknown",
        business_impact=recommendation.impact,
        recommended_capability=capability_id,
        target_resource_id=target,
        target_identity_verified=(
            bool(blast.get("verified"))
            and target in affected
            and stable_target_identity
        ),
        connector_id=definition.supported_connectors[0],
        required_parameters=parameters,
        preconditions=list(definition.preconditions),
        validation_plan=[str(item) for item in action.get("validation", []) if str(item).strip()],
        rollback_capability=definition.rollback_capability,
        risk_score=risk_scores.get(str(execution_plan.get("risk") or "medium").lower(), 45),
        autonomy_recommendation=(
            AutonomyRecommendation.HITL_REQUIRED
            if definition.mutating
            else AutonomyRecommendation.RECOMMEND
        ),
    )
    assessment = assess_remediation_plan(
        typed_plan,
        registry,
        environment={"prod": "production", "dev": "development"}.get(
            str(context.alert.environment or "unknown").lower(),
            str(context.alert.environment or "unknown").lower(),
        ),
    )
    recommendation.remediation_plan = typed_plan
    metadata["remediation_plan"] = typed_plan.model_dump(mode="json")
    metadata["remediation_plan_status"] = assessment.model_dump(mode="json")
    recommendation.metadata = metadata


def _build_resolution_event_payload(
    *,
    context: Context,
    incident: Incident,
    recommendation: Recommendation,
    decision_payload: dict[str, Any],
) -> dict[str, Any]:
    flow_id = str(decision_payload.get("flow_id") or incident.id)
    event_contract = build_agent_event_contract(
        flow_id=flow_id,
        incident_id=str(incident.id),
        trace_id=str(incident.trace_id or context.alert.trace_id or ""),
        correlation_id=str(context.alert.correlation_id or "") or None,
        agent="resolution-agent",
        payload={
            "recommended_action": recommendation.recommended_action,
            "risk": recommendation.risk,
            "topic": RESOLUTION_EVENTS,
        },
        metadata={
            "policy_version": recommendation.metadata.get("policy_version"),
            "policy_reason": recommendation.metadata.get("policy_reason"),
            "workflow": decision_payload.get("workflow"),
        },
        confidence=float(recommendation.confidence),
        reasoning=str(recommendation.metadata.get("reasoning") or recommendation.rationale or ""),
        citations=list(recommendation.metadata.get("citations", [])),
        evidence_ids=list(recommendation.metadata.get("evidence_ids", [])),
    )
    event_contract["event_id"] = str(uuid5(NAMESPACE_URL,
        f"kaims:resolution:{context.tenant_id}:{incident.id}:{recommendation.id}"))

    return {
        "recommendation": recommendation,
        "resolution_lifecycle": recommendation.metadata.get("resolution_lifecycle"),
        "context": context,
        "incident": incident,
        "decision": decision_payload,
        "event_contract": event_contract,
    }


def _resolution_projection_status(metadata: dict[str, Any], *, requires_approval: bool) -> str:
    plan = metadata.get("execution_plan") if isinstance(metadata.get("execution_plan"), dict) else {}
    iterative = (
        metadata.get("iterative_investigation")
        if isinstance(metadata.get("iterative_investigation"), dict)
        else {}
    )
    rca_analysis = metadata.get("rca_analysis") if isinstance(metadata.get("rca_analysis"), dict) else {}
    lifecycle = metadata.get("resolution_lifecycle") if isinstance(metadata.get("resolution_lifecycle"), dict) else {}
    lifecycle_state = str(lifecycle.get("state") or "").strip().lower()
    accepted_evidence = [value for value in rca_analysis.get("evidence_used", []) if str(value).strip()]
    # A grounded, conclusive RCA with no ready-to-execute mutating plan (no
    # safe catalog action exists yet, or the finding is informational) is a
    # real, distinct outcome from "still investigating" -- but until now it
    # fell all the way through to "investigating" because only a READY PLAN
    # advanced this projection's status, never RCA completion on its own.
    # This is what incident_projections.status actually drives (the main
    # incident board reads it via monitoring-adapter's /incidents/metadata,
    # a separate field from incidents.status which _advance_incident_status_
    # on_grounded_rca already advances correctly) -- so a fully grounded RCA
    # was showing as indistinguishable from "never looked at yet" on the
    # primary incident board. Reproduced live: every incident whose
    # incidents.status had correctly advanced to "rca_ready" still showed
    # incident_projections.status == "investigating".
    grounded_conclusive = (
        iterative.get("conclusive") is True
        and bool(accepted_evidence)
        and str(metadata.get("rca_status") or "").strip().lower() == "grounded"
        and not rca_analysis.get("missing_evidence")
        and not rca_analysis.get("conflicting_evidence")
    )
    recommendation_ready = (
        grounded_conclusive
        and plan.get("execution_ready") is True
        and plan.get("mutating") is True
    )
    if recommendation_ready and (requires_approval or lifecycle_state == "awaiting_approval"):
        return "awaiting_approval"
    if recommendation_ready and lifecycle_state == "ready_to_execute":
        return "approved"
    if grounded_conclusive:
        return "rca_ready"
    return "investigating"


async def _persist_resolution_event(
    *,
    app: FastAPI,
    context: Context,
    incident: Incident,
    recommendation: Recommendation,
    decision_payload: dict[str, Any],
) -> None:
    if not settings.database_enabled:
        return
    if getattr(app.state, "session_factory", None) is None:
        raise RuntimeError("Resolution persistence is unavailable; delivery must be retried")
    metadata = recommendation.metadata if isinstance(recommendation.metadata, dict) else {}
    orchestration = (
        metadata.get("orchestration_decision") if isinstance(metadata.get("orchestration_decision"), dict) else {}
    )
    requires_approval = decision_payload.get("requires_approval")
    if requires_approval is None:
        requires_approval = orchestration.get("requires_approval")
    status = _resolution_projection_status(metadata, requires_approval=bool(requires_approval))
    provider = decision_payload.get("message_bus_provider") or orchestration.get("message_bus_provider") or "unknown"
    async with app.state.session_factory() as session:
        repo = IncidentRepository(session)
        await repo.save_incident_event(
            build_event_envelope(
                event_type="incident.recommendation.generated",
                identity={
                    "incident_id": str(incident.id),
                    "alert_id": str(context.alert.id),
                    "trace_id": str(incident.trace_id or context.alert.trace_id or ""),
                    "correlation_id": str(context.alert.correlation_id or "") or None,
                    "causation_id": None,
                    "parent_event_id": None,
                },
                # build_event_envelope() defaults idempotency_key to
                # f"{event_type}:{incident_id}" when none is supplied, which is
                # identical for every RCA regeneration of the same incident.
                # Combined with the (transport_provider, idempotency_key)
                # unique constraint on incident_events, every event after the
                # first one to land with a given transport_provider (almost
                # always "unknown" here, since decision_payload rarely carries
                # message_bus_provider for regenerations) silently collides
                # and is swallowed by save_incident_event's IntegrityError
                # handling -- which also means _upsert_projection_from_record
                # never runs again, permanently freezing
                # IncidentProjectionRecord.recommendation_id at whichever RCA
                # version happened to get the key first. Key on the
                # recommendation's own id instead: it is unique per RCA
                # version (see incident_investigation_bindings.recommendation_id)
                # while still deduping true redeliveries of the exact same
                # recommendation.
                idempotency={
                    "idempotency_key": f"incident.recommendation.generated:{recommendation.id}",
                },
                scope={
                    "tenant_id": context.tenant_id,
                    "service": str(context.alert.service or "unknown"),
                    "environment": str(context.alert.environment or "prod"),
                    "region": None,
                    "team": str(context.alert.metadata.get("owner_team") or "") or None,
                },
                state={
                    "severity": str(
                        getattr(context.alert.severity, "value", context.alert.severity) or "warning"
                    ).lower(),
                    "status": status,
                    "owner": None,
                },
                policy={
                    "risk_tier": str(decision_payload.get("risk_tier") or orchestration.get("risk_tier") or "unknown"),
                    "execution_mode": str(
                        decision_payload.get("execution_mode") or orchestration.get("execution_mode") or "unknown"
                    ),
                    "requires_approval": requires_approval,
                    "policy_version": decision_payload.get("policy_version")
                    or orchestration.get("policy_version")
                    or metadata.get("policy_version"),
                    "policy_reason": decision_payload.get("policy_reason")
                    or orchestration.get("policy_reason")
                    or metadata.get("policy_reason"),
                },
                transport={
                    "provider": str(provider),
                    "channel": RESOLUTION_EVENTS,
                    "partition": None,
                    "offset": None,
                    "delivery_tag": None,
                },
                ai={
                    "confidence": float(recommendation.confidence),
                    "model_provider": str(
                        (metadata.get("model_usage") or [{}])[0].get("provider")
                        if isinstance(metadata.get("model_usage"), list) and metadata.get("model_usage")
                        else ""
                    )
                    or None,
                    "model_name": str(
                        (metadata.get("model_usage") or [{}])[0].get("model")
                        if isinstance(metadata.get("model_usage"), list) and metadata.get("model_usage")
                        else ""
                    )
                    or None,
                    "fallback_reason": None,
                },
                payload={
                    "recommendation_id": str(recommendation.id),
                    "recommended_action": recommendation.recommended_action,
                    "root_cause": recommendation.root_cause,
                    "impact": recommendation.impact,
                    "risk": recommendation.risk,
                    "resolution_lifecycle": metadata.get("resolution_lifecycle") or None,
                    "analysis_request_id": metadata.get("analysis_request_id"),
                    "context_snapshot_id": metadata.get("context_snapshot_id"),
                    "context_fingerprint": metadata.get("context_fingerprint"),
                    "rca_version": metadata.get("rca_version"),
                    "recommendation_version": metadata.get("recommendation_version"),
                },
            )
        )
        iterative = metadata.get("iterative_investigation") if isinstance(metadata.get("iterative_investigation"), dict) else {}
        plan = metadata.get("execution_plan") if isinstance(metadata.get("execution_plan"), dict) else {}
        policy_decision = plan.get("policy_decision") if isinstance(plan.get("policy_decision"), dict) else {}
        evidence_ids = list((iterative.get("conclusion") or {}).get("evidence_ids") or [])
        transition_path: list[tuple[ResolutionWorkflowState, ResolutionWorkflowState, str]]
        transition_path = [
            (ResolutionWorkflowState.EVIDENCE_PENDING, ResolutionWorkflowState.EVIDENCE_READY, "evidence_compiled"),
            (ResolutionWorkflowState.EVIDENCE_READY, ResolutionWorkflowState.HYPOTHESES_READY, "hypotheses_ranked"),
        ]
        for sequence, (previous_state, new_state, reason_code) in enumerate(transition_path, 1):
            event_id = uuid5(NAMESPACE_URL, f"kaims:resolution-transition:{recommendation.id}:{sequence}:{new_state.value}")
            transition_payload = {
                "tenant_id": context.tenant_id,
                "incident_id": str(incident.id),
                "recommendation_id": str(recommendation.id),
                "execution_plan_id": None,
                "previous_state": previous_state.value,
                "new_state": new_state.value,
                "event_id": str(event_id),
                "correlation_id": str(context.alert.correlation_id or "") or None,
                "causation_id": str(context.alert.id),
                "idempotency_key": transition_idempotency_key(str(incident.id), event_id, new_state),
                "actor": "resolution-agent",
                "reason_code": reason_code,
                "evidence_ids": evidence_ids,
                "policy_decision": policy_decision,
            }
            await repo.record_resolution_transition(transition_payload)
        missing = list((metadata.get("rca_analysis") or {}).get("missing_evidence") or [])
        enrichment_repo = ContextEnrichmentRepository(session)
        external_probe = (
            "blackbox" in str(context.alert.source or "").lower()
            or "synthetic" in str(context.alert.source or "").lower()
            or "public-internet" in str(context.alert.environment or "").lower()
            or "public internet" in str(context.alert.environment or "").lower()
        )
        if external_probe:
            await enrichment_repo.cancel_inapplicable_context_requirements(
                tenant_id=context.tenant_id,
                incident_id=incident.id,
                categories={"topology"},
                reason="Not applicable: external synthetic probe has no internal service topology.",
            )
            await enrichment_repo.cancel_inapplicable_context_requirements(
                tenant_id=context.tenant_id,
                incident_id=incident.id,
                categories={"traces"},
                questions={"Collect fresh distributed traces for the affected service and incident window."},
                reason="Superseded generic trace request: external probe assessment requires endpoint HTTP/DNS/TLS evidence. Explicit incident-specific trace requests are retained.",
            )
        existing_requirements = await enrichment_repo.list_context_evidence_requirements(
            tenant_id=context.tenant_id, incident_id=incident.id,
        )
        rca_version = max(1, int(metadata.get("rca_version") or 1))
        existing_questions = {
            str(row.get("question") or "").strip().casefold() for row in existing_requirements
            if requirement_blocks_recollection(row, rca_version)
        }
        # Initial probes run once; only explicit outstanding RCA gaps may
        # reopen completed collection in later versions.
        initial_questions = {str(row.get("question") or "").strip().casefold() for row in existing_requirements}
        reviewed_sources = (metadata.get("iterative_investigation") or {}).get("source_coverage") or {}
        initial_gaps = [
            gap for gap in initial_causal_collection_gaps(
                source=context.alert.source,
                environment=context.alert.environment,
            )
            if str(gap["question"]).strip().casefold() not in initial_questions
            and not evidence_category_reviewed(gap["category"], reviewed_sources)
        ]
        if initial_gaps:
            missing = [*initial_gaps, *missing]
            metadata["targeted_causal_collection"] = {
                "launched": True,
                "status": "collecting",
                "sources": list(dict.fromkeys(str(gap["category"]) for gap in initial_gaps)),
            }
        if missing:
            rca_version = max(1, int(metadata.get("rca_version") or 1))
            requirements = [
                requirement for requirement in build_evidence_requirements(
                    tenant_id=context.tenant_id, incident_id=incident.id,
                    rca_version=rca_version, missing_evidence=missing, now=datetime.now(UTC),
                    previous_requirements=existing_requirements,
                    reviewed_sources=reviewed_sources,
                )
                if requirement.question.strip().casefold() not in existing_questions
            ]
        else:
            requirements = []
        if requirements:
            await enrichment_repo.upsert_context_evidence_requirements(requirements)
            authorized = authorized_enrichment_connectors(
                alert_metadata=context.alert.metadata,
                context_payload=context.model_dump(mode="json"),
            )
            collection_now = datetime.now(UTC)
            window_start, window_end = incident_collection_window(context.alert, collection_now)
            for requirement in requirements:
                connector = next_authorized_enrichment_connector(
                    candidate_connectors=requirement.candidate_connectors,
                    authorized_connectors=authorized,
                )
                if connector:
                    await enrichment_repo.schedule_context_enrichment_job(
                        tenant_id=context.tenant_id, incident_id=incident.id,
                        requirement_id=requirement.requirement_id, connector_id=connector,
                        query_payload={
                            "schema_version": "kaiops.context-enrichment-query.v1",
                            "category": requirement.category,
                            "question": requirement.question,
                            "alert_id": str(context.alert.id),
                            "context_snapshot_id": str(metadata.get("context_snapshot_id") or ""),
                            "analysis_request_id": str(metadata.get("analysis_request_id") or ""),
                            "alert": context.alert.model_dump(mode="json"),
                            "incident": incident.model_dump(mode="json"),
                            "decision": dict(decision_payload),
                            "authorized_connectors": sorted(authorized),
                            "attempted_connectors": [],
                        },
                        observation_start=window_start,
                        observation_end=window_end.replace(microsecond=0),
                    )
                else:
                    assignment = await enrichment_repo.resolve_human_evidence_responder(
                        tenant_id=context.tenant_id, incident_id=incident.id,
                    )
                    await enrichment_repo.create_human_evidence_request(
                        automatic_fallback=True,
                        tenant_id=context.tenant_id, incident_id=incident.id,
                        requirement_id=requirement.requirement_id,
                        expected_responder=assignment["identity"] if assignment else None,
                        assignment_source=assignment["source"] if assignment else None,
                        assignment_failure_reason=None if assignment else "NO_AUTHORIZED_RESPONDER",
                        due_at=collection_now + timedelta(hours=1),
                        acceptable_format="A source reference and a concise factual observation.",
                        evidence_already_checked=list((metadata.get("rca_analysis") or {}).get("evidence_used") or []),
                        hypothesis_impact=requirement.reason,
                        investigation_can_continue=True,
                    )
        from fastapi.encoders import jsonable_encoder
        delivery = jsonable_encoder(_build_resolution_event_payload(
            context=context, incident=incident, recommendation=recommendation,
            decision_payload=decision_payload))
        await repo.enqueue_resolution_event(
            event_id=delivery["event_contract"]["event_id"],
            tenant_id=context.tenant_id, aggregate_id=str(incident.id),
            topic=RESOLUTION_EVENTS, partition_key=str(incident.id),
            payload=delivery, available_after_seconds=0,
        )

        await session.commit()
    knowledge_id = str(context.metadata.get("context_knowledge_id") or "").strip()
    if not knowledge_id:
        CONTEXT_KNOWLEDGE_OPERATIONS.labels("attach_resolution", "not_linked").inc()
        return
    quality_score = _resolution_quality_score(recommendation.model_dump(mode="json"))
    if (
        not bool(getattr(settings, "context_resolution_reuse_enabled", True))
        or quality_score <= _resolution_reuse_threshold()
    ):
        CONTEXT_KNOWLEDGE_OPERATIONS.labels("attach_resolution", "below_threshold").inc()
        return
    try:
        async with app.state.session_factory() as session:
            repo = IncidentRepository(session)
            attached = await repo.attach_context_knowledge_resolution(
                knowledge_id,
                recommendation.model_dump(mode="json"),
            )
            await session.commit()
        CONTEXT_KNOWLEDGE_OPERATIONS.labels("attach_resolution", "success" if attached else "not_found").inc()
    except Exception:
        CONTEXT_KNOWLEDGE_OPERATIONS.labels("attach_resolution", "error").inc()


async def _bootstrap_resolution_catalog(
    *, context: Context, incident: Incident, recommendation: Recommendation,
) -> dict[str, Any]:
    """Hand every completed analysis to the event-driven knowledge workflow."""
    token = str(getattr(settings, "ai_layer_auth_token", "") or "").strip()
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    url = f"{str(settings.knowledge_development_url).rstrip('/')}/incidents/bootstrap"
    async with httpx.AsyncClient(timeout=httpx.Timeout(20.0), headers=headers) as client:
        response = await client.post(url, json={
            "incident": incident.model_dump(mode="json"),
            "context": context.model_dump(mode="json"),
            "recommendation": recommendation.model_dump(mode="json"),
        })
        response.raise_for_status()
        result = response.json()
        return result if isinstance(result, dict) else {}


async def _refresh_context_to_latest_snapshot(context: Context) -> Context | None:
    """Re-fetch the incident's current context snapshot as a live Context.

    Investigation takes real wall-clock time (the LLM call alone can run
    several seconds); if fresh evidence lands while it's in flight, the
    snapshot this attempt was bound to is no longer the latest one, and
    persistence correctly refuses to bind an RCA to stale evidence. Retrying
    with the *same* payload can never succeed - it keeps re-checking the same
    now-stale snapshot_id. Returns None if no snapshot is available to bind
    to (fails closed; the caller falls through to the existing error path).
    """
    if not settings.database_enabled or getattr(app.state, "session_factory", None) is None:
        return None
    async with app.state.session_factory() as session:
        latest = await IncidentRepository(session).latest_context_snapshot(
            str(context.incident_id), tenant_id=context.tenant_id,
        )
    if latest is None or not isinstance(latest.get("context"), dict) or not latest["context"]:
        return None
    try:
        refreshed = Context.model_validate(latest["context"])
        if refreshed.tenant_id != context.tenant_id or refreshed.incident_id != context.incident_id:
            return None
        # A newer snapshot supplies evidence, not ownership of this analysis.
        # Taking its request ID collides with another immutable recommendation.
        metadata = dict(refreshed.metadata)
        for key in ("analysis_request_id", "analysis_mode", "force_full_analysis", "regeneration_requested", "regenerated_from_alert_id"):
            if key in context.metadata:
                metadata[key] = context.metadata[key]
        return refreshed.model_copy(update={"metadata": metadata})
    except Exception:
        return None


async def _initial_snapshot_for_replay(context: Context):
    try:
        return context, await _require_context_snapshot_binding(context)
    except HTTPException as exc:
        if exc.status_code != 409 or exc.detail != "the bound context snapshot has expired":
            raise
        refreshed = await _refresh_context_to_latest_snapshot(context)
        if refreshed is None:
            raise
        # Refresh evidence, never its TTL or the analysis request identity.
        # The replacement must pass every ordinary scope/fingerprint/expiry check.
        try:
            return refreshed, await _require_context_snapshot_binding(refreshed)
        except HTTPException as replacement_error:
            if (replacement_error.status_code != 409
                    or replacement_error.detail != "the bound context snapshot has expired"
                    or context.metadata.get("context_delivery_lane") != "initial"):
                raise
            # A delayed first investigation must collect new observations,
            # never extend the lifetime of old evidence or recycle its TTL.
            async with app.state.session_factory() as session:
                incident = await IncidentRepository(session).get_incident(
                    str(context.incident_id), tenant_id=context.tenant_id,
                )
            if not incident:
                raise
            scoped_incident = {key: value for key, value in incident.items() if key in Incident.model_fields}
            async with httpx.AsyncClient(timeout=httpx.Timeout(90)) as client:
                response = await client.post(
                    f"{settings.context_agent_url.rstrip('/')}/collect",
                    params={"publish_events": "false"},
                    headers={"x-kaiops-internal-token": settings.service_internal_token},
                    json={"alert": context.alert.model_dump(mode="json"), "incident": scoped_incident,
                          "context_strategy": "realtime"},
                )
                response.raise_for_status()
            collected = Context.model_validate(response.json())
            if collected.tenant_id != context.tenant_id or collected.incident_id != context.incident_id:
                raise ValueError("recollected evidence identity mismatch")
            metadata = dict(collected.metadata)
            for key in ("analysis_request_id", "analysis_mode", "force_full_analysis", "context_delivery_lane"):
                if key in context.metadata:
                    metadata[key] = context.metadata[key]
            collected = collected.model_copy(update={"metadata": metadata})
            return collected, await _require_context_snapshot_binding(collected)


async def _completed_analysis_for_replay(context: Context):
    """Reuse a committed immutable generation when its event is redelivered."""
    from common.database import AuditLogRecord, ContextSnapshotRecord, IncidentInvestigationBindingRecord
    if not settings.database_enabled or getattr(app.state, "session_factory", None) is None:
        return None
    recommendation_id = _deterministic_recommendation_id(context)
    async with app.state.session_factory() as session:
        binding = await session.get(IncidentInvestigationBindingRecord, recommendation_id)
        if binding is None:
            return None
        if (binding.tenant_id != context.tenant_id or binding.incident_id != context.incident_id
                or str(binding.analysis_request_id) != str(context.metadata.get("analysis_request_id"))):
            raise ValueError("completed analysis replay identity mismatch")
        audit = await session.get(AuditLogRecord, recommendation_id)
        snapshot = await session.get(ContextSnapshotRecord, binding.context_snapshot_id)
        if (audit is None or snapshot is None or audit.tenant_id != context.tenant_id
                or snapshot.tenant_id != context.tenant_id or str(snapshot.incident_id) != str(context.incident_id)):
            raise ValueError("completed analysis replay evidence is unavailable")
        recommendation = Recommendation.model_validate(audit.payload)
        if recommendation.incident_id != context.incident_id or recommendation.tenant_id != context.tenant_id:
            raise ValueError("completed analysis replay recommendation mismatch")
        _validate_recommendation_snapshot_evidence(recommendation, snapshot)
        bound_context = Context.model_validate(snapshot.payload)
        return bound_context, recommendation


async def startup(app: FastAPI) -> None:
    workers = max(1, int(getattr(settings, "message_bus_worker_count", 1) or 1))
    consumers: list[tuple[str, Any, ConsumeRunner]] = []
    # One reserved worker handles first investigations. It uses the same
    # handler, evidence gates, retry contract and shared analysis budget.
    consumers.append(("rabbitmq-initial", RabbitMQConsumer(settings, INITIAL_CONTEXT_EVENTS),
                      consume_rabbitmq_forever))
    for worker in range(workers):
        consumers.append(
            (f"rabbitmq-w{worker + 1}", RabbitMQConsumer(settings, CONTEXT_EVENTS), consume_rabbitmq_forever)
        )
    if settings.queue_backlog_enabled:
        # One bounded recovery slot prevents parked work waiting behind a
        # constantly replenished active FIFO. It shares the ordinary handler,
        # retries and DLQ, and does not subscribe to fresh topic publications.
        consumers.append(("rabbitmq-deferred", RabbitMQConsumer(settings, CONTEXT_EVENTS, deferred=True),
                          consume_rabbitmq_forever))
    if settings.kafka_enabled and MESSAGE_BUS_DUAL_CONSUME_ENABLED:
        for worker in range(workers):
            consumers.insert(
                worker,
                (f"kafka-w{worker + 1}", KafkaConsumer(settings, CONTEXT_EVENTS), consume_kafka_forever),
            )

    async def handle_attempt(payload: dict) -> None:
        context = Context.model_validate(payload["context"])
        incident = Incident.model_validate(payload["incident"])
        request_id = str(context.metadata.get("analysis_request_id") or "").strip()
        completed = await _completed_analysis_for_replay(context)
        if completed is not None:
            bound_context, recommendation = completed
            decision = payload.get("decision") if isinstance(payload.get("decision"), dict) else {}
            # Repair a potentially interrupted downstream handoff, without
            # recomputing or overwriting the committed immutable analysis.
            await _persist_resolution_event(app=app, context=bound_context, incident=incident,
                recommendation=recommendation, decision_payload=decision)
            if not settings.database_enabled:
                await app.state.producer.publish(RESOLUTION_EVENTS, _build_resolution_event_payload(
                    context=bound_context, incident=incident, recommendation=recommendation,
                    decision_payload=decision), key=str(context.incident_id))
            EVENTS_PROCESSED.labels(settings.service_name, CONTEXT_EVENTS, "ok").inc()
            return
        if settings.database_enabled:
            from common.analysis_admission import retire_ineligible_analysis
            async with app.state.session_factory() as session:
                retired = await retire_ineligible_analysis(
                    session, context.alert, incident, request_id or None, actor="resolution-agent",
                )
                if not retired and request_id:
                    await IncidentRepository(session).mark_analysis_request_progress(
                        request_id, tenant_id=context.tenant_id, stage="running",
                    )
                await session.commit()
            if retired:
                logger.info("Queued RCA retired before model work", extra={"incident_id": str(incident.id), "reason": retired})
                return
            try:
                snapshot_id = UUID(str(context.metadata.get("context_snapshot_id") or ""))
                analysis_id = UUID(str(context.metadata.get("analysis_request_id") or ""))
            except ValueError:
                pass  # Ordinary snapshot validation below reports invalid input.
            else:
                async with app.state.session_factory() as session:
                    successor = await IncidentRepository(session).coalesce_superseded_background_rca(
                        tenant_id=context.tenant_id, incident_id=context.incident_id,
                        snapshot_id=snapshot_id, request_id=analysis_id,
                    )
                    await session.commit()
                if successor:
                    logger.info("coalesced obsolete background RCA incident_id=%s request_id=%s successor=%s",
                                context.incident_id, analysis_id, successor)
                    EVENTS_PROCESSED.labels(settings.service_name, CONTEXT_EVENTS, "coalesced").inc()
                    return
        context, initial_snapshot = await _initial_snapshot_for_replay(context)
        # Context-agent's progressive enrichment can publish several
        # successive newer snapshots for the same incident within seconds.
        # Running the full iterative investigation (tens of seconds of real
        # tool calls) against a snapshot already known stale only guarantees
        # it gets discarded by the supersede check in
        # save_recommendation_as_audit once it finally finishes - reproduced
        # live as a genuine livelock (8 distinct investigation attempts for
        # one incident within 35 seconds, none reaching a terminal state,
        # because each took longer to run than the interval between new
        # snapshots). Refresh to whatever snapshot is actually latest right
        # now and proceed with THAT instead of paying the wasted cost.
        #
        # A first version of this fix bailed out here with a silent `return`
        # instead of refreshing - which avoided the wasted investigation but
        # broke a different guarantee: whatever triggered this `handle()`
        # call (an operator's "Refresh analysis", or this session's own bulk
        # reprocessing) has an `analysis_requests` row already marked
        # "published", and nothing else ever advances it to "complete" - a
        # silent early return meant that row, and the operator's request,
        # was abandoned forever with zero completion signal. Reproduced
        # live: reprocessing 50 real incidents at once left exactly the 8
        # whose snapshots were already superseded before their trigger even
        # started stuck at "published" indefinitely, while the other 42
        # completed normally. `handle()` must always drive toward one of its
        # own real terminal outcomes (a persisted recommendation, or the
        # existing supersede-retry-exhausted `raise`), never a bare `return`.
        if settings.database_enabled and getattr(app.state, "session_factory", None) is not None:
            async with app.state.session_factory() as session:
                still_latest = await IncidentRepository(session).is_latest_context_snapshot(
                    initial_snapshot["snapshot_id"], tenant_id=context.tenant_id, incident_id=context.incident_id,
                )
            if not still_latest:
                refreshed = await _refresh_context_to_latest_snapshot(context)
                if refreshed is not None:
                    logger.info(
                        "context snapshot already superseded before investigation started, "
                        "continuing with the latest snapshot instead incident_id=%s "
                        "stale_snapshot_id=%s",
                        context.incident_id, initial_snapshot["snapshot_id"],
                    )
                    context = refreshed
                    initial_snapshot = await _require_context_snapshot_binding(context)
        context = await _bind_next_rca_version(context)
        decision_payload = payload.get("decision", {}) if isinstance(payload.get("decision"), dict) else {}
        investigated_context, investigation_report = await investigate_context(context)
        context = investigated_context
        recommendation = await _resolve_context(context)
        recommendation.trace_id = str(incident.trace_id or context.alert.trace_id or "") or None
        recommendation.metadata["rag_documents"] = context.metadata.get("rag_documents", 0)
        recommendation.metadata["rag_matches"] = context.metadata.get("rag_matches", [])
        recommendation.metadata["rag_top_similarity"] = context.metadata.get("rag_top_similarity", 0.0)
        recommendation.metadata["rag_service_tagged_match"] = context.metadata.get("rag_service_tagged_match", False)
        recommendation.metadata["discovery_report"] = context.metadata.get("discovery_report", {})
        recommendation.metadata["discovery_evidence"] = context.metadata.get("discovery_evidence", {})
        recommendation.metadata["runbook_found"] = bool(context.runbook)
        # Apply the reviewed catalog even on direct RCA reruns and legacy
        # messages whose orchestration decision predates execution-plan v2.
        catalog_plan = _apply_catalog_plan(recommendation, context, decision_payload)
        policy_version = str(decision_payload.get("policy_version") or "").strip()
        policy_reason = str(decision_payload.get("policy_reason") or "").strip()
        if policy_version:
            recommendation.metadata["policy_version"] = policy_version
        if policy_reason:
            recommendation.metadata["policy_reason"] = policy_reason
        if decision_payload:
            recommendation.metadata["orchestration_decision"] = {
                "workflow": decision_payload.get("workflow"),
                "requires_approval": decision_payload.get("requires_approval"),
                "message_bus_provider": decision_payload.get("message_bus_provider"),
                "stream_count": decision_payload.get("stream_count"),
                "stream_threshold": decision_payload.get("stream_threshold"),
                "execution_plan_fingerprint": catalog_plan.get("plan_fingerprint")
                if isinstance(catalog_plan, dict)
                else None,
            }
        context = await _commit_investigation_recommendation(
            context, investigation_report, initial_snapshot["snapshot_id"], recommendation, decision_payload,
        )
        await _persist_resolution_event(
            app=app,
            context=context,
            incident=incident,
            recommendation=recommendation,
            decision_payload=decision_payload,
        )
        try:
            await _bootstrap_resolution_catalog(
                context=context, incident=incident, recommendation=recommendation,
            )
        except Exception as exc:
            # The recommendation is already durable. Periodic knowledge
            # development provides recovery without failing the RCA request.
            logger.warning(
                "resolution catalog bootstrap deferred incident_id=%s error=%s",
                incident.id, str(exc)[:500],
            )
        payload_out = _build_resolution_event_payload(
            context=context,
            incident=incident,
            recommendation=recommendation,
            decision_payload=decision_payload,
        )
        if not settings.database_enabled:
            await app.state.producer.publish(RESOLUTION_EVENTS, payload_out, key=str(context.incident_id))
        EVENTS_PROCESSED.labels(settings.service_name, CONTEXT_EVENTS, "ok").inc()

    async def handle(payload: dict) -> None:
        from resolution_agent.snapshot_retry import run_with_snapshot_refresh

        async def refresh_payload(current: dict) -> dict | None:
            refreshed = await _refresh_context_to_latest_snapshot(Context.model_validate(current["context"]))
            return {**current, "context": refreshed.model_dump(mode="json")} if refreshed is not None else None

        # Include final snapshot persistence as well as recommendation commit
        # in the same retry boundary. No transaction remains open on retry.
        await run_with_snapshot_refresh(payload, handle_attempt, refresh_payload)

    async def record_terminal_failure(payload: dict[str, Any], error: str) -> None:
        context_payload = payload.get("context") if isinstance(payload.get("context"), dict) else {}
        metadata = context_payload.get("metadata") if isinstance(context_payload.get("metadata"), dict) else {}
        decision = payload.get("decision") if isinstance(payload.get("decision"), dict) else {}
        request_id = str(metadata.get("analysis_request_id") or decision.get("analysis_request_id") or "").strip()
        tenant_id = str(context_payload.get("tenant_id") or "").strip()
        if not request_id or not tenant_id or not settings.database_enabled:
            return
        async with app.state.session_factory() as session:
            await IncidentRepository(session).fail_analysis_request(
                request_id, tenant_id=tenant_id, reason=error,
            )
            await session.commit()

    for source, consumer, consume_forever in consumers:
        runner = (
            consume_forever(consumer, handle, record_terminal_failure)
            if source.startswith("rabbitmq")
            else consume_forever(consumer, handle)
        )
        task = asyncio.create_task(runner, name=f"resolution-agent-{source}-consumer")
        tasks.append(task)


async def shutdown(_: FastAPI) -> None:
    for task in tasks:
        task.cancel()


app = create_app(title="KaiMS Resolution Intelligence Agent", settings=settings, startup=startup, shutdown=shutdown)


class ResolutionCatalogRequest(BaseModel):
    tenant_id: str
    incident_id: UUID
    alert_id: UUID
    analysis_request_id: UUID
    recommendation_id: UUID
    rca_version: int = Field(ge=1)
    context_snapshot_id: UUID
    context_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    issue: str
    service: str = "unknown"
    environment: str = "unknown"
    recommended_action: str = ""


class ResolutionSelectionRequest(BaseModel):
    tenant_id: str
    incident_id: UUID
    alert_id: UUID
    analysis_request_id: UUID
    recommendation_id: UUID
    rca_version: int = Field(ge=1)
    context_snapshot_id: UUID
    context_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    resolution_plan_id: UUID | None = None
    plan_fingerprint: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")
    option_id: str
    issue: str
    service: str = "unknown"
    environment: str = "unknown"
    actor: str


async def _require_catalog_readiness(request: ResolutionCatalogRequest | ResolutionSelectionRequest) -> dict[str, Any]:
    tenant_id = require_tenant_id(request.tenant_id, source="resolution catalog readiness")
    if not settings.database_enabled or getattr(app.state, "session_factory", None) is None:
        raise HTTPException(
            status_code=503,
            detail={
                "code": "readiness_store_unavailable",
                "blocking_reasons": ["investigation persistence is unavailable"],
            },
        )
    async with app.state.session_factory() as session:
        repository = IncidentRepository(session)
        current = await repository.current_incident_investigation_binding(
            tenant_id=tenant_id, incident_id=request.incident_id, alert_id=request.alert_id,
        )
        if current is None:
            raise HTTPException(
                status_code=409,
                detail={
                    "code": "investigation_binding_missing",
                    "blocking_reasons": ["no current incident investigation binding exists"],
                },
            )
        if current["recommendation_id"] != str(request.recommendation_id):
            raise HTTPException(
                status_code=409,
                detail={
                    "code": "stale_recommendation",
                    "blocking_reasons": ["recommendation is not the incident projection's current version"],
                },
            )
        bound = await repository.get_bound_incident_investigation(
            tenant_id=tenant_id,
            incident_id=request.incident_id,
            alert_id=request.alert_id,
            recommendation_id=request.recommendation_id,
        )
    integrity = bound.get("investigation_integrity") if isinstance(bound.get("investigation_integrity"), dict) else {}
    if integrity.get("verified") is not True:
        raise HTTPException(status_code=409, detail={
            "code": f"investigation_{integrity.get('status') or 'invalid'}",
            "blocking_reasons": integrity.get("blocking_reasons") or ["investigation integrity is not verified"],
        })
    recommendation = bound.get("recommendation") if isinstance(bound.get("recommendation"), dict) else {}
    metadata = recommendation.get("metadata") if isinstance(recommendation.get("metadata"), dict) else {}
    identity_mismatches = []
    if metadata.get("service") and metadata["service"] != request.service:
        identity_mismatches.append("target service does not match")
    if metadata.get("environment") and metadata["environment"] != request.environment:
        identity_mismatches.append("target environment does not match")
    if str(metadata.get("analysis_request_id") or "") != str(request.analysis_request_id):
        identity_mismatches.append("analysis request does not match")
    if str(metadata.get("context_snapshot_id") or "") != str(request.context_snapshot_id):
        identity_mismatches.append("context snapshot does not match")
    if str(metadata.get("context_fingerprint") or "") != request.context_fingerprint:
        identity_mismatches.append("context fingerprint does not match")
    try:
        persisted_rca_version = int(metadata.get("rca_version") or 0)
    except (TypeError, ValueError):
        persisted_rca_version = 0
    if persisted_rca_version != request.rca_version:
        identity_mismatches.append("RCA version does not match")
    if identity_mismatches:
        raise HTTPException(
            status_code=409,
            detail={"code": "stale_investigation_binding", "blocking_reasons": identity_mismatches},
        )
    blocks = _investigation_readiness_blocks(metadata)
    if blocks:
        raise HTTPException(status_code=409, detail={"code": "resolution_not_ready", "blocking_reasons": blocks})
    return bound


def _investigation_readiness_blocks(metadata: dict[str, Any]) -> list[str]:
    """Blocking reasons preventing catalog selection for a recommendation's metadata.

    `investigation_report` is a coverage/crawl-steps summary and has never
    carried `conclusive`/`status` fields -- the actual investigator verdict
    (IterativeInvestigator's conclusive/status/outcome) lives under
    `iterative_investigation`. Reading only `investigation_report` here made
    `investigation.get("conclusive")` permanently None for every incident in
    the system's history, so this gate rejected every single recommendation
    as "investigation is not conclusive" regardless of how well-grounded the
    RCA actually was -- meaning /resolution-catalog/select could never
    succeed for any incident, ever. repository.py's equivalent readiness
    computation already prefers `iterative_investigation` first (falling
    back to `investigation_report` only when it is absent) -- mirror that here.
    """
    analysis = metadata.get("rca_analysis") if isinstance(metadata.get("rca_analysis"), dict) else {}
    investigation = (
        metadata.get("iterative_investigation")
        if isinstance(metadata.get("iterative_investigation"), dict)
        else metadata.get("investigation_report")
        if isinstance(metadata.get("investigation_report"), dict)
        else {}
    )
    accepted = metadata.get("evidence_ids") if isinstance(metadata.get("evidence_ids"), list) else []
    blocks = []
    if investigation.get("conclusive") is not True or str(investigation.get("status") or "").lower() != "conclusive":
        blocks.append("investigation is not conclusive")
    if str(metadata.get("rca_status") or "").lower() != "grounded" or not accepted:
        blocks.append("RCA is not grounded in accepted evidence")
    if isinstance(analysis.get("missing_evidence"), list) and analysis["missing_evidence"]:
        blocks.append("declared evidence gaps remain")
    if isinstance(analysis.get("conflicting_evidence"), list) and analysis["conflicting_evidence"]:
        blocks.append("conflicting evidence remains unresolved")
    return blocks


@app.get("/investigations/{incident_id}")
async def latest_investigation(incident_id: str, tenant_id: str) -> dict[str, Any]:
    tenant_id = require_tenant_id(tenant_id, source="investigation query")
    if not settings.database_enabled or getattr(app.state, "session_factory", None) is None:
        raise HTTPException(status_code=503, detail="investigation persistence is unavailable")
    async with app.state.session_factory() as session:
        report = await IncidentRepository(session).latest_resolution_investigation(
            incident_id, tenant_id=tenant_id,
        )
    if report is None:
        raise HTTPException(status_code=404, detail="resolution investigation not found")
    return report


class ExecutionFailureRequest(BaseModel):
    incident_id: UUID
    action_id: UUID
    action_type: str
    target: str
    service: str = "unknown"
    environment: str = "prod"
    error: str
    execution_result: dict[str, Any] = Field(default_factory=dict)
    previous_recommendation: dict[str, Any] = Field(default_factory=dict)
    attempt: int = Field(default=1, ge=1)


@app.post("/reconsider-execution")
async def reconsider_execution(request: ExecutionFailureRequest) -> dict[str, Any]:
    """Produce a new recommendation after a failed executor attempt.

    The response always requires a fresh human approval; it never retries a
    mutating operation directly from failure feedback.
    """
    previous = request.previous_recommendation
    previous_metadata = previous.get("metadata", {}) if isinstance(previous.get("metadata"), dict) else {}
    failure = request.error.strip()
    platform = os.getenv("REMEDIATION_EXECUTION_PLATFORM", "kubernetes").strip().lower()
    safe_service = "".join(ch for ch in request.service if ch.isalnum() or ch in "_.-") or "unknown"
    if platform in {"docker", "docker-compose", "compose"}:
        project = os.getenv("REMEDIATION_COMPOSE_PROJECT", "kaiops_azure").strip()
        safe_project = "".join(ch for ch in project if ch.isalnum() or ch in "_.-") or "kaiops_azure"
        container = f"{safe_project}-{safe_service}-1"
        commands = [
            f"curl --fail --silent --show-error -X POST http://docker-socket-proxy:2375/containers/{container}/restart?t=30",
            f"curl --fail --silent --show-error --retry 15 --retry-connrefused --retry-delay 2 http://{safe_service}:8000/healthz",
        ]
        rationale = (
            f"The previous executor attempt failed ({failure}). Re-plan against the configured Docker Compose runtime."
        )
    else:
        namespace = str(previous_metadata.get("namespace") or "default")
        commands = [
            f"kubectl rollout undo deployment/{request.target} -n {namespace}",
            f"kubectl rollout status deployment/{request.target} -n {namespace} --timeout=180s",
        ]
        rationale = (
            f"The previous executor attempt failed ({failure}). Verify Jenkins tooling "
            "and cluster credentials before approving this revised Kubernetes plan."
        )
    # A failed execution is evidence, not authority to synthesize another live
    # command. Re-enter planning with a non-executable contract; the normal
    # catalog resolver must produce and bind the replacement plan.
    proposed_commands = commands
    commands = []
    recommendation_id = uuid4()
    recommendation = {
        "id": str(recommendation_id),
        "incident_id": str(request.incident_id),
        "root_cause": f"Execution of {request.action_type} failed: {failure}",
        "confidence": 0.8,
        "impact": "Incident remains unresolved until a corrected execution plan succeeds and recovery is validated.",
        "recommended_action": f"Reconsider and retry {request.action_type} with the corrected executor plan",
        "severity": str(previous.get("severity") or "warning"),
        "rationale": rationale,
        "commands": commands,
        "risk": "high",
        "metadata": {
            **previous_metadata,
            "execution_plan": {
                "schema_version": "kaims.execution-plan.v2",
                "commands": [],
                "scripts": [],
                "queries": [f"http://{safe_service}:8000/healthz"],
                "preflight_commands": [],
                "validation_commands": [],
                "rollback_commands": [],
                "mutating": False,
                "plan_kind": "diagnostic",
                "execution_ready": False,
                "readiness_blocks": ["failed execution requires catalog re-planning against fresh evidence"],
            },
            "model_proposed_execution_plan": {"commands": proposed_commands},
            "execution_reconsideration_attempt": request.attempt,
            "failed_action_id": str(request.action_id),
            "failure_feedback": failure,
            "auto_approved": False,
        },
    }
    return {
        "recommendation": recommendation,
        "incident": {
            "id": str(request.incident_id),
            "service": request.service,
            "environment": request.environment,
            "severity": recommendation["severity"],
        },
        "decision": {
            "flow_id": str(request.incident_id),
            "requires_approval": True,
            "execution_mode": "human_approval",
            "risk_tier": "high",
            "policy_reason": "A failed execution must be re-planned and approved before retry.",
        },
    }


@app.post("/resolution-catalog/relevant")
async def resolution_catalog(request: ResolutionCatalogRequest) -> dict[str, Any]:
    tenant_id = require_tenant_id(request.tenant_id, source="resolution catalog request")
    await _require_catalog_readiness(request)
    rows = relevant_resolutions(
        issue=request.issue, service=request.service, recommended_action=request.recommended_action
    )
    async with app.state.session_factory() as session:
        learned_records = (await session.execute(
            select(RunbookVersionRecord).where(
                RunbookVersionRecord.tenant_id == tenant_id,
                RunbookVersionRecord.approval_status == "approved",
            ).order_by(RunbookVersionRecord.last_validated_at.desc()).limit(200)
        )).scalars().all()
    learned = register_learned_runbooks(
        tenant_id=tenant_id,
        issue=request.issue,
        service=request.service,
        runbooks=[{
            "runbook_id": str(row.runbook_id), "version": row.version,
            "approval_status": row.approval_status, "risk_level": row.risk_level,
            "success_count": row.success_count, "failure_count": row.failure_count,
            "content": row.content or {},
        } for row in learned_records],
    )
    # A tenant-local recovery with a measured successful outcome is more
    # relevant than a generic discovery template. It still passes the current
    # incident readiness and execution-plan compilation gates below.
    rows = [*learned, *rows]
    best_relevance = float(rows[0].get("relevance") or 0.0) if rows else 0.0
    fallback = {"used": False, "cache_hit": False, "reason": None, "repository": "context-agent-rag", "error": None}
    if best_relevance < 0.35:
        fallback["reason"] = "No governed local option cleared the 0.35 relevance threshold."
        query = " ".join(
            part for part in (request.issue, request.service, request.recommended_action, "remediation runbook") if part
        ).strip()
        try:
            cache_key = f"{tenant_id}:" + " ".join(query.lower().split())
            cached = _GLOBAL_KNOWLEDGE_CACHE.get(cache_key)
            if cached and monotonic() - cached[0] < _GLOBAL_KNOWLEDGE_CACHE_TTL_SECONDS:
                matches = cached[1]
                fallback["cache_hit"] = True
            else:
                async with httpx.AsyncClient(timeout=httpx.Timeout(12.0)) as client:
                    response = await client.get(
                        f"{settings.context_agent_url.rstrip('/')}/rag/search",
                        params={"query": query, "limit": 6, "kind": "runbook", "tenant_id": tenant_id},
                    )
                    response.raise_for_status()
                    payload_matches = response.json().get("matches", [])
                matches = payload_matches if isinstance(payload_matches, list) else []
                if len(_GLOBAL_KNOWLEDGE_CACHE) >= _GLOBAL_KNOWLEDGE_CACHE_MAX_ENTRIES:
                    oldest_key = min(_GLOBAL_KNOWLEDGE_CACHE, key=lambda key: _GLOBAL_KNOWLEDGE_CACHE[key][0])
                    _GLOBAL_KNOWLEDGE_CACHE.pop(oldest_key, None)
                _GLOBAL_KNOWLEDGE_CACHE[cache_key] = (monotonic(), matches)
            knowledge_rows = register_global_knowledge(
                tenant_id=tenant_id,
                matches=matches if isinstance(matches, list) else [],
            )
            if knowledge_rows:
                rows = [*rows, *knowledge_rows]
                fallback["used"] = True
        except Exception as exc:
            fallback["error"] = str(exc)[:240]
    return {
        "rows": rows[:12],
        "catalog_size": len(RESOLUTION_CATALOG) + len(learned),
        "learned_matches": len(learned),
        "self_heal_matches": sum(bool(row.get("self_heal_eligible")) for row in learned),
        "local_best_relevance": best_relevance,
        "global_knowledge_fallback": fallback,
    }


def _selection_policy_decision(
    *, option: dict[str, Any], recommendation: dict[str, Any], environment: str,
) -> ResolutionPolicyDecision:
    """Real, risk-tiered auto-vs-human decision for an operator-selected catalog
    option - the only path in this service that ever produces a governed,
    executable plan (a model-proposed plan is advisory and can never execute
    regardless of this decision).

    Reuses `evaluate_resolution_policy` - the same engine every recommendation
    already runs through - rather than a second, parallel policy system.
    `canary_supported` has no equivalent field in a catalog option; a
    certified, learned, self_heal_eligible option (approved runbook, >=1
    verified prior success, zero failures - see catalog.register_learned_runbooks)
    stands in for it here, since a real supervised success is at least as
    strong a safety signal as a synthetic canary rollout would be. Every other
    catalog option (static, discovery, or global-knowledge sourced - never
    proven) always requires a human, regardless of the deployment override.
    """
    risk = str(option.get("risk") or "high").lower()
    if risk not in {"low", "medium", "high", "critical"}:
        risk = "high"
    self_heal_eligible = bool(option.get("self_heal_eligible"))
    successes = int(option.get("success_count") or 0)
    failures = int(option.get("failure_count") or 0)
    attempts = successes + failures
    # "approved" reflects platform review, not automatic-execution eligibility -
    # a built-in catalog entry is the platform's own reviewed content, and a
    # tenant-learned option only exists here because register_learned_runbooks
    # already filtered on RunbookVersionRecord.approval_status == "approved".
    # Only a global-knowledge-repository match (an external RAG fallback,
    # never platform- or tenant-reviewed) is genuinely unregistered - and
    # should be free to land on "block" if it lacks real validation/rollback,
    # exactly as it would have before this endpoint knew about policy at all.
    runbook_status = "unregistered" if option.get("source") == "global-knowledge-repository" else "approved"
    return evaluate_resolution_policy(
        ResolutionPolicyInput(
            environment=str(environment or "unknown").lower(),
            risk=risk,
            confidence=max(0.0, min(float(recommendation.get("confidence") or 0.0), 1.0)),
            runbook_status=runbook_status,
            runbook_success_rate=(successes / attempts) if attempts else 0.0,
            mutating=bool(option.get("steps")),
            reversible=bool(option.get("rollback")),
            canary_supported=self_heal_eligible,
            blast_radius="single-service",
            target_verified=bool(str(option.get("service") or "").strip() and option.get("service") != "unknown"),
            validation_available=bool(option.get("validation")),
            rollback_available=bool(option.get("rollback")),
            contradiction_count=0,  # already enforced by _require_catalog_readiness before this is reachable
            database_change=False,
            rca_conclusive=True,  # already enforced by _require_catalog_readiness before this is reachable
        ),
        auto_execution_enabled=settings.resolution_auto_execution_enabled,
    )


async def _auto_approve_selection(
    *, tenant_id: str, incident_id: UUID, recommendation_id: UUID,
    plan_id: Any, plan_fingerprint: Any, reason: str,
) -> None:
    """Programmatically calls approval-service's own /approve endpoint under
    the fixed policy-engine identity - the same call a human's "Approve"
    button makes, so every downstream consumer of the resulting
    incident.approval.recorded event behaves identically either way. Never
    called unless this deployment has RESOLUTION_AUTO_EXECUTION_ENABLED set
    (approval-service independently re-checks this and the approver/role/
    channel identity itself before accepting the request)."""
    async with httpx.AsyncClient(timeout=httpx.Timeout(10.0)) as client:
        response = await client.post(
            f"{settings.approval_service_url.rstrip('/')}/approve",
            headers={"x-kaiops-internal-token": settings.service_internal_token},
            json={
                "incident_id": str(incident_id),
                "recommendation_id": str(recommendation_id),
                "tenant_id": tenant_id,
                "plan_id": str(plan_id) if plan_id else None,
                "plan_fingerprint": str(plan_fingerprint) if plan_fingerprint else None,
                "approver": "kaims-auto-policy",
                "approver_role": "policy-engine",
                "channel": "policy-engine",
                "comment": f"Automatic approval: {reason}"[:500],
            },
        )
        response.raise_for_status()


@app.post("/resolution-catalog/auto-select")
async def automatically_select_resolution(
    request: ResolutionCatalogRequest, x_kaiops_internal_token: str = Header(default=""),
) -> dict[str, Any]:
    return await _prepare_certified_resolution(request, x_kaiops_internal_token, allow_hitl=False)


@app.post("/resolution-catalog/assist")
async def assist_resolution(
    request: ResolutionCatalogRequest, x_kaiops_internal_token: str = Header(default=""),
) -> dict[str, Any]:
    """Prepare a proven remedy for approval even when unattended execution is disabled."""
    return await _prepare_certified_resolution(request, x_kaiops_internal_token, allow_hitl=True)


async def _prepare_certified_resolution(
    request: ResolutionCatalogRequest, token: str, *, allow_hitl: bool,
) -> dict[str, Any]:
    from common.automatic_execution import automatic_execution_authorized
    from resolution_agent.automatic_selection import certified_option

    if not settings.service_internal_token or not hmac.compare_digest(token, settings.service_internal_token):
        raise HTTPException(status_code=403, detail="Internal service authentication failed")
    authorized = automatic_execution_authorized(settings, tenant=request.tenant_id,
                                                environment=request.environment, service=request.service)
    if not authorized and not allow_hitl:
        return {"status": "human_required", "reason": "automatic_execution_not_authorized_for_target"}
    bound = await _require_catalog_readiness(request)
    recommendation = bound.get("recommendation") or {}
    metadata = recommendation.get("metadata") or {}
    if metadata.get("service") != request.service or metadata.get("environment") != request.environment:
        return {"status": "human_required", "reason": "target_binding_mismatch"}
    catalog = await resolution_catalog(request)
    option = certified_option(catalog.get("rows") or [], service=request.service)
    if option is None and allow_hitl:
        from common.orchestration.compose_targets import compose_recovery_target
        target = compose_recovery_target(tenant=request.tenant_id,
            environment=request.environment, service=request.service)
        if target and target.get("catalog_option_id"):
            configured = prepare_resolution_plan(tenant_id=request.tenant_id,
                option_id=target["catalog_option_id"], issue=request.issue, service=request.service)
            if configured.get("source") == "kaims-governed-catalog-v1":
                option = configured  # Prepared for human review, never certified by configuration.
    if option is None:
        return {"status": "human_required", "reason": "no_unambiguous_certified_runbook"}
    prepared = prepare_resolution_plan(tenant_id=request.tenant_id, option_id=option["id"], issue=request.issue, service=request.service)
    policy = _selection_policy_decision(option=prepared, recommendation=recommendation, environment=request.environment)
    if policy.decision in {"block", "investigate"} or (policy.decision != "hotl" and not allow_hitl):
        return {"status": "human_required", "reason": policy.reason_codes}
    selection = ResolutionSelectionRequest(**request.model_dump(exclude={"recommended_action"}),
                                           option_id=option["id"], actor="kaims-auto-policy" if authorized and policy.decision == "hotl" else "kaims-resolution-assistant")
    result = await select_resolution(selection)
    if result.get("automatic_approval") == "deferred":
        raise HTTPException(status_code=503, detail="Compiled plan retained; automatic approval delivery requires retry")
    if result.get("automatic_approval") != "approved":
        if allow_hitl and (result.get("compilation") or {}).get("status") == "compiled":
            return {**result, "status": "awaiting_approval",
                    "reason": policy.reason_codes if policy.decision == "hitl" else ["automatic_execution_not_authorized_for_target"]}
        return {**result, "status": "human_required", "reason": "execution_plan_not_automatically_approved"}
    return {"status": "selected", **result}


@app.post("/resolution-catalog/select")
async def select_resolution(request: ResolutionSelectionRequest) -> dict[str, Any]:
    automatic_approval = "not_requested"
    tenant_id = require_tenant_id(request.tenant_id, source="resolution selection request")
    bound = await _require_catalog_readiness(request)
    try:
        option = prepare_resolution_plan(
            tenant_id=tenant_id,
            option_id=request.option_id,
            issue=request.issue,
            service=request.service,
        )
    except ValueError as exc:
        from fastapi import HTTPException

        raise HTTPException(status_code=404, detail=str(exc)) from exc
    async with app.state.session_factory() as session:
        repository = IncidentRepository(session)
        try:
            selection = await repository.persist_governed_resolution_selection(
                tenant_id=tenant_id,
                incident_id=request.incident_id,
                alert_id=request.alert_id,
                analysis_request_id=request.analysis_request_id,
                context_snapshot_id=request.context_snapshot_id,
                context_fingerprint=request.context_fingerprint,
                recommendation_id=request.recommendation_id,
                rca_version=request.rca_version,
                option=option,
                selected_by=request.actor,
            )
            recommendation = bound.get("recommendation") if isinstance(bound.get("recommendation"), dict) else {}
            metadata = recommendation.get("metadata") if isinstance(recommendation.get("metadata"), dict) else {}
            evidence_ids = [str(value) for value in metadata.get("evidence_ids", []) if str(value).strip()]
            policy_decision = _selection_policy_decision(
                option=option, recommendation=recommendation, environment=request.environment,
            )
            from common.automatic_execution import automatic_execution_authorized
            if policy_decision.decision == "hotl" and not automatic_execution_authorized(
                settings, tenant=tenant_id, environment=request.environment, service=request.service,
            ):
                policy_decision = policy_decision.model_copy(update={
                    "decision": "hitl", "reason_codes": ["automatic_execution_not_authorized_for_target"],
                })
            requires_approval = policy_decision.decision != "hotl"
            execution_mode = "human-approval" if requires_approval else "policy-engine-auto"
            source_context = ((bound.get("context_snapshot") or {}).get("context") or {})
            source_alert = source_context.get("alert") or {}
            alert = Alert(
                id=request.alert_id, tenant_id=tenant_id, source="resolution-selection",
                name=source_alert.get("name") or request.issue or "selected resolution", service=request.service,
                environment=request.environment, description=request.issue or request.option_id,
                metadata={"incident_id": str(request.incident_id)},
            )
            compiled = resolve_execution_plan(
                alert=alert, workflow_name="operator-resolution-selection", requires_approval=requires_approval,
                risk_tier=str(option.get("risk") or recommendation.get("risk") or "high"),
                execution_mode=execution_mode,
                resolution_hints=" ".join(filter(None, (
                    str(option.get("title") or option.get("name") or request.option_id),
                    str(option.get("description") or ""), str(recommendation.get("recommended_action") or ""),
                ))),
                evidence_basis=evidence_ids, incident_id=request.incident_id,
                root_cause=str(recommendation.get("root_cause") or "RCA not established"),
                confidence=float(recommendation.get("confidence") or 0.0),
            )
            compiled.update({
                "plan_id": uuid5(NAMESPACE_URL, f"execution-plan:{selection['selection_id']}"),
                "recommendation_id": request.recommendation_id,
                "recommendation_version": str(request.recommendation_id),
                "rca_version": request.rca_version,
                "evidence_snapshot_id": request.context_snapshot_id,
                "context_fingerprint": request.context_fingerprint,
                "resolution_selection_id": selection["selection_id"],
                "policy_version": "resolution-policy.v1",
                "policy_decision": policy_decision.model_dump(mode="json"),
            })
            if not requires_approval:
                compiled["approval_policy"] = {"decision": "policy_required", "required_approver_role": "policy-engine",
                                               "reason_codes": policy_decision.reason_codes}
            compiled = ExecutionPlanV2.model_validate(compiled).finalized().model_dump(mode="json")
            blocking_reasons = list(compiled.get("readiness_blocks") or [])
            execution_plan = await repository.persist_compiled_execution_plan(
                selection_id=selection["selection_id"], plan=compiled, blocking_reasons=blocking_reasons,
            )
            await session.commit()
            if not requires_approval and not blocking_reasons:
                # Reuses the exact same acceptance path a human's "Approve" click
                # goes through (save_approval + status update + the
                # incident.approval.recorded event every downstream consumer
                # already listens for) - a policy decision and a human decision
                # look identical to everything past this point. If this call
                # fails for any reason, the plan is simply left awaiting a human
                # approval exactly as it always was; auto-approval is additive,
                # never a substitute for the plan existing in a safe state.
                try:
                    await _auto_approve_selection(
                        tenant_id=tenant_id, incident_id=request.incident_id,
                        recommendation_id=request.recommendation_id,
                        plan_id=compiled.get("plan_id"), plan_fingerprint=compiled.get("plan_fingerprint"),
                        reason=", ".join(policy_decision.reason_codes),
                    )
                    automatic_approval = "approved"
                except Exception:
                    automatic_approval = "deferred"
                    logger.exception(
                        "policy-engine auto-approval failed for incident=%s selection=%s; leaving awaiting human approval",
                        request.incident_id, selection["selection_id"],
                    )
        except ValueError as exc:
            await session.rollback()
            raise HTTPException(
                status_code=409,
                detail={"code": "stale_or_invalid_resolution_selection", "blocking_reasons": [str(exc)]},
            ) from exc
    return {
        "selection": selection,
        "automatic_approval": automatic_approval,
        "compilation": {
            "status": "compiled" if execution_plan is not None else "blocked",
            "blocking_reasons": [] if execution_plan is not None else blocking_reasons,
        },
        "execution_plan": execution_plan,
    }


@app.post("/resolve", response_model=Recommendation)
async def resolve(context: Context, publish_events: bool = True) -> Recommendation:
    from resolution_agent.snapshot_retry import run_with_snapshot_refresh

    async def attempt(payload: dict) -> Recommendation:
        return await _resolve_attempt(Context.model_validate(payload), publish_events=publish_events)

    async def refresh(payload: dict) -> dict | None:
        latest = await _refresh_context_to_latest_snapshot(Context.model_validate(payload))
        return latest.model_dump(mode="json") if latest is not None else None

    return await run_with_snapshot_refresh(context.model_dump(mode="json"), attempt, refresh)


async def _resolve_attempt(context: Context, publish_events: bool = True) -> Recommendation:
    initial_snapshot = await _require_context_snapshot_binding(context)
    context = await _bind_next_rca_version(context)
    investigated_context, investigation_report = await investigate_context(context)
    context = investigated_context
    recommendation = await _resolve_context(context)
    recommendation.trace_id = str(context.alert.trace_id or "") or None
    recommendation.metadata["rag_documents"] = context.metadata.get("rag_documents", 0)
    recommendation.metadata["rag_matches"] = context.metadata.get("rag_matches", [])
    recommendation.metadata["rag_top_similarity"] = context.metadata.get("rag_top_similarity", 0.0)
    recommendation.metadata["rag_service_tagged_match"] = context.metadata.get("rag_service_tagged_match", False)
    recommendation.metadata["discovery_report"] = context.metadata.get("discovery_report", {})
    recommendation.metadata["discovery_evidence"] = context.metadata.get("discovery_evidence", {})
    recommendation.metadata["runbook_found"] = bool(context.runbook)
    context = await _commit_investigation_recommendation(
        context, investigation_report, initial_snapshot["snapshot_id"], recommendation,
    )
    synthetic_incident = Incident(
        id=context.incident_id,
        service=context.alert.service,
        severity=context.alert.severity,
        title=f"{context.alert.service}: {context.alert.name}",
    )
    payload_out = _build_resolution_event_payload(
        context=context,
        incident=synthetic_incident,
        recommendation=recommendation,
        decision_payload={},
    )
    # Temporal invokes this endpoint with publish_events=false because it owns
    # durable orchestration and must not create a second bus delivery. The
    # recommendation is still a business result and must always be persisted;
    # previously it was returned to Temporal and then lost from the incident
    # projection, leaving the cockpit permanently stuck at "RCA pending".
    await _persist_resolution_event(
        app=app,
        context=context,
        incident=synthetic_incident,
        recommendation=recommendation,
        decision_payload={},
    )
    try:
        await _bootstrap_resolution_catalog(
            context=context, incident=synthetic_incident, recommendation=recommendation,
        )
    except Exception as exc:
        logger.warning(
            "resolution catalog bootstrap deferred incident_id=%s error=%s",
            synthetic_incident.id, str(exc)[:500],
        )
    if publish_events:
        await app.state.producer.publish(RESOLUTION_EVENTS, payload_out)
    return recommendation
