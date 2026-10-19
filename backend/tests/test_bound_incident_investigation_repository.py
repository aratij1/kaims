from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from common.database import (
    ActionRecord,
    AlertRecord,
    AuditLogRecord,
    ContextSnapshotRecord,
    GovernedResolutionPlanRecord,
    IncidentInvestigationBindingRecord,
    IncidentProjectionRecord,
    IncidentRecord,
    ResolutionOutboxRecord,
    ResolutionPlanSupersessionRecord,
)
from common.repository import IncidentRepository
from sqlalchemy import func, select


async def _seed_pair(
    session,
    *,
    tenant_id: str,
    incident_id,
    alert_id,
    snapshot_id,
    recommendation_id,
    fingerprint: str,
    evidence_id: str,
    expires_at: datetime | None = None,
    rca_version: int = 1,
) -> None:
    now = datetime.now(UTC)
    analysis_request_id = uuid4()
    session.add(ContextSnapshotRecord(
        snapshot_id=snapshot_id,
        tenant_id=tenant_id,
        incident_id=str(incident_id),
        source_incident_id=str(incident_id),
        alert_signature="alert-signature",
        subject_fingerprint="b" * 64,
        context_fingerprint=fingerprint,
        contract_version="kaiops.context.v2",
        quality_score=0.9,
        reusable=True,
        source_manifest={},
        payload={
            "alert": {"id": str(alert_id), "service": "payments"},
            "metadata": {
                "alert_id": str(alert_id),
                "project_id": "payments",
                "context_quality": {
                    "coverage_score": 1.0, "freshness_score": 1.0,
                    "provenance_score": 1.0, "reusable": True,
                },
                "context_sources": {},
                "context_evidence": {
                    "telemetry": [{
                        "evidence_id": evidence_id, "category": "metrics",
                        "source_id": "prometheus", "connector": "prometheus",
                        "tenant_id": tenant_id, "project_id": "payments", "service": "payments",
                        "collected_at": now.isoformat(), "freshness": "fresh",
                        "provenance": {}, "citation": "prometheus://query/test",
                        "epistemic_role": "current_observation", "current_observation": True,
                    }],
                },
            },
        },
        collected_at=now - timedelta(minutes=1),
        expires_at=expires_at or now + timedelta(hours=1),
    ))
    session.add(AuditLogRecord(
        id=recommendation_id,
        tenant_id=tenant_id,
        actor="resolution-agent",
        action="recommendation.generated",
        resource_type="incident",
        resource_id=str(incident_id),
        payload={
            "id": str(recommendation_id),
            "incident_id": str(incident_id),
            "metadata": {
                "alert_id": str(alert_id),
                "project_id": "payments",
                "analysis_request_id": str(analysis_request_id),
                "context_snapshot_id": str(snapshot_id),
                "context_fingerprint": fingerprint,
                "evidence_ids": [evidence_id],
                "rca_version": rca_version,
                "rca_status": "grounded",
                "rca_analysis": {"evidence_used": [evidence_id], "missing_evidence": []},
                "investigation_report": {
                    "investigation_id": str(uuid4()), "status": "conclusive", "conclusive": True,
                },
                "execution_plan": {"execution_ready": False, "mutating": False, "readiness_blocks": []},
            },
        },
    ))
    session.add(IncidentInvestigationBindingRecord(
        binding_id=recommendation_id, tenant_id=tenant_id, project_id="payments",
        incident_id=incident_id, alert_id=alert_id, analysis_request_id=analysis_request_id,
        context_snapshot_id=snapshot_id, context_fingerprint=fingerprint,
        recommendation_id=recommendation_id, rca_version=rca_version, resolution_plan_id=None,
        plan_fingerprint=None, status="grounded", created_at=now,
        expires_at=expires_at or now + timedelta(hours=1),
    ))


@pytest.mark.asyncio
async def test_next_rca_version_uses_durable_incident_history(sqlite_session_factory) -> None:
    incident_id, alert_id = uuid4(), uuid4()
    async with sqlite_session_factory() as session:
        await _seed_pair(
            session, tenant_id="tenant-a", incident_id=incident_id, alert_id=alert_id,
            snapshot_id=uuid4(), recommendation_id=uuid4(), fingerprint="1" * 64,
            evidence_id="evidence-v1",
        )
        assert await IncidentRepository(session).next_incident_rca_version(
            tenant_id="tenant-a", incident_id=incident_id,
        ) == 2
        assert await IncidentRepository(session).next_incident_rca_version(
            tenant_id="tenant-a", incident_id=uuid4(),
        ) == 1


@pytest.mark.asyncio
async def test_bound_recommendation_keeps_its_snapshot_when_a_newer_snapshot_exists(
    sqlite_session_factory,
) -> None:
    incident_id, alert_id = uuid4(), uuid4()
    snapshot_v1, recommendation_v1 = uuid4(), uuid4()
    async with sqlite_session_factory() as session:
        await _seed_pair(
            session, tenant_id="tenant-a", incident_id=incident_id, alert_id=alert_id,
            snapshot_id=snapshot_v1, recommendation_id=recommendation_v1,
            fingerprint="1" * 64, evidence_id="evidence-v1",
        )
        session.add(ContextSnapshotRecord(
            snapshot_id=uuid4(), tenant_id="tenant-a", incident_id=str(incident_id),
            source_incident_id=str(incident_id), alert_signature="newer",
            subject_fingerprint="c" * 64, context_fingerprint="2" * 64,
            contract_version="kaiops.context.v2", quality_score=1.0, reusable=True,
            source_manifest={}, payload={}, collected_at=datetime.now(UTC),
            expires_at=datetime.now(UTC) + timedelta(hours=2),
        ))
        await session.commit()
        result = await IncidentRepository(session).get_bound_incident_investigation(
            tenant_id="tenant-a", incident_id=incident_id, alert_id=alert_id,
            recommendation_id=recommendation_v1,
        )

    assert result["investigation_integrity"]["status"] == "verified"
    assert result["context_snapshot"]["snapshot_id"] == str(snapshot_v1)


@pytest.mark.asyncio
async def test_processed_result_uses_projection_recommendation_snapshot_and_emits_integrity(
    sqlite_session_factory,
) -> None:
    incident_id, alert_id = uuid4(), uuid4()
    snapshot_v1, recommendation_v1 = uuid4(), uuid4()
    now = datetime.now(UTC)
    async with sqlite_session_factory() as session:
        await _seed_pair(
            session, tenant_id="tenant-a", incident_id=incident_id, alert_id=alert_id,
            snapshot_id=snapshot_v1, recommendation_id=recommendation_v1,
            fingerprint="1" * 64, evidence_id="evidence-v1",
        )
        session.add(AlertRecord(
            id=alert_id, tenant_id="tenant-a", source="prometheus", name="LatencyHigh",
            service="payments", environment="prod", severity="critical", fingerprint="alert-fp",
            payload={"id": str(alert_id), "tenant_id": "tenant-a", "project_id": "payments", "labels": {}},
        ))
        session.add(IncidentRecord(
            id=incident_id, tenant_id="tenant-a", service="payments", environment="prod",
            severity="critical", status="investigating", title="Payments latency", ticket_id=None,
            payload={"id": str(incident_id), "project_id": "payments", "alert_ids": [str(alert_id)]},
        ))
        session.add(IncidentProjectionRecord(
            incident_id=incident_id, alert_id=alert_id, recommendation_id=recommendation_v1,
            tenant_id="tenant-a", service="payments", environment="prod", severity="critical",
            status="investigating", first_seen_at=now, projection_payload={},
        ))
        legacy_action_id = uuid4()
        session.add(ActionRecord(
            id=legacy_action_id, tenant_id="tenant-a", incident_id=incident_id,
            recommendation_id=None, resolution_plan_id=None, plan_fingerprint=None,
            approval_id=None, action_type="restart", target="payments",
            idempotency_key=f"legacy-{legacy_action_id}", status="succeeded",
            payload={"id": str(legacy_action_id), "status": "succeeded"},
        ))
        session.add(ContextSnapshotRecord(
            snapshot_id=uuid4(), tenant_id="tenant-a", incident_id=str(incident_id),
            source_incident_id=str(incident_id), alert_signature="newer",
            subject_fingerprint="c" * 64, context_fingerprint="2" * 64,
            contract_version="kaiops.context.v2", quality_score=1.0, reusable=True,
            source_manifest={}, payload={"marker": "snapshot-v2"}, collected_at=now + timedelta(seconds=1),
            expires_at=now + timedelta(hours=2),
        ))
        await session.commit()
        result = await IncidentRepository(session).get_processed_result_by_alert_id(
            str(alert_id), tenant_id="tenant-a",
        )

    assert result is not None
    assert result["investigation_integrity"]["status"] == "verified"
    assert result["incident_investigation"]["context_snapshot_id"] == str(snapshot_v1)
    assert result["context"]["metadata"]["snapshot"]["snapshot_id"] == str(snapshot_v1)
    assert result["remediation_action"] == {}
    assert result["metrics"]["remediation_status"] == "unknown"
    assert result["legacy_lifecycle_records"][0]["record_id"] == str(legacy_action_id)
    assert result["legacy_lifecycle_records"][0]["status"] == "legacy_unbound"


@pytest.mark.asyncio
async def test_processed_result_prefers_newest_binding_over_stale_projection(
    sqlite_session_factory,
) -> None:
    incident_id, alert_id = uuid4(), uuid4()
    snapshot_v1, recommendation_v1 = uuid4(), uuid4()
    snapshot_v2, recommendation_v2 = uuid4(), uuid4()
    now = datetime.now(UTC)
    async with sqlite_session_factory() as session:
        await _seed_pair(
            session, tenant_id="tenant-a", incident_id=incident_id, alert_id=alert_id,
            snapshot_id=snapshot_v1, recommendation_id=recommendation_v1,
            fingerprint="1" * 64, evidence_id="evidence-v1",
            expires_at=now - timedelta(seconds=1), rca_version=1,
        )
        await _seed_pair(
            session, tenant_id="tenant-a", incident_id=incident_id, alert_id=alert_id,
            snapshot_id=snapshot_v2, recommendation_id=recommendation_v2,
            fingerprint="2" * 64, evidence_id="evidence-v2", rca_version=2,
        )
        session.add(AlertRecord(
            id=alert_id, tenant_id="tenant-a", source="prometheus", name="LatencyHigh",
            service="payments", environment="prod", severity="critical", fingerprint="alert-fp",
            payload={"id": str(alert_id), "tenant_id": "tenant-a", "project_id": "payments", "labels": {}},
        ))
        session.add(IncidentRecord(
            id=incident_id, tenant_id="tenant-a", service="payments", environment="prod",
            severity="critical", status="investigating", title="Payments latency", ticket_id=None,
            payload={"id": str(incident_id), "project_id": "payments", "alert_ids": [str(alert_id)]},
        ))
        session.add(IncidentProjectionRecord(
            incident_id=incident_id, alert_id=alert_id, recommendation_id=recommendation_v1,
            tenant_id="tenant-a", service="payments", environment="prod", severity="critical",
            status="investigating", first_seen_at=now, projection_payload={},
        ))
        await session.commit()
        result = await IncidentRepository(session).get_processed_result_by_alert_id(
            str(alert_id), tenant_id="tenant-a",
        )

    assert result is not None
    assert result["investigation_integrity"]["status"] == "verified"
    assert result["incident_investigation"]["recommendation_id"] == str(recommendation_v2)
    assert result["incident_investigation"]["context_snapshot_id"] == str(snapshot_v2)


@pytest.mark.asyncio
async def test_duplicate_occurrence_uses_canonical_incident_rca_binding(
    sqlite_session_factory,
) -> None:
    incident_id, canonical_alert_id, duplicate_alert_id = uuid4(), uuid4(), uuid4()
    snapshot_id, recommendation_id = uuid4(), uuid4()
    now = datetime.now(UTC)
    async with sqlite_session_factory() as session:
        await _seed_pair(
            session, tenant_id="tenant-a", incident_id=incident_id,
            alert_id=canonical_alert_id, snapshot_id=snapshot_id,
            recommendation_id=recommendation_id, fingerprint="3" * 64,
            evidence_id="canonical-evidence", rca_version=3,
        )
        session.add(AlertRecord(
            id=duplicate_alert_id, tenant_id="tenant-a", source="prometheus",
            name="LatencyHigh", service="payments", environment="prod",
            severity="critical", fingerprint="duplicate-fp",
            payload={"id": str(duplicate_alert_id), "labels": {"kaiops_incident_id": str(incident_id)}},
        ))
        session.add(IncidentRecord(
            id=incident_id, tenant_id="tenant-a", service="payments", environment="prod",
            severity="critical", status="investigating", title="Payments latency",
            payload={"id": str(incident_id), "alert_ids": [str(canonical_alert_id), str(duplicate_alert_id)]},
        ))
        session.add(IncidentProjectionRecord(
            incident_id=incident_id, alert_id=canonical_alert_id,
            recommendation_id=recommendation_id, tenant_id="tenant-a",
            service="payments", environment="prod", severity="critical",
            status="investigating", first_seen_at=now, projection_payload={},
        ))
        await session.commit()
        result = await IncidentRepository(session).get_processed_result_by_alert_id(
            str(duplicate_alert_id), tenant_id="tenant-a",
        )

    assert result is not None
    assert result["alert"]["id"] == str(duplicate_alert_id)
    assert result["incident"]["id"] == str(incident_id)
    assert result["incident_investigation"]["recommendation_id"] == str(recommendation_id)
    assert result["incident_investigation"]["context_snapshot_id"] == str(snapshot_id)
    assert result["incident_investigation"]["rca_version"] == 3
    assert result["investigation_integrity"]["status"] == "verified"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("mutation", "expected"),
    [
        ("fingerprint", "fingerprint_mismatch"),
        ("alert", "alert_mismatch"),
        ("evidence", "evidence_mismatch"),
        ("expired", "context_expired"),
    ],
)
async def test_bound_investigation_fails_closed(
    sqlite_session_factory, mutation: str, expected: str,
) -> None:
    incident_id, alert_id = uuid4(), uuid4()
    snapshot_id, recommendation_id = uuid4(), uuid4()
    async with sqlite_session_factory() as session:
        await _seed_pair(
            session, tenant_id="tenant-a", incident_id=incident_id, alert_id=alert_id,
            snapshot_id=snapshot_id, recommendation_id=recommendation_id,
            fingerprint="a" * 64, evidence_id="evidence-1",
            expires_at=(datetime.now(UTC) - timedelta(seconds=1)) if mutation == "expired" else None,
        )
        recommendation = await session.get(AuditLogRecord, recommendation_id)
        metadata = dict(recommendation.payload["metadata"])
        if mutation == "fingerprint":
            metadata["context_fingerprint"] = "f" * 64
        elif mutation == "alert":
            metadata["alert_id"] = str(uuid4())
        elif mutation == "evidence":
            metadata["evidence_ids"] = ["not-in-snapshot"]
        recommendation.payload = {**recommendation.payload, "metadata": metadata}
        await session.commit()
        result = await IncidentRepository(session).get_bound_incident_investigation(
            tenant_id="tenant-a", incident_id=incident_id, alert_id=alert_id,
            recommendation_id=recommendation_id,
        )

    assert result["investigation_integrity"]["status"] == expected
    assert result["investigation_integrity"]["verified"] is False
    assert result["context_snapshot"] == {}


def _catalog_option(option_id: str = "latency-kubernetes-diagnose") -> dict:
    return {
        "id": option_id,
        "source": "kaims-governed-catalog-v1",
        "service": "payments",
        "target_resource": "payments",
        "connector_id": "diagnostic-only",
        "risk": "low",
        "commands": [],
        "validation": ["Latency returns within SLO"],
        "rollback": ["No mutation is permitted before approval"],
        "execution_eligible": False,
        "requires_operator_review": True,
    }


@pytest.mark.asyncio
async def test_catalog_selection_persists_once_with_projection_audit_and_outbox(
    sqlite_session_factory,
) -> None:
    incident_id, alert_id, snapshot_id, recommendation_id = uuid4(), uuid4(), uuid4(), uuid4()
    async with sqlite_session_factory() as session:
        await _seed_pair(
            session, tenant_id="tenant-a", incident_id=incident_id, alert_id=alert_id,
            snapshot_id=snapshot_id, recommendation_id=recommendation_id,
            fingerprint="a" * 64, evidence_id="evidence-1",
        )
        binding = await session.get(IncidentInvestigationBindingRecord, recommendation_id)
        session.add(IncidentProjectionRecord(
            incident_id=incident_id, alert_id=alert_id, recommendation_id=recommendation_id,
            tenant_id="tenant-a", service="payments", environment="prod", severity="critical",
            status="investigating", first_seen_at=datetime.now(UTC), projection_payload={},
        ))
        await session.commit()
        repo = IncidentRepository(session)
        kwargs = dict(
            tenant_id="tenant-a", incident_id=incident_id, alert_id=alert_id,
            analysis_request_id=binding.analysis_request_id, context_snapshot_id=snapshot_id,
            context_fingerprint="a" * 64, recommendation_id=recommendation_id, rca_version=1,
            option=_catalog_option(), selected_by="operator-a",
        )
        first = await repo.persist_governed_resolution_selection(**kwargs)
        await session.commit()
        second = await repo.persist_governed_resolution_selection(**kwargs)
        await session.commit()

        assert second == first
        assert first["schema_version"] == "kaims.resolution-selection.v1"
        assert first["status"] == "selected"
        assert await session.scalar(select(func.count()).select_from(GovernedResolutionPlanRecord)) == 1
        assert await session.scalar(select(func.count()).select_from(ResolutionOutboxRecord)) >= 1
        projection = await session.get(IncidentProjectionRecord, incident_id)
        assert projection.projection_payload["resolution_selection"]["selection_id"] == first["selection_id"]
        assert "execution_plan" not in projection.projection_payload
        audit = await session.scalar(select(AuditLogRecord).where(AuditLogRecord.action == "resolution.plan.selected"))
        assert audit.payload["selection_id"] == first["selection_id"]


@pytest.mark.asyncio
async def test_new_catalog_option_creates_immutable_supersession_relation(sqlite_session_factory) -> None:
    incident_id, alert_id, snapshot_id, recommendation_id = uuid4(), uuid4(), uuid4(), uuid4()
    async with sqlite_session_factory() as session:
        await _seed_pair(
            session, tenant_id="tenant-a", incident_id=incident_id, alert_id=alert_id,
            snapshot_id=snapshot_id, recommendation_id=recommendation_id,
            fingerprint="b" * 64, evidence_id="evidence-1",
        )
        binding = await session.get(IncidentInvestigationBindingRecord, recommendation_id)
        session.add(IncidentProjectionRecord(
            incident_id=incident_id, alert_id=alert_id, recommendation_id=recommendation_id,
            tenant_id="tenant-a", service="payments", environment="prod", severity="critical",
            status="investigating", first_seen_at=datetime.now(UTC), projection_payload={},
        ))
        await session.commit()
        repo = IncidentRepository(session)
        base = dict(
            tenant_id="tenant-a", incident_id=incident_id, alert_id=alert_id,
            analysis_request_id=binding.analysis_request_id, context_snapshot_id=snapshot_id,
            context_fingerprint="b" * 64, recommendation_id=recommendation_id, rca_version=1,
            selected_by="operator-a",
        )
        first = await repo.persist_governed_resolution_selection(**base, option=_catalog_option("option-one"))
        await session.commit()
        second = await repo.persist_governed_resolution_selection(**base, option=_catalog_option("option-two"))
        await session.commit()
        relation = await session.scalar(select(ResolutionPlanSupersessionRecord))
        assert first["selection_id"] != second["selection_id"]
        assert str(relation.supersedes) == first["selection_id"]
        assert str(relation.superseded_by) == second["selection_id"]


@pytest.mark.asyncio
async def test_stale_catalog_selection_writes_nothing(sqlite_session_factory) -> None:
    incident_id, alert_id, snapshot_id, recommendation_id = uuid4(), uuid4(), uuid4(), uuid4()
    async with sqlite_session_factory() as session:
        await _seed_pair(
            session, tenant_id="tenant-a", incident_id=incident_id, alert_id=alert_id,
            snapshot_id=snapshot_id, recommendation_id=recommendation_id,
            fingerprint="c" * 64, evidence_id="evidence-1",
        )
        binding = await session.get(IncidentInvestigationBindingRecord, recommendation_id)
        session.add(IncidentProjectionRecord(
            incident_id=incident_id, alert_id=alert_id, recommendation_id=uuid4(),
            tenant_id="tenant-a", service="payments", environment="prod", severity="critical",
            status="investigating", first_seen_at=datetime.now(UTC), projection_payload={},
        ))
        await session.commit()
        with pytest.raises(ValueError, match="stale recommendation"):
            await IncidentRepository(session).persist_governed_resolution_selection(
                tenant_id="tenant-a", incident_id=incident_id, alert_id=alert_id,
                analysis_request_id=binding.analysis_request_id, context_snapshot_id=snapshot_id,
                context_fingerprint="c" * 64, recommendation_id=recommendation_id, rca_version=1,
                option=_catalog_option(), selected_by="operator-a",
            )
        await session.rollback()
        assert await session.scalar(select(func.count()).select_from(GovernedResolutionPlanRecord)) == 0
        assert await session.scalar(select(func.count()).select_from(ResolutionOutboxRecord)) == 0


@pytest.mark.asyncio
async def test_grounded_rca_advances_a_stalled_looking_incident_to_rca_ready(sqlite_session_factory) -> None:
    """Reproduced live across a 20-incident sample: 8 investigations reached
    "grounded" underneath while every one of their outer incidents still
    read "investigating" in every list view - the only other writer of
    IncidentRecord.status is a human/policy approval decision, so a
    genuinely completed RCA had zero operator-visible signal."""
    incident_id = uuid4()
    async with sqlite_session_factory() as session:
        session.add(IncidentRecord(
            id=incident_id, tenant_id="tenant-a", service="payments", environment="prod",
            severity="critical", status="investigating", title="Payments latency", ticket_id=None,
            payload={"id": str(incident_id), "project_id": "payments"},
        ))
        await session.commit()

        await IncidentRepository(session)._advance_incident_status_on_grounded_rca(
            incident_id=incident_id, tenant_id="tenant-a", rca_status="grounded",
        )
        await session.commit()

        incident = await session.get(IncidentRecord, incident_id)
        assert incident.status == "rca_ready"
        assert incident.payload["status"] == "rca_ready"


@pytest.mark.asyncio
async def test_insufficient_evidence_rca_never_touches_incident_status(sqlite_session_factory) -> None:
    incident_id = uuid4()
    async with sqlite_session_factory() as session:
        session.add(IncidentRecord(
            id=incident_id, tenant_id="tenant-a", service="payments", environment="prod",
            severity="critical", status="investigating", title="Payments latency", ticket_id=None,
            payload={"id": str(incident_id), "project_id": "payments"},
        ))
        await session.commit()

        await IncidentRepository(session)._advance_incident_status_on_grounded_rca(
            incident_id=incident_id, tenant_id="tenant-a", rca_status="insufficient_evidence",
        )
        await session.commit()

        incident = await session.get(IncidentRecord, incident_id)
        assert incident.status == "investigating"


@pytest.mark.asyncio
async def test_insufficient_evidence_rca_retreats_an_incident_from_rca_ready(sqlite_session_factory) -> None:
    """"rca_ready" claims the *current* analysis is grounded and ready to
    act on - unlike the approval/remediation statuses past it, nothing has
    actually been committed to yet, so leaving it sticky when a later
    regeneration comes back "insufficient_evidence" is actively misleading:
    an operator opening the incident sees "ready to resolve" for one whose
    own latest analysis just said otherwise. Reproduced live: incident
    fc99d4e6-687c-48e0-8b28-91f07a0cf49b reached "grounded" on RCA v1, then
    two later regenerations both came back "insufficient_evidence" -
    IncidentRecord.status stayed "rca_ready" throughout regardless.
    """
    incident_id = uuid4()
    async with sqlite_session_factory() as session:
        session.add(IncidentRecord(
            id=incident_id, tenant_id="tenant-a", service="payments", environment="prod",
            severity="critical", status="rca_ready", title="Payments latency", ticket_id=None,
            payload={"id": str(incident_id), "project_id": "payments", "status": "rca_ready"},
        ))
        await session.commit()

        await IncidentRepository(session)._advance_incident_status_on_grounded_rca(
            incident_id=incident_id, tenant_id="tenant-a", rca_status="insufficient_evidence",
        )
        await session.commit()

        incident = await session.get(IncidentRecord, incident_id)
        assert incident.status == "investigating"
        assert incident.payload["status"] == "investigating"


@pytest.mark.asyncio
async def test_insufficient_evidence_rca_never_retreats_an_incident_already_past_rca_ready(
    sqlite_session_factory,
) -> None:
    """Retreating only from exactly "rca_ready" (never from
    "awaiting_approval" or anything further along) preserves the existing,
    deliberate rule that real human/policy-engine progress must never be
    undone by a later regeneration."""
    incident_id = uuid4()
    async with sqlite_session_factory() as session:
        session.add(IncidentRecord(
            id=incident_id, tenant_id="tenant-a", service="payments", environment="prod",
            severity="critical", status="awaiting_approval", title="Payments latency", ticket_id=None,
            payload={"id": str(incident_id), "project_id": "payments"},
        ))
        await session.commit()

        await IncidentRepository(session)._advance_incident_status_on_grounded_rca(
            incident_id=incident_id, tenant_id="tenant-a", rca_status="insufficient_evidence",
        )
        await session.commit()

        incident = await session.get(IncidentRecord, incident_id)
        assert incident.status == "awaiting_approval"


@pytest.mark.asyncio
async def test_grounded_rca_never_regresses_an_incident_already_past_investigation(sqlite_session_factory) -> None:
    """A later, stale-arriving RCA version reaching "grounded" must never pull
    an incident that already has real approval/execution progress backward -
    this only ever moves a stalled-looking incident forward."""
    incident_id = uuid4()
    async with sqlite_session_factory() as session:
        session.add(IncidentRecord(
            id=incident_id, tenant_id="tenant-a", service="payments", environment="prod",
            severity="critical", status="awaiting_approval", title="Payments latency", ticket_id=None,
            payload={"id": str(incident_id), "project_id": "payments"},
        ))
        await session.commit()

        await IncidentRepository(session)._advance_incident_status_on_grounded_rca(
            incident_id=incident_id, tenant_id="tenant-a", rca_status="grounded",
        )
        await session.commit()

        incident = await session.get(IncidentRecord, incident_id)
        assert incident.status == "awaiting_approval"


@pytest.mark.asyncio
async def test_grounded_rca_advances_the_projection_the_triage_queue_actually_reads(
    sqlite_session_factory,
) -> None:
    """IncidentRecord and IncidentProjectionRecord are two independent
    tables. `_advance_incident_status_on_grounded_rca` mutates IncidentRecord
    directly, bypassing the incident-event stream that is
    IncidentProjectionRecord's only normal writer - so fixing only
    IncidentRecord.status left every UI view built on the projection (the
    Triage queue included) reading "investigating" forever, no matter how
    many times the RCA regenerated. Reproduced live: IncidentRecord.status
    correctly read "rca_ready" while IncidentProjectionRecord.status for the
    exact same incident still read "investigating".
    """
    incident_id = uuid4()
    async with sqlite_session_factory() as session:
        session.add(IncidentRecord(
            id=incident_id, tenant_id="tenant-a", service="payments", environment="prod",
            severity="critical", status="investigating", title="Payments latency", ticket_id=None,
            payload={"id": str(incident_id), "project_id": "payments"},
        ))
        session.add(IncidentProjectionRecord(
            incident_id=incident_id, tenant_id="tenant-a", service="payments",
            environment="prod", status="investigating", first_seen_at=datetime.now(UTC),
            projection_payload={},
        ))
        await session.commit()

        await IncidentRepository(session)._advance_incident_status_on_grounded_rca(
            incident_id=incident_id, tenant_id="tenant-a", rca_status="grounded",
        )
        await session.commit()

        projection = await session.get(IncidentProjectionRecord, incident_id)
        assert projection.status == "rca_ready"


@pytest.mark.asyncio
async def test_grounded_rca_advances_a_lagging_projection_even_when_the_incident_record_already_did(
    sqlite_session_factory,
) -> None:
    """The two tables can genuinely disagree: a prior run may have already
    advanced IncidentRecord.status to "rca_ready" (making it exit the early-
    return guard above every time since), while IncidentProjectionRecord -
    the table the Triage queue actually reads - never got the same update
    and is stuck on an older "investigating". A first attempt at this fix
    gated the projection update on the same guard as IncidentRecord's own,
    so it could never fire for exactly this - the only incidents actually
    stuck - case. The projection must be free to catch up independently.
    """
    incident_id = uuid4()
    async with sqlite_session_factory() as session:
        session.add(IncidentRecord(
            id=incident_id, tenant_id="tenant-a", service="payments", environment="prod",
            severity="critical", status="rca_ready", title="Payments latency", ticket_id=None,
            payload={"id": str(incident_id), "project_id": "payments", "status": "rca_ready"},
        ))
        session.add(IncidentProjectionRecord(
            incident_id=incident_id, tenant_id="tenant-a", service="payments",
            environment="prod", status="investigating", first_seen_at=datetime.now(UTC),
            projection_payload={},
        ))
        await session.commit()

        await IncidentRepository(session)._advance_incident_status_on_grounded_rca(
            incident_id=incident_id, tenant_id="tenant-a", rca_status="grounded",
        )
        await session.commit()

        projection = await session.get(IncidentProjectionRecord, incident_id)
        assert projection.status == "rca_ready"


@pytest.mark.asyncio
async def test_grounded_rca_never_regresses_a_projection_already_past_investigation(
    sqlite_session_factory,
) -> None:
    """A later, stale-arriving RCA version reaching "grounded" must never
    pull a projection that already has real approval/execution progress
    backward - mirrors the equivalent IncidentRecord-only guard above, now
    for the projection the Triage queue actually reads."""
    incident_id = uuid4()
    async with sqlite_session_factory() as session:
        session.add(IncidentRecord(
            id=incident_id, tenant_id="tenant-a", service="payments", environment="prod",
            severity="critical", status="awaiting_approval", title="Payments latency", ticket_id=None,
            payload={"id": str(incident_id), "project_id": "payments"},
        ))
        session.add(IncidentProjectionRecord(
            incident_id=incident_id, tenant_id="tenant-a", service="payments",
            environment="prod", status="approved", first_seen_at=datetime.now(UTC),
            projection_payload={},
        ))
        await session.commit()

        await IncidentRepository(session)._advance_incident_status_on_grounded_rca(
            incident_id=incident_id, tenant_id="tenant-a", rca_status="grounded",
        )
        await session.commit()

        projection = await session.get(IncidentProjectionRecord, incident_id)
        assert projection.status == "approved"


@pytest.mark.asyncio
async def test_grounded_rca_never_touches_a_different_tenants_incident(sqlite_session_factory) -> None:
    incident_id = uuid4()
    async with sqlite_session_factory() as session:
        session.add(IncidentRecord(
            id=incident_id, tenant_id="tenant-a", service="payments", environment="prod",
            severity="critical", status="investigating", title="Payments latency", ticket_id=None,
            payload={"id": str(incident_id), "project_id": "payments"},
        ))
        await session.commit()

        await IncidentRepository(session)._advance_incident_status_on_grounded_rca(
            incident_id=incident_id, tenant_id="tenant-b", rca_status="grounded",
        )
        await session.commit()

        incident = await session.get(IncidentRecord, incident_id)
        assert incident.status == "investigating"


@pytest.mark.asyncio
async def test_is_latest_context_snapshot_detects_a_snapshot_already_superseded(
    sqlite_session_factory,
) -> None:
    """resolution-agent's `handle()` uses this as a cheap pre-check before
    running the full iterative investigation (tens of seconds of real tool
    calls), rather than only discovering staleness after the fact via
    `save_recommendation_as_audit`'s own supersede guard. Context-agent's
    progressive enrichment can publish several successive newer snapshots
    for one incident within seconds, and reproduced live as a genuine
    livelock: 8 distinct investigation attempts for one incident within 35
    seconds, none reaching a terminal state, because each one took longer
    to run than the interval between new snapshots.
    """
    incident_id, tenant_id = uuid4(), "tenant-a"
    now = datetime.now(UTC)
    async with sqlite_session_factory() as session:
        older = uuid4()
        newer = uuid4()
        session.add(ContextSnapshotRecord(
            snapshot_id=older, tenant_id=tenant_id, incident_id=str(incident_id),
            alert_signature="signature", subject_fingerprint="s" * 64,
            context_fingerprint="a" * 64, contract_version="kaiops.context.v2",
            snapshot_version=1, quality_score=0.4, reusable=False,
            source_manifest={}, evidence_ids=[], payload={},
            collected_at=now, expires_at=now + timedelta(hours=1),
        ))
        session.add(ContextSnapshotRecord(
            snapshot_id=newer, tenant_id=tenant_id, incident_id=str(incident_id),
            alert_signature="signature", subject_fingerprint="s" * 64,
            context_fingerprint="b" * 64, contract_version="kaiops.context.v2",
            snapshot_version=2, quality_score=0.4, reusable=False,
            source_manifest={}, evidence_ids=[], payload={},
            collected_at=now + timedelta(seconds=1), expires_at=now + timedelta(hours=1),
        ))
        await session.commit()

        repo = IncidentRepository(session)
        assert await repo.is_latest_context_snapshot(
            older, tenant_id=tenant_id, incident_id=incident_id,
        ) is False
        assert await repo.is_latest_context_snapshot(
            newer, tenant_id=tenant_id, incident_id=incident_id,
        ) is True
        assert await repo.is_latest_context_snapshot(
            uuid4(), tenant_id=tenant_id, incident_id=incident_id,
        ) is False


@pytest.mark.asyncio
async def test_compact_incident_list_exposes_completed_analysis_blockers(sqlite_session_factory) -> None:
    incident_id, recommendation_id = uuid4(), uuid4()
    async with sqlite_session_factory() as session:
        session.add(IncidentRecord(
            id=incident_id, tenant_id="tenant-a", service="payments", environment="prod",
            severity="critical", status="investigating", title="Payments unavailable", payload={},
        ))
        session.add(IncidentProjectionRecord(
            incident_id=incident_id, tenant_id="tenant-a", service="payments",
            environment="prod", status="investigating", recommendation_id=recommendation_id,
            first_seen_at=datetime.now(UTC), projection_payload={},
        ))
        session.add(AuditLogRecord(
            id=recommendation_id, tenant_id="tenant-a", actor="resolution-agent",
            action="recommendation.generated", resource_type="incident", resource_id=str(incident_id),
            payload={"id": str(recommendation_id), "metadata": {
                "rca_status": "insufficient_evidence",
                "iterative_investigation": {"outcome": "INSUFFICIENT_EVIDENCE",
                    "completed_at": datetime.now(UTC).isoformat(),
                    "rca_result": {"missing_evidence": ["causal_corroboration"]}},
                "execution_plan": {"readiness_blocks": ["Approved recovery profile is missing"]},
                "large_evidence_payload": "must not be sent in compact response",
            }},
        ))
        await session.commit()
        repo = IncidentRepository(session)
        await repo._advance_incident_status_on_grounded_rca(
            incident_id=incident_id, tenant_id="tenant-a", rca_status="insufficient_evidence",
        )
        await session.commit()
        assert (await session.get(IncidentProjectionRecord, incident_id)).status == "investigating"
        rows = await repo.list_incident_projections(tenant_id="tenant-a", include_enrichment=False)
        row = next(r for r in rows if r["incident_id"] == str(incident_id))
        assert row["analysis_summary"]["rca_status"] == "insufficient_evidence"
        assert row["analysis_summary"]["blockers"] == ["Approved recovery profile is missing"]
        assert row["analysis_summary"]["missing_evidence"] == ["causal_corroboration"]
        assert row["recommendation"] == {}
        assert await repo.list_incident_projections(tenant_id="tenant-b", include_enrichment=False) == []


@pytest.mark.asyncio
async def test_rca_reservations_survive_sessions_and_do_not_reuse_unfinished_versions(sqlite_session_factory):
    iid, first, second = uuid4(), uuid4(), uuid4()
    async with sqlite_session_factory() as session:
        session.add(IncidentRecord(id=iid, tenant_id="tenant-a", service="api", environment="test",
            severity="warning", status="investigating", title="Reservation test", payload={}))
        await session.commit()
        repo = IncidentRepository(session)
        assert await repo.reserve_incident_rca_version(tenant_id="tenant-a", incident_id=iid, recommendation_id=first) == 1
        await session.commit()
    async with sqlite_session_factory() as session:
        repo = IncidentRepository(session)
        assert await repo.reserve_incident_rca_version(tenant_id="tenant-a", incident_id=iid, recommendation_id=second) == 2
        await session.commit()
        assert await repo.reserve_incident_rca_version(tenant_id="tenant-a", incident_id=iid, recommendation_id=first) == 1
        with pytest.raises(ValueError, match="existing scoped incident"):
            await repo.reserve_incident_rca_version(tenant_id="other", incident_id=iid, recommendation_id=uuid4())


@pytest.mark.asyncio
async def test_compact_projection_does_not_load_source_or_workflow_documents(sqlite_session_factory):
    from common.database import PendingWorkflowRecord
    from sqlalchemy import event
    iid, aid, rid = uuid4(), uuid4(), uuid4()
    async with sqlite_session_factory() as session:
        session.add(AlertRecord(id=aid, tenant_id="compact", source="prometheus", name="Latency", service="api",
            environment="prod", severity="high", payload={"project_id": "kaims", "evidence": "x" * 100000,
                "labels": {"operation": "/checkout", "method": "POST", "unrelated_payload": "not-returned"}}))
        session.add(IncidentProjectionRecord(incident_id=iid, alert_id=aid, tenant_id="compact", service="api",
            environment="prod", severity="high", status="investigating", first_seen_at=datetime.now(UTC), projection_payload={}))
        session.add(PendingWorkflowRecord(incident_id=iid, recommendation_id=rid, flow_id="flow-1", payload={"evidence": "x" * 100000}))
        await session.commit()
    async with sqlite_session_factory() as session:
        statements = []
        engine = session.bind.sync_engine
        def capture(conn, cursor, statement, parameters, context, many): statements.append(statement)
        event.listen(engine, "before_cursor_execute", capture)
        try:
            rows = await IncidentRepository(session).list_incident_projections(tenant_id="compact", include_enrichment=False)
        finally:
            event.remove(engine, "before_cursor_execute", capture)
        assert rows[0]["flow_id"] == "flow-1"
        assert rows[0]["title"] == "Latency"
        assert rows[0]["alert_id"] == str(aid)
        assert rows[0]["operation"] == "/checkout"
        assert rows[0]["source_alert"] == {"labels": {"operation": "/checkout", "method": "POST"}}
        import re
        assert all(not re.search(r"(?<!\()alerts\.payload(?=\s*(?:,|AS|FROM))", sql, re.I)
                   and "pending_workflows.payload" not in sql for sql in statements)
