from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from importlib import util
from pathlib import Path
from uuid import uuid4

import pytest
from common.database import AlertRecord, IncidentCorrelationOwnershipRecord, IncidentProjectionRecord
from common.models import Incident, IncidentStatus
from common.repository import IncidentRepository
from sqlalchemy import select, text


def _load_alert_app():
    path = Path("backend/src/alert-intelligence/app.py")
    spec = util.spec_from_file_location("alert_intelligence_persistence_contract", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load alert-intelligence app")
    module = util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_incident_domain_supports_every_persisted_lifecycle_status() -> None:
    assert IncidentStatus.APPROVED.value == "approved"
    assert IncidentStatus.RESOLVED.value == "resolved"
    assert IncidentStatus.CANCELLED.value == "cancelled"


def test_persisted_read_model_annotations_are_not_domain_model_fields() -> None:
    module = _load_alert_app()
    payload = {
        "id": "11111111-1111-4111-8111-111111111111",
        "service": "checkout",
        "environment": "prod",
        "severity": "warning",
        "status": "approved",
        "title": "Checkout incident",
        "state": "approved",
        "approval_status": "approved",
        "approval": {"decision": "approved"},
    }

    incident = module._incident_from_persisted_payload(payload)

    assert incident.status == IncidentStatus.APPROVED
    assert "state" not in incident.model_dump()


@pytest.mark.asyncio
async def test_canonical_incident_lookup_does_not_require_jira(sqlite_session_factory) -> None:
    incident = Incident(
        service="checkout",
        environment="prod",
        severity="critical",
        status=IncidentStatus.INVESTIGATING,
        title="Checkout errors",
        summary="Elevated checkout failures",
        metadata={"incident_candidate": {"correlation_key": "checkout-error-family"}},
    )
    assert incident.ticket_id is None

    async with sqlite_session_factory() as session:
        repository = IncidentRepository(session)
        await repository.acquire_canonical_incident(
            incident=incident,
            occurrence_id=uuid4(),
            correlation_key="checkout-error-family",
            project_id="commerce",
            idempotency_key="alert-checkout-1",
        )
        await repository.save_incident(incident)
        await session.commit()

    async with sqlite_session_factory() as session:
        repository = IncidentRepository(session)
        canonical = await repository.find_open_incident_by_correlation_key("checkout-error-family")
        jira_key = await repository.find_open_jira_by_correlation_key(
            "checkout-error-family",
            tenant_id="default",
            project_id="commerce",
            environment="prod",
            service="checkout",
        )

    assert canonical is not None
    assert canonical["id"] == str(incident.id)
    assert jira_key is None


@pytest.mark.asyncio
async def test_jira_reuse_requires_the_complete_authoritative_scope(sqlite_session_factory) -> None:
    incident = Incident(
        tenant_id="tenant-a",
        service="checkout",
        environment="prod",
        severity="critical",
        status=IncidentStatus.INVESTIGATING,
        title="Checkout errors",
        ticket_id="KAIMS-42",
        metadata={"incident_candidate": {"correlation_key": "shared-family"}},
    )
    async with sqlite_session_factory() as session:
        repository = IncidentRepository(session)
        await repository.acquire_canonical_incident(
            incident=incident,
            occurrence_id=uuid4(),
            correlation_key="shared-family",
            project_id="commerce-a",
            idempotency_key="jira-scope-source-1",
        )
        await repository.save_incident(incident)
        await session.commit()

    async with sqlite_session_factory() as session:
        repository = IncidentRepository(session)
        matching = await repository.find_open_jira_by_correlation_key(
            "shared-family",
            tenant_id="tenant-a",
            project_id="commerce-a",
            environment="prod",
            service="checkout",
        )
        other_project = await repository.find_open_jira_by_correlation_key(
            "shared-family",
            tenant_id="tenant-a",
            project_id="commerce-b",
            environment="prod",
            service="checkout",
        )

    assert matching == "KAIMS-42"
    assert other_project is None


@pytest.mark.asyncio
async def test_matching_occurrences_acquire_one_canonical_incident(sqlite_session_factory) -> None:
    first = Incident(
        service="checkout",
        environment="prod",
        severity="critical",
        status=IncidentStatus.INVESTIGATING,
        title="Checkout errors",
    )
    second = Incident(
        service="checkout",
        environment="prod",
        severity="critical",
        status=IncidentStatus.INVESTIGATING,
        title="Checkout errors",
    )
    async with sqlite_session_factory() as session:
        repository = IncidentRepository(session)
        first_owner = await repository.acquire_canonical_incident(
            incident=first,
            occurrence_id=uuid4(),
            correlation_key="checkout-errors",
            project_id="commerce",
            idempotency_key="source-event-1",
        )
        await repository.save_incident(first)
        second_owner = await repository.acquire_canonical_incident(
            incident=second,
            occurrence_id=uuid4(),
            correlation_key="checkout-errors",
            project_id="commerce",
            idempotency_key="source-event-2",
        )
        await session.commit()

    assert first_owner["canonical_incident_id"] == second_owner["canonical_incident_id"] == first.id
    assert first_owner["correlation_generation"] == second_owner["correlation_generation"] == 1


@pytest.mark.asyncio
async def test_incident_groups_include_legacy_projections_until_backfill(sqlite_session_factory) -> None:
    incident_id = uuid4()
    async with sqlite_session_factory() as session:
        session.add(
            IncidentProjectionRecord(
                incident_id=incident_id,
                tenant_id="tenant-a",
                service="checkout",
                environment="prod",
                severity="critical",
                status="investigating",
                first_seen_at=datetime.now(UTC),
                projection_payload={
                    "incident_id": str(incident_id),
                    "title": "Historical checkout incident",
                    "service": "checkout",
                    "environment": "prod",
                    "status": "investigating",
                },
            )
        )
        await session.commit()

    async with sqlite_session_factory() as session:
        result = await IncidentRepository(session).list_incident_groups(tenant_id="tenant-a")

    assert result["migration_state"] == "legacy_fallback"
    assert result["total_count"] == result["filtered_count"] == 1
    assert result["rows"][0]["incident_id"] == str(incident_id)
    assert result["rows"][0]["project_id"] == "legacy-unassigned"
    assert result["rows"][0]["needs_scope_review"] is True


@pytest.mark.asyncio
async def test_simultaneous_matching_alerts_converge_on_one_owner(sqlite_session_factory) -> None:
    async def acquire(index: int):
        incident = Incident(
            service="checkout",
            environment="prod",
            severity="critical",
            status=IncidentStatus.INVESTIGATING,
            title="Checkout errors",
        )
        async with sqlite_session_factory() as session:
            repository = IncidentRepository(session)
            owner = await repository.acquire_canonical_incident(
                incident=incident,
                occurrence_id=uuid4(),
                correlation_key="concurrent-checkout-errors",
                project_id="commerce",
                idempotency_key=f"concurrent-source-event-{index}",
            )
            if owner["canonical_incident_id"] == incident.id:
                await repository.save_incident(incident)
            await session.commit()
            return owner

    owners = await asyncio.gather(acquire(1), acquire(2))

    assert len({owner["canonical_incident_id"] for owner in owners}) == 1
    assert {owner["correlation_generation"] for owner in owners} == {1}


@pytest.mark.asyncio
async def test_terminal_incident_creates_a_new_correlation_generation(sqlite_session_factory) -> None:
    first = Incident(
        service="checkout",
        environment="prod",
        severity="critical",
        status=IncidentStatus.INVESTIGATING,
        title="Checkout errors",
    )
    async with sqlite_session_factory() as session:
        repository = IncidentRepository(session)
        first_owner = await repository.acquire_canonical_incident(
            incident=first,
            occurrence_id=uuid4(),
            correlation_key="checkout-errors",
            project_id="commerce",
            idempotency_key="source-event-1",
        )
        await repository.save_incident(first)
        first.status = IncidentStatus.RESOLVED
        await repository.save_incident(first)
        recurrence = Incident(
            service="checkout",
            environment="prod",
            severity="critical",
            status=IncidentStatus.INVESTIGATING,
            title="Checkout errors recurring",
        )
        recurrence_owner = await repository.acquire_canonical_incident(
            incident=recurrence,
            occurrence_id=uuid4(),
            correlation_key="checkout-errors",
            project_id="commerce",
            idempotency_key="source-event-2",
        )
        await repository.save_incident(recurrence)
        await session.commit()

    assert recurrence_owner["canonical_incident_id"] == recurrence.id
    assert recurrence_owner["canonical_incident_id"] != first_owner["canonical_incident_id"]
    assert recurrence_owner["correlation_generation"] == 2
    assert recurrence_owner["correlation_family_id"] == first_owner["correlation_family_id"]


@pytest.mark.asyncio
async def test_event_older_than_terminal_generation_does_not_create_phantom_recurrence(
    sqlite_session_factory,
) -> None:
    observed_at = datetime.now(UTC)
    first = Incident(
        service="checkout",
        environment="prod",
        severity="critical",
        status=IncidentStatus.RESOLVED,
        title="Resolved checkout errors",
    )
    delayed = Incident(
        service="checkout",
        environment="prod",
        severity="critical",
        status=IncidentStatus.INVESTIGATING,
        title="Delayed historical checkout event",
    )
    async with sqlite_session_factory() as session:
        repository = IncidentRepository(session)
        terminal_owner = await repository.acquire_canonical_incident(
            incident=first,
            occurrence_id=uuid4(),
            correlation_key="historical-checkout-errors",
            project_id="commerce",
            idempotency_key="terminal-source-event",
            observed_at=observed_at,
        )
        await repository.save_incident(first)
        delayed_owner = await repository.acquire_canonical_incident(
            incident=delayed,
            occurrence_id=uuid4(),
            correlation_key="historical-checkout-errors",
            project_id="commerce",
            idempotency_key="delayed-source-event",
            observed_at=observed_at - timedelta(minutes=5),
        )
        await session.commit()

    assert delayed_owner["canonical_incident_id"] == terminal_owner["canonical_incident_id"]
    assert delayed_owner["correlation_generation"] == terminal_owner["correlation_generation"] == 1


@pytest.mark.asyncio
async def test_correlation_isolated_by_tenant_and_environment(sqlite_session_factory) -> None:
    async with sqlite_session_factory() as session:
        repository = IncidentRepository(session)
        owners = []
        for index, (tenant, environment) in enumerate(
            (("tenant-a", "prod"), ("tenant-b", "prod"), ("tenant-a", "stage"))
        ):
            incident = Incident(
                tenant_id=tenant,
                service="checkout",
                environment=environment,
                severity="critical",
                status=IncidentStatus.INVESTIGATING,
                title="Checkout errors",
            )
            owners.append(
                await repository.acquire_canonical_incident(
                    incident=incident,
                    occurrence_id=uuid4(),
                    correlation_key="same-key",
                    project_id="commerce",
                    idempotency_key=f"source-event-{index}",
                )
            )
            await repository.save_incident(incident)
        await session.commit()

    assert len({owner["canonical_incident_id"] for owner in owners}) == 3
    assert all(owner["correlation_generation"] == 1 for owner in owners)


@pytest.mark.asyncio
async def test_incident_groups_paginate_after_correlation_with_server_counts(sqlite_session_factory) -> None:
    now = datetime.now(UTC)
    async with sqlite_session_factory() as session:
        repository = IncidentRepository(session)
        for index in range(3):
            incident = Incident(
                tenant_id="tenant-a",
                service=f"service-{index}",
                environment="prod",
                severity="critical",
                status=IncidentStatus.INVESTIGATING,
                title=f"Incident {index}",
            )
            await repository.acquire_canonical_incident(
                incident=incident,
                occurrence_id=uuid4(),
                correlation_key=f"family-{index}",
                project_id="commerce",
                idempotency_key=f"page-event-{index}",
                observed_at=now - timedelta(minutes=index),
            )
            await repository.save_incident(incident)
        other_tenant = Incident(
            tenant_id="tenant-b",
            service="service-x",
            environment="prod",
            severity="critical",
            status=IncidentStatus.INVESTIGATING,
            title="Other tenant",
        )
        await repository.acquire_canonical_incident(
            incident=other_tenant,
            occurrence_id=uuid4(),
            correlation_key="family-x",
            project_id="commerce",
            idempotency_key="other-tenant-event",
            observed_at=now,
        )
        await repository.save_incident(other_tenant)
        await session.commit()

    async with sqlite_session_factory() as session:
        repository = IncidentRepository(session)
        first = await repository.list_incident_groups(tenant_id="tenant-a", limit=2)
        second = await repository.list_incident_groups(tenant_id="tenant-a", limit=2, cursor=first["next_cursor"])

    first_ids = {row["canonical_incident_id"] for row in first["rows"]}
    second_ids = {row["canonical_incident_id"] for row in second["rows"]}
    assert first["total_count"] == first["filtered_count"] == first["active_count"] == 3
    assert first["needs_attention_count"] == first["unlinked_signal_count"] == 0
    assert len(first["rows"]) == 2
    assert len(second["rows"]) == 1
    assert first_ids.isdisjoint(second_ids)
    assert second["previous_cursor"]

    async with sqlite_session_factory() as session:
        repository = IncidentRepository(session)
        with pytest.raises(ValueError, match="active filters"):
            await repository.list_incident_groups(
                tenant_id="tenant-a",
                limit=2,
                cursor=first["next_cursor"],
                service="service-1",
            )


@pytest.mark.asyncio
async def test_incident_group_cursor_scales_to_ten_thousand_and_uses_page_index(sqlite_session_factory) -> None:
    now = datetime.now(UTC)
    rows = []
    for index in range(10_100):
        tenant = "tenant-scale" if index < 10_000 else "tenant-other"
        incident_id = uuid4()
        rows.append(
            IncidentCorrelationOwnershipRecord(
                tenant_id=tenant,
                project_id=f"project-{index % 5}",
                environment="prod" if index % 2 == 0 else "stage",
                service=f"service-{index % 40}",
                correlation_key=f"family-{index}",
                correlation_family_id=uuid4(),
                correlation_generation=1,
                canonical_incident_id=incident_id,
                first_seen_at=now - timedelta(seconds=index),
                last_seen_at=now - timedelta(seconds=index),
                correlation_window_expires_at=now + timedelta(hours=1),
                lifecycle_state="investigating",
            )
        )
    async with sqlite_session_factory() as session:
        session.add_all(rows)
        await session.commit()

    async with sqlite_session_factory() as session:
        repository = IncidentRepository(session)
        first = await repository.list_incident_groups(tenant_id="tenant-scale", limit=50)
        oldest_on_page = uuid4()
        ownership = (
            await session.execute(
                select(IncidentCorrelationOwnershipRecord)
                .where(IncidentCorrelationOwnershipRecord.tenant_id == "tenant-scale")
                .order_by(IncidentCorrelationOwnershipRecord.first_seen_at.asc())
                .limit(1)
            )
        ).scalar_one()
        oldest_on_page = ownership.canonical_incident_id
        ownership.last_seen_at = now + timedelta(hours=2)
        await session.commit()
        second = await repository.list_incident_groups(tenant_id="tenant-scale", limit=50, cursor=first["next_cursor"])
        indexes = {
            row[1] for row in (await session.execute(text("PRAGMA index_list('incident_correlation_ownership')"))).all()
        }

    assert first["total_count"] == first["filtered_count"] == 10_000
    assert len(first["rows"]) == len(second["rows"]) == 50
    assert {row["canonical_incident_id"] for row in first["rows"]}.isdisjoint(
        {row["canonical_incident_id"] for row in second["rows"]}
    )
    assert oldest_on_page not in {row["canonical_incident_id"] for row in first["rows"]}
    assert "idx_incident_correlation_page" in indexes


@pytest.mark.asyncio
async def test_unified_inbox_filters_and_paginates_in_database_with_snapshot_consistency(
    sqlite_session_factory,
) -> None:
    now = datetime.now(UTC)
    incident_ids = [uuid4() for _ in range(3)]
    family_ids = [uuid4() for _ in range(3)]
    async with sqlite_session_factory() as session:
        for index, incident_id in enumerate(incident_ids):
            session.add(IncidentCorrelationOwnershipRecord(
                tenant_id="tenant-inbox", project_id="commerce", environment="prod",
                service="checkout", correlation_key=f"inbox-{index}",
                correlation_family_id=family_ids[index], correlation_generation=1,
                canonical_incident_id=incident_id, first_seen_at=now - timedelta(minutes=index),
                last_seen_at=now - timedelta(minutes=index),
                correlation_window_expires_at=now + timedelta(hours=1),
                lifecycle_state="awaiting_approval" if index == 0 else "investigating",
            ))
            session.add(IncidentProjectionRecord(
                incident_id=incident_id, tenant_id="tenant-inbox", service="checkout",
                environment="prod", severity="warning" if index == 1 else ("critical" if index == 0 else "high"),
                status="awaiting_approval" if index == 0 else "investigating",
                first_seen_at=now - timedelta(minutes=index), projection_payload={},
            ))
        session.add(AlertRecord(
            id=uuid4(), tenant_id="tenant-inbox", source="prometheus", name="Orphan alert",
            service="checkout", environment="prod", severity="critical", fingerprint="orphan",
            payload={"project_id": "commerce", "name": "Orphan alert"},
        ))
        session.add(AlertRecord(
            id=uuid4(), tenant_id="tenant-inbox", source="prometheus", name="Warning live alert",
            service="checkout", environment="prod", severity="warning", fingerprint="warning-only",
            payload={"project_id": "commerce"},
        ))
        session.add(AlertRecord(
            id=uuid4(), tenant_id="other-tenant", source="prometheus", name="Hidden alert",
            service="checkout", environment="prod", severity="critical", fingerprint="hidden",
            payload={"project_id": "commerce"},
        ))
        session.add(AlertRecord(
            id=uuid4(), tenant_id="tenant-inbox", source="prometheus", name="Linked occurrence",
            service="checkout", environment="prod", severity="critical", fingerprint="linked",
            payload={"project_id": "commerce", "metadata": {"deduplication": {
                "disposition": "duplicate", "canonical_incident_id": str(incident_ids[0]),
            }}},
        ))
        await session.commit()

    async with sqlite_session_factory() as session:
        repository = IncidentRepository(session)
        first = await repository.list_unified_inbox(
            tenant_id="tenant-inbox", project_id="commerce", service="checkout", limit=2,
            record_type="all",
        )
        assert first["total_count"] == first["filtered_count"] == 3
        assert first["record_counts"] == {"incidents": 2, "alerts": 1}
        assert first["view_counts"]["needs_me"] == 2
        assert len(first["rows"]) == 2
        assert first["next_cursor"]
        snapshot = first["snapshot_at"]
        session.add(AlertRecord(
            id=uuid4(), tenant_id="tenant-inbox", source="prometheus", name="Late alert",
            service="checkout", environment="prod", severity="critical", fingerprint="late",
            payload={"project_id": "commerce"}, created_at=datetime.now(UTC) + timedelta(seconds=1),
        ))
        await session.commit()
        second = await repository.list_unified_inbox(
            tenant_id="tenant-inbox", project_id="commerce", service="checkout", limit=2,
            cursor=first["next_cursor"], record_type="all",
        )
        with pytest.raises(ValueError, match="Invalid unified inbox cursor"):
            await repository.list_unified_inbox(
                tenant_id="tenant-inbox", project_id="commerce", service="checkout",
                severity="warning", limit=2, cursor=first["next_cursor"], record_type="all",
            )
        assert second["previous_cursor"]
        previous = await repository.list_unified_inbox(
            tenant_id="tenant-inbox", project_id="commerce", service="checkout", limit=2,
            cursor=second["previous_cursor"], record_type="all",
        )
        assert [row["row"]["id"] for row in previous["rows"]] == [row["row"]["id"] for row in first["rows"]]
        assert previous["previous_cursor"] is None
        needs_me = await repository.list_unified_inbox(
            tenant_id="tenant-inbox", project_id="commerce", service="checkout", limit=25,
            inbox_view="needs_me", record_type="all",
        )
        assert needs_me["total_count"] == 3
        assert needs_me["filtered_count"] == len(needs_me["rows"]) == 2
        projection = await session.get(IncidentProjectionRecord, incident_ids[2])
        projection.status = "waiting_for_human"
        await session.commit()
        waiting = await repository.list_unified_inbox(
            tenant_id="tenant-inbox", project_id="commerce", service="checkout", limit=25,
            inbox_view="needs_me", record_type="incidents",
        )
        assert any(row["row"]["status"] == "waiting_for_human" for row in waiting["rows"])
        from common.database import ContextEvidenceRequirementRecord, HumanEvidenceRequestRecord
        requirement_id = uuid4()
        projection.status = "rca_ready"
        session.add(ContextEvidenceRequirementRecord(
            requirement_id=requirement_id, tenant_id="tenant-inbox", incident_id=incident_ids[2],
            rca_version=1, requirement_key="incident-metrics", category="metrics", question="Incident-window metrics", reason="Confirm cause",
            priority="high", collection_mode="automatic", status="human_requested",
            candidate_connectors=["prometheus"],
        ))
        session.add(HumanEvidenceRequestRecord(
            tenant_id="tenant-inbox", incident_id=incident_ids[2], requirement_id=requirement_id,
            due_at=now + timedelta(hours=1), acceptable_format="source reference", hypothesis_impact="Confirm cause",
            status="pending",
        ))
        await session.commit()
        current_work = await repository.list_unified_inbox(
            tenant_id="tenant-inbox", project_id="commerce", service="checkout", record_type="incidents",
            inbox_view="needs_me",
        )
        assert current_work["filtered_count"] == 2
        assert next(row["row"]["status"] for row in current_work["rows"]
                    if row["row"]["id"] == str(incident_ids[2])) == "waiting_for_human"
        warning_only = await repository.list_unified_inbox(
            tenant_id="tenant-inbox", project_id="commerce", service="checkout",
            severity="warning", limit=2, record_type="incidents",
        )

    assert second["snapshot_at"] == snapshot
    assert second["total_count"] == 3
    assert len(second["rows"]) == 1
    assert {item["row"]["id"] for item in first["rows"]}.isdisjoint(
        {item["row"]["id"] for item in second["rows"]}
    )
    assert warning_only["rows"] == []
    assert warning_only["record_counts"]["incidents"] == 0


@pytest.mark.asyncio
async def test_unified_inbox_cursor_is_bound_to_filters(sqlite_session_factory) -> None:
    async with sqlite_session_factory() as session:
        repository = IncidentRepository(session)
        page = await repository.list_unified_inbox(tenant_id="tenant-empty", limit=1)
        assert page["rows"] == []
        with pytest.raises(ValueError, match="Invalid unified inbox cursor"):
            await repository.list_unified_inbox(tenant_id="tenant-empty", cursor="invalid")


@pytest.mark.asyncio
async def test_unified_inbox_does_not_starve_new_alerts_behind_older_attention_incidents(
    sqlite_session_factory,
) -> None:
    now = datetime.now(UTC)
    incident_id = uuid4()
    async with sqlite_session_factory() as session:
        session.add(IncidentCorrelationOwnershipRecord(
            tenant_id="tenant-recency", project_id="commerce", environment="prod",
            service="checkout", correlation_key="older-blocked",
            correlation_family_id=uuid4(), correlation_generation=1,
            canonical_incident_id=incident_id, first_seen_at=now - timedelta(hours=1),
            last_seen_at=now - timedelta(hours=1),
            correlation_window_expires_at=now + timedelta(hours=1), lifecycle_state="failed",
        ))
        session.add(IncidentProjectionRecord(
            incident_id=incident_id, tenant_id="tenant-recency", service="checkout",
            environment="prod", severity="critical", status="failed",
            first_seen_at=now - timedelta(hours=1), projection_payload={},
        ))
        new_alert_id = uuid4()
        session.add(AlertRecord(
            id=new_alert_id, tenant_id="tenant-recency", source="prometheus",
            name="Newest actionable alert", service="checkout", environment="prod",
            severity="high", fingerprint="newest-high",
            payload={"project_id": "commerce"}, created_at=now,
        ))
        await session.commit()

    async with sqlite_session_factory() as session:
        page = await IncidentRepository(session).list_unified_inbox(
            tenant_id="tenant-recency", limit=2, record_type="all",
        )

    assert [item["record_type"] for item in page["rows"]] == ["alert", "incident"]
    assert page["rows"][0]["row"]["alert_id"] == str(new_alert_id)


@pytest.mark.asyncio
async def test_closed_history_pages_include_older_rows_and_exclude_other_tenants_and_failures(sqlite_session_factory):
    now = datetime.now(UTC)
    ids = [uuid4() for _ in range(5)]
    async with sqlite_session_factory() as session:
        for index, incident_id in enumerate(ids):
            session.add(IncidentProjectionRecord(
                incident_id=incident_id, tenant_id="other" if index == 4 else "history-page",
                service="checkout", environment="prod", severity="high",
                status="failed" if index == 3 else "closed", latest_event_at=now,
                first_seen_at=now, projection_payload={},
            ))
        await session.commit()
        repo = IncidentRepository(session)
        first = await repo.list_closed_incidents(tenant_id="history-page", limit=2)
        second = await repo.list_closed_incidents(tenant_id="history-page", limit=2, offset=2)
        assert len(first) == 2 and len(second) == 1
        found = [row["incident_id"] for row in first + second]
        assert found == sorted([str(i) for i in ids[:3]], reverse=True)


@pytest.mark.asyncio
async def test_inbox_search_matches_partial_service_project_and_signal_without_crossing_scope(sqlite_session_factory):
    now = datetime.now(UTC)
    iid = uuid4()
    async with sqlite_session_factory() as session:
        session.add(IncidentCorrelationOwnershipRecord(
            tenant_id="search-test", project_id="telemetry", environment="prod", service="frontend-proxy",
            correlation_key="search", correlation_family_id=uuid4(), correlation_generation=1,
            canonical_incident_id=iid, first_seen_at=now, last_seen_at=now,
            correlation_window_expires_at=now + timedelta(hours=1), lifecycle_state="investigating",
        ))
        session.add(IncidentProjectionRecord(incident_id=iid, tenant_id="search-test", service="frontend-proxy",
            environment="prod", severity="critical", status="investigating", first_seen_at=now,
            projection_payload={"title": "TelemetryApplicationUnavailable"}))
        session.add(AlertRecord(id=uuid4(), tenant_id="search-test", source="prometheus", name="TelemetryApplicationUnavailable",
            service="frontend-proxy", environment="prod", severity="critical", fingerprint="search-alert", payload={"project": "telemetry"}))
        await session.commit()
    async with sqlite_session_factory() as session:
        repo = IncidentRepository(session)
        for query in ["front", "TELEMETRY", "ApplicationUnavailable"]:
            page = await repo.list_unified_inbox(tenant_id="search-test", project_id="telemetry", service=query, record_type="all")
            assert page["record_counts"] == {"incidents": 1, "alerts": 1}
        for query in ["%", "_"]:
            assert (await repo.list_unified_inbox(tenant_id="search-test", service=query))["filtered_count"] == 0
        assert (await repo.list_unified_inbox(tenant_id="other", service="front"))["filtered_count"] == 0
        assert (await repo.list_unified_inbox(tenant_id="search-test", project_id="kaims", service="front"))["filtered_count"] == 0

@pytest.mark.asyncio
async def test_same_prometheus_fingerprint_new_onset_creates_new_generation_after_closure(sqlite_session_factory):
    from common.models import Alert
    module=_load_alert_app()
    now=datetime.now(UTC)
    first=Incident(service='checkout',environment='prod',severity='critical',status=IncidentStatus.INVESTIGATING,title='Checkout down')
    alert=Alert(tenant_id=first.tenant_id,source='prometheus',name='ServiceDown',service='checkout',environment='prod',
        severity='critical',description='HTTP down',starts_at=now)
    first_key=module._occurrence_idempotency_key('same-prometheus-fingerprint',alert)
    assert first_key==module._occurrence_idempotency_key('same-prometheus-fingerprint',alert.model_copy(update={'id':uuid4()}))
    async with sqlite_session_factory() as session:
        repo=IncidentRepository(session)
        a=await repo.acquire_canonical_incident(incident=first,occurrence_id=alert.id,correlation_key='same-rule',
            project_id='commerce',idempotency_key=first_key,observed_at=alert.starts_at)
        await repo.save_incident(first)
        first.status=IncidentStatus.CLOSED
        await repo.save_incident(first)
        recurrence=first.model_copy(update={'id':uuid4(),'status':IncidentStatus.INVESTIGATING})
        next_alert=alert.model_copy(update={'id':uuid4(),'starts_at':now+timedelta(minutes=10)})
        second_key=module._occurrence_idempotency_key('same-prometheus-fingerprint',next_alert)
        assert second_key!=first_key
        b=await repo.acquire_canonical_incident(incident=recurrence,occurrence_id=next_alert.id,correlation_key='same-rule',
            project_id='commerce',idempotency_key=second_key,observed_at=next_alert.starts_at)
        await session.commit()
    assert b['canonical_incident_id']==recurrence.id and b['canonical_incident_id']!=a['canonical_incident_id']
    assert b['correlation_generation']==2
    assert b['correlation_family_id']==a['correlation_family_id']
