from __future__ import annotations

from datetime import UTC, datetime, timedelta
import importlib.util
from pathlib import Path
import sys
from uuid import uuid4

import pytest
from common.database import AlertRecord, IncidentProjectionRecord, IncidentRecord
from common.repository import IncidentRepository


def load_monitoring_app_module():
    existing = sys.modules.get("monitoring_adapter_app")
    if existing is not None:
        return existing
    module_path = Path("backend/src/monitoring-adapter/app.py")
    spec = importlib.util.spec_from_file_location("monitoring_adapter_app", module_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["monitoring_adapter_app"] = module
    spec.loader.exec_module(module)
    return module


@pytest.mark.asyncio
async def test_compact_request_150_alerts_honored(sqlite_session_factory, monkeypatch) -> None:
    """Verify that a request for 150 compact alerts returns exactly 150 when at least 150 exist."""
    base_time = datetime(2026, 10, 1, 0, 0, 0, tzinfo=UTC)
    async with sqlite_session_factory() as session:
        # Seed 170 alerts
        for idx in range(170):
            alert_id = uuid4()
            session.add(
                AlertRecord(
                    id=alert_id,
                    tenant_id="default",
                    source="prometheus",
                    name=f"Alert-{idx}",
                    service="checkout",
                    environment="production",
                    severity="warning",
                    payload={
                        "id": str(alert_id),
                        "name": f"Alert-{idx}",
                        "service": "checkout",
                        "severity": "warning",
                        "source": "prometheus",
                        "tenant_id": "default",
                        "created_at": (base_time + timedelta(seconds=idx)).isoformat(),
                    },
                    created_at=base_time + timedelta(seconds=idx),
                    updated_at=base_time + timedelta(seconds=idx),
                )
            )
        await session.commit()

        repo = IncidentRepository(session)
        # 1. Repository direct call with limit=150
        repo_rows = await repo.list_alerts(limit=150, include_incident_context=False)
        assert len(repo_rows) == 150, f"Expected 150 rows from repo.list_alerts, got {len(repo_rows)}"

    # 2. Monitoring adapter route call with limit=150 and compact=True
    module = load_monitoring_app_module()
    monkeypatch.setattr(module.settings, "database_enabled", True)
    module.app.state.session_factory = sqlite_session_factory

    route_response = await module.get_all_alerts(limit=150, compact=True)
    assert route_response["count"] == 150
    assert len(route_response["rows"]) == 150
    # Ensure compact serialization schema
    sample = route_response["rows"][0]
    assert "name" in sample
    assert "service" in sample
    assert "severity" in sample
    assert "source" in sample


@pytest.mark.asyncio
async def test_requests_above_configured_cap_clamped_to_200(sqlite_session_factory, monkeypatch) -> None:
    """Verify that requests exceeding 200 are clamped to at most 200 across repository and routes."""
    base_time = datetime(2026, 10, 1, 0, 0, 0, tzinfo=UTC)
    async with sqlite_session_factory() as session:
        # Seed 230 alerts
        for idx in range(230):
            alert_id = uuid4()
            session.add(
                AlertRecord(
                    id=alert_id,
                    tenant_id="default",
                    source="prometheus" if idx % 2 == 0 else "logs",
                    name=f"CapAlert-{idx}",
                    service="orders",
                    environment="production",
                    severity="error",
                    payload={
                        "id": str(alert_id),
                        "name": f"CapAlert-{idx}",
                        "service": "orders",
                        "severity": "error",
                        "source": "prometheus" if idx % 2 == 0 else "logs",
                        "tenant_id": "default",
                        "application": "ecommerce-app",
                    },
                    created_at=base_time + timedelta(seconds=idx),
                    updated_at=base_time + timedelta(seconds=idx),
                )
            )
        await session.commit()

        repo = IncidentRepository(session)
        # Verify repo.list_alerts with limit=500 and limit=10000
        alerts_500 = await repo.list_alerts(limit=500, include_incident_context=False)
        assert len(alerts_500) == 200, f"Expected 200 clamped rows, got {len(alerts_500)}"

        alerts_10k = await repo.list_alerts(limit=10000, include_incident_context=False)
        assert len(alerts_10k) == 200

        # Verify repo.list_alerts_source_balanced with limit=500 and limit=5000
        balanced_500 = await repo.list_alerts_source_balanced(limit=500)
        assert len(balanced_500) == 200

        balanced_5k = await repo.list_alerts_source_balanced(limit=5000)
        assert len(balanced_5k) == 200

    # Verify route-level clamps in monitoring-adapter
    module = load_monitoring_app_module()
    monkeypatch.setattr(module.settings, "database_enabled", True)
    module.app.state.session_factory = sqlite_session_factory

    resp_all_compact = await module.get_all_alerts(limit=500, compact=True)
    assert resp_all_compact["count"] == 200
    assert len(resp_all_compact["rows"]) == 200

    resp_all_balanced = await module.get_all_alerts(limit=5000, compact=False)
    assert resp_all_balanced["count"] == 200
    assert len(resp_all_balanced["rows"]) == 200

    resp_apps = await module.get_alert_applications(limit=5000)
    assert resp_apps["scanned_alerts"] == 200


@pytest.mark.asyncio
async def test_linked_incident_query_bounded_to_500(sqlite_session_factory) -> None:
    """Verify that linked incident queries are bounded between 150 and 500, never exceeding 500."""
    base_time = datetime(2026, 10, 1, 0, 0, 0, tzinfo=UTC)
    async with sqlite_session_factory() as session:
        for idx in range(10):
            alert_id = uuid4()
            session.add(
                AlertRecord(
                    id=alert_id,
                    tenant_id="default",
                    source="prometheus",
                    name=f"BoundAlert-{idx}",
                    service="checkout",
                    environment="production",
                    severity="warning",
                    payload={"id": str(alert_id), "name": f"BoundAlert-{idx}"},
                    created_at=base_time + timedelta(seconds=idx),
                    updated_at=base_time + timedelta(seconds=idx),
                )
            )
        await session.commit()

        captured_incident_limits: list[int | None] = []
        original_execute = session.execute

        async def spy_execute(statement, *args, **kwargs):
            # Check if this query is selecting from incidents table
            sql_text = str(statement)
            if "FROM incidents" in sql_text:
                captured_incident_limits.append(statement._limit)
            return await original_execute(statement, *args, **kwargs)

        session.execute = spy_execute
        repo = IncidentRepository(session)

        # 1. When limit=200 is requested, safe_limit*3 = 600, but clamp must bound it to 500
        captured_incident_limits.clear()
        await repo.list_alerts_source_balanced(limit=200)
        assert len(captured_incident_limits) >= 1
        for query_limit in captured_incident_limits:
            assert query_limit is not None
            assert query_limit <= 500, f"Expected incident query limit <= 500, got {query_limit}"
            assert query_limit == 500, f"Expected capped limit of 500, got {query_limit}"

        # 2. When list_alerts with include_incident_context=True is called
        captured_incident_limits.clear()
        await repo.list_alerts(limit=200, include_incident_context=True)
        assert len(captured_incident_limits) >= 1
        for query_limit in captured_incident_limits:
            assert query_limit is not None
            assert query_limit <= 500, f"Expected incident query limit <= 500, got {query_limit}"
            assert query_limit == 500, f"Expected capped limit of 500, got {query_limit}"

        # 3. When limit=3 is requested, safe_limit*3 = 9, so min baseline of 150 is preserved
        captured_incident_limits.clear()
        await repo.list_alerts_source_balanced(limit=3)
        assert len(captured_incident_limits) >= 1
        assert captured_incident_limits[0] == 150


@pytest.mark.asyncio
async def test_tenant_filtering_and_source_balancing(sqlite_session_factory) -> None:
    """Verify that tenant isolation and source balancing remain correct under the new limit clamps."""
    base_time = datetime(2026, 10, 1, 0, 0, 0, tzinfo=UTC)
    async with sqlite_session_factory() as session:
        # Seed Tenant A: 1 email, 10 logs, 1 jira
        session.add(
            AlertRecord(
                id=uuid4(),
                tenant_id="tenant-alpha",
                source="email",
                name="Email Alpha",
                service="auth",
                environment="production",
                severity="info",
                payload={"name": "Email Alpha", "source": "email", "tenant_id": "tenant-alpha"},
                created_at=base_time,
                updated_at=base_time,
            )
        )
        for i in range(10):
            session.add(
                AlertRecord(
                    id=uuid4(),
                    tenant_id="tenant-alpha",
                    source="logs",
                    name=f"Log Alpha {i}",
                    service="auth",
                    environment="production",
                    severity="warning",
                    payload={"name": f"Log Alpha {i}", "source": "logs", "tenant_id": "tenant-alpha"},
                    created_at=base_time + timedelta(seconds=i + 1),
                    updated_at=base_time + timedelta(seconds=i + 1),
                )
            )
        session.add(
            AlertRecord(
                id=uuid4(),
                tenant_id="tenant-alpha",
                source="jira",
                name="Jira Alpha",
                service="auth",
                environment="production",
                severity="low",
                payload={"name": "Jira Alpha", "source": "jira", "tenant_id": "tenant-alpha"},
                created_at=base_time + timedelta(seconds=20),
                updated_at=base_time + timedelta(seconds=20),
            )
        )

        # Seed Tenant B: 5 prometheus
        for i in range(5):
            session.add(
                AlertRecord(
                    id=uuid4(),
                    tenant_id="tenant-beta",
                    source="prometheus",
                    name=f"Prom Beta {i}",
                    service="billing",
                    environment="production",
                    severity="critical",
                    payload={"name": f"Prom Beta {i}", "source": "prometheus", "tenant_id": "tenant-beta"},
                    created_at=base_time + timedelta(seconds=i),
                    updated_at=base_time + timedelta(seconds=i),
                )
            )
        await session.commit()

        repo = IncidentRepository(session)

        # Test Tenant Alpha with source balancing
        alpha_rows = await repo.list_alerts_source_balanced(limit=5, tenant_id="tenant-alpha")
        assert len(alpha_rows) == 5
        assert all(r.get("tenant_id") == "tenant-alpha" for r in alpha_rows)
        alpha_sources = {r.get("source") for r in alpha_rows}
        assert "email" in alpha_sources
        assert "jira" in alpha_sources
        assert "logs" in alpha_sources

        # Test Tenant Beta
        beta_rows = await repo.list_alerts_source_balanced(limit=10, tenant_id="tenant-beta")
        assert len(beta_rows) == 5
        assert all(r.get("tenant_id") == "tenant-beta" for r in beta_rows)
        assert all(r.get("source") == "prometheus" for r in beta_rows)

        # Test list_alerts tenant filtering
        alpha_list = await repo.list_alerts(limit=50, tenant_id="tenant-alpha", include_incident_context=False)
        assert len(alpha_list) == 12
        assert all(r.get("tenant_id") == "tenant-alpha" for r in alpha_list)


@pytest.mark.asyncio
async def test_existing_schemas_and_enrichment_compatibility(sqlite_session_factory) -> None:
    """Verify that alert enrichment with IncidentRecord and IncidentProjectionRecord remains intact."""
    base_time = datetime(2026, 10, 1, 0, 0, 0, tzinfo=UTC)
    async with sqlite_session_factory() as session:
        alert_id = uuid4()
        incident_id = uuid4()

        session.add(
            AlertRecord(
                id=alert_id,
                tenant_id="default",
                source="prometheus",
                name="EnrichedAlert",
                service="payments",
                environment="production",
                severity="high",
                payload={"id": str(alert_id), "name": "EnrichedAlert", "service": "payments"},
                created_at=base_time,
                updated_at=base_time,
            )
        )
        session.add(
            IncidentRecord(
                id=incident_id,
                tenant_id="default",
                service="payments",
                environment="production",
                severity="high",
                status="investigating",
                title="Payment latency incident",
                ticket_id="PAY-999",
                payload={"alert_ids": [str(alert_id)]},
                created_at=base_time + timedelta(seconds=1),
                updated_at=base_time + timedelta(seconds=1),
            )
        )
        session.add(
            IncidentProjectionRecord(
                incident_id=incident_id,
                tenant_id="default",
                service="payments",
                environment="production",
                status="in_progress",
                document_available=True,
            )
        )
        await session.commit()

        repo = IncidentRepository(session)
        # Test list_alerts with enrichment
        enriched_alerts = await repo.list_alerts(limit=10, include_incident_context=True)
        assert len(enriched_alerts) == 1
        item = enriched_alerts[0]
        assert item["incident_id"] == str(incident_id)
        assert item["status"] == "in_progress"
        assert item["document_available"] is True

        # Test list_alerts_source_balanced with incident ticket enrichment
        balanced_alerts = await repo.list_alerts_source_balanced(limit=10)
        assert len(balanced_alerts) == 1
        b_item = balanced_alerts[0]
        assert b_item["incident_id"] == str(incident_id)
        assert b_item["ticket_id"] == "PAY-999"
        assert b_item["incident_disposition"] == "new_incident"
