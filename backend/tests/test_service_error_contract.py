from __future__ import annotations

from common.config import get_settings
from common.errors import sanitize_handler_failure_text
from common.service import create_app
from fastapi import HTTPException
from fastapi.testclient import TestClient
from pydantic import BaseModel, Field


class ValidatedPayload(BaseModel):
    count: int = Field(ge=1, le=10)


def error_contract_app():
    settings = get_settings()
    settings.service_name = "error-contract-test"
    settings.database_enabled = False
    app = create_app(title="Error contract test", settings=settings)

    @app.post("/validated")
    async def validated(payload: ValidatedPayload):
        return payload

    @app.get("/missing")
    async def missing():
        raise HTTPException(status_code=404, detail="Incident was not found")

    @app.get("/unexpected")
    async def unexpected():
        raise RuntimeError("database password must never reach the client")

    @app.get("/busy")
    async def busy():
        raise HTTPException(
            status_code=409,
            detail={"code": "target_execution_busy", "message": "Target is busy.", "retryable": True},
        )

    return app


def test_validation_error_is_safe_versioned_and_traceable() -> None:
    response = TestClient(error_contract_app()).post(
        "/validated",
        headers={"x-trace-id": "validation-trace"},
        json={"count": 99, "password": "do-not-echo"},
    )

    assert response.status_code == 422
    assert response.headers["x-trace-id"] == "validation-trace"
    assert response.json()["error"]["contract_version"] == "kaiops.error.v1"
    assert response.json()["error"]["code"] == "request_validation_failed"
    assert response.json()["error"]["validation_errors"][0]["location"] == ["body", "count"]
    assert "do-not-echo" not in response.text


def test_http_error_preserves_detail_and_adds_machine_contract() -> None:
    response = TestClient(error_contract_app()).get("/missing")

    assert response.status_code == 404
    assert response.json()["detail"] == "Incident was not found"
    assert response.json()["error"]["code"] == "http_404"
    assert response.json()["error"]["retryable"] is False
    assert response.json()["trace_id"]


def test_unhandled_error_does_not_leak_internal_exception() -> None:
    response = TestClient(error_contract_app(), raise_server_exceptions=False).get("/unexpected")

    assert response.status_code == 500
    assert response.json()["error"]["code"] == "internal_error"
    assert response.json()["error"]["retryable"] is False
    assert "database password" not in response.text


def test_structured_conflict_can_be_declared_retryable() -> None:
    response = TestClient(error_contract_app()).get("/busy")

    assert response.status_code == 409
    assert response.json()["error"]["code"] == "target_execution_busy"
    assert response.json()["error"]["message"] == "Target is busy."
    assert response.json()["error"]["retryable"] is True


def test_build_info_exposes_safe_release_contract(monkeypatch) -> None:
    monkeypatch.setenv("KAIMS_RELEASE_SHA", "a" * 40)
    monkeypatch.setenv("KAIMS_BUILD_TIME", "2026-08-31T11:00:00Z")

    response = TestClient(error_contract_app()).get("/build-info")

    assert response.status_code == 200
    assert response.json() == {
        "release_sha": "a" * 40,
        "schema_version": "20261015_snapshot_alert_retention_index",
        "contract_version": "kaiops.incident-operations.v1",
        "build_time": "2026-08-31T11:00:00Z",
    }


def test_readiness_rejects_missing_required_release_sha(monkeypatch) -> None:
    monkeypatch.setenv("KAIMS_RELEASE_SHA", "dev")
    monkeypatch.setenv("KAIMS_REQUIRE_RELEASE_PROVENANCE", "true")

    response = TestClient(error_contract_app()).get("/readyz")

    assert response.status_code == 503
    assert response.json()["detail"] == "release provenance is not ready"


def test_sanitize_handler_failure_text_categorizes_a_real_sql_integrity_error() -> None:
    """The exact production leak: this text reached AnalysisRequestRecord.
    terminal_reason and was displayed to an operator verbatim.
    """
    raw = (
        "(pymysql.err.IntegrityError) (1062, \"Duplicate entry "
        "'rabbitmq-incident.context.collected:8a3c3d3b' for key "
        "'uq_incident_events_idempotency'\") [SQL: INSERT INTO incident_events ...]"
    )

    sanitized = sanitize_handler_failure_text(raw)

    assert sanitized == "A duplicate or conflicting record was detected; this was safely coalesced."
    assert "pymysql" not in sanitized
    assert "uq_incident_events_idempotency" not in sanitized
    assert "INSERT INTO" not in sanitized


def test_sanitize_handler_failure_text_covers_common_failure_categories() -> None:
    assert sanitize_handler_failure_text("Can't connect to MySQL server on 'mysql'") == (
        "A required downstream service was temporarily unreachable."
    )
    assert sanitize_handler_failure_text("Request timed out after 30s") == (
        "The operation exceeded its time budget."
    )
    assert sanitize_handler_failure_text("403 Forbidden: access denied") == (
        "The operation was not authorized."
    )
    assert sanitize_handler_failure_text("validation error: field is required") == (
        "The message payload failed validation."
    )


def test_sanitize_handler_failure_text_falls_back_to_default_not_raw_text() -> None:
    raw = "NoneType object has no attribute 'foo' at line 42 of internal_module.py"

    sanitized = sanitize_handler_failure_text(raw)

    assert sanitized == "handler_failed"
    assert "internal_module" not in sanitized


def test_sanitize_handler_failure_text_handles_empty_input() -> None:
    assert sanitize_handler_failure_text("") == "handler_failed"
    assert sanitize_handler_failure_text("  ") == "handler_failed"
    assert sanitize_handler_failure_text("", default="custom_default") == "custom_default"
