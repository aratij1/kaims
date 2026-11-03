from __future__ import annotations

import os
from collections.abc import AsyncIterator
from functools import wraps
from pathlib import Path

import pytest
import pytest_asyncio
from common.config import Settings, get_settings
from common.database import create_schema
from common.rag_governance import content_checksum
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

# Unit and contract tests must never inherit developer credentials, live
# provider switches, or infrastructure addresses from the repository `.env`.
# Individual tests can still supply explicit values or an explicit _env_file.
_settings_init = Settings.__init__


@wraps(_settings_init)
def _isolated_settings_init(self, *args, **kwargs):
    kwargs.setdefault("_env_file", None)
    _settings_init(self, *args, **kwargs)


Settings.__init__ = _isolated_settings_init


@pytest.fixture(autouse=True)
def isolate_model_provider_environment(monkeypatch: pytest.MonkeyPatch):
    """Keep unit tests independent from credentials in the developer shell."""
    prefixes = (
        "OPENAI_",
        "AZURE_OPENAI_",
        "REASONING_",
        "MODEL_ROUTER_",
        "GEMINI_",
        "GROQ_",
        "ANTHROPIC_",
    )
    for name in tuple(os.environ):
        if name.startswith(prefixes):
            monkeypatch.delenv(name, raising=False)
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture
def clear_execution_catalog_cache():
    from common.orchestration.execution_plan import _execution_catalogs

    _execution_catalogs.cache_clear()
    yield
    _execution_catalogs.cache_clear()


@pytest.fixture
def governed_rag_root(tmp_path: Path) -> Path:
    """Create explicit, globally approved operational knowledge for positive-path tests."""
    documents = {
        "runbooks/payments-latency.md": (
            "runbook",
            "Payments latency response",
            "# Payments latency response\nConfirm the rollout diff, inspect latency, and validate recovery.",
            {},
        ),
        "incidents/payments-rollout.md": (
            "incident",
            "Payments rollout latency",
            "# Payments rollout latency\nA prior payments rollout increased latency and was safely rolled back.",
            {"dependencies": "payments-db", "deployment": "payments-api"},
        ),
    }
    for relative_path, (kind, title, body, extra) in documents.items():
        path = tmp_path / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        headers = {
            "kind": kind,
            "title": title,
            "tenant_scope": "global",
            "services": "payments",
            "owner_team": "payments-sre",
            "source_system": "test-fixture",
            "source_ref": f"fixture://{relative_path}",
            "review_status": "approved",
            "corpus_classification": "PRODUCTION_CURATED",
            "content_version": "1",
            "created_at": "2026-08-01T00:00:00Z",
            "updated_at": "2026-08-01T00:00:00Z",
            "last_reviewed": "2026-08-01T00:00:00Z",
            "reviewed_by": "test-reviewer",
            "approved_by": "test-administrator",
            "approved_at": "2026-08-01T00:00:00Z",
            "content_checksum": content_checksum(body),
            **extra,
        }
        header_text = "\n".join(f"{key}: {value}" for key, value in headers.items())
        path.write_text(f"{header_text}\n{body}\n", encoding="utf-8")
    return tmp_path


@pytest_asyncio.fixture
async def sqlite_session_factory() -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    """A fresh in-memory SQLite database with the full app schema, per test.

    StaticPool keeps all connections in a test pointed at the same in-memory
    database (plain :memory: gives each connection its own empty database).
    """
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    await create_schema(engine)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        yield session_factory
    finally:
        await engine.dispose()
