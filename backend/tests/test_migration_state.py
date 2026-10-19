from pathlib import Path

import pytest
from common.migration_state import (
    current_schema_version,
    inspect_schema_compatibility,
    migration_manifest,
    require_compatible_schema,
)


def test_manifest_and_schema_version_follow_forward_filename_order(tmp_path: Path) -> None:
    (tmp_path / "20260102_second.sql").write_text("SELECT 2;", encoding="utf-8")
    (tmp_path / "20260101_first.sql").write_text("SELECT 1;", encoding="utf-8")

    manifest = migration_manifest(tmp_path)

    assert list(manifest) == ["20260101_first.sql", "20260102_second.sql"]
    assert current_schema_version(tmp_path) == "20260102_second"


def test_incompatible_schema_fails_closed() -> None:
    with pytest.raises(RuntimeError, match="checksum mismatch"):
        require_compatible_schema({"compatible": False, "changed": ["changed.sql"]})
    with pytest.raises(RuntimeError, match="pending"):
        require_compatible_schema({"compatible": False, "changed": [], "pending": ["pending.sql"]})


@pytest.mark.asyncio
async def test_non_mysql_development_schema_is_compatible(sqlite_session_factory) -> None:
    async with sqlite_session_factory() as session:
        connection = await session.connection()
        state = await inspect_schema_compatibility(connection)
    assert state["compatible"] is True
    assert state["schema_version"] == Path(next(reversed(migration_manifest()))).stem


@pytest.mark.asyncio
async def test_schema_compatibility_reports_checksum_drift_without_rewriting_it(monkeypatch):
    from types import SimpleNamespace
    from unittest.mock import AsyncMock

    import common.migration_state as module

    monkeypatch.setattr(module, "migration_manifest", lambda: {"example.sql": "a" * 64})
    connection = SimpleNamespace(
        dialect=SimpleNamespace(name="mysql"),
        scalar=AsyncMock(return_value=1),
        execute=AsyncMock(return_value=SimpleNamespace(all=lambda: [("example.sql", "b" * 64)])),
    )
    state = await module.inspect_schema_compatibility(connection)
    assert state["compatible"] is False
    assert state["changed"] == ["example.sql"]
    assert all(str(call.args[0]).startswith("SELECT") for call in connection.execute.await_args_list)
