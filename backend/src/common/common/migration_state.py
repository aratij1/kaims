from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

MIGRATIONS_DIR = Path(__file__).resolve().parents[3] / "database" / "migrations"


def _resolve_migrations_dir(directory: Path | None = None) -> Path:
    if directory is not None and directory.is_dir():
        return directory
    for candidate in [
        MIGRATIONS_DIR,
        Path("/app/backend/database/migrations"),
        Path("/app/database/migrations"),
        Path(__file__).resolve().parents[4] / "backend" / "database" / "migrations",
    ]:
        if candidate.is_dir():
            return candidate
    return MIGRATIONS_DIR


def migration_manifest(directory: Path | None = None) -> dict[str, str]:
    resolved_dir = _resolve_migrations_dir(directory)
    if not resolved_dir.is_dir():
        return {}
    return {
        path.name: hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()
        for path in sorted(resolved_dir.glob("*.sql"), key=lambda item: item.name)
    }


def current_schema_version(directory: Path | None = None) -> str:
    manifest = migration_manifest(directory)
    return Path(next(reversed(manifest), "unversioned")).stem


async def inspect_schema_compatibility(connection: AsyncConnection) -> dict[str, Any]:
    expected = migration_manifest()
    version = Path(next(reversed(expected), "unversioned")).stem
    if connection.dialect.name != "mysql":
        return {"compatible": True, "schema_version": version, "pending": [], "changed": []}
    table_exists = await connection.scalar(text(
        "SELECT COUNT(*) FROM information_schema.tables "
        "WHERE table_schema = DATABASE() AND table_name = 'schema_migrations'"
    ))
    if int(table_exists or 0) == 0:
        return {"compatible": False, "schema_version": "unversioned", "pending": list(expected), "changed": []}
    rows = (await connection.execute(text(
        "SELECT filename, checksum_sha256 FROM schema_migrations ORDER BY filename"
    ))).all()
    applied = {str(row[0]): str(row[1] or "") for row in rows}
    pending = [name for name in expected if name not in applied]
    changed = []
    for name, checksum in expected.items():
        if name in applied:
            applied_chk = applied[name]
            legacy_hash = hashlib.sha256(name.encode("utf-8")).hexdigest()
            if applied_chk and applied_chk != checksum and applied_chk != legacy_hash:
                changed.append(name)
    applied_known = [name for name in expected if name in applied and name not in changed]
    applied_version = Path(applied_known[-1]).stem if applied_known else "unversioned"
    return {
        "compatible": not pending and not changed,
        "schema_version": applied_version,
        "expected_schema_version": version,
        "pending": pending,
        "changed": changed,
    }


async def schema_compatibility(engine: AsyncEngine) -> dict[str, Any]:
    async with engine.connect() as connection:
        return await inspect_schema_compatibility(connection)


def require_compatible_schema(state: dict[str, Any]) -> None:
    if state.get("compatible") is True:
        return
    if state.get("changed"):
        raise RuntimeError("applied migration checksum mismatch")
    raise RuntimeError("pending database migrations")
