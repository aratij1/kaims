"""Apply pending backend/database/migrations/*.sql files against MySQL.

README.md has always said "Apply migration manually for existing DBs before
starting services" with no tooling to track which files were already run —
operators either re-ran a whole migration by hand (safe here only because
every migration is written with IF NOT EXISTS / information_schema-guarded
conditional DDL) or had to remember state themselves. This script tracks
applied filenames in a `schema_migrations` table and only runs what's new,
in filename order (files are date-prefixed, so lexicographic order is
chronological order). It is intentionally forward-only: no migration in this
repo ships a down-migration, so there is nothing to roll back to here by
design — see the rollback runbook referenced from
docs/END_USER_RELEASE_READINESS_2026-08-03.md for the manual rollback story.

Usage:

    python scripts/apply-migrations.py
    python scripts/apply-migrations.py --dry-run
    python scripts/apply-migrations.py --database-url "mysql+pymysql://user:pass@host:3306/kaiops"
"""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
from urllib.parse import unquote, urlparse

import pymysql
from pymysql.constants import CLIENT

MIGRATIONS_DIR = Path(__file__).resolve().parent.parent / "backend" / "database" / "migrations"
BASE_SCHEMA_PATH = MIGRATIONS_DIR.parent / "schema.sql"

_CREATE_TRACKING_TABLE = """
CREATE TABLE IF NOT EXISTS schema_migrations (
    filename VARCHAR(255) PRIMARY KEY,
    checksum_sha256 CHAR(64) NOT NULL,
    applied_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
"""


def resolve_connection_kwargs(database_url: str | None) -> dict:
    """Parse a mysql(+driver)://user:pass@host:port/db URL, or fall back to
    the same DB_HOST/DB_PORT/DB_USER/DB_PASSWORD/DB_DATABASE env vars every
    service already reads (see backend/src/common/common/config.py)."""
    url = database_url or os.environ.get("DATABASE_URL")
    if url and not url.startswith(("mysql", "mysql+")):
        raise ValueError(f"only MySQL is supported by this migration runner, got: {url.split('://')[0]}")
    if url:
        parsed = urlparse(url.replace("mysql+aiomysql", "mysql").replace("mysql+pymysql", "mysql"))
        return {
            "host": parsed.hostname or "localhost",
            "port": parsed.port or 3306,
            "user": unquote(parsed.username or "kaiops"),
            "password": unquote(parsed.password or "kaiops"),
            "database": (parsed.path or "/kaiops").lstrip("/") or "kaiops",
        }
    return {
        "host": os.environ.get("DB_HOST", "localhost"),
        "port": int(os.environ.get("DB_PORT", "3306")),
        "user": os.environ.get("DB_USER", "kaiops"),
        "password": os.environ.get("DB_PASSWORD", "kaiops"),
        "database": os.environ.get("DB_DATABASE", "kaiops"),
    }


def list_migration_files() -> list[Path]:
    return sorted(MIGRATIONS_DIR.glob("*.sql"), key=lambda path: path.name)


def ensure_checksum_column(cursor) -> None:  # noqa: ANN001
    cursor.execute("SHOW COLUMNS FROM schema_migrations LIKE 'checksum_sha256'")
    if cursor.fetchone() is None:
        cursor.execute("ALTER TABLE schema_migrations ADD COLUMN checksum_sha256 CHAR(64) NULL AFTER filename")


def already_applied(cursor) -> dict[str, str | None]:  # noqa: ANN001
    """Read migration state without creating or upgrading tracking tables."""
    cursor.execute("SHOW TABLES LIKE 'schema_migrations'")
    if cursor.fetchone() is None:
        return {}
    cursor.execute("SHOW COLUMNS FROM schema_migrations LIKE 'checksum_sha256'")
    checksum = "checksum_sha256" if cursor.fetchone() is not None else "NULL"
    cursor.execute(f"SELECT filename, {checksum} FROM schema_migrations")
    return {row[0]: row[1] for row in cursor.fetchall()}


def validate_applied_checksums(files: list[Path], applied: dict[str, str | None]) -> None:
    changed = [
        path.name
        for path in files
        if path.name in applied and not is_acceptable_checksum(path.name, applied[path.name], migration_checksum(path))
    ]
    if changed:
        raise RuntimeError(
            "Applied migration checksum mismatch: "
            + ", ".join(changed)
            + ". Restore the applied file and add a forward migration."
        )


def migration_checksum(path: Path) -> str:
    content = path.read_bytes().replace(b"\r\n", b"\n")
    return hashlib.sha256(content).hexdigest()


def is_acceptable_checksum(filename: str, applied_checksum: str | None, current_checksum: str) -> bool:
    if applied_checksum is None or applied_checksum == current_checksum:
        return True
    filename_hash = hashlib.sha256(filename.encode("utf-8")).hexdigest()
    if applied_checksum == filename_hash:
        return True
    return False


def current_schema_version(files: list[Path] | None = None) -> str:
    ordered = files if files is not None else list_migration_files()
    return ordered[-1].stem if ordered else "unversioned"


def apply_migration(cursor, path: Path) -> None:  # noqa: ANN001
    sql = path.read_text(encoding="utf-8-sig")
    if sql.strip():
        cursor.execute(sql)
        while cursor.nextset():
            pass
    cursor.execute(
        "INSERT INTO schema_migrations (filename, checksum_sha256) VALUES (%s, %s)",
        (path.name, migration_checksum(path)),
    )


def ensure_baseline_schema(cursor, path: Path = BASE_SCHEMA_PATH) -> bool:  # noqa: ANN001
    """Install the repository baseline only for a genuinely fresh database."""
    cursor.execute("SHOW TABLES LIKE 'incidents'")
    if cursor.fetchone() is not None:
        return False
    if not path.is_file():
        raise RuntimeError(f"fresh database requires baseline schema: {path}")
    cursor.execute(path.read_text(encoding="utf-8"))
    while cursor.nextset():
        pass
    return True


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--database-url",
        default=None,
        help="Optional database connection URL (defaults to DATABASE_URL or DB_* environment variables).",
    )
    parser.add_argument("--dry-run", action="store_true", help="List pending migrations without applying them.")
    args = parser.parse_args()

    files = list_migration_files()
    if not files:
        raise RuntimeError(f"no migration files found in {MIGRATIONS_DIR}")

    connection_kwargs = resolve_connection_kwargs(args.database_url)

    connection = pymysql.connect(
        host=connection_kwargs["host"],
        port=connection_kwargs["port"],
        user=connection_kwargs["user"],
        password=connection_kwargs["password"],
        database=connection_kwargs["database"],
        client_flag=CLIENT.MULTI_STATEMENTS,
        autocommit=True,
    )
    locked = False
    lock_name = "kaims:migrations:" + hashlib.sha256(connection_kwargs["database"].encode()).hexdigest()[:40]
    try:
        with connection.cursor() as cursor:
            if not args.dry_run:
                cursor.execute("SELECT GET_LOCK(%s, 0)", (lock_name,))
                locked = bool(cursor.fetchone()[0] == 1)
                if not locked:
                    raise RuntimeError("Another database migration runner holds the migration lock")
            applied = already_applied(cursor)
            validate_applied_checksums(files, applied)
            pending = [path for path in files if path.name not in applied]
            if args.dry_run:
                for path in pending:
                    print(f"  {path.name}")
                print(f"Dry run: {len(pending)} pending migration(s); no schema or tracking rows changed.")
                return
            cursor.execute("SET SESSION lock_wait_timeout=10")
            cursor.execute(_CREATE_TRACKING_TABLE)
            ensure_checksum_column(cursor)
            if ensure_baseline_schema(cursor):
                print(f"Applied fresh database baseline: {BASE_SCHEMA_PATH.name}")
            # Only known legacy markers may be materialized. A real content
            # checksum mismatch was rejected before any schema/data mutation.
            for path in files:
                if path.name in applied and applied[path.name] != migration_checksum(path):
                    cursor.execute(
                        "UPDATE schema_migrations SET checksum_sha256=%s WHERE filename=%s",
                        (migration_checksum(path), path.name),
                    )
            for path in pending:
                print(f"Applying {path.name} ...")
                apply_migration(cursor, path)
                print(f"Applied {path.name}")
            print(f"Schema version: {current_schema_version(files)}")
    finally:
        try:
            if locked:
                with connection.cursor() as cursor:
                    cursor.execute("SELECT RELEASE_LOCK(%s)", (lock_name,))
        finally:
            connection.close()


if __name__ == "__main__":
    main()
