"""Fail closed when an ORM model drifts from the live, migrated schema.

Three of the bugs found during the 2026-09-04 agentic-loop review were the
same shape: a SQLAlchemy model declared a column the live MySQL table never
had (`incident_projections.created_at`), or omitted a constraint the live
table has always enforced (`incident_events`'s idempotency unique key). Both
were invisible to the test suite because SQLite test databases are built
straight from the ORM models (`Base.metadata.create_all()`), so a model that
disagrees with the real migrated schema still "passes" every test that never
touches a real MySQL instance -- and then fails closed for every request in
production, exactly as `incident_projections.created_at` did until today.

This script closes that gap the same way CI already has the tools to: it
runs against the CI job's already-migrated MySQL service (see .github/workflows/ci.yml,
which applies backend/database/schema.sql and every migration before this
would run), and diffs every SQLAlchemy model in common.database against what
information_schema actually has.

  A column the model declares but the live table lacks -> hard failure.
    This is exactly the class of bug that made every incident silently fail
    to persist; nothing should be allowed to reintroduce it.
  A column the live table has but no model declares -> reported, not failed.
    Legacy or forward-compatible columns are common and not inherently wrong;
    this is a prompt to look, not a broken build.
  A model with no live table at all -> hard failure.
    Either a migration is missing or the table name drifted.

Usage:

    python scripts/check_schema_drift.py
    python scripts/check_schema_drift.py --database-url "mysql+pymysql://user:pass@host:3306/kaiops"
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from urllib.parse import unquote, urlparse

import pymysql

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "backend" / "src" / "common"))


def resolve_connection_kwargs(database_url: str | None) -> dict:
    """Mirrors scripts/apply-migrations.py's connection resolution (kept as
    a small duplicate, not an import, since that module's hyphenated
    filename is not importable as a normal Python module)."""
    url = database_url or os.environ.get("DATABASE_URL")
    if url and not url.startswith(("mysql", "mysql+")):
        raise ValueError(f"only MySQL is supported by this check, got: {url.split('://')[0]}")
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


def live_columns_by_table(cursor, database: str) -> dict[str, set[str]]:
    cursor.execute(
        "SELECT TABLE_NAME, COLUMN_NAME FROM information_schema.columns WHERE TABLE_SCHEMA = %s",
        (database,),
    )
    columns: dict[str, set[str]] = {}
    for table_name, column_name in cursor.fetchall():
        columns.setdefault(table_name, set()).add(column_name)
    return columns


def diff_schema(
    modeled_columns_by_table: dict[str, set[str]],
    live_columns: dict[str, set[str]],
) -> tuple[list[str], dict[str, set[str]], dict[str, set[str]]]:
    """Pure comparison, independent of SQLAlchemy metadata or a live
    connection, so the exact bug class this script exists to catch (a model
    column the live table lacks) has a regression test that needs neither."""
    missing_tables: list[str] = []
    missing_columns: dict[str, set[str]] = {}
    extra_columns: dict[str, set[str]] = {}
    for table_name, modeled in modeled_columns_by_table.items():
        if table_name not in live_columns:
            missing_tables.append(table_name)
            continue
        gap = modeled - live_columns[table_name]
        if gap:
            missing_columns[table_name] = gap
        surplus = live_columns[table_name] - modeled
        if surplus:
            extra_columns[table_name] = surplus
    return missing_tables, missing_columns, extra_columns


def unique_keys_by_table(cursor, database: str) -> dict[str, set[tuple[str, ...]]]:
    cursor.execute(
        "SELECT TABLE_NAME, INDEX_NAME, GROUP_CONCAT(COLUMN_NAME ORDER BY SEQ_IN_INDEX) "
        "FROM information_schema.statistics WHERE TABLE_SCHEMA=%s AND NON_UNIQUE=0 "
        "GROUP BY TABLE_NAME, INDEX_NAME",
        (database,),
    )
    result: dict[str, set[tuple[str, ...]]] = {}
    for table, _, columns in cursor.fetchall():
        result.setdefault(table, set()).add(tuple(columns.split(",")))
    return result


def diff_unique_keys(modeled, live):
    """Unique-key names may differ; the column combination must be enforced."""
    return {table: keys - live.get(table, set()) for table, keys in modeled.items() if keys - live.get(table, set())}


def check_drift(database_url: str | None = None) -> int:
    from common.database import Base  # noqa: PLC0415 -- deliberately deferred until sys.path is set

    connection_kwargs = resolve_connection_kwargs(database_url)
    connection = pymysql.connect(
        host=connection_kwargs["host"],
        port=connection_kwargs["port"],
        user=connection_kwargs["user"],
        password=connection_kwargs["password"],
        database=connection_kwargs["database"],
    )
    try:
        with connection.cursor() as cursor:
            live = live_columns_by_table(cursor, connection_kwargs["database"])
            live_unique = unique_keys_by_table(cursor, connection_kwargs["database"])
    finally:
        connection.close()

    modeled_columns_by_table = {
        table.name: {column.name for column in table.columns} for table in Base.metadata.sorted_tables
    }
    from sqlalchemy import UniqueConstraint

    modeled_unique = {
        table.name: {
            tuple(column.name for column in constraint.columns)
            for constraint in table.constraints
            if isinstance(constraint, UniqueConstraint)
        }
        | {tuple(column.name for column in index.columns) for index in table.indexes if index.unique}
        for table in Base.metadata.sorted_tables
    }
    missing_unique = diff_unique_keys(modeled_unique, live_unique)
    missing_tables, missing_columns, extra_columns = diff_schema(modeled_columns_by_table, live)
    table_count = len(modeled_columns_by_table)

    if extra_columns:
        print("Columns present in the live schema but not modeled (informational, not a failure):")
        for table_name in sorted(extra_columns):
            print(f"  {table_name}: {', '.join(sorted(extra_columns[table_name]))}")
        print()

    ok = True
    if missing_tables:
        ok = False
        print("Models with no backing table in the live schema:")
        for table_name in sorted(missing_tables):
            print(f"  {table_name}")
        print()

    if missing_columns:
        ok = False
        print("Models declaring a column the live schema does not have:")
        print("(every request touching these will fail closed, exactly like incident_projections.created_at did)")
        for table_name in sorted(missing_columns):
            print(f"  {table_name}: {', '.join(sorted(missing_columns[table_name]))}")
        print()

    if missing_unique:
        ok = False
        print("Modeled unique keys missing from the live schema:")
        for table, keys in sorted(missing_unique.items()):
            print(f"  {table}: {sorted(keys)}")
        print()

    if ok:
        print(f"No schema drift: {table_count} models match the live schema.")
        return 0
    return 1


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--database-url",
        default=None,
        help="Optional database connection URL (defaults to DATABASE_URL or DB_* environment variables).",
    )
    args = parser.parse_args()
    sys.exit(check_drift(args.database_url))


if __name__ == "__main__":
    main()
