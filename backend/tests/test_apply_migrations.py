import importlib.util
import sys
from pathlib import Path

import pytest


def load_migrations_module():
    module_path = Path("scripts/apply-migrations.py")
    spec = importlib.util.spec_from_file_location("apply_migrations", module_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_resolve_connection_kwargs_parses_database_url() -> None:
    module = load_migrations_module()

    kwargs = module.resolve_connection_kwargs("mysql+aiomysql://kaiops:s3cr%40t@dbhost:3307/kaiops")

    assert kwargs == {
        "host": "dbhost",
        "port": 3307,
        "user": "kaiops",
        "password": "s3cr@t",
        "database": "kaiops",
    }


def test_resolve_connection_kwargs_falls_back_to_discrete_env_vars(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_migrations_module()
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.setenv("DB_HOST", "envhost")
    monkeypatch.setenv("DB_PORT", "3308")
    monkeypatch.setenv("DB_USER", "envuser")
    monkeypatch.setenv("DB_PASSWORD", "envpass")
    monkeypatch.setenv("DB_DATABASE", "envdb")

    kwargs = module.resolve_connection_kwargs(None)

    assert kwargs == {
        "host": "envhost",
        "port": 3308,
        "user": "envuser",
        "password": "envpass",
        "database": "envdb",
    }


def test_resolve_connection_kwargs_rejects_non_mysql_url() -> None:
    module = load_migrations_module()

    with pytest.raises(ValueError, match="only MySQL"):
        module.resolve_connection_kwargs("postgresql://user:pass@host:5432/db")


def test_list_migration_files_returns_sorted_sql_files() -> None:
    module = load_migrations_module()

    files = module.list_migration_files()

    names = [f.name for f in files]
    assert names == sorted(names)
    assert all(name.endswith(".sql") for name in names)
    assert "20260701_user_rbac.sql" in names
    assert module.current_schema_version(files) == files[-1].stem


def test_migration_checksum_is_stable_and_content_sensitive(tmp_path: Path) -> None:
    module = load_migrations_module()
    migration = tmp_path / "20260101_example.sql"
    migration.write_text("SELECT 1;\n", encoding="utf-8")
    first = module.migration_checksum(migration)

    assert module.migration_checksum(migration) == first
    migration.write_text("SELECT 2;\n", encoding="utf-8")
    assert module.migration_checksum(migration) != first


def test_fresh_database_baseline_is_packaged() -> None:
    module = load_migrations_module()

    assert module.BASE_SCHEMA_PATH.is_file()
    assert "CREATE TABLE IF NOT EXISTS incidents" in module.BASE_SCHEMA_PATH.read_text(encoding="utf-8")


@pytest.mark.parametrize("tracking,checksum_column", [(False, False), (True, False), (True, True)])
def test_dry_run_never_changes_schema_or_tracking_rows(monkeypatch, tmp_path, tracking, checksum_column):
    from unittest.mock import MagicMock

    module = load_migrations_module()
    path = tmp_path / "20260101_example.sql"
    path.write_text("SELECT 1;")
    cursor = MagicMock()
    cursor.fetchone.side_effect = [(1,) if tracking else None] + (
        [(1,) if checksum_column else None] if tracking else []
    )
    cursor.fetchall.return_value = []
    cursor.__enter__.return_value = cursor
    connection = MagicMock()
    connection.cursor.return_value = cursor
    monkeypatch.setattr(module.pymysql, "connect", lambda **kwargs: connection)
    monkeypatch.setattr(module, "list_migration_files", lambda: [path])
    monkeypatch.setattr(sys, "argv", ["apply-migrations.py", "--dry-run"])
    module.main()
    assert all(call.args[0].startswith(("SELECT", "SHOW")) for call in cursor.execute.call_args_list)
    connection.close.assert_called_once()


def test_real_checksum_drift_cannot_be_silently_adopted(tmp_path):
    module = load_migrations_module()
    path = tmp_path / "example.sql"
    path.write_text("SELECT 1;")
    with pytest.raises(RuntimeError, match="Restore the applied file"):
        module.validate_applied_checksums([path], {path.name: "f" * 64})
    import hashlib

    for legacy in [None, hashlib.sha256(path.name.encode()).hexdigest(), module.migration_checksum(path)]:
        module.validate_applied_checksums([path], {path.name: legacy})


def test_concurrent_migration_runner_fails_before_schema_mutation(monkeypatch, tmp_path):
    from unittest.mock import MagicMock

    module = load_migrations_module()
    path = tmp_path / "example.sql"
    path.write_text("SELECT 1;")
    cursor = MagicMock()
    cursor.fetchone.return_value = (0,)
    cursor.__enter__.return_value = cursor
    connection = MagicMock()
    connection.cursor.return_value = cursor
    monkeypatch.setattr(module.pymysql, "connect", lambda **kwargs: connection)
    monkeypatch.setattr(module, "list_migration_files", lambda: [path])
    monkeypatch.setattr(sys, "argv", ["apply-migrations.py"])
    with pytest.raises(RuntimeError, match="migration lock"):
        module.main()
    assert len(cursor.execute.call_args_list) == 1
    connection.close.assert_called_once()
