"""Archival must stop on corrupt backups, wrong tenants and restore conflicts."""

import hashlib
import importlib.util
import json
from pathlib import Path
import pytest

spec = importlib.util.spec_from_file_location(
    "alert_retention", Path(__file__).resolve().parents[2] / "scripts/manage_alert_retention.py"
)
retention = importlib.util.module_from_spec(spec)
spec.loader.exec_module(retention)
POLICY = {
    "schema_version": "kaims.alert-retention.v1",
    "tenant_id": "default",
    "unlinked_live_days": 30,
    "archive_minimum_days": 365,
    "automatic_archive_deletion": False,
    "preserve_incident_and_analysis_references": True,
    "batch_size": 500,
}
BATCH = "8c4eb0eb-e535-48b1-9cca-561a588be41e"


class Connection:
    def __init__(self, archive=None, existing=None):
        self.archive = archive
        self.existing = existing
        self.sql = []
        self.rollbacks = 0
        self.last = ""

    def cursor(self):
        return self

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def execute(self, sql, params=None):
        self.sql.append(sql)
        self.last = sql

    def fetchall(self):
        return [self.archive] if "retained_alert_archives" in self.last and self.archive else []

    def fetchone(self):
        return self.existing if "FROM alerts WHERE" in self.last else {"present": 0}

    def commit(self):
        pass

    def begin(self):
        pass

    def rollback(self):
        self.rollbacks += 1


def archive(tenant="default"):
    row = {key: None for key in retention.COLUMNS}
    row.update(id="a" * 32, tenant_id=tenant)
    raw = json.dumps(row)
    return {"record_json": raw, "checksum_sha256": hashlib.sha256(raw.encode()).hexdigest(), "alert_id": "a" * 32}


@pytest.mark.parametrize("failure", ["checksum", "tenant", "existing"])
def test_restore_refuses_corruption_cross_tenant_and_changed_live_record(failure):
    saved = archive("other" if failure == "tenant" else "default")
    if failure == "checksum":
        saved["checksum_sha256"] = "0" * 64
    c = Connection(saved, existing={"id": "changed"} if failure == "existing" else None)
    with pytest.raises(ValueError):
        retention.run(c, POLICY, execute=True, restore_batch=BATCH)
    assert c.rollbacks == 1
    assert not any(sql.startswith(("INSERT INTO alerts", "DELETE FROM alerts")) for sql in c.sql)


def test_missing_reference_index_stops_cleanup_before_writes_or_full_json_scan():
    c = Connection()
    with pytest.raises(RuntimeError, match="20261015_snapshot_alert_retention_index"):
        retention.run(c, POLICY, execute=True)
    assert not any(sql.startswith(("DELETE", "CREATE", "ALTER", "INSERT")) for sql in c.sql)
    assert not any("FROM alerts a" in sql for sql in c.sql)
