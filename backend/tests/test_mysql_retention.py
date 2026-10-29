"""Run Docker integration coverage with MYSQL_RETENTION_INTEGRATION=1."""
import importlib.util
import json
import os
import subprocess
from datetime import datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest

spec = importlib.util.spec_from_file_location("mysql_retention", Path(__file__).parents[2] / "scripts/manage_mysql_retention.py")
retention = importlib.util.module_from_spec(spec)
spec.loader.exec_module(retention)


def test_reference_timeout_preserves_snapshot():
    class TimeoutCursor:
        def execute(self, *args):
            raise RuntimeError(3024, "Query execution was interrupted")

    assert retention.snapshot_referenced(
        TimeoutCursor(), {"snapshot_id": str(uuid4()), "context_fingerprint": "fingerprint"},
        [{"TABLE_NAME": "audit_logs", "COLUMN_NAME": "payload", "DATA_TYPE": "json"}],
    ) is True


def test_archive_detects_corruption_before_source_mutation(tmp_path):
    row = {"event_id": "event", "payload": {"evidence": "test"}}
    receipt = retention.archive_row(tmp_path, "resolution_outbox", row)
    assert retention.archive_row(tmp_path, "resolution_outbox", row) == receipt
    (tmp_path / receipt["archive"]).write_bytes(b"corrupt")
    with pytest.raises(Exception):
        retention.archive_row(tmp_path, "resolution_outbox", row)


def test_rejects_short_retention_and_unsafe_identifiers():
    with pytest.raises(ValueError):
        retention.run(None, ".", outbox_days=1)
    with pytest.raises(ValueError):
        retention.quote("table; DROP DATABASE")


def _resolve_container(default_name: str, fallback_name: str) -> str:
    for candidate in (default_name, fallback_name):
        if subprocess.run(["docker", "inspect", candidate], capture_output=True, text=True).returncode == 0:
            return candidate
    return default_name


@pytest.mark.skipif(os.getenv("MYSQL_RETENTION_INTEGRATION") != "1", reason="Explicit local Docker integration")
def test_mysql_retention_preserves_live_data_references_and_event_identity(tmp_path):
    import inspect
    info = json.loads(subprocess.check_output(["docker", "inspect", _resolve_container("kaims-mysql-1", "kaims-latest-mysql-1")], text=True))[0]
    env = dict(entry.split("=", 1) for entry in info["Config"]["Env"] if "=" in entry)
    payload = {"password": env["MYSQL_ROOT_PASSWORD"], "source": Path(retention.__file__).read_text(),
               "exercise": inspect.getsource(_exercise_retention)}
    runner = """import json,sys,tempfile,types,pymysql
from pathlib import Path
from datetime import datetime,timedelta
from uuid import uuid4
payload=json.load(sys.stdin)
retention=types.ModuleType('retention')
exec(payload['source'],retention.__dict__)
exec(payload['exercise'])
conn=pymysql.connect(host='mysql',user='root',password=payload['password'],cursorclass=pymysql.cursors.DictCursor,autocommit=False)
with tempfile.TemporaryDirectory() as directory:
 _exercise_retention(conn,Path(directory))
print('MySQL integration passed')
"""
    result = subprocess.run(["docker", "exec", "-i", _resolve_container("kaims-api-gateway-1", "kaims-latest-api-gateway-1"), "python", "-c", runner],
                            input=json.dumps(payload),text=True,capture_output=True,timeout=120)
    assert result.returncode == 0, result.stderr


def _exercise_retention(conn, tmp_path):
    db = "retention_test_" + uuid4().hex
    try:
        with conn.cursor() as c:
            c.execute("CREATE DATABASE " + retention.quote(db))
            c.execute("USE " + retention.quote(db))
            c.execute("CREATE TABLE incidents (id CHAR(32) PRIMARY KEY,tenant_id VARCHAR(128),status VARCHAR(32))")
            c.execute("CREATE TABLE resolution_outbox (event_id VARCHAR(160) PRIMARY KEY,tenant_id VARCHAR(128),aggregate_id VARCHAR(128),status VARCHAR(32),published_at DATETIME,updated_at DATETIME,payload JSON)")
            c.execute("CREATE TABLE context_snapshots (snapshot_id CHAR(32) PRIMARY KEY, tenant_id VARCHAR(128),incident_id VARCHAR(128),context_fingerprint VARCHAR(64),snapshot_version INT,collected_at DATETIME,expires_at DATETIME,payload JSON)")
            c.execute("CREATE TABLE bindings (context_snapshot_id CHAR(32),payload JSON)")
            closed, active = uuid4().hex, uuid4().hex
            c.executemany("INSERT INTO incidents VALUES (%s,'test',%s)", [(closed, "closed"), (active, "investigating")])
            old, now = datetime.now()-timedelta(days=40), datetime.now()
            for eid, status, incident, published in [("eligible","published",closed,old), ("active","published",active,old), ("pending","pending",closed,None), ("failed","retry",closed,None), ("recent","published",closed,now)]:
                c.execute("INSERT INTO resolution_outbox VALUES (%s,'test',%s,%s,%s,%s,%s)",
                          (eid,incident,status,published,old,json.dumps({"evidence": "original"})))
            ids = [uuid4().hex for _ in range(5)]
            for i, sid in enumerate(ids):
                c.execute("INSERT INTO context_snapshots VALUES (%s,'test',%s,%s,%s,%s,%s,%s)",
                          (sid,closed,"fingerprint"+str(i),i+1,old,old,"{}"))
            c.execute("INSERT INTO bindings VALUES (%s,%s)", (ids[1],json.dumps({"nested": {"snapshot_id":str(__import__('uuid').UUID(ids[2]))}})))
            c.execute("INSERT INTO bindings VALUES (NULL,%s)", (json.dumps({"context_fingerprint":"fingerprint3"}),))
        conn.commit()
        preview = retention.run(conn,tmp_path,execute=False)
        assert preview["outbox_candidates"] == 1
        assert preview["snapshots_protected"] == 4
        result = retention.run(conn,tmp_path,execute=True)
        assert result["outbox_compacted"] == 1
        assert result["snapshots_deleted"] == 1
        with conn.cursor() as c:
            c.execute("SELECT event_id,payload,status FROM resolution_outbox")
            rows = {r["event_id"]:r for r in c.fetchall()}
            assert len(rows) == 5  # Deduplication keys remain.
            assert json.loads(rows["eligible"]["payload"])["schema"] == retention.MARKER
            for eid in ("active","pending","failed","recent"):
                assert json.loads(rows[eid]["payload"]) == {"evidence":"original"}
            c.execute("SELECT snapshot_id FROM context_snapshots")
            assert {r["snapshot_id"] for r in c.fetchall()} == set(ids[1:])
        conn.commit()
        assert retention.run(conn,tmp_path,execute=True)["outbox_compacted"] == 0
        archives = list(tmp_path.glob("*.json.gz"))
        assert len(archives) == 2
        for path in archives:
            assert retention.restore_archive(conn,path,execute=True)["restored"]
        with conn.cursor() as c:
            c.execute("SELECT payload FROM resolution_outbox WHERE event_id='eligible'")
            assert json.loads(c.fetchone()["payload"]) == {"evidence":"original"}
            c.execute("SELECT COUNT(*) AS n FROM context_snapshots")
            assert c.fetchone()["n"] == 5
        conn.commit()
    finally:
        conn.rollback()
        with conn.cursor() as c:
            c.execute("DROP DATABASE " + retention.quote(db))
        conn.close()


@pytest.mark.skipif(os.getenv("MYSQL_RETENTION_INTEGRATION") != "1", reason="Explicit local Docker integration")
def test_backup_restores_temporary_mysql_database(tmp_path):
    import gzip
    import hashlib
    import sys
    db = "retention_backup_test_" + uuid4().hex
    command = ["docker", "exec", "-i", _resolve_container("kaims-mysql-1", "kaims-latest-mysql-1"), "sh", "-c",
               'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" mysql -uroot --batch --skip-column-names']
    def sql(statement):
        result = subprocess.run(command,input=statement,text=True,capture_output=True,timeout=60)
        assert result.returncode == 0, result.stderr
        return result.stdout
    try:
        sql("CREATE DATABASE " + db + "; CREATE TABLE " + db + ".probe (id INT PRIMARY KEY, note VARCHAR(64)); "
            "INSERT INTO " + db + ".probe VALUES (1,'backup-roundtrip');")
        result = subprocess.run([sys.executable, str(Path(__file__).parents[2] / "scripts/backup_mysql.py"),
                                 "--database", db, "--directory", str(tmp_path)],
                                capture_output=True,text=True,timeout=60)
        assert result.returncode == 0, result.stderr
        manifest = json.loads(result.stdout)
        backup = tmp_path / manifest["file"]
        assert hashlib.sha256(backup.read_bytes()).hexdigest() == manifest["sha256"]
        sql("DROP DATABASE " + db)
        sql(gzip.decompress(backup.read_bytes()).decode())
        assert sql("SELECT note FROM " + db + ".probe WHERE id=1").strip() == "backup-roundtrip"
    finally:
        sql("DROP DATABASE IF EXISTS " + db)



def test_compact_alert_and_projection_payloads_preserve_identity_and_generated_column_paths(tmp_path):
    alert_payload = {
        "id": "alert-123",
        "tenant_id": "tenant-a",
        "source": "prometheus",
        "name": "PaymentGatewayTimeout",
        "service": "payments",
        "environment": "prod",
        "severity": "critical",
        "status": "firing",
        "description": "Upstream timeout",
        "labels": {"project": "PROJ-1", "service": "payments", "env": "prod"},
        "annotations": {"summary": "Gateway timeout"},
        "metadata": {
            "incident_id": "inc-123",
            "deduplication": {
                "canonical_incident_id": "inc-123",
                "is_duplicate": True,
                "matched_alert_ids": [f"alert-{i}" for i in range(25)],
                "matches": [{"alert_id": f"alert-{i}", "description": "x" * 400} for i in range(25)],
            },
            "raw_payload": {"series": ["y" * 500 for _ in range(10)]},
        },
    }
    alert_row = {
        "id": "alert-123",
        "tenant_id": "tenant-a",
        "incident_id": "inc-123",
        "payload": alert_payload,
    }
    alert_receipt = retention.archive_row(tmp_path, "alerts", alert_row)
    compacted_alert = retention.compact_alert_payload(alert_payload, alert_receipt)

    assert compacted_alert["retention_archive"]["schema"] == retention.MARKER
    # Virtual generated column JSON paths on `alerts` must remain intact:
    assert compacted_alert["labels"]["project"] == "PROJ-1"
    assert compacted_alert["metadata"]["deduplication"]["canonical_incident_id"] == "inc-123"
    assert compacted_alert["metadata"]["deduplication"]["matches_compacted_count"] == 25
    assert compacted_alert["metadata"]["deduplication"]["matched_alert_ids_compacted_count"] == 25
    assert "matches" not in compacted_alert["metadata"]["deduplication"]
    assert "matched_alert_ids" not in compacted_alert["metadata"]["deduplication"]
    assert "raw_payload" not in compacted_alert["metadata"]
    assert len(json.dumps(compacted_alert)) < len(json.dumps(alert_payload))

    projection_payload = {
        "incident_id": "inc-123",
        "alert_id": "alert-123",
        "tenant_id": "tenant-a",
        "service": "payments",
        "environment": "prod",
        "status": "closed",
        "lifecycle_state": "closed",
        "recommendation_id": "rec-123",
        "jira_issue_key": "PAY-101",
        "rca": {"root_cause": "Pool exhausted", "confidence": 0.91},
        "recommendation": {"summary": "Increase pool size"},
        "event_payload": {
            "incident_id": "inc-123",
            "alert_id": "alert-123",
            "status": "closed",
            "context_evidence": {"telemetry": [{"blob": "z" * 4000}]},
            "discovery_evidence": {"logs": [{"blob": "w" * 4000}]},
            "related_incidents": [{"id": f"rel-{i}", "notes": "n" * 500} for i in range(20)],
            "context": {
                "service": "payments",
                "environment": "prod",
                "metadata": {
                    "alert_id": "alert-123",
                    "project_id": "PROJ-1",
                    "context_quality": {"score": 0.92, "reusable": True},
                    "context_evidence": {"telemetry": [{"blob": "z" * 4000}]},
                    "context_package": {"bundle": "b" * 4000},
                    "prior_resolution": {
                        "incident_id": "inc-prior",
                        "summary": "Prior pool exhaustion fix",
                        "confidence": 0.88,
                        "metadata": {
                            "iterative_investigation": {"rounds": ["r" * 8000 for _ in range(10)]},
                        },
                    },
                },
            },
        },
    }
    proj_row = {
        "incident_id": "inc-123",
        "tenant_id": "tenant-a",
        "status": "closed",
        "projection_payload": projection_payload,
    }
    proj_receipt = retention.archive_row(tmp_path, "incident_projections", proj_row)
    compacted_proj = retention.compact_projection_payload(projection_payload, proj_receipt)

    assert compacted_proj["retention_archive"]["schema"] == retention.MARKER
    assert compacted_proj["incident_id"] == "inc-123"
    assert compacted_proj["jira_issue_key"] == "PAY-101"
    assert compacted_proj["rca"]["root_cause"] == "Pool exhausted"
    assert compacted_proj["event_payload"]["context"]["metadata"]["context_quality"]["score"] == 0.92
    assert compacted_proj["event_payload"]["context"]["metadata"]["prior_resolution"]["incident_id"] == "inc-prior"
    assert "iterative_investigation" not in compacted_proj["event_payload"]["context"]["metadata"]["prior_resolution"].get("metadata", {})
    assert "context_evidence" not in compacted_proj["event_payload"]
    assert len(json.dumps(compacted_proj)) < len(json.dumps(projection_payload))


def test_restore_archive_supports_compacted_alerts_and_incident_projections(tmp_path):
    executed_queries = []
    alert_row = {
        "id": "alert-restore-1",
        "tenant_id": "tenant-a",
        "payload": {"id": "alert-restore-1", "labels": {"project": "P1"}},
    }
    proj_row = {
        "incident_id": "inc-restore-1",
        "tenant_id": "tenant-a",
        "projection_payload": {"incident_id": "inc-restore-1", "status": "closed"},
    }
    alert_receipt = retention.archive_row(tmp_path, "alerts", alert_row)
    proj_receipt = retention.archive_row(tmp_path, "incident_projections", proj_row)

    compacted_alert_db = {
        "id": "alert-restore-1",
        "tenant_id": "tenant-a",
        "payload": json.dumps(retention.compact_alert_payload(alert_row["payload"], alert_receipt)),
    }
    compacted_proj_db = {
        "incident_id": "inc-restore-1",
        "tenant_id": "tenant-a",
        "projection_payload": json.dumps(retention.compact_projection_payload(proj_row["projection_payload"], proj_receipt)),
    }

    class FakeCursor:
        def __init__(self):
            self._last_sql = ""

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def execute(self, sql, params=None):
            self._last_sql = sql
            executed_queries.append((sql, params))

        def fetchone(self):
            if "FROM `alerts`" in self._last_sql:
                return dict(compacted_alert_db)
            if "FROM `incident_projections`" in self._last_sql:
                return dict(compacted_proj_db)
            return None

    class FakeConnection:
        def begin(self):
            executed_queries.append(("BEGIN", None))

        def cursor(self):
            return FakeCursor()

        def commit(self):
            executed_queries.append(("COMMIT", None))

        def rollback(self):
            executed_queries.append(("ROLLBACK", None))

    conn = FakeConnection()
    dry_alert = retention.restore_archive(conn, tmp_path / alert_receipt["archive"], execute=False)
    assert dry_alert == {"dry_run": True, "restored": False, "table": "alerts"}
    assert not any(sql.startswith("UPDATE") for sql, _ in executed_queries)

    live_alert = retention.restore_archive(conn, tmp_path / alert_receipt["archive"], execute=True)
    assert live_alert["restored"] is True
    assert live_alert["table"] == "alerts"

    live_proj = retention.restore_archive(conn, tmp_path / proj_receipt["archive"], execute=True)
    assert live_proj["restored"] is True
    assert live_proj["table"] == "incident_projections"

    update_sqls = [sql for sql, _ in executed_queries if sql.startswith("UPDATE")]
    assert any("UPDATE `alerts` SET `payload`=" in sql for sql in update_sqls)
    assert any("UPDATE `incident_projections` SET `projection_payload`=" in sql for sql in update_sqls)
