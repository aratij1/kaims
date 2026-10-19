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


@pytest.mark.skipif(os.getenv("MYSQL_RETENTION_INTEGRATION") != "1", reason="Explicit local Docker integration")
def test_mysql_retention_preserves_live_data_references_and_event_identity(tmp_path):
    import inspect
    info = json.loads(subprocess.check_output(["docker", "inspect", "kaims-mysql-1"], text=True))[0]
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
    result = subprocess.run(["docker", "exec", "-i", "kaims-api-gateway-1", "python", "-c", runner],
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
    command = ["docker", "exec", "-i", "kaims-mysql-1", "sh", "-c",
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
