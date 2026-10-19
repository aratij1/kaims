"""Bounded local-development retention; dry-run unless --execute is supplied.

Preserve event identities, active incidents, referenced snapshots and audit history.
Archive original rows on the host before compacting/deleting them.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import re
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import UUID

MARKER = "kaims.retained-outbox.v1"


def quote(name):
    if not re.fullmatch(r"[A-Za-z0-9_]+", name):
        raise ValueError("Unsafe schema identifier")
    return "`" + name + "`"


def archive_row(directory, table, row):
    raw = json.dumps({"table": table, "row": row}, sort_keys=True,
                     separators=(",", ":"), default=str).encode()
    checksum = hashlib.sha256(raw).hexdigest()
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / (checksum + ".json.gz")
    if not target.exists():
        temp = target.with_suffix(".tmp")
        with open(temp, "wb") as stream:
            with gzip.GzipFile(fileobj=stream, mode="wb", mtime=0) as compressed:
                compressed.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, target)
    if hashlib.sha256(gzip.decompress(target.read_bytes())).hexdigest() != checksum:
        raise ValueError("Archive verification failed; source retained")
    return {"schema": MARKER, "archive": target.name, "sha256": checksum}


def restore_archive(connection, path, *, execute=False):
    path = Path(path)
    raw = gzip.decompress(path.read_bytes())
    checksum = hashlib.sha256(raw).hexdigest()
    if path.name != checksum + ".json.gz":
        raise ValueError("Archive checksum mismatch")
    archived = json.loads(raw)
    table, row = archived["table"], archived["row"]
    if table not in {"resolution_outbox", "context_snapshots"}:
        raise ValueError("Unsupported archive table")
    key = "event_id" if table == "resolution_outbox" else "snapshot_id"
    result = {"dry_run": not execute, "table": table, "restored": False}
    connection.begin()
    try:
        with connection.cursor() as c:
            c.execute("SELECT * FROM " + quote(table) + " WHERE " + quote(key) + "=%s FOR UPDATE", (row[key],))
            current = c.fetchone()
            if table == "resolution_outbox":
                if current is None:
                    raise ValueError("Missing delivery record; refusing to recreate an event")
                payload = current["payload"]
                payload = json.loads(payload) if isinstance(payload, str) else payload
                if payload.get("schema") != MARKER or payload.get("sha256") != checksum:
                    raise ValueError("Outbox changed since archival")
                original_metadata = {k:v for k,v in row.items() if k != "payload"}
                current_metadata = json.loads(json.dumps({k:v for k,v in current.items() if k != "payload"}, default=str))
                if original_metadata != current_metadata:
                    raise ValueError("Delivery metadata changed since archival")
                if execute:
                    c.execute("UPDATE resolution_outbox SET payload=%s WHERE event_id=%s", (row["payload"], row[key]))
            else:
                if current is not None:
                    raise ValueError("Snapshot already exists; refusing overwrite")
                if execute:
                    keys = list(row)
                    c.execute("INSERT INTO context_snapshots (" + ",".join(quote(k) for k in keys) +
                              ") VALUES (" + ",".join(["%s"]*len(keys)) + ")", [row[k] for k in keys])
            result["restored"] = execute
        connection.commit()
        return result
    except Exception:
        connection.rollback()
        raise


def reference_columns(cursor):
    cursor.execute("SELECT TABLE_NAME, COLUMN_NAME, DATA_TYPE FROM information_schema.COLUMNS "
                   "WHERE TABLE_SCHEMA=DATABASE()")
    return cursor.fetchall()


def snapshot_referenced(cursor, row, columns):
    sid = str(row["snapshot_id"])
    tokens = [sid, str(UUID(sid)), row["context_fingerprint"]]
    for col in columns:
        table, column = col["TABLE_NAME"], col["COLUMN_NAME"]
        dtype = col["DATA_TYPE"]
        if dtype == "json":
            predicate = " OR ".join("JSON_SEARCH(" + quote(column) + ", 'one', %s) IS NOT NULL" for _ in tokens)
            params = list(tokens)
        elif column in {"context_snapshot_id", "parent_snapshot_id", "snapshot_id", "context_fingerprint"}:
            predicate = quote(column) + " IN (%s,%s,%s)"
            params = list(tokens)
        else:
            continue
        sql = "SELECT /*+ MAX_EXECUTION_TIME(2000) */ 1 FROM " + quote(table) + " WHERE (" + predicate + ")"
        if table == "context_snapshots":
            sql += " AND snapshot_id <> %s"
            params.append(sid)
        try:
            cursor.execute(sql + " LIMIT 1", params)
        except Exception as exc:
            # A timed-out reference search cannot prove that deletion is safe.
            # Protect this snapshot and let other bounded retention work finish.
            if exc.args and exc.args[0] == 3024:
                return True
            raise
        if cursor.fetchone():
            return True
    return False


def run(connection, archive_dir, *, execute=False, batch_size=20, max_batches=50,
        outbox_days=7, snapshot_days=30, outbox_after="", snapshot_after=None):
    if not (1 <= batch_size <= 100 and 1 <= max_batches <= 100):
        raise ValueError("Invalid work limits")
    if outbox_days < 7 or snapshot_days < 30:
        raise ValueError("Retention cannot be shorter than seven/thirty days")
    deadline = time.monotonic() + 120
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    outbox_cutoff = now - timedelta(days=outbox_days)
    snapshot_cutoff = now - timedelta(days=snapshot_days)
    result = {"dry_run": not execute, "outbox_compacted": 0, "snapshots_deleted": 0,
              "outbox_candidates": 0, "snapshot_candidates": 0, "snapshots_protected": 0}
    with connection.cursor() as c:
        c.execute("SELECT DATABASE() AS db")
        lock_name = "kaims_retention:" + hashlib.sha256(c.fetchone()["db"].encode()).hexdigest()[:32]
        c.execute("SELECT GET_LOCK(%s,0) AS acquired", (lock_name,))
        if c.fetchone()["acquired"] != 1:
            return {"skipped": "another retention worker owns the lock"}
    phase = "setup"
    try:
        with connection.cursor() as c:
            c.execute("SET SESSION innodb_lock_wait_timeout=3")
            c.execute("SET SESSION TRANSACTION ISOLATION LEVEL SERIALIZABLE")
            columns = reference_columns(c)
        connection.commit()
        # Retaining the row's primary key preserves enqueue_resolution_event deduplication.
        # Only known closed incidents qualify; unresolvable aggregate identities stay intact.
        outbox_filter = ("o.status='published' AND o.published_at < %s AND o.updated_at < %s "
            "AND COALESCE(JSON_UNQUOTE(JSON_EXTRACT(o.payload,'$.schema')),'') <> %s "
            "AND EXISTS (SELECT 1 FROM incidents i WHERE i.tenant_id=o.tenant_id "
            "AND REPLACE(i.id,'-','')=REPLACE(o.aggregate_id,'-','') AND i.status='closed')")
        phase = "outbox"
        after = outbox_after
        for _ in range(max_batches):
            if time.monotonic() >= deadline:
                result["time_budget_reached"] = True
                break
            connection.begin()
            with connection.cursor() as c:
                c.execute("SELECT /*+ MAX_EXECUTION_TIME(2000) */ o.event_id FROM resolution_outbox o "
                          "WHERE o.status='published' AND o.published_at < %s AND o.updated_at < %s "
                          "AND o.event_id > %s ORDER BY o.event_id LIMIT %s",
                          (outbox_cutoff, outbox_cutoff, after, batch_size))
                ids = [r["event_id"] for r in c.fetchall()]
                if not ids:
                    connection.rollback()
                    after = ""
                    break
                after = ids[-1]
                for event_id in ids:
                    c.execute("SELECT " + ("o.*" if execute else "o.event_id") + " FROM resolution_outbox o WHERE " + outbox_filter +
                              " AND o.event_id=%s FOR UPDATE", (outbox_cutoff, outbox_cutoff, MARKER, event_id))
                    row = c.fetchone()
                    if not row:
                        continue
                    result["outbox_candidates"] += 1
                    if not execute:
                        continue
                    receipt = archive_row(archive_dir, "resolution_outbox", row)
                    c.execute("UPDATE resolution_outbox SET payload=%s WHERE event_id=%s",
                              (json.dumps(receipt), event_id))
                    result["outbox_compacted"] += 1
            connection.commit()
        result["outbox_after"] = after
        # No audit/investigation tables are purged. Snapshot deletion is deliberately
        # conservative: expired, superseded, closed incident, no structured or JSON reference.
        phase = "snapshots"
        snapshot_position = snapshot_after or ["1970-01-01 00:00:00", ""]
        connection.begin()
        with connection.cursor() as c:
            c.execute("SELECT /*+ MAX_EXECUTION_TIME(2000) */ s.snapshot_id, s.collected_at FROM context_snapshots s "
                      "WHERE s.collected_at < %s AND s.expires_at < %s "
                      "AND (s.collected_at > %s OR (s.collected_at=%s AND s.snapshot_id>%s)) "
                      "ORDER BY s.collected_at,s.snapshot_id LIMIT %s",
                      (snapshot_cutoff, now, snapshot_position[0], snapshot_position[0], snapshot_position[1], batch_size))
            candidates = c.fetchall()
            ids = [r["snapshot_id"] for r in candidates]
            result["snapshot_after"] = [str(candidates[-1]["collected_at"]), ids[-1]] if candidates else None
            result["snapshot_candidates"] = len(ids)
            for sid in ids:
                c.execute("SELECT s.* FROM context_snapshots s WHERE s.snapshot_id=%s "
                          "AND EXISTS (SELECT 1 FROM incidents i WHERE i.tenant_id=s.tenant_id "
                          "AND REPLACE(i.id,'-','')=REPLACE(s.incident_id,'-','') AND i.status='closed') "
                          "AND EXISTS (SELECT 1 FROM context_snapshots newer WHERE newer.tenant_id=s.tenant_id "
                          "AND newer.incident_id=s.incident_id AND newer.snapshot_version>s.snapshot_version) FOR UPDATE", (sid,))
                row = c.fetchone()
                if row is None or snapshot_referenced(c, row, columns):
                    result["snapshots_protected"] += 1
                elif execute:
                    archive_row(archive_dir, "context_snapshots", row)
                    c.execute("DELETE FROM context_snapshots WHERE snapshot_id=%s", (sid,))
                    result["snapshots_deleted"] += 1
        connection.commit()
        with connection.cursor() as c:
            c.execute("SELECT table_name, data_length+index_length AS allocated_bytes, data_free "
                      "FROM information_schema.tables WHERE table_schema=DATABASE() "
                      "ORDER BY data_length+index_length DESC LIMIT 8")
            result["largest_tables"] = c.fetchall()
        connection.commit()
        return result
    except Exception as exc:
        connection.rollback()
        exc.retention_phase = phase
        raise
    finally:
        with connection.cursor() as c:
            c.execute("SELECT RELEASE_LOCK(%s)", (lock_name,))
        connection.commit()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--restore-archive")
    parser.add_argument("--daemon", action="store_true")
    parser.add_argument("--max-batches", type=int, default=50)
    parser.add_argument("--archive-dir", default="backend/retention-archives")
    parser.add_argument("--interval-seconds", type=int, default=86400)
    args = parser.parse_args()
    if args.restore_archive and args.daemon:
        parser.error("Restore cannot run as a daemon")
    if args.interval_seconds < 3600:
        parser.error("Run no more than once per hour")
    import pymysql
    from sqlalchemy.engine import make_url
    from common.config import get_settings
    url = make_url(get_settings().database_url)
    completed = Path(args.archive_dir) / "last-run.json"
    if args.daemon and completed.exists() and not (Path(args.archive_dir) / "last-error.json").exists():
        delay = max(0, min(args.interval_seconds, args.interval_seconds - (time.time() - completed.stat().st_mtime)))
        print(json.dumps({"next_run_in_seconds": round(delay)}), flush=True)
        time.sleep(delay)
    while True:
        try:
            connection = pymysql.connect(host=url.host, port=url.port or 3306, user=url.username,
                password=url.password, database=url.database, charset="utf8mb4",
                cursorclass=pymysql.cursors.DictCursor, autocommit=False, connect_timeout=10,
                read_timeout=30, write_timeout=30)
            try:
                if args.restore_archive:
                    print(json.dumps(restore_archive(connection, args.restore_archive, execute=args.execute)))
                    return
                report = Path(args.archive_dir) / "last-run.json"
                previous = json.loads(report.read_text()) if report.exists() else {}
                after = previous.get("outbox_after", "") if args.execute and not previous.get("dry_run", True) else ""
                result = run(connection, args.archive_dir, execute=args.execute, outbox_after=after, max_batches=args.max_batches,
                             snapshot_after=previous.get("snapshot_after") if args.execute and not previous.get("dry_run", True) else None)
            finally:
                connection.close()
            if result.get("skipped"):
                print(json.dumps(result), flush=True)
                if not args.daemon:
                    return
                time.sleep(args.interval_seconds)
                continue
            if args.execute:
                (Path(args.archive_dir) / "last-error.json").unlink(missing_ok=True)
            result["completed_at"] = datetime.now(timezone.utc).isoformat()
            print(json.dumps(result, default=str), flush=True)
            report = Path(args.archive_dir) / ("last-run.json" if args.execute else "last-preview.json")
            report.parent.mkdir(parents=True, exist_ok=True)
            report.write_text(json.dumps(result, default=str, indent=2), encoding="utf-8")
        except Exception as exc:
            # Avoid logging credentials, SQL parameters or incident payloads.
            print(json.dumps({"retention_failed": type(exc).__name__, "phase": getattr(exc, "retention_phase", "connect"),
                              "mysql_error_code": exc.args[0] if exc.args and isinstance(exc.args[0], int) else None}), flush=True)
            error_path = Path(args.archive_dir) / ("last-error.json" if args.execute else "preview-error.json")
            error_path.parent.mkdir(parents=True, exist_ok=True)
            error_path.write_text(json.dumps({"error": type(exc).__name__, "phase": getattr(exc, "retention_phase", "connect")}), encoding="utf-8")
            if not args.daemon:
                raise SystemExit(1) from None
            # Docker may restart this worker before MySQL is ready. Retry a
            # transient failure promptly instead of missing an entire interval.
            time.sleep(min(60, args.interval_seconds))
            continue
        if not args.daemon:
            break
        time.sleep(args.interval_seconds)


if __name__ == "__main__":
    main()
