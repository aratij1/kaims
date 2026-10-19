"""Explicit local maintenance: retain the newest N incidents and linked evidence.

Run in an isolated maintenance container with connection JSON on stdin. Dry-run
unless execute=true. Never changes users, onboarding, credentials or runbooks.
"""
import json
import re
import sys
import time
from uuid import UUID

import pymysql


def norm(value):
    try:
        return UUID(str(value)).hex
    except (ValueError, TypeError, AttributeError):
        return str(value or "")


def variants(values):
    result = set()
    for value in values:
        result.add(str(value))
        try:
            result.add(str(UUID(str(value))))
            result.add(UUID(str(value)).hex)
        except ValueError:
            pass
    return sorted(result)


def quote(value):
    if not re.fullmatch(r"[A-Za-z0-9_]+", value):
        raise ValueError("Unsafe identifier")
    return "`" + value + "`"


def main(config):
    db = pymysql.connect(host="mysql", user="root", password=config["password"],
        database=config["database"], autocommit=True, read_timeout=300,
        cursorclass=pymysql.cursors.DictCursor)
    execute = bool(config.get("execute"))
    with db.cursor() as c:
        c.execute("SELECT GET_LOCK(%s,0) AS acquired", ('kaims_latest_incident_cleanup:' + config['database'][:32],))
        if c.fetchone()["acquired"] != 1:
            raise RuntimeError("Another cleanup owns the lock")
        # This is maintenance of a local instance without replicas. Avoid writing
        # every deleted multi-MB JSON payload into another set of binary logs.
        if execute:
            c.execute("SET SESSION sql_log_bin=0")
        c.execute("SET SESSION innodb_lock_wait_timeout=5")
        c.execute("SELECT id,tenant_id,created_at FROM incidents ORDER BY created_at DESC,id DESC")
        incidents = c.fetchall()
        keep = incidents[:int(config.get("keep", 30))]
        if len(keep) != 30 or len(incidents) <= len(keep):
            raise RuntimeError("Expected exactly 30 retained incidents and an older population")
        keep_ids = variants([r["id"] for r in keep])
        old_ids = variants([r["id"] for r in incidents[30:]])
        c.execute("SELECT TABLE_NAME,COLUMN_NAME FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE()")
        columns = {}
        for row in c.fetchall():
            columns.setdefault(row["TABLE_NAME"], set()).add(row["COLUMN_NAME"])
        c.execute("SELECT TABLE_NAME,COLUMN_NAME,REFERENCED_TABLE_NAME FROM information_schema.KEY_COLUMN_USAGE "
                  "WHERE TABLE_SCHEMA=DATABASE() AND REFERENCED_TABLE_NAME IS NOT NULL")
        foreign_keys = c.fetchall()
        c.execute("SELECT TABLE_NAME,INDEX_NAME,COLUMN_NAME,SEQ_IN_INDEX FROM information_schema.STATISTICS "
                  "WHERE TABLE_SCHEMA=DATABASE() ORDER BY TABLE_NAME,INDEX_NAME,SEQ_IN_INDEX")
        indexes = {}
        for row in c.fetchall():
            indexes.setdefault(row['TABLE_NAME'], {}).setdefault(row['INDEX_NAME'], []).append(row['COLUMN_NAME'])

        def source(table, predicate):
            choices = indexes.get(table, {})
            for owner in ('incident_id', 'canonical_incident_id', 'aggregate_id', 'investigation_id', 'resource_id'):
                if owner not in predicate:
                    continue
                for prefix in (['tenant_id', owner], [owner]):
                    if prefix[0] == 'tenant_id' and 'tenant_id' not in predicate:
                        continue
                    match = next((name for name, cols in choices.items() if cols[:len(prefix)] == prefix), None)
                    if match:
                        return quote(table) + ' FORCE INDEX (' + quote(match) + ')'
            return quote(table)

        def membership(column, values, negative=False):
            if not values:
                return ("1=1" if negative else "0=1"), []
            return quote(column) + (" NOT IN (" if negative else " IN (") + ",".join(["%s"] * len(values)) + ")", list(values)

        def ids_for(table, column, condition, params):
            c.execute("SELECT " + quote(column) + " AS value FROM " + source(table, condition) + " WHERE " + condition, params)
            return [r["value"] for r in c.fetchall() if r["value"]]

        def owner_membership(table, column, values, tenants):
            predicate, params = membership(column, values)
            if 'tenant_id' in columns[table]:
                scope, scope_params = membership('tenant_id', sorted(set(tenants)))
                return scope + ' AND ' + predicate, scope_params + params
            return predicate, params

        conditions = {}
        for table, cols in columns.items():
            owner = "incident_id" if "incident_id" in cols else "canonical_incident_id" if "canonical_incident_id" in cols else None
            if owner:
                conditions[table] = owner_membership(table, owner, old_ids, [r['tenant_id'] for r in incidents[30:]])
        conditions["incidents"] = membership("id", old_ids)
        for table in ("resolution_outbox", "resolution_inbox"):
            if table in columns:
                conditions[table] = membership("aggregate_id", old_ids)
        if "resolution_investigations" in conditions:
            predicate, params = conditions["resolution_investigations"]
            old_investigations = variants(ids_for("resolution_investigations", "investigation_id", predicate, params))
            for table in ("resolution_hypotheses", "resolution_investigation_steps"):
                if table in columns:
                    conditions[table] = membership("investigation_id", old_investigations)

        # Preserve snapshots referenced by a retained incident, even when their
        # original owner was an older incident (reused context).
        protected_snapshots = set()
        for table, cols in columns.items():
            if "context_snapshot_id" in cols and "incident_id" in cols:
                predicate, params = owner_membership(table, 'incident_id', keep_ids, [r['tenant_id'] for r in keep])
                protected_snapshots.update(ids_for(table, "context_snapshot_id", predicate, params))
        predicate, params = owner_membership('context_snapshots', 'incident_id', keep_ids, [r['tenant_id'] for r in keep])
        protected_snapshots.update(ids_for("context_snapshots", "snapshot_id", predicate, params))
        frontier = set(protected_snapshots)
        while frontier:
            predicate, params = membership("snapshot_id", variants(frontier))
            parents = set(ids_for("context_snapshots", "parent_snapshot_id", predicate, params))
            normalized_protected = {norm(s) for s in protected_snapshots}
            new = {p for p in parents if norm(p) not in normalized_protected}
            if not new:
                break
            protected_snapshots.update(new)
            frontier = new
        predicate, params = conditions["context_snapshots"]
        exclusion, values = membership("snapshot_id", variants(protected_snapshots), negative=True)
        conditions["context_snapshots"] = (predicate + " AND " + exclusion, params + values)

        # Retain source alerts referenced by any of the kept incident's versions.
        keep_alerts = set()
        for table, cols in columns.items():
            owner = "incident_id" if "incident_id" in cols else "canonical_incident_id" if "canonical_incident_id" in cols else None
            if "alert_id" in cols and owner:
                predicate, params = owner_membership(table, owner, keep_ids, [r['tenant_id'] for r in keep])
                keep_alerts.update(ids_for(table, "alert_id", predicate, params))
        predicate, params = membership("id", keep_ids)
        c.execute("SELECT payload FROM incidents WHERE " + predicate, params)
        def collect_alerts(value):
            if isinstance(value, dict):
                for key, item in value.items():
                    if key == "alert_id" and isinstance(item, str):
                        keep_alerts.add(item)
                    elif key == "alert_ids" and isinstance(item, list):
                        keep_alerts.update(v for v in item if isinstance(v, str))
                    elif key in ("alert", "source_alert") and isinstance(item, dict) and item.get("id"):
                        keep_alerts.add(item["id"])
                    collect_alerts(item)
            elif isinstance(value, list):
                for item in value:
                    collect_alerts(item)
        for row in c.fetchall():
            collect_alerts(json.loads(row["payload"]) if isinstance(row["payload"], str) else row["payload"])
        if not keep_alerts:
            raise RuntimeError("No retained source alerts found; refusing alert deletion")
        conditions["alerts"] = membership("id", variants(keep_alerts), negative=True)
        if 'retained_alert_archives' in columns:
            conditions['retained_alert_archives'] = membership('alert_id', variants(keep_alerts), negative=True)

        # Use existing indexed ownership links for audit rows, never scan every
        # large JSON payload for arbitrary UUID matches.
        c.execute("CREATE TEMPORARY TABLE cleanup_old_resources (id VARCHAR(160) PRIMARY KEY)")
        c.executemany("INSERT IGNORE INTO cleanup_old_resources VALUES (%s)", [(v,) for v in old_ids])
        c.execute("SELECT TABLE_NAME,COLUMN_NAME FROM information_schema.KEY_COLUMN_USAGE "
                  "WHERE TABLE_SCHEMA=DATABASE() AND CONSTRAINT_NAME='PRIMARY'")
        primary_keys = {}
        for key in c.fetchall():
            primary_keys.setdefault(key['TABLE_NAME'], []).append(key['COLUMN_NAME'])
        for table, (predicate, params) in list(conditions.items()):
            keys = primary_keys.get(table, [])
            if len(keys) == 1:
                values = variants(ids_for(table, keys[0], predicate, params))
                for offset in range(0, len(values), 1000):
                    c.executemany("INSERT IGNORE INTO cleanup_old_resources VALUES (%s)",
                                  [(v,) for v in values[offset:offset+1000] if len(v) <= 160])
        if "audit_logs" in columns:
            conditions["audit_logs"] = ("resource_id IN (SELECT id FROM cleanup_old_resources)", [])

        order = []
        pending = set(conditions)
        while pending:
            ready = sorted(t for t in pending if not any(
                fk["REFERENCED_TABLE_NAME"] == t and fk["TABLE_NAME"] in pending and fk["TABLE_NAME"] != t
                for fk in foreign_keys))
            if not ready:
                raise RuntimeError("Unresolved foreign-key dependency cycle")
            order.extend(ready)
            pending.difference_update(ready)
        plan = {"keep": [dict(row, created_at=str(row["created_at"])) for row in keep],
                "incidents_before": len(incidents), "older_incidents": len(incidents)-30,
                "protected_snapshots": len(protected_snapshots), "retained_alert_ids": variants(keep_alerts),
                "old_incident_ids": old_ids, "tables": []}
        for table in order:
            predicate, params = conditions[table]
            c.execute("SELECT COUNT(*) AS n FROM " + source(table, predicate) + " WHERE " + predicate, params)
            plan["tables"].append({"table": table, "rows": c.fetchone()["n"]})
        print(json.dumps({"plan": plan}), flush=True)
        if not execute:
            return
        expected = config.get("expected_keep")
        if expected and [norm(r["id"]) for r in keep] != [norm(v) for v in expected]:
            raise RuntimeError("Retained incident list changed; review a fresh plan")
        for table in order:
            predicate, params = conditions[table]
            count = 0
            while True:
                keys = primary_keys.get(table, [])
                if len(keys) == 1:
                    c.execute('SELECT ' + quote(keys[0]) + ' AS value FROM ' + source(table, predicate) +
                              ' WHERE ' + predicate + ' LIMIT 250', params)
                    ids = [row['value'] for row in c.fetchall()]
                    if not ids:
                        break
                    selected, selected_params = membership(keys[0], ids)
                    c.execute('DELETE FROM ' + quote(table) + ' WHERE ' + selected, selected_params)
                else:
                    c.execute("DELETE FROM " + quote(table) + " WHERE " + predicate + " LIMIT 250", params)
                n = c.rowcount
                count += n
                if n == 0:
                    break
                time.sleep(0.02)
            print(json.dumps({"deleted_from": table, "rows": count}), flush=True)
        c.execute("SELECT id FROM incidents ORDER BY created_at DESC,id DESC")
        remaining = [norm(r["id"]) for r in c.fetchall()]
        assert remaining == [norm(r["id"]) for r in keep], "Retained incident verification failed"
        print(json.dumps({"verified_incidents_remaining": len(remaining)}), flush=True)
    db.close()


if __name__ == "__main__":
    main(json.load(sys.stdin))
