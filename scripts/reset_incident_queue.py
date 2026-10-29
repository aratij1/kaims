"""Safe, localized maintenance script to reset the Incident Queue in the LOCAL KaiMS environment.

Strict Requirements & Guardrails:
1. Localhost verification: strictly refuses to run if host is not 127.0.0.1/localhost or if hostname contains remote/Azure indicators.
2. Dry-run by default: previews all affected tables and current row counts without making any modifications.
3. Explicit confirmation: requires --execute flag AND explicit confirmation prompt to delete.
4. Preserves configuration: does NOT touch users, roles, applications, onboarding, alert rules, prometheus configs, runbooks, or knowledge base.
5. Preserves binary logging, database structure, and Docker volumes.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import socket
import sys
import time
from typing import Any
import pymysql

# Explicit list of tables storing incident state to be cleared, ordered to respect foreign keys
INCIDENT_TABLES_ORDERED = [
    # Child / Action / Execution tables
    "actions",
    "remediation_attempts",
    "remediation_outcomes",
    "recovery_evidence",
    "validation_observations",
    "approvals",
    "approval_assignments",
    "execution_plans",
    "governed_resolution_plans",
    "resolution_plan_supersessions",
    "rca_reports",
    "resolution_hypotheses",
    "resolution_investigation_steps",
    "resolution_investigations",
    "resolution_state_transitions",
    "resolution_outbox",
    "runbook_outcomes",
    "runbook_execution_history",
    "pending_workflows",
    "evaluation_records",
    # Context & Evidence tables
    "context_enrichment_jobs",
    "human_evidence_requests",
    "context_evidence_requirements",
    "incident_investigation_bindings",
    "incident_rca_version_reservations",
    "incident_evidence",
    "canonical_evidence",
    "evidence_rejections",
    "evidence_rag_drafts",
    "context_snapshots",
    # Correlation, Occurrences & Projections
    "incident_lifecycle_transitions",
    "incident_events",
    "incident_occurrences",
    "incident_correlation_ownership",
    "incident_correlation_backfill",
    "incident_projections",
    "jira_incident_bindings",
    # Canonical Incident Table
    "incidents",
    # Live Operational Alerts feeding the inbox / queue
    "alerts",
]

PRESERVED_TABLES = [
    "users",
    "roles",
    "user_sessions",
    "schema_migrations",
    "applications",
    "application_environments",
    "application_labels",
    "monitoring_profiles",
    "monitoring_connection_audit",
    "onboarding_state",
    "onboarding_history",
    "onboarding_control_planes",
    "prometheus_configs",
    "alert_rules",
    "recording_rules",
    "grafana_dashboards",
    "knowledge_base",
    "context_knowledge",
    "governed_rag_documents",
    "knowledge_rag_drafts",
    "failure_patterns",
    "runbooks",
    "runbook_approvals",
    "runbook_versions",
]


def verify_local_target(host: str, port: int, database: str) -> None:
    """Ensure the target database is strictly local and reject any remote/Azure endpoints."""
    prohibited_keywords = ["azure", "windows.net", "database.windows.net", "cloud", "prod", "remote", "stage"]
    lower_host = host.lower()
    for kw in prohibited_keywords:
        if kw in lower_host:
            raise ValueError(f"SECURITY VIOLATION: Host '{host}' contains prohibited keyword '{kw}'. Script refused.")

    # Resolve hostname to ensure it maps to a loopback address
    try:
        resolved_ips = {addrinfo[4][0] for addrinfo in socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)}
    except Exception as exc:
        raise ValueError(f"Could not resolve host '{host}': {exc}") from exc

    loopback_prefixes = ("127.", "::1", "0.0.0.0")
    if not any(ip.startswith(loopback_prefixes) for ip in resolved_ips):
        raise ValueError(f"SECURITY VIOLATION: Target host '{host}' resolves to non-loopback IP(s) {resolved_ips}. Refusing.")

    if database.lower() != "kaiops":
        raise ValueError(f"SECURITY VIOLATION: Target database must be 'kaiops', got '{database}'. Refusing.")


def get_connection(host: str, port: int, user: str, password: str, database: str):
    return pymysql.connect(
        host=host,
        port=port,
        user=user,
        password=password,
        database=database,
        autocommit=False,
        cursorclass=pymysql.cursors.DictCursor,
    )


def inspect_state(conn) -> dict[str, int]:
    """Return row counts for all tables."""
    counts = {}
    with conn.cursor() as cur:
        cur.execute("SHOW TABLES")
        tables = [row[f"Tables_in_{conn.db.decode() if isinstance(conn.db, bytes) else conn.db}"] for row in cur.fetchall()]
        for t in tables:
            cur.execute(f"SELECT COUNT(*) AS cnt FROM `{t}`")
            counts[t] = cur.fetchone()["cnt"]
    return counts


def run_reset(
    host: str = "127.0.0.1",
    port: int = 3307,
    user: str = "kaiops",
    password: str = "kaiops",
    database: str = "kaiops",
    execute: bool = False,
    auto_confirm: bool = False,
) -> dict[str, Any]:
    verify_local_target(host, port, database)

    conn = get_connection(host, port, user, password, database)
    try:
        counts_before = inspect_state(conn)

        # Check which incident tables exist and have rows
        affected_tables = []
        total_incident_rows = 0
        for table in INCIDENT_TABLES_ORDERED:
            if table in counts_before:
                cnt = counts_before[table]
                affected_tables.append({"table": table, "rows": cnt})
                total_incident_rows += cnt

        print("\n=======================================================")
        print(f"LOCAL KAIMS INCIDENT QUEUE RESET PLAN ({'EXECUTE MODE' if execute else 'DRY RUN'})")
        print("=======================================================")
        print(f"Target Host    : {host}:{port}")
        print(f"Target Database: {database}")
        print(f"Total Incident Tables Identified: {len(affected_tables)}")
        print(f"Total Incident-Related Records  : {total_incident_rows}")
        print("-------------------------------------------------------")
        print(f"{'TABLE NAME':42} | {'ROWS TO CLEAR':>15}")
        print("-------------------------------------------------------")
        for item in affected_tables:
            print(f"{item['table']:42} | {item['rows']:15,}")
        print("-------------------------------------------------------")

        print("\nPreserved System & Configuration Tables (UNCHANGED):")
        for pt in PRESERVED_TABLES:
            if pt in counts_before:
                print(f"  [PRESERVED] {pt:38} : {counts_before[pt]:,} rows")

        if not execute:
            print("\n[DRY RUN COMPLETE] No records were deleted. Run with --execute to perform reset.")
            return {"status": "dry_run", "affected_tables": affected_tables, "total_rows": total_incident_rows}

        # Execution confirmation
        if not auto_confirm:
            print("\nWARNING: You are about to permanently delete all active & past incidents")
            print("and operational alert queue records from the LOCAL database.")
            print("Application configs, users, runbooks, and Prometheus rules will remain intact.")
            confirmation = input("\nType 'RESET LOCAL INBOX' to confirm deletion: ")
            if confirmation.strip() != "RESET LOCAL INBOX":
                print("Confirmation mismatch. Aborting reset.")
                return {"status": "aborted", "reason": "confirmation_failed"}

        print("\nExecuting transactional deletion...")
        start_time = time.time()
        deleted_summary = {}

        with conn.cursor() as cur:
            # 1. Clean audit logs referencing deleted incidents/plans
            cur.execute("""
                DELETE FROM audit_logs 
                WHERE resource_type IN ('incident', 'plan', 'approval', 'remediation', 'rca')
                   OR resource_id IN (SELECT id FROM incidents)
            """)
            deleted_summary["audit_logs (incident events)"] = cur.rowcount

            # 2. Delete from each incident table in reverse dependency order
            # Disable FK checks strictly for the transaction duration to avoid cyclic lock contention
            cur.execute("SET FOREIGN_KEY_CHECKS = 0")
            for item in affected_tables:
                table = item["table"]
                cur.execute(f"DELETE FROM `{table}`")
                deleted_summary[table] = cur.rowcount
            cur.execute("SET FOREIGN_KEY_CHECKS = 1")

        conn.commit()
        elapsed = time.time() - start_time
        print(f"Deletion committed successfully in {elapsed:.2f}s!")

        counts_after = inspect_state(conn)
        print("\nVerification of Incident Tables after Reset:")
        for item in affected_tables:
            table = item["table"]
            print(f"  {table:42} : {counts_after.get(table, 0)} rows (cleared)")

        print("\nVerification of Preserved Tables:")
        for pt in PRESERVED_TABLES:
            if pt in counts_after:
                print(f"  [INTACT] {pt:38} : {counts_after[pt]:,} rows")

        return {"status": "success", "deleted": deleted_summary}

    finally:
        conn.close()


def main():
    parser = argparse.ArgumentParser(description="Reset Local KaiMS Incident Queue")
    parser.add_argument("--host", default="127.0.0.1", help="Target MySQL host (must be local)")
    parser.add_argument("--port", type=int, default=3307, help="Target MySQL port")
    parser.add_argument("--user", default="kaiops", help="MySQL user")
    parser.add_argument("--password", default="kaiops", help="MySQL password")
    parser.add_argument("--database", default="kaiops", help="Target database")
    parser.add_argument("--execute", action="store_true", help="Execute deletion (default is dry-run)")
    parser.add_argument("--confirm", action="store_true", help="Bypass interactive confirmation (for non-interactive execution)")

    args = parser.parse_args()
    run_reset(
        host=args.host,
        port=args.port,
        user=args.user,
        password=args.password,
        database=args.database,
        execute=args.execute,
        auto_confirm=args.confirm,
    )


if __name__ == "__main__":
    main()
