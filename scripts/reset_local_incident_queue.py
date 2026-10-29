#!/usr/bin/env python3
"""Safely reset the LOCAL KaiMS Incident Queue and related incident/alert state.

Safety guarantees:
- Defaults to --dry-run mode (read-only inspection; zero rows, queues, or keys modified).
- Refuses to run if any environment variable or argument points to a remote or Azure host.
- Verifies Docker container `kaims-latest-mysql-1` belongs to Compose project `kaims-latest`
  and uses local volume `kaims-latest_mysql-data`.
- Verifies live MySQL `@@hostname` matches the container's short ID, `DATABASE() == 'kaiops'`,
  and `@@log_bin == 1`.
- Never drops the database, never deletes Docker volumes, and never disables binary logging.
- Preserves users, roles, sessions, applications, onboarding state, monitoring configs,
  runbooks, RAG/knowledge base, Jira sync cursors, audit logs, and schema migrations.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

CONFIRMATION_TOKEN = "RESET_LOCAL_KAIOPS_INCIDENTS"
EXPECTED_COMPOSE_PROJECT = "kaims-latest"
EXPECTED_MYSQL_CONTAINER = "kaims-latest-mysql-1"
EXPECTED_MYSQL_VOLUME = "kaims-latest_mysql-data"
EXPECTED_DATABASE = "kaiops"
EXPECTED_RABBITMQ_CONTAINER = "kaims-latest-rabbitmq-1"
EXPECTED_REDIS_CONTAINER = "kaims-latest-redis-1"

FORBIDDEN_REMOTE_MARKERS = (
    ".mysql.database.azure.com",
    ".database.windows.net",
    ".azure.com",
    ".servicebus.windows.net",
    ".redis.cache.windows.net",
    ".amazonaws.com",
    ".rds.amazonaws.com",
)
ALLOWED_LOCAL_HOSTS = {"127.0.0.1", "localhost", "mysql", "rabbitmq", "redis", "::1", ""}

# Ordered in strict foreign-key dependency order (child tables -> canonical tables -> context/workflow tables).
INCIDENT_RESET_TABLES: list[tuple[str, str, str]] = [
    # Tier 1: Foreign-Key Child Tables (must be cleared before `incidents`, `incident_projections`, `resolution_investigations`)
    ("Tier 1 (FK Child)", "recovery_evidence", "FK -> remediation_attempts.id, incidents.id"),
    ("Tier 1 (FK Child)", "remediation_outcomes", "FK -> remediation_attempts.id, incidents.id"),
    ("Tier 1 (FK Child)", "remediation_attempts", "FK -> actions.id, approvals.id, execution_plans.id, incidents.id"),
    ("Tier 1 (FK Child)", "actions", "FK -> incidents.id, incidents.tenant_id"),
    ("Tier 1 (FK Child)", "approvals", "FK -> incidents.id, incidents.tenant_id"),
    ("Tier 1 (FK Child)", "execution_plans", "Self-FK supersedes_plan_id; FK -> incidents.id"),
    ("Tier 1 (FK Child)", "rca_reports", "FK -> incidents.id"),
    ("Tier 1 (FK Child)", "incident_lifecycle_transitions", "FK -> incident_projections.incident_id"),
    ("Tier 1 (FK Child)", "resolution_hypotheses", "FK -> resolution_investigations.investigation_id"),
    ("Tier 1 (FK Child)", "resolution_investigation_steps", "FK -> resolution_investigations.investigation_id"),
    ("Tier 1 (FK Child)", "canonical_tickets", "Self-FK duplicate_of -> ticket_id"),
    # Tier 2: Canonical Incident, Projection, Correlation & Alert Queue Tables (directly populate the Incident Queue / Unified Inbox)
    ("Tier 2 (Incident Queue Core)", "incident_projections", "Materialized incident read model for Incident Queue & Closed tab"),
    ("Tier 2 (Incident Queue Core)", "incident_correlation_ownership", "Correlation family ownership driving list_unified_inbox incident_query"),
    ("Tier 2 (Incident Queue Core)", "incident_occurrences", "Links alerts/occurrences to canonical incidents"),
    ("Tier 2 (Incident Queue Core)", "incident_correlation_backfill", "Correlation backfill tracking records"),
    ("Tier 2 (Incident Queue Core)", "incident_events", "Append-only incident event stream consumed by projection worker"),
    ("Tier 2 (Incident Queue Core)", "incident_evidence", "Evidence bound directly to incidents"),
    ("Tier 2 (Incident Queue Core)", "incident_investigation_bindings", "Binds incidents to RCA versions and investigation runs"),
    ("Tier 2 (Incident Queue Core)", "incident_rca_version_reservations", "Per-incident monotonic RCA version counters"),
    ("Tier 2 (Incident Queue Core)", "incidents", "Canonical incident records"),
    ("Tier 2 (Incident Queue Core)", "alerts", "Ingested alert rows driving list_unified_inbox alert_query"),
    ("Tier 2 (Incident Queue Core)", "monitoring_normalized_alerts", "Normalized alert staging records"),
    ("Tier 2 (Incident Queue Core)", "monitoring_received_alerts", "Raw received alert staging records"),
    ("Tier 2 (Incident Queue Core)", "ingestion_events", "Landing-pad ingestion event records"),
    ("Tier 2 (Incident Queue Core)", "object_storage_metadata", "Archived alert payload object metadata"),
    # Tier 3: Incident Context, Investigation, Workflow, Outbox & Draft State Tables
    ("Tier 3 (Context & Workflow)", "resolution_investigations", "RCA investigation sessions for incidents"),
    ("Tier 3 (Context & Workflow)", "resolution_outbox", "Durable outbox for incident/resolution events"),
    ("Tier 3 (Context & Workflow)", "resolution_inbox", "Idempotency inbox for resolution events"),
    ("Tier 3 (Context & Workflow)", "resolution_state_transitions", "State machine transitions for incident resolution"),
    ("Tier 3 (Context & Workflow)", "resolution_plan_supersessions", "Supersession links between resolution plans"),
    ("Tier 3 (Context & Workflow)", "governed_resolution_plans", "Governed remediation plans for incidents"),
    ("Tier 3 (Context & Workflow)", "analysis_requests", "Incident analysis admission requests"),
    ("Tier 3 (Context & Workflow)", "pending_workflows", "Pending human-in-the-loop / approval workflows"),
    ("Tier 3 (Context & Workflow)", "agent_work_items", "Active agent work items shown in operator queues"),
    ("Tier 3 (Context & Workflow)", "approval_assignments", "Incident approval routing assignments"),
    ("Tier 3 (Context & Workflow)", "validation_observations", "Post-remediation validation observations for incidents"),
    ("Tier 3 (Context & Workflow)", "context_enrichment_jobs", "Scheduled/collected/dead-letter context enrichment jobs"),
    ("Tier 3 (Context & Workflow)", "context_evidence_requirements", "Per-incident evidence requirements checked by list_unified_inbox"),
    ("Tier 3 (Context & Workflow)", "context_reconciliation_leases", "Active lease for context reconciliation worker"),
    ("Tier 3 (Context & Workflow)", "context_reconciliation_runs", "Historical context reconciliation run records"),
    ("Tier 3 (Context & Workflow)", "context_snapshots", "Collected incident context snapshots"),
    ("Tier 3 (Context & Workflow)", "canonical_evidence", "Collected incident/alert evidence items"),
    ("Tier 3 (Context & Workflow)", "evidence_rejections", "Rejected incident evidence diagnostics"),
    ("Tier 3 (Context & Workflow)", "human_evidence_requests", "Human evidence requests checked by list_unified_inbox"),
    ("Tier 3 (Context & Workflow)", "evidence_rag_drafts", "Auto-generated per-incident evidence RAG drafts"),
    ("Tier 3 (Context & Workflow)", "evaluation_records", "Per-incident RCA evaluation records"),
    ("Tier 3 (Context & Workflow)", "jira_incident_bindings", "Bindings between Jira issues and canonical incidents"),
    ("Tier 3 (Context & Workflow)", "jira_ticket_links", "Links between Jira tickets and incidents"),
    ("Tier 3 (Context & Workflow)", "jira_webhook_events", "Ingested Jira webhook delivery events"),
]

PRESERVED_TABLES: list[str] = [
    # Users, Roles & Auth
    "users",
    "roles",
    "user_sessions",
    "approval_capacity",
    # Applications & Onboarding
    "applications",
    "application_environments",
    "application_labels",
    "onboarding_state",
    "onboarding_history",
    "onboarding_control_planes",
    "service_onboarding_profiles",
    "service_readiness_scores",
    "service_resource_mappings",
    # Monitoring, Rules, Dashboards & Integration Cursors
    "monitoring_profiles",
    "monitoring_connection_audit",
    "monitoring_integrations",
    "monitoring_credentials",
    "monitoring_webhook_endpoints",
    "monitoring_alert_mappings",
    "monitoring_connection_health",
    "prometheus_configs",
    "alert_rules",
    "recording_rules",
    "grafana_dashboards",
    "validation_history",
    "jira_sync_cursors",
    # Cloud & Discovery Configuration
    "provider_connections",
    "connection_health_checks",
    "connector_definitions",
    "discovery_runs",
    "discovered_resources",
    "resource_relationships",
    "cloud_audit_events",
    "cloud_compensations",
    "cloud_compiled_plans",
    "cloud_credential_sessions",
    "cloud_execution_policies",
    "cloud_maintenance_windows",
    "cloud_plan_approvals",
    "cloud_plan_executions",
    "cloud_plan_simulations",
    # Runbooks, Curated Knowledge & RAG
    "runbooks",
    "runbook_versions",
    "runbook_approvals",
    "runbook_outcomes",
    "runbook_parameters",
    "runbook_execution_history",
    "knowledge_base",
    "context_knowledge",
    "failure_patterns",
    "governed_rag_documents",
    "knowledge_rag_drafts",
    "learning_audit_log",
    "human_corrections",
    "draft_pull_request_outbox",
    # Platform Audit & Schema Migrations
    "audit_logs",
    "schema_migrations",
]

# Only incident/alert pipeline queues are targeted; application onboarding & RAG queues are preserved.
INCIDENT_RABBITMQ_QUEUE_PREFIXES: tuple[str, ...] = (
    "kaiops.alert-intelligence.raw-alerts",
    "kaiops.alert-intelligence.jira-investigations",
    "kaiops.orchestrator.enriched-alerts",
    "kaiops.orchestrator.incident-lifecycle-events",
    "kaiops.context-agent.orchestration-events",
    "kaiops.resolution-agent.context-initial-events",
    "kaiops.resolution-agent.context-events",
    "kaiops.approval-service.resolution-events",
    "kaiops.remediation-engine.resolution-events",
    "kaiops.remediation-engine.approval-events",
    "kaiops.closure-service.remediation-events",
    "kaiops.notification-service.resolution-events",
    "kaiops.audit-service.incident-lifecycle-events",
    "kaiops.audit-service.resolution.events",
    "kaiops.audit-service.closure-events",
    "kaiops.audit-service.human-evidence-assignment-events",
)

INCIDENT_REDIS_KEY_PATTERNS: tuple[str, ...] = (
    "kaiops:alert-analysis:active*",
    "kaiops:context-maintenance:*",
    "kaims:cancelled-processing",
)

INCIDENT_WORKER_CONTAINERS: tuple[str, ...] = (
    "kaims-latest-monitoring-ingestion-worker-1",
    "kaims-latest-monitoring-adapter-1",
    "kaims-latest-alert-intelligence-1",
    "kaims-latest-orchestrator-1",
    "kaims-latest-context-agent-1",
    "kaims-latest-resolution-agent-1",
    "kaims-latest-approval-service-1",
    "kaims-latest-remediation-engine-1",
    "kaims-latest-closure-service-1",
    "kaims-latest-temporal-pilot-worker-1",
    "kaims-latest-mysql-retention-1",
)


def _run(cmd: list[str], *, check: bool = True, timeout: int = 120) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, capture_output=True, text=True, check=check, timeout=timeout)


def _mysql_query(container: str, database: str, sql: str) -> str:
    script = (
        'MYSQL_PWD="$MYSQL_PASSWORD" exec mysql -u"$MYSQL_USER" '
        '--batch --raw --skip-column-names "$1" -e "$2"'
    )
    proc = _run(["docker", "exec", container, "sh", "-c", script, "mysql-exec", database, sql], timeout=300)
    return proc.stdout.strip()


def verify_local_environment(container: str, database: str) -> dict[str, Any]:
    """Perform multi-layer verification that the target is the local kaims-latest MySQL container."""
    # Layer 1: Check host environment variables for any remote/Azure markers
    env_vars_to_check = (
        "DATABASE_URL",
        "DB_HOST",
        "MYSQL_HOST",
        "AZURE_MYSQL_HOST",
        "RABBITMQ_URL",
        "REDIS_URL",
    )
    for var in env_vars_to_check:
        val = os.environ.get(var, "").strip().lower()
        if not val:
            continue
        for marker in FORBIDDEN_REMOTE_MARKERS:
            if marker in val:
                raise RuntimeError(
                    f"SAFETY ABORT: Environment variable {var} contains remote marker '{marker}'. "
                    "Refusing to run against a remote or Azure environment."
                )
        if var in {"DB_HOST", "MYSQL_HOST"} and val not in ALLOWED_LOCAL_HOSTS:
            raise RuntimeError(
                f"SAFETY ABORT: Environment variable {var}='{val}' is not a recognized local host."
            )

    if container != EXPECTED_MYSQL_CONTAINER:
        raise RuntimeError(
            f"SAFETY ABORT: Expected container '{EXPECTED_MYSQL_CONTAINER}', got '{container}'."
        )
    if database != EXPECTED_DATABASE:
        raise RuntimeError(
            f"SAFETY ABORT: Expected database '{EXPECTED_DATABASE}', got '{database}'."
        )

    # Layer 2: Inspect Docker container labels, running state, and volume mounts
    inspect_proc = _run(["docker", "inspect", container], check=False)
    if inspect_proc.returncode != 0:
        raise RuntimeError(f"SAFETY ABORT: Cannot inspect local Docker container '{container}'.")
    info_list = json.loads(inspect_proc.stdout)
    if not info_list:
        raise RuntimeError(f"SAFETY ABORT: Empty docker inspect result for '{container}'.")
    info = info_list[0]
    state = info.get("State") or {}
    if not state.get("Running"):
        raise RuntimeError(f"SAFETY ABORT: Container '{container}' is not running.")

    labels = (info.get("Config") or {}).get("Labels") or {}
    compose_project = labels.get("com.docker.compose.project", "")
    if compose_project != EXPECTED_COMPOSE_PROJECT:
        raise RuntimeError(
            f"SAFETY ABORT: Container '{container}' belongs to project '{compose_project}', "
            f"expected '{EXPECTED_COMPOSE_PROJECT}'."
        )

    mounts = info.get("Mounts") or []
    mysql_volumes = [
        m.get("Name")
        for m in mounts
        if m.get("Destination") == "/var/lib/mysql" and m.get("Type") == "volume"
    ]
    if EXPECTED_MYSQL_VOLUME not in mysql_volumes:
        raise RuntimeError(
            f"SAFETY ABORT: Container '{container}' does not mount expected volume "
            f"'{EXPECTED_MYSQL_VOLUME}' at /var/lib/mysql (found: {mysql_volumes})."
        )

    container_hostname = (info.get("Config") or {}).get("Hostname", "")

    # Layer 3: Query MySQL server directly and verify @@hostname, DATABASE(), @@log_bin, @@read_only
    meta_out = _mysql_query(
        container,
        database,
        "SELECT @@hostname, DATABASE(), @@port, @@log_bin, @@read_only, @@version;",
    )
    parts = meta_out.split("\t")
    if len(parts) < 6:
        raise RuntimeError(f"SAFETY ABORT: Unexpected MySQL metadata response: {meta_out!r}")
    mysql_hostname, mysql_db, mysql_port, log_bin, read_only, version = parts[:6]

    if mysql_hostname != container_hostname:
        raise RuntimeError(
            f"SAFETY ABORT: MySQL @@hostname ('{mysql_hostname}') does not match container "
            f"Hostname ('{container_hostname}')."
        )
    if mysql_db != EXPECTED_DATABASE:
        raise RuntimeError(
            f"SAFETY ABORT: Connected database ('{mysql_db}') does not match '{EXPECTED_DATABASE}'."
        )
    if int(log_bin) != 1:
        raise RuntimeError(
            f"SAFETY ABORT: MySQL binary logging (@@log_bin) is {log_bin}; expected 1."
        )
    if int(read_only) != 0:
        raise RuntimeError(f"SAFETY ABORT: MySQL server is in read_only mode ({read_only}).")

    return {
        "container": container,
        "compose_project": compose_project,
        "volume": EXPECTED_MYSQL_VOLUME,
        "container_hostname": container_hostname,
        "mysql_hostname": mysql_hostname,
        "database": mysql_db,
        "mysql_port": int(mysql_port),
        "log_bin": int(log_bin),
        "read_only": int(read_only),
        "version": version,
    }


def collect_table_counts(container: str, database: str, tables: list[str]) -> dict[str, int]:
    union_queries = [f"SELECT '{tbl}' AS t, COUNT(*) AS c FROM `{tbl}`" for tbl in tables]
    counts: dict[str, int] = {}
    chunk_size = 25
    for idx in range(0, len(union_queries), chunk_size):
        sql = " UNION ALL ".join(union_queries[idx : idx + chunk_size]) + ";"
        out = _mysql_query(container, database, sql)
        for line in out.splitlines():
            if not line.strip():
                continue
            name, cnt = line.split("\t", 1)
            counts[name] = int(cnt)
    return counts


def inspect_rabbitmq_queues(rabbitmq_container: str) -> list[dict[str, Any]]:
    proc = _run(
        [
            "docker",
            "exec",
            rabbitmq_container,
            "rabbitmqctl",
            "--quiet",
            "list_queues",
            "name",
            "messages",
            "messages_ready",
            "messages_unacknowledged",
            "consumers",
        ],
        check=False,
    )
    if proc.returncode != 0:
        return []
    rows: list[dict[str, Any]] = []
    for line in proc.stdout.splitlines():
        parts = line.strip().split("\t")
        if len(parts) != 5 or parts[0] == "name":
            continue
        q_name, msgs, ready, unacked, consumers = parts
        targeted = any(
            q_name == prefix or q_name.startswith(prefix + ".")
            for prefix in INCIDENT_RABBITMQ_QUEUE_PREFIXES
        )
        rows.append(
            {
                "queue": q_name,
                "messages": int(msgs),
                "ready": int(ready),
                "unacked": int(unacked),
                "consumers": int(consumers),
                "targeted_for_purge": targeted,
            }
        )
    return rows


def inspect_redis_keys(redis_container: str) -> list[dict[str, Any]]:
    proc = _run(["docker", "exec", redis_container, "redis-cli", "--scan"], check=False)
    if proc.returncode != 0:
        return []
    keys = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
    result: list[dict[str, Any]] = []
    for key in sorted(set(keys)):
        targeted = (
            key.startswith("kaiops:alert-analysis:active")
            or key.startswith("kaiops:context-maintenance:")
            or key == "kaims:cancelled-processing"
        )
        result.append({"key": key, "targeted_for_delete": targeted})
    return result


def find_latest_backup(backup_dir: Path) -> dict[str, Any] | None:
    if not backup_dir.is_dir():
        return None
    manifests = sorted(backup_dir.glob("kaiops-*.sql.gz.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    for manifest_path in manifests:
        try:
            data = json.loads(manifest_path.read_text(encoding="utf-8"))
            archive_path = backup_dir / str(data.get("file") or "")
            if archive_path.is_file() and archive_path.stat().st_size > 0:
                return {
                    "manifest_path": str(manifest_path.resolve()),
                    "archive_path": str(archive_path.resolve()),
                    "bytes": archive_path.stat().st_size,
                    "sha256": data.get("sha256"),
                    "created_at": data.get("created_at"),
                }
        except Exception:
            continue
    return None


def execute_reset(
    *,
    container: str,
    database: str,
    batch_size: int,
    pause_alertmanager: bool,
    repo_root: Path,
) -> dict[str, Any]:
    stopped_containers: list[str] = []
    containers_to_stop = list(INCIDENT_WORKER_CONTAINERS)
    if pause_alertmanager:
        containers_to_stop.append("monitoring-alertmanager-1")

    print("\n[1/6] Stopping incident ingestion and workflow workers to prevent mid-reset recreation...")
    for worker in containers_to_stop:
        check_proc = _run(
            ["docker", "inspect", "--format", "{{.State.Running}}", worker],
            check=False,
        )
        if check_proc.returncode == 0 and check_proc.stdout.strip().lower() == "true":
            print(f"  - Stopping {worker} ...")
            _run(["docker", "stop", "-t", "15", worker], check=True)
            stopped_containers.append(worker)

    try:
        print("\n[2/6] Purging targeted incident/alert RabbitMQ queues (preserving onboarding & RAG queues)...")
        queues = inspect_rabbitmq_queues(EXPECTED_RABBITMQ_CONTAINER)
        purged_queues: list[dict[str, Any]] = []
        for q in queues:
            if q["targeted_for_purge"] and q["messages"] > 0:
                print(f"  - Purging {q['queue']} ({q['messages']} messages)...")
                _run(
                    ["docker", "exec", EXPECTED_RABBITMQ_CONTAINER, "rabbitmqctl", "--quiet", "purge_queue", q["queue"]],
                    check=True,
                )
                purged_queues.append({"queue": q["queue"], "purged_messages": q["messages"]})

        print("\n[3/6] Clearing targeted incident/alert Redis keys...")
        redis_keys = inspect_redis_keys(EXPECTED_REDIS_CONTAINER)
        deleted_redis_keys: list[str] = []
        for item in redis_keys:
            if item["targeted_for_delete"]:
                _run(["docker", "exec", EXPECTED_REDIS_CONTAINER, "redis-cli", "DEL", item["key"]], check=True)
                deleted_redis_keys.append(item["key"])
                print(f"  - Deleted Redis key: {item['key']}")

        print("\n[4/6] Archiving any pending landing-pad input files so watcher does not replay them...")
        input_dir = repo_root / "backend" / "ingested_alerts" / "input"
        archived_files: list[str] = []
        if input_dir.is_dir():
            stamp = datetime.now(timezone.utc).strftime("%Y/%m/%d")
            replayed_dir = repo_root / "backend" / "ingested_alerts" / "input_replayed" / stamp
            for fpath in input_dir.iterdir():
                if fpath.is_file() and fpath.suffix.lower() in {".json", ".csv", ".txt", ".eml"}:
                    replayed_dir.mkdir(parents=True, exist_ok=True)
                    dest = replayed_dir / fpath.name
                    fpath.replace(dest)
                    archived_files.append(fpath.name)

        print("\n[5/6] Deleting rows from 49 incident/alert tables in FK-safe order (binary logging ENABLED)...")
        # Null out self-referential foreign keys before deleting from execution_plans and canonical_tickets
        _mysql_query(
            container,
            database,
            "UPDATE `execution_plans` SET `supersedes_plan_id` = NULL WHERE `supersedes_plan_id` IS NOT NULL; "
            "UPDATE `canonical_tickets` SET `duplicate_of` = NULL WHERE `duplicate_of` IS NOT NULL;",
        )

        deleted_by_table: dict[str, int] = {}
        for _tier, table_name, _desc in INCIDENT_RESET_TABLES:
            total_deleted = 0
            while True:
                out = _mysql_query(
                    container,
                    database,
                    f"DELETE FROM `{table_name}` LIMIT {int(batch_size)}; SELECT ROW_COUNT();",
                )
                deleted_now = int(out.splitlines()[-1].strip()) if out.strip() else 0
                total_deleted += deleted_now
                if deleted_now < batch_size:
                    break
            deleted_by_table[table_name] = total_deleted
            if total_deleted > 0:
                print(f"  - Cleared {table_name}: {total_deleted:,} rows deleted")

        # Advance jira_sync_cursors poll timestamp so historical Jira issues are not re-polled
        _mysql_query(
            container,
            database,
            "UPDATE `jira_sync_cursors` SET `last_successful_poll_at` = UTC_TIMESTAMP(6), `updated_at` = UTC_TIMESTAMP(6);",
        )
    finally:
        print("\n[6/6] Restarting stopped KaiMS worker containers...")
        for worker in reversed(stopped_containers):
            if worker == "monitoring-alertmanager-1" and pause_alertmanager:
                print(f"  - Leaving {worker} paused as requested by --pause-alertmanager")
                continue
            print(f"  - Starting {worker} ...")
            _run(["docker", "start", worker], check=True)

    return {
        "deleted_by_table": deleted_by_table,
        "total_rows_deleted": sum(deleted_by_table.values()),
        "purged_queues": purged_queues,
        "deleted_redis_keys": deleted_redis_keys,
        "archived_landing_pad_files": archived_files,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument(
        "--dry-run",
        action="store_true",
        default=True,
        help="Inspect target environment, backup status, table counts, queues, and Redis keys without deleting anything (default).",
    )
    mode_group.add_argument(
        "--execute",
        action="store_true",
        help="Execute the local Incident Queue reset (requires --confirm RESET_LOCAL_KAIOPS_INCIDENTS).",
    )
    parser.add_argument(
        "--confirm",
        default="",
        help=f"Required confirmation token when --execute is used: {CONFIRMATION_TOKEN}",
    )
    parser.add_argument("--container", default=EXPECTED_MYSQL_CONTAINER)
    parser.add_argument("--database", default=EXPECTED_DATABASE)
    parser.add_argument("--batch-size", type=int, default=1000, help="Bounded DELETE LIMIT per SQL statement (default: 1000).")
    parser.add_argument(
        "--pause-alertmanager",
        action="store_true",
        help="Keep monitoring-alertmanager-1 stopped after reset so background Prometheus rules do not immediately push new alerts.",
    )
    args = parser.parse_args()

    is_execute = bool(args.execute)
    repo_root = Path(__file__).resolve().parents[1]
    backup_dir = repo_root / "backend" / "retention-archives" / "backups"

    print("=" * 88)
    print(f"KaiMS Local Incident Queue Reset Utility — Mode: {'EXECUTE (DESTRUCTIVE)' if is_execute else 'DRY-RUN (READ-ONLY)'}")
    print("=" * 88)

    verification = verify_local_environment(args.container, args.database)
    print("\n[Local Database Verification: PASSED]")
    print(f"  Docker Container   : {verification['container']} (Hostname: {verification['container_hostname']})")
    print(f"  Compose Project    : {verification['compose_project']}")
    print(f"  Local Data Volume  : {verification['volume']}")
    print(f"  MySQL @@hostname   : {verification['mysql_hostname']} (Matches container ID)")
    print(f"  MySQL Database     : {verification['database']} (Version: {verification['version']})")
    print(f"  Binary Logging     : ENABLED (@@log_bin = {verification['log_bin']}, will NOT be disabled)")

    latest_backup = find_latest_backup(backup_dir)
    print("\n[Pre-Reset Backup Verification]")
    if latest_backup:
        print(f"  Latest Backup File : {latest_backup['archive_path']}")
        print(f"  Manifest File      : {latest_backup['manifest_path']}")
        print(f"  Created At         : {latest_backup['created_at']}")
        print(f"  Size (bytes)       : {latest_backup['bytes']:,}")
        print(f"  SHA-256            : {latest_backup['sha256']}")
    else:
        print(f"  WARNING: No verified backup found in {backup_dir}")

    target_table_names = [t[1] for t in INCIDENT_RESET_TABLES]
    target_counts = collect_table_counts(args.container, args.database, target_table_names)
    preserved_counts = collect_table_counts(args.container, args.database, PRESERVED_TABLES)

    print(f"\n[Affected Incident/Alert Tables to Clear ({len(INCIDENT_RESET_TABLES)} tables)]")
    total_to_delete = 0
    for idx, (tier, tbl, desc) in enumerate(INCIDENT_RESET_TABLES, start=1):
        cnt = target_counts.get(tbl, 0)
        total_to_delete += cnt
        print(f"  {idx:2d}. {tbl:<36} {cnt:>10,} rows  | {tier} — {desc}")
    print(f"  {'-' * 82}")
    print(f"  TOTAL ROWS TO CLEAR ACROSS {len(INCIDENT_RESET_TABLES)} TABLES : {total_to_delete:>10,} rows")

    non_empty_preserved = {k: v for k, v in preserved_counts.items() if v > 0}
    print(f"\n[Preserved Configuration, User, Onboarding, Knowledge & Audit Tables ({len(PRESERVED_TABLES)} tables)]")
    for tbl, cnt in sorted(non_empty_preserved.items()):
        print(f"  - {tbl:<38} {cnt:>10,} rows (PRESERVED)")
    print(f"  (+ {len(PRESERVED_TABLES) - len(non_empty_preserved)} additional empty configuration/cloud/onboarding tables preserved)")

    queues = inspect_rabbitmq_queues(EXPECTED_RABBITMQ_CONTAINER)
    targeted_non_empty_queues = [q for q in queues if q["targeted_for_purge"] and q["messages"] > 0]
    print(f"\n[Targeted RabbitMQ Incident/Alert Queues With Messages ({len(targeted_non_empty_queues)} of {sum(1 for q in queues if q['targeted_for_purge'])} targeted queues)]")
    if targeted_non_empty_queues:
        for q in targeted_non_empty_queues:
            print(
                f"  - {q['queue']:<54} messages={q['messages']} (ready={q['ready']}, unacked={q['unacked']})"
            )
    else:
        print("  - All targeted incident/alert queues currently have 0 messages.")

    redis_keys = inspect_redis_keys(EXPECTED_REDIS_CONTAINER)
    targeted_redis = [k["key"] for k in redis_keys if k["targeted_for_delete"]]
    print(f"\n[Targeted Redis Processing State Keys ({len(targeted_redis)} keys)]")
    for key in targeted_redis:
        print(f"  - {key}")

    if not is_execute:
        print("\n[DRY-RUN COMPLETE] No database records, RabbitMQ queues, or Redis keys were modified.")
        print(
            f"To execute this reset after approval, run:\n"
            f'  python "{Path(__file__).resolve()}" --execute --confirm {CONFIRMATION_TOKEN}'
        )
        return 0

    if args.confirm != CONFIRMATION_TOKEN:
        raise RuntimeError(
            f"SAFETY ABORT: --execute requires --confirm {CONFIRMATION_TOKEN} (got {args.confirm!r})."
        )
    if latest_backup is None:
        raise RuntimeError(
            f"SAFETY ABORT: Refusing to execute reset without a verified backup in {backup_dir}."
        )

    outcome = execute_reset(
        container=args.container,
        database=args.database,
        batch_size=max(100, min(int(args.batch_size), 5000)),
        pause_alertmanager=bool(args.pause_alertmanager),
        repo_root=repo_root,
    )
    post_counts = collect_table_counts(args.container, args.database, target_table_names)
    remaining_rows = sum(post_counts.values())
    print("\n" + "=" * 88)
    print(f"RESET COMPLETE: {outcome['total_rows_deleted']:,} rows deleted; remaining rows across 49 target tables: {remaining_rows}")
    print("=" * 88)
    return 0


if __name__ == "__main__":
    sys.exit(main())
