# Local MySQL retention

## Active development defaults

- Binary logs: 3 days (259200 seconds), persisted live with SET PERSIST and in Compose via MYSQL_BINLOG_RETENTION_SECONDS. No replicas or connected binlog consumers were found; no repository backup job was found before applying the approved change. Expired logs were removed using PURGE BINARY LOGS, not filesystem deletion. The volume fell from approximately 197 GiB to 148 GiB immediately after this step; ongoing application writes continue.
- Published resolution outbox payloads: archive after seven days only for known closed incidents, with both publication and update timestamps older than the cutoff. Keep primary keys and published state as delivery tombstones to preserve idempotency. Pending, failed, recently updated and active-incident records remain unchanged.
- Snapshots: consider after 30 days, only expired and superseded snapshots for closed incidents. Check live structured IDs, fingerprints and JSON references before removal. Preserve parents, bound findings, active incidents, current snapshots and audit history. Current snapshots are younger than the cutoff.
- Schedule: mysql-retention runs daily. At most 1000 outbox metadata candidates and 20 snapshot candidates per pass. It stops admitting outbox batches after two minutes; a running batch and reference checks can take longer. Persisted cursors advance through protected records on subsequent days. SQL/lock timeouts fail closed. Separate database-scoped advisory locks prevent concurrent cleanup on the same database.

## Archives and recovery

Original rows are compressed, flushed and checksum-verified before source modification. Archives reside in backend/retention-archives on the Windows host, outside the MySQL volume, and are excluded from Git and Docker build contexts. They may contain operational evidence. No automatic archive deletion is configured. Monitor this directory and move older archives to your chosen backup storage; another directory on the same host is not disaster recovery.

Preview cleanup:

```powershell
docker compose run --rm --no-deps mysql-retention python /app/scripts/manage_mysql_retention.py --max-batches 1 --archive-dir /archives
```

Preview restoration; add --execute only to perform it:

```powershell
docker compose run --rm --no-deps mysql-retention python /app/scripts/manage_mysql_retention.py --restore-archive /archives/<sha256>.json.gz
```

Restore checks the checksum and refuses to overwrite changed delivery metadata or existing snapshots. It retains outbox event identity and publication state.

Create a full compressed logical backup outside the Docker volume:

```powershell
.venv\Scripts\python.exe scripts/backup_mysql.py --directory backend/retention-archives/backups
```

The backup tool streams mysqldump with a consistent transaction, validates gzip integrity and writes a SHA-256 manifest. Failed dumps remain marked partial. A backup/restore roundtrip was tested on an isolated temporary MySQL database. A full backup of the live 76 GiB application dataset has NOT been run or scheduled. Plan storage capacity and avoid schema migrations during a full dump. Binlog retention limits available point-in-time recovery history.

## Operations

```powershell
docker compose ps mysql-retention
docker compose logs --tail 5 mysql-retention
Get-Content backend/retention-archives/last-run.json
```

The daily report records counts, cursors and largest table allocations. A stale report or last-error.json makes the worker unhealthy. Log output does not contain incident payloads or credentials. Retention indexes are recorded in the ORM and an idempotent migration, and were installed online without a MySQL restart.

Compaction/deletion makes InnoDB pages reusable; it does not necessarily shrink table files or Docker Desktop's virtual disk immediately. No automatic OPTIMIZE TABLE, table truncation, audit-history deletion or full database rebuild is performed.

## Validation

Four tests passed, including real MySQL archive/restore and backup/restore roundtrips using isolated temporary databases. Coverage includes active/pending/failed event protection, deduplication keys, structured/JSON/fingerprint snapshot references, latest snapshot protection, repeated cleanup and archive corruption. Compose validation passed.

## Remaining growth work

Recent snapshots and outbox messages remain large. Retention does not replace an application-level change to store shared evidence once and pass references. No message contract or investigation evidence format was changed in this rollout. Closed-incident audit archival needs an agreed history policy; those records remain intact.

## Rollout verification
The daily worker completed successful passes, archived eligible closed-incident outbox payloads and removed no snapshots. The latest bounded pass reported 30 payloads compacted and stopped at its time budget; the prior completed pass reported 116. The API health endpoint returned HTTP 200. Binary-log expiry is 259200 seconds. Manual previews write a separate report and cannot reset the worker cursor. Worker restarts respect the last successful daily run.
