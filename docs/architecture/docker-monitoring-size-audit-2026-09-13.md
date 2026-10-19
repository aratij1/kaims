# Monitoring storage audit

Monitoring's four container filesystems total approximately 630 MB including image layers. Its two metrics volumes contain approximately 317 MiB. Recreated all four containers from pinned images, preserving volumes; all four report healthy and both Prometheus host readiness endpoints respond. Verified active json-file rotation: 10m, three files per container. Added telemetry TSDB size retention of 2GB, matching the existing main Prometheus limit. This retention target excludes transient head/WAL overhead.

Docker-wide accounting before recreation: images 38.96 GB, volumes 228.1 GB, build cache 19.35 GB. The largest volume is kaims_mysql-data at 210.8 GB. MySQL filesystem inspection shows approximately 121 GiB of binary logs and 76 GiB of kaiops data. Binary logging and automatic purge are enabled, with expiry 2,592,000 seconds (30 days).

Largest application table files: context_snapshots 36 GiB, resolution_outbox 23 GiB, resolution_investigations 6.9 GiB, audit_logs 6.5 GiB, resolution_investigation_steps 2.1 GiB. These are allocated file sizes, not necessarily live row sizes. Jaeger occupies another 12.79 GB.

The separate monitoring-adapter image is approximately 914 MB. Its largest uncompressed build layers are shared Python dependencies (399 MB) and apt packages including the MySQL client (153 MB); application source layers are much smaller. No adapter image rebuild was performed because the monitoring Compose group uses upstream Prometheus/Alertmanager/exporter images.

No MySQL records, binary logs, Jaeger traces, unrelated images, or volumes were deleted. A database cleanup must account for incident history, audit retention, replication and point-in-time recovery requirements. Rebuilding monitoring cannot reclaim the MySQL volume.
