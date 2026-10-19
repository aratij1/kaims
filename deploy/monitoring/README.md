# Independent monitoring

Start from the repository root:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File deploy/monitoring/start.ps1
```

The `monitoring` Compose project owns both Prometheus instances, Alertmanager, and the blackbox exporter. KaiMS and telemetry launchers ensure this project is running, but application stop/down commands do not own its containers, networks, or volumes. Both application networks are external and shared with monitoring.

- http://localhost:9090: KaiMS metrics and external telemetry HTTP availability checks.
- http://localhost:19090: telemetry OTLP metrics and collector/signal alerts.
- http://localhost:9093: Alertmanager; webhook delivery to KaiMS has `send_resolved: true`.

Two Prometheus versions are retained to preserve the existing metrics, OTLP receiver, and application endpoints. They are both outside the application projects. The ignored `local.env` binds this installation to its preexisting data volumes, including the former anonymous telemetry and Alertmanager volumes. Keep that file for subsequent starts. A fresh installation without it creates named monitoring volumes.

Stop monitoring explicitly (include `--env-file deploy/monitoring/local.env` on a migrated installation):

```powershell
docker compose --project-name monitoring --env-file deploy/monitoring/local.env -f deploy/monitoring/compose.yaml stop
```

Telemetry must be launched with `deploy/telemetry/start.ps1`, which uses the local `compose.observability.yaml` application layer. The upstream demo Compose layer still contains its original Prometheus service and is not the supported local launcher.

Monitoring remains on the same Docker host. A Docker engine or host outage stops monitoring too. If KaiMS is stopped, Prometheus continues evaluating alerts and Alertmanager retries webhook delivery; KaiMS cannot ingest until it returns. This is not a durable event archive for arbitrary downtime. An alert resolving records a recovery signal; incident closure still requires KaiMS recovery verification.

## Jaeger availability

`telemetry-jaeger` independently probes `http://host.docker.internal:26686/jaeger/ui/api/services` every 15 seconds. `TelemetryJaegerUnavailable` fires after 30 seconds of failed probes or failed probe collection. It is a high-severity Telemetry/jaeger incident, separate from an application outage. Allow approximately 45?75 seconds for scrape, evaluation, grouping, and ingestion. Recovery clears the alert and sends a resolved webhook; incident closure remains governed.

Rule regression check:

```powershell
docker cp observability/tests/telemetry-jaeger.test.yml monitoring-prometheus-1:/tmp/telemetry-jaeger.test.yml
docker exec monitoring-prometheus-1 promtool test rules /tmp/telemetry-jaeger.test.yml
```

The regression covers the pending window, failed API probe, unavailable probe exporter, and alert clearance on recovery. `deploy/telemetry/verify.py` includes the Jaeger probe.

## Storage limits and clean recreation

All four containers rotate JSON logs at 10 MB with three files per container. Both Prometheus services set a 2 GB TSDB retention target; KaiMS retains up to three days, telemetry up to seven days. Prometheus head/WAL data can exceed the block retention target, so this is not a hard filesystem quota.

Recreate monitoring from the pinned upstream images, preserving metrics and Alertmanager state:

```powershell
docker compose --env-file deploy/monitoring/local.env -f deploy/monitoring/compose.yaml up -d --force-recreate --no-build --pull never --wait --wait-timeout 120
```

These services use published images and have no local Dockerfile build step. Do not remove the external database volumes as part of container recreation.
