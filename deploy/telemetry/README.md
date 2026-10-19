> Monitoring now runs in the independent `monitoring` Compose project. See [monitoring setup](../monitoring/README.md). Use `start.ps1`; Prometheus is excluded from the local application layer. Earlier verification below describes the original deployment.

# Telemetry Docker deployment

Deployed and verified on 2026-09-11. Application: http://localhost:18080

## Start or rebuild

From the repository root:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File deploy/telemetry/start.ps1
```

The execution-policy override applies only to this process. The launcher starts OpenSearch, installs the log mapping, and waits for the full stack. To rebuild the frontend from source, add `-RebuildFrontend`.

The local frontend image is `telemetry-local/frontend:20260911`. Other services use the upstream images declared by the demo. Source revision: `2d1bc923654bcf6db415c4f1582952cdbf19f872`. Upstream demo image tags are mutable.

The local resource profile uses one HTTP-only load-generator user; browser
traffic is disabled. Grafana and the load generator each have a 0.5 CPU limit,
and flagd has a 0.25 CPU limit. Grafana has 512 MiB memory with a 384 MiB Go
memory target, and flagd has 128 MiB with a 96 MiB target. These settings bound
background demo load while retaining metrics, traces, logs, and alerting.

Endpoints:

- Application: http://localhost:18080
- Prometheus: http://localhost:19090
- Grafana: http://localhost:13000/grafana/
- Jaeger: http://localhost:26686/jaeger/ui/

## Verified behavior

- All 25 telemetry containers were running; every configured Docker health check passed.
- Fresh frontend image built successfully and serves the shop with HTTP 200.
- KaiMS runtime discovery returns telemetry container evidence. Frontend evidence discovery successfully queries Prometheus, Jaeger, and OpenSearch.
- A bounded proxy outage produced `TelemetryApplicationUnavailable` in Prometheus and Alertmanager, and KaiMS captured it as alert `8141fa10-e055-404a-9822-bed425d366fc`.
- The proxy was restored in the test's cleanup block. KaiMS persisted the resolved notification at `2026-09-11T07:03:36.557564+00:00`.
- The startup collector alert also has a persisted resolved notification.
- Final verification showed a successful application probe and zero active telemetry alerts in Prometheus and Alertmanager.
- The associated KaiMS incidents remain in the investigation workflow. Source resolution is verified; incident closure and automatic remediation are not claimed. The application test incident is `32f77019-ab6b-4945-8942-4b305022b18d`.

See `verification-20260911.json` for runtime evidence and incident states.

## Configuration fixes

- Dedicated Jaeger host port 26686 and corrected discovery API base path `/jaeger/ui`.
- Collector log processor name updated to match the downloaded collector.
- Local application availability probe through the existing KaiMS blackbox exporter on port 9115.
- Missing-span rule checks the application collector specifically and detects a zero accepted-span rate.
- New log indices use `otel-logs-v2-*` with explicit attribute mappings, fixing observed OpenSearch field-type conflicts. Some startup records were rejected before this fix; subsequent indexing was verified. Existing indices were not deleted by the mapping repair.

The mapping uses OpenSearch's [flat object field type](https://docs.opensearch.org/latest/field-types/flat-object/) for variable log attributes. Install the template before collector startup, as the launcher does.

The upstream demo does not mount durable OpenSearch storage. Its logs can be lost when that container is replaced; this deployment is a local demo, not a fully hardened production installation. KaiMS intake observations are stored separately.

## Repeat read-only checks

```powershell
Get-Content deploy/telemetry/verify.py | docker exec -i kaims-monitoring-adapter-1 python -
```

This reports application probes, collector metrics, telemetry discovery, current alerts, intake firing/resolved observations, and incident states. It does not close incidents or inject faults.
