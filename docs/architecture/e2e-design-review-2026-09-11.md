# End-to-end design and code review ? 11 September 2026

Scope: independent Docker monitoring, Prometheus/Alertmanager delivery, persistence and inbox queries, Overview/inbox navigation, context evidence, and governed recovery. This is a targeted review of the exercised paths, not certification of every service or production readiness.

## Fixed in this review

| Finding | Consequence | Fix and evidence |
|---|---|---|
| Inbox advertises service/application/signal search but uses exact service equality | Searching Telemetry, Jaeger, or a partial service can hide existing incidents | Case-insensitive literal substring matching over service, project and incident/signal title. Tenant and project constraints remain mandatory. SQLite regression and deployed MySQL checks pass. |
| Blank incident_id wins over a valid linked projection | Navigation can fail despite having a durable incident identity | Skip blank identifiers while retaining canonical projection precedence over fallback id. Regression test added. |
| Missing local.env changes monitoring volume names to fresh defaults | Apparent loss of metric history and Alertmanager state on restart | Startup compares intended mounts with existing monitoring container mounts and rejects mismatches before creating volumes or starting containers. Positive live startup and negative missing-file checks pass. |

Deployed inbox search proof: Telemetry + `front` returns its application incident; `Telemetry` returns four incidents; `Jaeger` returns its dedicated incident; `%` returns zero rather than matching everything. Monitoring adapter and UI are healthy. Previous images have rollback tags `kaims-monitoring-adapter:before-e2e-review` and `kaims-ui:before-e2e-review`.

## Existing fixes checked

- Monitoring owns both Prometheus instances, Alertmanager and the probe exporter outside application Compose lifecycles.
- Overview and inbox route to one durable incident page; legacy query links redirect.
- Jaeger has an independent query API alert with pending-window, failure and recovery rule tests.
- Actual prior outage tests captured firing and resolved notifications for KaiMS, telemetry and Jaeger. See `deploy/monitoring/e2e-*.json` and the monitoring README.
- Grounded RCA is not inferred solely from a confidence label; accepted evidence and requirements gate it.

## Remaining gaps and limits

1. **High ? per-component coverage is incomplete.** Application HTTP health, collector signals, telemetry Prometheus and Jaeger are explicitly covered. That is not proof that stopping every telemetry microservice or backend creates its own incident. Add a service coverage inventory with an owned probe/metric, alert rule, incident scope and recovery check for each required component. Prefer health/transaction checks over assuming a running container is healthy.
2. **High ? failure domain is still one Docker host.** Independent projects survive application shutdown, not host/engine shutdown. A separate monitoring host or external watchdog is needed for host failure detection. Alertmanager retries are not a permanent event archive for arbitrary KaiMS downtime.
3. **High ? incident recovery is not fully automatic.** Recorded resolved notifications do not close incidents. The inspected incidents still have insufficient corroborated RCA/impact evidence, unbound executable plans and/or recovery validation not started. Keep these gates; implement and validate governed recovery profiles instead of clearing incidents based only on a webhook.
4. **Medium ? inbox excludes lower-severity incidents by design.** Backend tests explicitly preserve high/critical-only incident admission. The Watching UI implies broader incident visibility than that policy supplies. Product policy needs alignment; this review did not silently change severity admission.
5. **Medium ? lifecycle projections can lag canonical state.** The prior KaiMS test showed canonical WAITING_FOR_HUMAN while its inbox row remained investigating. Projection synchronization and attention-state mapping need a dedicated event-replay regression before changing lifecycle precedence.
6. **Medium ? deployment provenance is weak in local fallback builds.** Registry failures required packaging validated code on existing local images. Standard Dockerfiles remain the reproducible build path, but immutable release SHA/build metadata and automated image verification should be required for releases. The existing build metadata was not treated as proof of the fallback build's identity.
7. **Medium ? authenticated browser coverage is incomplete.** Router integration tests render the real IncidentCommand with controlled API responses. They do not prove session/role behavior in a real authenticated browser. CI should use a dedicated test account and isolated application fixtures, not extract a production/admin password from container configuration.
8. **Medium ? optional Online Boutique cAdvisor target is down.** Live scrape fails because ob-cadvisor does not resolve. KaiMS and Telemetry targets were healthy. Left this separate application's optional deployment unchanged; enable its exporter or explicitly scope its target to the deployment profile.
9. **Medium ? telemetry log durability is limited.** The demo OpenSearch deployment has no persistent data volume. A container replacement can lose investigation logs. A storage migration should preserve current contents and be validated before changing mounts.
10. **Storage safeguard boundary.** The new check protects existing-container restarts. If both containers and local.env are removed, their previous volume association cannot be inferred reliably. Back up the mapping and data volumes; external volumes alone are not a backup.

## Verification

- Backend: 69 tests across alert/incident persistence, context findings, recovery assessments and recovery observer runtime passed (68 in the wider run, followed by the corrected mixed-record test).
- Frontend: 66 tests across inbox/entry-point navigation, dashboard, durable identity and incident truth passed.
- TypeScript, production build and bundle budget passed.
- Live MySQL-backed filtered inbox and healthy deployed UI/adapter verified.
- Existing-volume startup accepted; missing-mapping startup rejected before mutation.

No synthetic incident closure, lowered RCA threshold, or new approval credential was used to make the review pass.
