# Alerts inbox and monitoring verification

Open http://127.0.0.1:8502/#/alerts after connecting with the preview token.

The inbox reads scoped Prometheus snapshots, displays source coverage and automatic intake status, and links alert occurrences to their durable investigations. Search covers name, summary, application and service; state and severity filters and 25-row pages operate on the current snapshot. Four applications are queried per request; use Load next applications to inspect additional registrations. Counts apply to displayed applications. Automatic refresh runs every 15 seconds, including after a failed request. Alert disappearance is not recorded as verified recovery.

The existing incident inbox retains assessed investigations after alerts disappear. Manual monitoring checks are labelled `monitoring-check-*` and do not simulate outages or authorize remediation.

Live verification on 2026-09-14 used the current two-minute window for KaiMS api-gateway and telemetry frontend. Both passed API admission -> RabbitMQ collection -> assessment -> browser evidence display. KaiMS returned 112 metric samples and 80 trace spans. Telemetry returned 10 metric samples and 42 spans. Both trace collections reached the configured limit; telemetry also returned upstream trace warnings. These checks prove sampled connectivity and the collection path, not complete monitoring coverage for every service or causal RCA. No log connector is configured. The existing KaiMS registration also selects telemetry-traces, which returned no matches for api-gateway; that registration was preserved.

The live inbox showed one KaiMS alert linked to its investigation and successful alert snapshots for both applications. No matching telemetry firing alert was present; automatic firing-alert admission is covered by the isolated real-broker contract suite, not by an induced telemetry production fault.

Approval, remediation, and recovery verification remain unavailable. Full signal-to-recovery qualification is still outstanding.

Evidence: `live-monitoring-verification.json`, `tests/verify_live_alerts.cjs`, `ui-verification.json`, and the replacement pytest suite.

Update: the policy-scoped approval, execution and recovery workflow is now implemented and qualified on a disposable target. See RESOLUTION_WORKFLOW.md. KaiMS and telemetry production remediation remain unqualified.
