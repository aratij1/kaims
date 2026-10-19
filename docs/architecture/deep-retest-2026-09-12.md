# Deep retest - 12 September 2026

## New defect found and fixed

A live check of twelve recent investigations found one operations-state HTTP 500. MySQL reported error 1038 (out of sort memory) while selecting the latest context snapshot. The query sorted full evidence JSON rows. The projection now orders narrow snapshot and binding IDs first, then loads the selected records by primary key. No sort-buffer setting or evidence deletion was needed. The context-agent image was rebuilt and deployed.

## Results

- Complete backend suite: 1,228 passed, two deprecation warnings. This run began before the query fix; the final query change also passed 34 targeted persistence/projection tests.
- Frontend quality: lint, architecture checks, TypeScript and 241 tests across 50 files passed.
- Recovery topology and replay safeguards: five tests passed.
- Deployed Prometheus configuration and its five rule files validated; main rules contain 67 alerts/recordings. Jaeger rule tests passed firing and recovery cases.
- Isolated broker checks passed unstarted-publisher rejection, transient retry delivery and exact malformed-byte quarantine. Test exchange/queues were cleaned up.
- Live browser application-selection checks passed saved Telemetry selection, KaiMS reload persistence and registry failure/recovery retention.
- Expanded post-fix read-model sample: all 50 recent investigating incidents returned matching identity, context and investigation workspace; the formerly failing incident now returns 200.
- All 25 reviewed containers match recorded images with zero restarts and configured health checks passing; all 24 HTTP services pass liveness and readiness.

## Limits

This does not establish complete live alert-to-remediation-to-recovery success. No incidents were replayed, remediated or administratively closed for this test. Automatic approval review rejected sending stored private context to the model router, interpreting the request for deeper testing as insufficiently specific disclosure authorization. That inference test was not executed. Explicit authorization naming stored incident context and the configured model router is required for that remaining check.
