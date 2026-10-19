# Governed resolution workflow

The replacement supports discovery ? document context ? incident evidence ? assessment ? configured diagnosis ? approval ? execution ? recovery verification. The API's background workers deliver all eight asynchronous stages over durable RabbitMQ queues. Approval persists its bound plan decision and execution outbox event in one database transaction.

## Verified result

`pipeline-validation/maintenance-recovery-20260914T021720Z` reached `recovered` through the live preview API, RabbitMQ and browser UI. The disposable HTTP target initially returned 503, was repaired once, and then returned 200. Two distinct fresh healthy diagnostic observations carried the same execution action ID. All eight messages were published and consumed, and the resolution queues had no ready or unacknowledged messages afterward.

See `resolution-e2e-verification.json` and `tests/verify_resolution_e2e.cjs`. The browser verifier performs a repair only on the disposable target; it expects that specific target to be awaiting approval. It is not a read-only test and is not intended to reset/re-break a recovered target automatically.

## Policy and execution boundary

`resolution-policies.local.json` maps tenant/application/service to server-managed diagnostic and execution URLs, exact failure code, action, and reviewed descriptions. Currently only pipeline-validation has a policy. KaiMS and telemetry have no approved repair policies and are not modified by this demonstration. A match confirms the current condition; it does not retroactively establish the entire incident history.

The diagnostic contract returns service, boolean healthy, failure_code, revision, observed_at, and last_action. Responses must be recent and correctly scoped. Execution receives a fixed action, service, expected_revision and stable Idempotency-Key. The connector MUST enforce revision matching and atomically retain an idempotent receipt with its side effect. It returns service, action_id and status=executed. A generic arbitrary HTTP endpoint is not a conforming executor.

Approval binds an immutable plan digest and expires after ten minutes. Policy changes invalidate approval. The preview tenant token authorizes approve/reject; independent multi-user separation of duties is not implemented. Plans and public artifacts exclude connector credentials and URLs.

Execution retries reuse the same key. A missing/invalid receipt can leave the outcome uncertain; the incident becomes resolution_failed after retry exhaustion rather than claiming recovery. Verification requires two fresh, increasing timestamps after the execution receipt, healthy=true, no failure code, and the same action ID. A failed recovery check does not close the incident.

## UI

Open the pipeline-validation investigation from Incident inbox. It displays the diagnostic cause, operational impact, approved target/action, and recovery observations. Awaiting plans expose Approve and execute plan and Reject plan. Recovered is separate from Assessed. Older assessments remain available after manual reruns.

## Deployment

The optional compose profile `validation` runs the disposable target with a dedicated persistent volume, no host port and a 64 MB memory limit. Its maintenance flag starts enabled only when its state database is first created. It remains healthy after recovery and does not automatically inject another fault.

The existing real-broker contract suite also verifies publisher-confirm handling, redelivery deduplication, isolated retries and quarantine. Unit tests cover changed policy rejection, operator rejection, stale diagnostics, lost-commit retry with exactly one target mutation, and failed verification.


## Real container-stop automatic recovery (14 September 2026)

The incident `diagnostic-4abd8f1095352cc072fc97b762ceca55` was generated automatically after an actual Docker stop of the disposable validation target. Docker restart policy was `no`. The external diagnostic observer detected `container_stopped`; six incident events passed through RabbitMQ: collection, assessment, planning, policy authorization, execution, and verification. The bound decision records `preauthorized_policy`. No browser approval or manual start was used.

The stop completed at 02:55:11 UTC; the container started at 02:55:20 UTC, and the second independent HTTP health observation passed at 02:55:22 UTC. Exactly one connector start call occurred. The final service response was HTTP 200, all queues were drained, and a browser check verified the historical impact/cause, resolution, and recovered lifecycle. The target's own evidence endpoint was unavailable while stopped; the separate host diagnostic supplied the operational failure evidence. Customer/business impact remains unquantified.

See `container-stop-e2e-verification.json` for the recorded result and audit. `node replacement/tests/verify_container_stop_ui.cjs` is a read-only browser check of that result.

`host_recovery_connector.py` runs separately on the Windows host. Its ignored `.local-recovery/connector.json` holds a bearer token, port, and exact validation container ID. Every operation rechecks the pinned ID and Compose labels. It exposes only diagnostic and fixed container-start operations, with revision checking and persistent idempotency receipts. The application receives no Docker socket. Recreating the target changes its ID and requires explicitly configuring a new connector target.

The local automatic policy expires at 03:19:19 UTC (08:49:19 IST) on 14 September 2026. Diagnostic intake skips expired policies. The helper process does not stop automatically at policy expiry; its process ID is recorded in `.local-recovery/process-id.txt`. This bounded test does not enable automatic repairs for KaiMS or telemetry. It confirms that the stopped-container condition can be recovered; it does not diagnose why an arbitrary production process stopped.
