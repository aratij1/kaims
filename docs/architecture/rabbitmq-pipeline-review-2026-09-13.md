# RabbitMQ pipeline review ? 2026-09-13

## Findings and changes

1. Publisher channels accepted returned, unroutable messages without raising. Enable publisher confirms and on_return_raises on publisher and consumer channels. A broker acknowledgment alone does not prove routing.
2. Several independent subscribers shared topic.dlq routing keys. Live bindings showed seven collisions, including resolution-events across approval, notification and remediation. Use the service-specific durable DLQ name as the routing key. Keep queue names and retained messages unchanged. Historical bindings remain for compatibility during rollout; new publishers use isolated routes.
3. Terminal failure persistence had no timeout; it could occupy a consumer indefinitely. Bound it to ten seconds. If it fails, preserve the original delivery rather than acknowledging a terminal state that was never recorded.
4. Normal DLQ publishing had no timeout although malformed-input quarantine did. Bound both publish paths. Failed or timed-out handoffs requeue the original delivery.
5. Cancellation-store failures incurred a fresh Redis timeout for every delivery. Cache the existing fail-open decision for two seconds, matching the successful-read cache window. The test proves 20 immediate checks make one failed request and cancellation is checked again after recovery.
6. Zero prefetch means unlimited unacknowledged deliveries. Reject zero/negative prefetch and publisher pool sizes, negative retries, and nonpositive handler timeouts at configuration validation.
7. Producer connection logging included the broker URL. Remove that field to avoid logging embedded credentials.

## Verification

60 regression cases passed. The real RabbitMQ test passed 42 assertions across eight stage topics, on a unique temporary exchange with synthetic handlers. All temporary test queues and their messages are removed during cleanup. Production alerts are neither injected nor replayed by this test.

| Case | Verification |
| --- | --- |
| 1 | Publish before startup raises |
| 2 | Configured publisher channel pool |
| 3 | Default publisher channel pool |
| 4 | Round-robin publishing |
| 5 | Circuit breaker on repeated publish failure |
| 6 | Configured consumer prefetch |
| 7 | Default consumer prefetch |
| 8 | Hung business handler bounded |
| 9 | Sanitized persisted failure and diagnostic DLQ payload |
| 10 | Malformed JSON preserved in quarantine |
| 11 | Invalid payload type quarantined |
| 12 | Failed quarantine retains original delivery |
| 13 | Deferred consumer has prefetch one |
| 14 | Deferred consumer does not subscribe to fresh events |
| 15 | Active/deferred consumers use the same service DLQ |
| 16 | Old backlog restored above the low watermark |
| 17 | Replayed delivery not parked repeatedly |
| 18 | No restoration without an active consumer |
| 19 | Failed backlog transfer preserves source delivery |
| 20 | Queue manager confirms replacement before acknowledgment |
| 21 | Hung terminal-state persistence requeues |
| 22 | Failed terminal-state persistence requeues |
| 23 | Hung DLQ publish requeues |
| 24 | Failed DLQ publish requeues |
| 25 | Successful terminal handoff acknowledges |
| 26 | Redis outage checks throttled and recovery rechecked |
| 27 | Unsafe numeric transport settings rejected |
| 28 | Zero retries and small positive timeouts supported |
| 29 | Real broker rejects unroutable publish |
| 30 | Real broker isolates sibling subscriber DLQs |
| 31?38 | Each of eight stage topics: handoff, retry, deduplication, permanent failure and malformed-byte preservation |

Stage topics: raw-alerts, enriched-alerts, orchestration-events, context-events, resolution-events, approval-events, remediation-events, closure-events.

## Live observations and limits

The initial audit contained 49 application queues. Active queues had zero ready/unacknowledged deliveries at that observation. The RCA DLQ retained 144 deliveries. A bounded sample of 20 dated September 7?9; all sampled messages were returned to the same DLQ. No deletion or automatic replay of historical failures occurred.

Transport remains at-least-once. A publish-confirm timeout can leave an uncertain delivery outcome; durable business idempotency is still required. In-memory duplicate suppression does not provide exactly-once execution across restarts. This review does not certify that real RCA, impact analysis or remediation succeeds for every alert. Those need incident-specific evidence and governed business tests.

The optional transient requeue mode defaults off; enabling it can keep dependency failures retrying beyond one delivery's retry budget. Historical DLQ recovery needs an explicit classification/replay policy and fresh context where required. Do not blindly replay old evidence snapshots.

Artifacts: rabbitmq-review-tests-2026-09-13.log, rabbitmq-live-transport-2026-09-13.log, rabbitmq-queues-review-2026-09-13.json, rabbitmq-dlq-sample-2026-09-13.json. Deployment results are recorded separately in rabbitmq-rollout-2026-09-13.json.

## Deployment status

The all-service rolling restart was rejected by automatic approval review because of broad service-disruption risk without explicit rollout authorization. No runtime restart was performed by that rejected action. Final images are prepared in build-only mode; scripts/deploy_rabbitmq_review.py requires the explicit --deploy switch to restart services. The fixes are tested source/build changes until deployment is approved. The 42 broker assertions ran the reviewed transport code inside an isolated test process, not by replacing deployed service modules.

Final preparation complete: 24 images for 25 services, all expected image IDs and reviewed source hashes verified. Gateway, context and RCA image contents independently checked. No application service restart performed. Run the prepared rolling deployment only after explicit approval.


## Approved deployment completed

The user explicitly approved the rollout. All 25 application services were rolled and verified against expected image IDs; all health/readiness endpoint checks passed. The deployed transport passed 42 isolated broker assertions across eight stages. The deployed MySQL connection/session ownership test passed without business writes. All 49 application queues have their expected subscriber-specific DLQ binding.

Live verification exposed an additional MySQL 1038 out-of-sort-memory failure: the outbox query sorted full rows containing large context payloads. The query now sorts only event IDs and fetches payloads separately, preserving due order. Sixteen targeted tests passed; a live read-only check loaded 100 records in 11.042 seconds without the sort failure. The three dispatcher services were rebuilt and rolled with this correction, then the full service verification passed again.

The outbox started with 637 due context events. At the final observation, 496 remained and published records had increased from 9,678 to 9,824. Processing is continuing; this is not a claim that every historical incident has resolved. The broker showed 63 ready and 4 unacknowledged active/recovery deliveries. All 144 historical RCA dead letters remain retained; none were purged or manually replayed.

Evidence: mq-final-service-verification-2026-09-13.json, mq-deployed-transport-tests-2026-09-13.log, mq-deployed-lock-verification-2026-09-13.log, mq-deployed-broker-summary-2026-09-13.json, mq-deployed-outbox-status-2026-09-13.json, mq-outbox-live-query-fix-2026-09-13.log.
