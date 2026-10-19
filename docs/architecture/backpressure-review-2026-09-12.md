# Recoverable backlog control and code review

## Implemented and deployed

The context worker now manages the resolution-agent context-events queue. Old ready messages are copied to a durable .deferred queue with publisher confirms and mandatory routing before the original is acknowledged. Message bodies, identities and correlation metadata are preserved. No TTL or purge destroys deferred work. Active consumer deliveries and historical dead letters are not moved. The controller does not create or complete analysis requests; replay goes back through the ordinary handler and its evidence, cancellation and governance checks.

| Setting | Default | Behavior |
|---|---:|---|
| QUEUE_BACKLOG_ENABLED | true | Enable the RCA backlog controller |
| QUEUE_BACKLOG_HIGH | 50 | Start a parking batch when ready depth reaches this value |
| QUEUE_BACKLOG_LOW | 10 | Replay only at or below this ready depth, with a consumer present |
| QUEUE_BACKLOG_AGE_SECONDS | 300 | Minimum age from the recorded production timestamp |
| QUEUE_BACKLOG_BATCH | 10 | Maximum scanned/transferred messages per cycle |
| QUEUE_BACKLOG_POLL_SECONDS | 15 | Time between cycles |

Thresholds are validated at configuration load. Between the high and low thresholds, the controller holds deferred work. Missing, malformed or timezone-less timestamps do not qualify for age-based parking. Other pipeline queues are not automatically parked by this implementation; the identified RCA bottleneck is the scope. An exclusive broker queue prevents concurrent controllers moving the same backlog in opposite directions. Durable parked messages survive controller restarts. Delivery is at least once: a crash after confirmed publication but before acknowledgement can duplicate a message; existing handler/execution idempotency remains necessary.

The Queue Manager now shows a separate Deferred total. Deferred messages are excluded from active ready/in-flight counts and worker scaling recommendations. The normal admin controls still apply.

## Code-review findings corrected

- Strict new-job priority starved retries and expired leases. Batches of at least three now reserve one slot each for expired leases, retries and new jobs; remaining slots take oldest due work. Small batches use oldest due ordering. Row locks with SKIP LOCKED remain in place for multiple workers.
- Five collection jobs were leased before sequential execution. They now start together, with a 90-second per-job deadline below the 120-second lease. Deadline failures are recorded as retry or terminal dead-letter/blocked state, with four attempts maximum.
- Lease owners previously relied on service and PID, which can match across containers. They now include the container hostname.
- Failed batch tasks could otherwise leave siblings running while the next batch starts. The batch runner joins all siblings before reporting a failure.
- Live rollout testing found an initial controller startup condition that only recognized a secondary RabbitMQ publisher. It was corrected to support the primary RabbitMQ transport, with explicit regression cases for both configurations and disabled mode.

## Tests and live verification

The broad backend run passed 1,242 tests. Subsequent final worker/context checks passed 71 tests, and final startup/backpressure checks passed 46 tests; these overlap and are not additive totals. The frontend passed lint, architecture checks, type checks and 241 tests, with one opt-in fixture skipped. Production build and independent bundle limits passed.

Real-broker tests on unique synthetic queues verified four old messages parked, two fresh messages retained, no replay without consumers, and all four parked messages replayed byte-for-byte in two bounded batches. Failure tests verify no acknowledgement on failed publication, source requeue and connection cleanup, fair lease recovery, hung collection timeout, and sibling completion. Eight isolated pipeline topics passed handoff, retry, duplicate suppression, permanent-failure quarantine and malformed-message retention on the deployed code.

The first corrected production controller cycle logged active ready depth 81 and parked 10 messages. The following live audit showed 71 active ready, four in flight, 10 deferred and 56 broker dead letters. The 56 dead letters existed before enabling the corrected controller. Expired collection leases were three at that snapshot, versus eleven in the earlier rollout snapshot; snapshots are observations, not a throughput guarantee. Further controller cycles continue automatically.

## Remaining limits

This is recoverable load deferral, not a resolution of the RCA/evidence bottleneck. Sustained load above the low threshold keeps deferred jobs parked. Old evidence may need recollection when replayed; no freshness or approval gate is bypassed. The durable collection backlog remains substantial and its historical failures are retained. No live governed plan, human approval, infrastructure remediation or verified incident recovery was manufactured by these tests. The isolated topic chain tests transport, while backend regressions test business contracts with controlled dependencies; they do not establish a production incident completed end to end.

Rollback images are retained as kaims-context-agent:before-backpressure-20260912, kaims-api-gateway:before-backpressure-20260912 and kaims-ui:before-backpressure-20260912. Disabling QUEUE_BACKLOG_ENABLED stops both automatic parking and automatic replay; parked messages remain durable and require re-enabling the controller or explicit administrative recovery. Do not purge the deferred queue to improve a dashboard count.

Artifacts: backpressure-backend-tests-2026-09-12.xml, backpressure-deployed-broker-2026-09-12.log, backpressure-pipeline-transport-2026-09-12.log and backpressure-live-state-2026-09-12.json.
