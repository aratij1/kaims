# RCA processing investigation and fixes - 13 September 2026

## Root causes confirmed

The dominant database bottleneck was an unindexed enrichment-job lookup executed inside RCA/incident transactions. Live transactions remained open for 100-165 seconds while reading `context_enrichment_jobs` by tenant, requirement and connector. The live database lacked the supporting index. Added `(tenant_id, requirement_id, connector_id, created_at)` through an idempotent migration and narrowed the lookup to job IDs before fetching one payload. The measured lookup now uses the new covering index, estimates one row, and took 0.0707s cold, 0.0026s and 0.0018s warm. See `rca-enrichment-query-performance-2026-09-13.json`.


1. **Deferred queue starvation.** Three original replay request IDs were found in the deferred queue, still carrying publication timestamps from 12 September 15:49 UTC. The controller restored work only when active ready depth fell to 10 or fewer; steady arrivals kept it above that threshold. At inspection, active ready depth was 16 and deferred depth was 120. An additional defect allowed restored old messages to be parked again because their original age never changed.
2. **Redundant background RCA.** Every successful enrichment emits a new snapshot and analysis generation. The worker refreshed obsolete generations to the latest snapshot and still performed a complete investigation for each queued generation. Logs showed repeated superseded-snapshot investigations, often for the same incident approximately once per minute. This consumed capacity while explicit reruns waited.
3. **Incorrect lifecycle reporting.** The gateway updated publication status only on its direct publish path. The outbox dispatcher could successfully publish while the analysis request stayed queued, even after completion. The RCA worker did not record when work began.

## Changes

- One dedicated recovery consumer processes deferred RCA through the same ordinary handler, retries and existing DLQ, with prefetch one. It is enabled with the backlog controller and has no fresh-topic binding, preventing duplicate ingestion. This reserves capacity instead of relying only on restoration to the tail of the active queue.
- Deferred work receives one restoration per controller cycle when active depth is above the low watermark but below the high watermark. Low-load batch restoration remains. Restored messages cannot be parked repeatedly. Publisher confirmation precedes acknowledgement; message content, IDs, and governance checks are preserved.
- Obsolete enrichment-generated RCA events can be coalesced only when a newer unexpired enriched snapshot contains every prior evidence ID and has a durable successor context event. A durable `rca.background.coalesced` audit records the successor. Explicit operator requests are excluded, as are missing successors, evidence loss, expired evidence, or scope mismatches. Previously committed RCA generations still repair their downstream handoff normally.
- Shared outbox publication updates request delivery atomically; RCA workers record running state. Delayed receipts cannot reopen terminal states or regress running to published. Tenant isolation is retained. Reconciled only the seven inspected request delivery fields against verified published outbox receipts.

## Validation

- Queue tests: 17 passed, including sustained arrivals, no workers, failed publish, and repeated parking.
- Lifecycle and governed handoff tests: 23 passed.
- Regeneration endpoint tests: six passed.
- New background coalescing tests: eight passed, including explicit reruns, tenant mismatch, absent successor, missing evidence, expired snapshot, and idempotent audit recording.
- Recovery consumer/routing tests: 14 passed.
- Real RabbitMQ test on isolated synthetic queues: restoration above the low watermark passed, restored-message protection passed, and body preservation passed. Synthetic queues cleaned up.
- Rebuilt and deployed context-agent, resolution-agent, and api-gateway; then built the additional resolution-agent coalescing and recovery-consumer patches.

## Evidence and remaining interpretation

Four of the seven original reruns completed on 12 September at 16:08-16:10 UTC, after the original 15-minute test deadline. Their result was insufficient evidence. This does not invalidate the original deadline failure and is not technical recovery.

Request-specific audit: `rca-request-outcomes-2026-09-13.json`.
Original queued message locations: `rca-message-locations-2026-09-13.json`.
Before queue counters: `rca-queues-before-2026-09-13.json`.

The environment also recorded SQL lock waits/deadlocks, transient broker connection failures, and handler timeouts. These are distinct from the confirmed deferred location of the three stuck requests. No evidence freshness checks, approval requirements, or recovery validation gates were bypassed.

The full deployment verifier flags a historical restart count of one for the currently healthy Temporal worker; changed service image/health checks are reported separately. No authenticated browser session has been claimed as tested.


## Live-load correction and recovery

The first coalescing query selected full JSON snapshot rows while sorting. Production evidence volume exposed MySQL error 1038 (out of sort memory), which the small SQLite fixtures did not reproduce. Corrected the query to sort only snapshot IDs, then fetch the selected row by primary key. The correction is included in the final image. Recovered nine messages affected by that specific query error; all unrelated dead letters were retained. Details: `rca-sort-recovery-2026-09-13.json`.

The final worker includes two ordinary RCA consumers and one deferred recovery consumer in this deployment. Live inspection confirmed the three original requests moved out of the deferred queue into active processing order (positions 16, 19, and 20 at the recorded observation); they were not replaced with new requests. See `rca-message-locations-after-2026-09-13.json`.


## Database migration and final recovery

Migration: `backend/database/migrations/20260913_context_enrichment_requirement_index.sql`. Online DDL first hit its bounded metadata-lock wait due to open worker transactions. Briefly paused context-agent and resolution-agent, waited for transactions to exit, applied the index in 2.92 seconds, and resumed workers. No queues were purged. Both workers now run permanent images containing the narrow lookup. Scheduling/coalescing regression suite: 38 passed.

The original node-exporter requests `42858999-4caf-4401-bbe1-b07e86bb744c` and `4d5ed83c-2df3-4c2a-9c02-a22073fd6bc0` completed at 05:38:27 and 05:39:49 UTC on 13 September. The original RabbitMQ request failed at 05:38:34 because its bound context snapshot had expired during the long wait. A new fresh-context retry `9516693b-6194-4a44-944a-379330e21b1d` was submitted through the ordinary durable regeneration path with human approval retained. The old failed record remains intact.


## Shared dispatcher deployment

The closure and remediation services also publish the shared outbox. Their older images explained a remaining queued-delivery label on the fresh retry after publication. Rebuilt and deployed both dispatchers with the common lifecycle fix, verified no remediation actions were active before restarting them, and reconciled the fresh retry against its published receipt. This extends the publication fix to every shared outbox dispatcher.

During recovery, the deferred queue fell from 120 ready messages to 14 and the active queue fell to 26. Final per-request outcomes and final queue counts below supersede these intermediate measurements.


## Final verified outcome

All seven selected incidents now have a request-bound completed RCA. Six original requests completed; the seventh original request explicitly failed due to expired evidence, and its fresh-context retry completed at 05:47:44 UTC on 13 September (RCA version 1). The fresh retry preserved approval controls and completed without extending the old snapshot expiry.

The last queue observation found zero deferred messages and five active ready messages, compared with 120 deferred at diagnosis and a later active peak above 50. All five changed services run the expected permanent images; configured health checks pass. See `rca-changed-services-verification-2026-09-13.json`.

**Processing recovery is verified; causal sufficiency and technical recovery are not.** All seven recorded analysis outcomes are insufficient evidence, with explicit missing-evidence requirements. No execution or recovery has been claimed. Historical unrelated dead-letter messages remain for separate diagnosis; no bulk purge was performed.


| Incident | Request | Result | RCA version |
|---|---|---|---|
| `6a5de180-3238-486c-aa78-198684f555a6` | `6572c322-acce-43a8-a889-336c945198e3` | complete | 5 |
| `1ec829a9-b698-4246-b9c9-acf34f9fecc9` | `7e200948-cfc8-47d2-b536-b30af3ca8060` | complete | 46 |
| `71d802b3-bad0-4acd-ab6f-e3eb43c3ef8b` | `91cbf754-4228-4816-9611-19eba861f08c` | complete | 14 |
| `ccad68dc-9092-49fe-b326-08fcee0e1e6a` | `42858999-4caf-4401-bbe1-b07e86bb744c` | complete | 20 |
| `b02361f7-c4e4-4282-a16a-56a1f78d9122` | `6f120aa4-b0ac-45bf-9e7a-bcab2e8558aa` | complete | 15 |
| `6671d158-e976-4731-a2da-a9d10a0cef37` | `4d5ed83c-2df3-4c2a-9c02-a22073fd6bc0` | complete | 43 |
| `11626e40-4ebb-4a2d-acef-cbbff9f30891` | `ce556ca7-0213-4a44-81b4-ae36cdc04571` | failed | - |
| `11626e40-4ebb-4a2d-acef-cbbff9f30891` | `9516693b-6194-4a44-944a-379330e21b1d` | complete | 1 |


## Incident-view verification

Final view verification exposed an additional missing index on snapshot version ordering. Enrichment's locking lookup sorted full JSON-bearing context rows, causing sort-memory errors and exhausting the context-agent connection pool; operations-state returned 500. Added `idx_context_snapshots_incident_version (tenant_id, incident_id, snapshot_version, collected_at)` through `20260913_context_snapshot_version_index.sql`, applied in 4.54 seconds while workers were paused, then resumed workers.

Afterward, operations-state returned HTTP 200 for all three recovered incidents: 11.720s, 7.352s, and 8.616s. One reports active autonomous collection; two report human-evidence requirements. The latest RabbitMQ incident view now carries a hypothesis from a later analysis, while the verified retry itself completed with insufficient evidence. Impact remains not established. These results are backend/API verification, not an authenticated browser E2E test.

Remaining limits: incident-view reads are still slower than desirable (7-12 seconds in this check); source/evidence gaps still prevent confirmed causality and automatic resolution. Historical unrelated dead-letter messages were retained. Those limitations are separate from the recovered RCA queue/commit stall.
