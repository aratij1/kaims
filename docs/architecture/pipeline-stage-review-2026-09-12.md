# Pipeline stage test ? 12 September 2026

## Result

1,237 backend regression tests passed. Eight isolated RabbitMQ topic stages passed transport handoff, retry, duplicate suppression, permanent-failure quarantine and malformed-byte retention checks. No production business event was injected, no approval was forged, no model inference was invoked by the test harness, and no infrastructure remediation or ticket write was performed. The normal application continued processing existing work during read-only observation.

These results do not establish live end-to-end incident recovery. Production has active collection and RCA work but no persisted governed resolution plans or execution actions. Empty downstream queues are not counted as successful resolution.

## Live stage observations

Observation interval: 2026-09-12T13:29:21.073956+00:00 to 2026-09-12T13:32:28.832297+00:00. Counts span the configured broker namespace and application database, not just the UI-selected project. Broker counters are deltas over this interval; database creation counts use a rolling hour.

| Consumer / topic | Ready before ? after | In flight after | Consumers | Received delta | Ack delta |
|---|---:|---:|---:|---:|---:|
| kaiops.alert-intelligence.raw-alerts | 0 ? 0 | 0 | 8 | 1 | 1 |
| kaiops.approval-service.resolution-events | 0 ? 0 | 0 | 1 | 6 | 6 |
| kaiops.closure-service.remediation-events | 0 ? 0 | 0 | 1 | 0 | 0 |
| kaiops.context-agent.orchestration-events | 0 ? 0 | 0 | 2 | 0 | 0 |
| kaiops.notification-service.resolution-events | 0 ? 0 | 0 | 1 | 6 | 6 |
| kaiops.orchestrator.enriched-alerts | 0 ? 0 | 0 | 1 | 0 | 0 |
| kaiops.remediation-engine.approval-events | 0 ? 0 | 0 | 1 | 0 | 0 |
| kaiops.remediation-engine.resolution-events | 0 ? 0 | 0 | 1 | 6 | 6 |
| kaiops.resolution-agent.context-events | 28 ? 27 | 4 | 2 | 5 | 6 |

The raw-alert queue received and acknowledged one event. No enriched-alert or orchestration deliveries occurred in this window, so this observation does not prove a fresh incident traversed those stages. Resolution consumed six context events and its downstream consumers each acknowledged six resolution events. No approval-event or remediation-event delivery was observed.

## Blockers and gaps

- RCA backlog remains: 27 ready and four in flight at the second snapshot. The 54 broker dead letters were unchanged during observation.
- Durable collection work remains outside RabbitMQ: 533 active jobs, 515 due scheduled/retry jobs, and 14 collecting jobs whose leases were expired or absent. These counts overlap; they must not be added together.
- The first snapshot contained 20,908 historical database collection dead letters. This is distinct from the 54 broker dead letters and is not a count of new failures during this test.
- Current leasing code prioritizes every scheduled job ahead of expired collecting jobs and retries. Under sustained new arrivals, recovery and retry work can starve. This is a code-supported risk; this observation does not establish the cause of each expired lease.
- All recorded outbox rows were published at the first snapshot. That confirms broker handoff state, not completion of downstream RCA. There were 183 context-event outbox creations in the rolling hour at the second snapshot.
- No governed resolution plans or actions exist in the audited tables. Four historical approvals are rejected. No new approval/action/recovery record appeared in the first snapshot rolling-hour checks. Live STP and HITL execution are therefore unproven.
- Collection errors in the most recent hour included expired evidence and timeouts; many errors remained in the generic classification. The test does not claim those generic errors are diagnosed.

## Regression coverage

The full backend suite covers ingestion normalization/correlation, context persistence and snapshot attribution, outbox handoffs, RCA replay/readiness, approval governance, remediation idempotency, and recovery/stability validation. These tests use controlled dependencies; they are not equivalent to running production executors.

Broker fault tests additionally cover handler timeout, failed quarantine retaining the message for redelivery, prefetch limits and sanitized terminal failure callbacks. Duplicate suppression in the isolated chain is tested within a running consumer; durable execution idempotency is covered separately by backend tests.

## Next engineering work

1. Introduce bounded fairness for new, expired-lease and retry jobs; test sustained arrivals and crashed workers.
2. Expose durable backlog and lease age alongside broker depth, with current-versus-historical dead-letter counts.
3. Coalesce obsolete context snapshots while explicitly completing or superseding associated analysis requests; never silently discard their durable state.
4. Diagnose the remaining generic evidence failures, then exercise a controlled grounded incident through plan publication, HITL/STP, execution and verified recovery. Preserve evidence and approval gates.

## Artifacts

- pipeline-stage-tests-2026-09-12.xml: full regression results.
- pipeline-stages-before-2026-09-12.json and pipeline-stages-after-2026-09-12.json: live counters, bindings and database aggregates.
- pipeline-transport-test-2026-09-12.log: eight-stage isolated broker result.
- scripts/audit_pipeline_stages.py: reusable read-only audit; run in a configured service environment.
- scripts/test_pipeline_broker_stages.py: reusable isolated transport test; cleans up only its unique test queues/exchange.

## Relevant test-module counts

| Module | Passed tests |
|---|---:|
| test_approval_capacity_tenant_isolation | 2 |
| test_approval_context | 22 |
| test_approval_service_evaluation_feedback | 5 |
| test_closure_incident_payload | 11 |
| test_closure_pipeline_handoffs | 19 |
| test_closure_reconciliation | 4 |
| test_closure_validation_contract | 10 |
| test_context_enrichment_authorization | 5 |
| test_context_enrichment_lifecycle | 30 |
| test_context_resolution_flow | 34 |
| test_draft_pr_outbox_workflow | 3 |
| test_governed_resolution_handoff | 7 |
| test_message_processing | 3 |
| test_mock_remediation | 2 |
| test_new_alerts_ingestion_history | 1 |
| test_new_alerts_ingestion_recent | 1 |
| test_opensearch_log_ingestion | 8 |
| test_rabbitmq_channel_pool | 5 |
| test_rabbitmq_consumer_hardening | 9 |
| test_rag_ingestion | 7 |
| test_remediation_auto_resolution_path | 35 |
| test_remediation_closure | 4 |
| test_remediation_engine_inference | 4 |
| test_remediation_idempotency | 15 |
| test_remediation_plan | 4 |
| test_remediation_rollback_contract | 3 |
| test_remediation_tool_registry | 20 |
| test_resolution_readiness_handoff | 1 |
| test_resolution_workflow | 3 |
| test_safe_remediation_contracts | 5 |
