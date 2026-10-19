# Latest 30 alert replay ? 12 September 2026

The frozen selection and per-request observations are in `last30-alert-replay-2026-09-12.json`.

## Scope

Selected the latest 30 persisted alerts in the default tenant at 15:48 UTC. Fourteen alerts resolve to seven unique incidents; submitted seven fresh analysis requests through the existing durable regeneration handoff, sharing the request across correlated alerts. Human approval remains required for remediation.

Of the other 16 records, nine have persisted noise disposition and seven are Jira evidence-request records without a resolvable incident. These were inspected and not promoted into new incidents or submitted as duplicate operational alerts. Thus this is not 30 independent RCA executions.

## Findings

- All seven regeneration commands were published at 15:48:56 UTC; all seven request-specific context handoffs were published by 15:49:04 UTC. Initial context collection and broker handoff work for this sample. Evidence collection does not establish causal sufficiency.
- The RCA queue audit observed 29 ready, four in flight, 70 deferred, and 65 dead-lettered messages. Collection jobs had 984 due jobs and no expired collecting leases. These are environment-wide counts, not all attributable to this replay.
- An active resolution-agent failure reported `placeholder HITL responder is not actionable`. Resolution persistence supplied `incident-owner` when alert ownership was missing, although the repository rejects placeholder responders.
- Corrected the resolution-agent caller to use the same governed responder lookup as context-agent. When no responder is available, it now records an explicit assignment blocker instead of causing that placeholder exception. This retains assignment controls and does not fabricate human evidence.
- Ten focused regression and governed-handoff tests pass. Rebuilt and deployed resolution-agent. The deployment verifier passed image, running-state and service health checks. Logs: `last30-resolution-tests.log`, `last30-resolution-build.log`, `last30-deployment-verification.log`.
- Request delivery remains labelled queued even after durable outbox publication. The report uses separate outbox receipts rather than treating that label as authoritative transport state. This lifecycle reporting discrepancy remains open.

## Limits

Canonical operations-state APIs were checked per incident. An authenticated browser session was not exercised. No remediation approval, execution, closure, or recovery was fabricated. The deployed handoff correction alone does not establish that backlog drainage or end-to-end resolution now succeeds.

## Final outcome: FAIL for end-to-end completion

All seven requests exceeded their configured 15-minute deadline without a request-bound RCA or completed analysis. All seven still persisted status/delivery `queued`, despite published ingress and context receipts. Deadline expiry is recorded by this read-only observer; it did not cancel requests, so they can still be processed later.

Initial snapshot payloads contain context-evidence dictionaries in all seven cases; six have empty discovery-evidence dictionaries. Dictionary lengths in the JSON are field counts, not verified evidence-record counts. Initial snapshot normalized evidence-ID lists are empty because `save_context_snapshot` does not populate them. These observations do not prove complete or causally sufficient context.

Resolution execution and recovery validation remain not started. The successful health checks and focused handoff fix do not change this failed end-to-end result.

Priority follow-ups: diagnose deferred/backlogged RCA scheduling; reconcile published/expired analysis-request lifecycle with transport receipts; investigate empty discovery results for the affected service scopes; make evidence indexing consistent with the payload and final RCA snapshot. Seven Jira evidence-request records in the alert selection also warrant ingestion classification review rather than being treated as new outages.


Observed at 2026-09-12T16:04:04.200591+00:00

| Incident | Context published | Request-bound RCA | Deadline exceeded |
|---|---|---|---|
| `6a5de180-3238-486c-aa78-198684f555a6` | published | No | True |
| `1ec829a9-b698-4246-b9c9-acf34f9fecc9` | published | No | True |
| `71d802b3-bad0-4acd-ab6f-e3eb43c3ef8b` | published | No | True |
| `ccad68dc-9092-49fe-b326-08fcee0e1e6a` | published | No | True |
| `b02361f7-c4e4-4282-a16a-56a1f78d9122` | published | No | True |
| `6671d158-e976-4731-a2da-a9d10a0cef37` | published | No | True |
| `11626e40-4ebb-4a2d-acef-cbbff9f30891` | published | No | True |
