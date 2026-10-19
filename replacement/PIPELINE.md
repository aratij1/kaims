# Replacement pipeline contract

Status: implementation in progress. This directory is isolated from the deployed application. It is not a complete replacement or a production-qualified RCA engine.

## Required flow

1. Application onboarding saves tenant, application, environment, services and explicit connector/document scopes, together with application.discovery.requested in one database transaction.
2. RabbitMQ discovery workers inventory the configured document repositories, runbooks, code/change sources and observability connections. They record a result for every source: collected, no_matches, not_configured, not_applicable, failed or timed_out. No source applicability is invented from an empty list.
3. Documents and evidence are stored once, addressed by immutable IDs and content hashes, with tenant/application ownership, source URI, version, actual observation time and collection time. RabbitMQ messages carry references, not full context snapshots.
4. Discovery commits its manifest and application.context.requested atomically. The context worker validates ownership, indexes documents and creates a versioned application baseline.
5. Application context readiness releases waiting incidents. An alert always requests fresh, incident-window metrics/logs/traces and dependency evidence; onboarding documents alone cannot prove current RCA or impact.
6. Incident context completion requests resolution. The result contains separately evaluated root cause, observed impact, unknowns, citations and next actions. Inconclusive is a terminal result for a bounded attempt, not an endless collecting state. Only new evidence or an explicit retry starts another attempt.
7. Remediation, approvals, verification and closure retain separate governed transitions. Onboarding must not invent an incident or execute remediation.

## RabbitMQ requirements

- Durable topic exchange and a separate durable queue per logical consumer; no competing unrelated subscribers on one queue.
- Persistent messages, mandatory routing and publisher confirmations. Predeclare all required bindings before accepting onboarding traffic.
- Transactional outbox for every state-to-message handoff. Broker failure leaves the outbox pending.
- Durable consumer inbox/idempotency keyed by consumer and event ID; commit before acknowledgment. Delivery remains at-least-once, never advertised as exactly-once.
- Bounded retries, per-stage deadlines, durable failure state and a consumer-specific dead-letter queue. Confirm failure handoff before acknowledging the original message. No blind historical replay.
- Versioned event envelopes carry tenant/application/incident identity, correlation and causation IDs, schema version, timestamp and artifact references. Validate ownership on artifact retrieval.
- A single authoritative state record owns each attempt. The UI renders it; it must not infer workflow state from competing snapshots or event counts.

## Acceptance gates

A real broker test must cover onboarding while RabbitMQ is unavailable, confirmed publication, duplicate delivery, process death after commit but before ACK, broker restart, failed artifact persistence, wrong-tenant references, no matching documents, connector timeout, and terminal RCA results. A controlled fault must be assessed from genuine source observations and checked against its known cause and measured impact. Healthy queues or UI tests do not establish RCA correctness.

## Preserved rewrite scope

Incident workflow is the first working milestone. Onboarding, discovery/document indexing, knowledge, cloud operations, approvals, remediation, verification, notifications, audit, authentication/authorization and migration remain on the replacement checklist. No existing module is silently removed. Cutover requires end-to-end qualification and a reversible migration plan.

## Current observations driving this design

The deployed onboarding endpoint publishes before its request transaction commits. Its discovery consumer commits state and then publishes directly. Either ordering has a failure window. The existing discovery chain focuses on monitoring configuration rather than guaranteeing a document baseline for incident context. Previous incidents also exhibited copied ingestion files as logs, inferred timestamps, stale source manifests, alias-driven empty UI fields, repeated full context payloads and indefinite collection. These are explicit regression cases for the replacement.

## Verified implementation progress
Onboarding registration, local scoped document discovery, document context readiness/blocking, durable state handoffs and confirmed RabbitMQ retry/quarantine are implemented. Eighteen local tests pass. Real RabbitMQ tests pass the actual document-worker chain with a test document, duplicate redelivery, unroutable publication and retry isolation. Docker was recovered without deleting volumes; the existing UI/API health checks returned HTTP 200. Incident-context collection and RCA/impact qualification remain unfinished.
