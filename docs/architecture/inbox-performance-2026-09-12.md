# Unified inbox latency and RCA/impact investigation

The live repository request for tenant default, project KaiMS, record_type all and 25 rows took 10.185 seconds before the change. Profiling showed seven separate counter scans over the same scoped feed, followed by the page query. Counter scans dominated the request.

All record and view counts now use one conditional aggregation over the scoped candidate set. Pagination, filters, tenant scoping and detail hydration remain unchanged. The deployed monitoring adapter returned the same-sized 25-row page in 2.761 and 2.826 seconds (about 72% faster). These are server-side repository timings, not a signed-in browser navigation measurement. Further optimization may be needed for larger datasets or slow concurrent requests.

39 inbox/event persistence regressions passed. The monitoring adapter and the ingestion worker that shares its image were deployed. No frontend code change was needed for this query optimization.

For incident 37e41453-9538-45ad-aa5d-6bb10ab325e3, the live operations-state response reported RCA insufficient_evidence with grounded=false, impact not_established, and next action HUMAN_EVIDENCE. Its three current requirements are category validation and status human_requested. The impact claim exists but does not establish impact. The UI is reflecting these backend states; no cause or customer-impact conclusion was invented to move the journey forward.

The queue audit separately showed 49 ready RCA events, four in flight and 40 deferred. There were zero expired collecting leases, but 707 active collection jobs and no governed resolution plans. Thus the inbox delay was a query defect; RCA backlog and unmet human validation remain operational blockers after that fix. See inbox-rca-live-audit-2026-09-12.json for the timestamped snapshot. This work does not claim verified incident recovery.
