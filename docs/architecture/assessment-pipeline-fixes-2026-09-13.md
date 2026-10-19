# Impact, RCA, resolution and warning admission review

## Deployed corrections

1. Warning alerts are persisted with pipeline_outcome=live_alert_only and retained in Live Alerts without publishing raw-alert work. Alert Intelligence also stops older queued warnings before discovery, correlation and Jira work. This does not purge already-created downstream jobs or close historical incidents.
2. The unified inbox already excluded warning incident projections but still admitted unlinked warning alert records. SQL now excludes those records before counting and pagination; frontend alternate inbox views also exclude warning/warn records.
3. The evidence compiler now recognizes plural traces/changes/dependencies and source_code categories, prioritizes typed/category identity over provider names, and retains source_reference/citation URIs. Initial evidence retains its bucket category.
4. RCA gathering now includes every context evidence bucket, retains normalized source_type/source_uri, and selects a bounded sample across categories. Previously the first 24 matching records could consume the complete model input before traces or changes were reached.
5. The iterative investigator emits a provisional not-established impact claim before the separate impact stage executes. Recommendation persistence now reconciles that claim with the actual impact assessment. Observed status requires corroborating incident-window current evidence from multiple direct categories, valid citations, readiness and sufficient assessment confidence. Unsupported assessments remain not-established with their actual statement and limitations visible.
6. A generic latency fallback no longer overwrites a successful impact-stage response. It is used only when model processing falls back.

Services deployed: monitoring-adapter, monitoring-ingestion-worker, alert-intelligence, resolution-agent, and UI. Final resolution-agent follow-up deployed after the controlled replay completed. Containers were healthy after deployment.

## Validation

- 96 pipeline/evidence/investigation/inbox/retention regressions passed.
- 17 resolution confidence, evaluation and human-handoff regressions passed.
- Final impact follow-up suite: 25 passed (overlaps earlier suites).
- Frontend: lint, types, architecture checks, build/bundle budgets; 250 tests passed, one optional fixture skipped.
- Live warning check: 920d73c0-40eb-434b-9507-52524371484a persisted with live_alert_only; warning-filtered unified inbox count was zero.
- Live browser unified inbox: 10 returned and rendered records, zero warning rows.
- Controlled replay: incident 773a3406-3cdf-49e7-a764-2edbaa5210ee; request 67dc394d-42af-474a-b61a-ceb94cc8c1d0. Outbox published, request progressed to running and then complete. Completed recommendation e4002dea-69f5-5ef6-a9ca-5c48773cd71b, completed at 08:50:19 UTC, around two minutes after submission. Human approval was retained; no execution was requested.
- Subsequent canonical operations and deployed browser checks passed. Background enrichment continued to publish newer recommendations; the latest inspected workspace was waiting for human evidence, RCA insufficient_evidence, impact not_established and resolution blocked.

## Unresolved operational gaps

The rerun is completed analysis, not recovered service or verified remediation. Latest canonical blockers include missing incident-window resource metrics, incomplete dependency/deployment evidence, inconclusive causal corroboration, and no published executable governed plan/rollback. Earlier queue audit also found repeated unattributable/malformed evidence, expired traces and database deadlocks. Those collection failures were diagnosed but not repaired in this change. The evidence/impact corrections do not establish a root cause where evidence does not support one.

Logs: assessment-pipeline-tests-2026-09-13.log, assessment-resolution-regression-2026-09-13.log, assessment-impact-final-tests-2026-09-13.log, warning-inbox-ui-tests-2026-09-13.log, warning-live-verification-2026-09-13.log, warning-inbox-live-browser-2026-09-13.log, assessment-pipeline-live-rerun-2026-09-13.log, assessment-pipeline-live-progress-2026-09-13.log, assessment-pipeline-live-result-2026-09-13.log, assessment-pipeline-ui-result-2026-09-13.log.
