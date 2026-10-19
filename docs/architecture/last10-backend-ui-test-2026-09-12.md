# Ten-incident backend and UI retest

Selected the ten most recently updated default-tenant incidents. Captured monitoring-adapter incident data and context-agent operations data, then built the same canonical command workspace as the gateway. All ten passed backend workspace construction and rendered through IncidentCommand and the real ContextEnrichmentPanel in local DOM tests. Human escalation was stubbed; no approval or evidence submission was performed. This does not reproduce a signed-in browser session or prove live remediation.

The snapshot contained three investigating, one detected, three waiting-for-human and three collecting incidents. See the adjacent JSON for identities, RCA versions and collection states. Failures included unsupported evidence categories, incomplete Prometheus series, missing required evidence fields and no attributable discovery evidence.

Fixed unsupported routing: validation and database categories are not normalized by the canonical evidence contract, so they must not schedule automatic collectors, including through explicit candidate overrides. Requirements stay visible as needing an appropriate source/contract. This does not add database evidence support or establish causality.

Fixed deterministic retries: unsupported categories, binding mismatches and missing required evidence fields stop after one attempt; unavailable/incomplete observations retain bounded retry. Existing jobs pick up the worker behavior on their next attempt. Context and resolution services were rebuilt with coherent source and deployed.

Validation: 69 backend regressions passed; all ten captured workspaces rendered in the opt-in real-data UI test. Test harness reads only a local temporary fixture via KAIMS_WORKSPACE_FIXTURE and is skipped when absent. It neither includes private fixtures in source control nor transmits them to a model.

No historical RCA was regenerated and no incident was marked recovered. Model-context disclosure and Jira/remediation execution remain outside this test. The persistent human requests and missing sources are unresolved operational work, not a successful end-to-end recovery claim.


## Follow-up ingestion corrections

Calculated Prometheus series with a recorded query and samples are now retained even when __name__ is absent. They are labeled query_result with a null metric_name and the original expression; no metric identity is invented. Nameless samples without a query remain rejected. Discovery source_uri/citation attribution is retained, and retrieved log snippets map to the canonical message field. Logs without source attribution remain rejected.

65 ingestion, lifecycle, governance and planning tests passed. Context and resolution images were rebuilt and deployed. Ten existing requests across four sampled incidents were identified as repair candidates in evidence-repair-proposal-2026-09-12.json. That proposal is not executed: collection can trigger stored-context RCA inference, which previous automatic approval review required explicit authorization for. Missing traces, absent source data, database-category contract support and human-only causal validation remain unresolved; they are not repaired by accepting malformed evidence or forcing closure.


## Recoverable queue backlog follow-up

Automatic RCA message deferral, low-load replay and collection scheduling fixes are deployed. See [the backlog process, validation evidence and remaining limits](backpressure-review-2026-09-12.md). This does not change the earlier report into a claim of verified incident recovery.
