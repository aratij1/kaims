# Accuracy, HITL and STP recheck

144 backend tests passed across resolution confidence/quality, evidence compilation, human evidence lifecycle, Jira governance, approval context, selection automation, governed handoff and execution safety. 22 frontend incident/evidence tests passed; TypeScript, production build and compressed-asset budgets passed.

The deployed resolution auto-execution flag is true. Policy tests verify that eligible low-risk actions can select automatic processing when enabled, while inconclusive RCA, missing validation/rollback, unresolved contradictions, high risk and other unmet gates prevent that path. These are contract tests, not a new live remediation execution or an empirical model-accuracy benchmark.

The screenshot shows collected evidence and remaining requests, not an established root cause. The latest context can contain more records than the immutable snapshot bound to the current RCA. Collection does not itself authorize execution.

The oversized evidence-ID list was replaced with a collapsed details section and a bounded scroll area, retaining all source IDs. A collection-versus-causality explanation was added. The UI image was rebuilt, deployed and its served asset verified against the tested build. No live incident approval, Jira update or remediation was performed.
