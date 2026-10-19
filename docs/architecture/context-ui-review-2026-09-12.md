# Incident context UI review ? 2026-09-12

## Findings and repairs

- Failed command-workspace refreshes cleared retained evidence and fell back to compact inbox rows. The page now retains the last successful workspace for the same incident and session, shows a refresh warning and retry button, and prevents execution/approval/closure based on that stale workspace. Initial failures show an explicit load error.
- Unrelated inbox failures could hide a successfully loaded incident. Detail rendering now depends on its canonical command workspace.
- Late responses after navigation could overwrite the selected incident context. Aborted responses are ignored and returned incident identity is checked before assigning workspace data.
- Context provenance depended on duplicate incident context fields. Canonical evidence counts now also make provenance visible.
- Evidence and collection panels now have distinct incident-specific React keys, isolating panel state across incidents and avoiding duplicate-key rendering during refresh.
- Authorization failures (401/403) and removed incidents (404) clear retained context. A retry keeps the stale warning until a successful refresh.

## Live data review

Read-only inspection of 20 recent incident operations states found context in all 20. Latest context counts, bound snapshot counts, and workspace evidence lengths matched for each sampled incident (51?335 records). Examples:

| Incident | Records |
| --- | ---: |
| 3196fef1-9307-4605-88fd-19dc3b0060d7 | 151 |
| 32f77019-ab6b-4945-8942-4b305022b18d | 159 |
| 01bcc68f-84a2-44b7-a215-b344997530e7 | 151 |
| 7a2ce293-5b00-4483-9fff-a4bcf16f7933 | 64 |
| ec3442b6-e252-48aa-b057-e5e55df843b3 | 121 |

The sampled RCA results still reported insufficient evidence. Available context is not proof of causality, impact, or recovery. These UI changes do not bypass investigation gates.

## Validation and deployment

- 42 tests passed across nine incident UI test files, including canonical entry routes, failed refresh retention, initial load failure, independent inbox failure, late responses, mismatched identity, and 401/403/404 clearing.
- TypeScript typecheck and production build with bundle budgets passed.
- Rebuilt local UI image from the existing nginx runtime plus the freshly compiled UI. Rollback image: `kaims-ui:before-context-loading-fix`.
- Local UI HTTP 200 and served incident JavaScript matched the compiled artifact byte-for-byte.

## Limits

Router/component tests use controlled API responses; this is not a full authenticated browser walkthrough. The live audit sampled 20 incidents, not every retained incident. No external Jira issue was created or linked as part of this review. The runtime image inherits existing build metadata; the served asset hash validates this UI deployment.
