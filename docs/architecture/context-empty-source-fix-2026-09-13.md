# Empty context sections: mapping correction

The previous context browser incorrectly counted empty dictionaries/arrays as available sections and buried collected records in metadata.context_evidence. The reported incident 773a3406-3cdf-49e7-a764-2edbaa5210ee had empty Cloud and Kubernetes objects but populated logs, traces, changes and other evidence buckets.

Implemented in IncidentContextDetails.tsx:
- Promote each evidence bucket into a directly selectable source, with record counts.
- Exclude recursively empty sources from the available selector and list them explicitly as no data returned. Do not infer connector success, failure or applicability from an empty object.
- Preserve zero/false observations, discovery reports and collection status metadata.
- Group identity fields separately; default to populated evidence rather than an empty infrastructure object.
- Retain source provenance, bounded record pagination and canonical RCA/impact semantics.

Validation:
- Lint, architecture and TypeScript checks passed. Full unit run passed 249 cases and exposed one test text-node selection error; correcting that assertion produced 4/4 passing source-component tests. One optional fixture test skipped.
- Delayed-response/reload/pagination browser regression passed.
- Deployed live browser assertions passed on four incidents, including the reported incident. Tests now select every populated evidence bucket and assert recorded scalar content is rendered, plus verify empty Cloud is absent from available options and explicitly reported unavailable. This replaces the earlier insufficient check that only verified a section container existed.
- Reported incident at final check: logs 46, traces 82, changes 16; counts can grow as collection continues. Categories may overlap and are not a unique-evidence total.
- Other verified incidents: ccad68dc-9092-49fe-b326-08fcee0e1e6a, 6671d158-e976-4731-a2da-a9d10a0cef37, 11626e40-4ebb-4a2d-acef-cbbff9f30891.
- Deployed bundle /assets/index-BfP5BvWH.js matches localhost:8501. Rollback: kaims-ui:before-context-sources-20260913.

Limits: empty backend sources remain empty; this change fixes visibility and source mapping, not connector data collection. The inspected RCA statuses remain insufficient_evidence and impact remains not_established. No causal confirmation or recovery is claimed.

Evidence: context-empty-inspection-2026-09-13.log, context-source-quality-2026-09-13.log, context-source-unit-final-2026-09-13.log, context-source-browser-2026-09-13.log, context-source-live-2026-09-13.log.
