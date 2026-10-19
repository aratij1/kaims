# Previous repository documentation

The source is the existing local KaiMS working tree (`docs/`) and its OpenTelemetry demo checkout (`external/telemetry/opentelemetry-demo/`). This import does not fetch another repository or migrate the legacy database.

`repository-document-import.json` records 38 copied source documents with original relative paths, destination paths, byte counts, and SHA-256 checksums. Copies preserve original bytes. Each application also has a `repository-index.md` identifying reference authority. The original three documents per application remain available.

- KaiMS: 18 documents total, including architecture, lifecycle, orchestration, evidence, executor, authorization, and onboarding references.
- Telemetry: 28 documents total, including service READMEs and telemetry schema documentation.

Read these in the running preview at `/#/applications/kaims/documents` and `/#/applications/telemetry/documents`.

Discovery refresh uses the normal durable outbox and RabbitMQ workers. The offline `kaims_next.maintenance.refresh_documents` helper requires stopping API, intake, and consumers sharing the database first. It rejects active collection/analysis and pending unpublished events. It keeps registration, historical artifacts, and incident results; clears the current baseline pointer; and queues fresh discovery. Restart the API after maintenance. New incidents wait for the refreshed baseline. This helper is not an online refresh endpoint; online refresh needs versioned discovery generations.

These are historical reference documents, not confirmed current topology, incident evidence, or permission to execute runbooks. Existing assessed incidents are not automatically reanalyzed. Importing documentation does not complete the still-missing approval, execution, and recovery-verification stages.

Validation: replacement pytest suite and read-only browser checks; results in `repository-document-verification.json` and `overview-verification.json`.

## Online registration updates

The application Registration tab now supports version-checked updates to services and configured document/telemetry sources. Saving a changed registration queues rediscovery and retains configuration snapshots and historical incident baselines. Updates require idle discovery and investigations, including consumption of earlier discovery notifications. Source URLs and credentials are still server-managed. The offline helper remains appropriate for unchanged registrations when only document contents have changed.

Update: the policy-scoped approval, execution and recovery workflow is now implemented and qualified on a disposable target. See RESOLUTION_WORKFLOW.md. KaiMS and telemetry production remediation remain unqualified.
