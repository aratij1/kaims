# Existing KaiMS connector routing

KaiMS discovery sources are configured in backend/config/discovery-projects.json under the kaiops profile. The default tenant has no onboarding monitoring_integrations rows; that is not proof that the file-based discovery connectors are absent.

Corrected three concrete routing defects:

- Known legacy prose requests for deployment history, resource telemetry and dependency health were converted to validation with zero connector candidates. They now map to deployment, metrics and topology respectively and can select the already-authorized discovery-mcp connector. Unknown prose still requires an explicit scoped source.
- The MCP request builder omitted metadata.project_id and metadata.project. These now propagate to discovery, while existing label identities remain fallback inputs.
- The context agent omitted resource-health.search from its selectable tools even though the discovery server supports it. Resource telemetry collection now targets that existing tool. Explicit kaims and kaims-core aliases reuse the kaiops profile.

Normal requirement reconciliation supersedes matching legacy validation requests only in the same tenant, incident and RCA version, and only if no job, accepted evidence or human response exists. The old requirement and human request remain recorded as cancelled/superseded; a supported discovery requirement replaces them. Submitted human responses are preserved. Cancelled requirements no longer count as outstanding evidence gaps.

68 connector, discovery and lifecycle tests passed, including project-metadata forwarding, supported legacy routing, unknown-request protection, targeted resource health, idempotent reconciliation and preservation of human responses.

Read-only live calls to existing resource-health.search, dependency-health.search and changes.search all returned evidence without JSON-RPC errors. Repeating the calls with project=kaims also returned evidence, verifying the configured alias. These checks did not invoke model inference, publish Jira messages or execute remediation. Returned records alone do not establish historical incident causality or satisfy every evidence request; normal normalization and freshness gates still apply.

Historical replacements occur through normal reconciliation; this change does not bulk-delete or reset incident records, and it does not claim all existing human-evidence requests or incidents are resolved.
