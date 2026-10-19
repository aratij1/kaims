# Proposed Jira linkage repair

Destination: https://kaiops-test.atlassian.net, project KAN, issue type Bug.

Scope: only KaiMS incident 3196fef1-9307-4605-88fd-19dc3b0060d7.

First check for an existing issue with the incident/candidate correlation label; reuse a unique match. Otherwise create one issue with:

- Summary: KaiOpsHighLatencyP99
- Description: KaiMS incident 3196fef1-9307-4605-88fd-19dc3b0060d7; service api-gateway; environment prod; observed signal KaiOpsHighLatencyP99. Root cause and customer impact are not established. Investigation remains open.
- Labels: managed_by_kaiops and the incident/candidate correlation identifiers.

Persist the returned issue key and browse URL on this incident, preserving its current investigation state. No comments, attachments, raw logs, credentials, bulk backfill, closure or remediation are included.

Status: awaiting user approval. Automatic approval review rejected the prior proposed repair because it could create a Jira issue and export internal incident details to an external SaaS destination without specific authorization. No repair request was executed.
