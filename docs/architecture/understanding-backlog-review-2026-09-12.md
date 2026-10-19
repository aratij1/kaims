# Understanding-stage backlog review

The read-only database audit found 472 investigating incidents, 10 RCA-ready incidents and 135 closed incidents. These are stored aggregate states, not proof that every incident has recently run. Requirements included 5,067 human requests and 3,609 identified items; collection history included 20,454 dead letters. Large historical failure groups were no attributable discovery evidence (9,725), no matching approved evidence (5,403), and expired/missing traces (4,635). These counts are cumulative, not unique outages.

## Corrected shared behavior

- RCA prompts now request structured category/question/reason gaps. The planner preserves these fields and chooses existing authorized collection sources; prose fallback remains explicit validation work.
- Initial follow-up queries now use the alert incident window, matching reconciliation, rather than the time at which delayed analysis happens. Human response deadlines still use current time.
- Reconciliation respects active collection and human requests, chooses unattempted fallback connectors, carries attempted-source history, and avoids assigning human work while another collection job remains active.

## Verification and deployment

63 targeted tests passed. Context agent, resolution agent and model router were rebuilt with the full coherent source package and import checks. All 25 reviewed containers match recorded images with zero restarts; all 24 HTTP services return 200 on liveness/readiness and the Temporal process probe passes.

A live synthetic model call returned seven structured gaps: metrics, logs, traces, topology, deployment, change and validation. It did not persist an incident or trigger remediation. Automatic approval review rejected the proposed call using stored private context because its transmission through the model router lacked specific authorization; no stored-context inference was run.

Existing saved RCA results have not been rewritten. Missing/expired traces and absent approved evidence remain real blockers. These changes do not establish that the entire historical backlog has progressed beyond Understanding, and no grounding or recovery gate was bypassed.
