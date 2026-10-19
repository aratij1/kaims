# KaiOps Jenkins application remediation

## Architecture boundary

Jenkins is an execution adapter, not the source of truth for the incident
lifecycle. KaiOps owns approval, idempotency, policy, terminal-state polling,
validation, persistence, and closure. A Jenkins HTTP `201 Created` only means
that a build was queued; KaiOps must wait until the build API reports both
`building=false` and a non-empty terminal `result` before publishing
`incident.remediation.executed`.

A successful dry run records `dry_run_validated=true`, `executed=false`,
`recovery_validated=false`, and zero executed scripts. It proves plan validation,
not service recovery. Live execution rejects artifacts from dry runs and requires
matching approval, target, plan digest, script count, execution and recovery evidence.

For the current Docker Compose environment Jenkins remains the compatibility
executor because the governed job and allowlist already exist. The preferred
production direction is:

1. Temporal owns the durable remediation workflow and human approval signals.
2. Jenkins remains an optional activity for legacy application pipelines.
3. Native Azure remediations run as Azure Container Apps Jobs with managed
   identity, bounded retries, and per-execution logs.
4. Every executor returns the same queue/run identifier and terminal execution
   contract to the remediation engine.

Do not move approval or incident closure into Jenkins. That would split the
audit trail and make recovery after API, worker, or Jenkins restarts ambiguous.

KaiOps uses one governed Jenkins job per registered application. Every job uses
`Jenkinsfile.auto-remediation`; application-specific resolution choices come
from `application-resolution-catalog.json`.

Generate the job inventory from a running KaiOps application registry:

```bash
python scripts/generate_jenkins_application_jobs.py \
  --applications http://application-onboarding:8000/applications \
  --output deploy/jenkins/generated/application-jobs.json
```

Create a Jenkins Pipeline job for each `jobs[]` entry using its `job_name` and
`jenkinsfile`. Configure the remediation-engine connection profile with the
same job name, Jenkins endpoint, secret-manager credential reference, and
allowed operation IDs.

The resolution agent supplies a `kaiops.remediation.v2` plan. Jenkins then:

1. validates the incident, target, resolution, command allowlist, and approval;
2. prevents concurrent and stale builds from mutating the same application;
3. captures preflight evidence and runs in dry-run mode by default;
4. executes only allowlisted commands from a persisted approval;
5. retries recovery validation three times within a global time budget;
6. automatically runs the executable rollback contract when validation fails;
7. fingerprints immutable request/result JSON artifacts for closure and audit.

The job uses maximum Pipeline durability because it changes production state.
Do not replace executable validation or rollback commands with prose. A live
mutating request without all three phases is rejected before the first change.

Validate the catalog and pipeline safety contract before publishing jobs:

```bash
python scripts/validate_jenkins_remediation.py
pytest -q backend/tests/test_jenkins_self_healing_contract.py backend/tests/test_jenkins_application_jobs.py
```

Jenkins credentials must be injected into remediation-engine as
`JENKINS_USERNAME` and `JENKINS_API_TOKEN`. Store only the credential reference
in application or connector configuration.
