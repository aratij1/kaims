"""Controlled end-to-end verification of the governed Jenkins executor.

Dry-run is the default. Pass --execute to perform a real restart of one KaiOps
Compose service through the restricted Docker socket proxy.
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import re
import uuid
from urllib.parse import urljoin

import httpx


async def verify(*, service: str, execute: bool) -> dict[str, object]:
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,62}", service):
        raise ValueError("service must be a safe Compose service name")
    endpoint = os.getenv("REMEDIATION_JENKINS_URL", "http://jenkins:8080").rstrip("/")
    username = os.environ["JENKINS_USERNAME"]
    token = os.environ["JENKINS_API_TOKEN"]
    project = re.sub(r"[^A-Za-z0-9_.-]", "", os.getenv("REMEDIATION_COMPOSE_PROJECT", "kaiops_azure"))
    container = f"{project}-{service}-1"
    plan = {
        "schema_version": "kaiops.remediation.v2",
        "commands": [
            "curl --fail --silent --show-error --retry 3 --retry-all-errors --retry-delay 1 "
            f"-X POST http://docker-socket-proxy:2375/containers/{container}/restart?t=30"
        ],
        "preflight": [
            "curl --fail --silent --show-error --output /dev/null "
            f"http://docker-socket-proxy:2375/containers/{container}/json"
        ],
        "validation_commands": [
            "curl --fail --silent --show-error --retry 15 --retry-all-errors "
            f"--retry-connrefused --retry-delay 2 http://{service}:8000/healthz"
        ],
        "rollback_commands": [],
        "rollback_mode": "not_applicable",
    }
    incident_id = str(uuid.uuid4())
    execution_plan_json = json.dumps(plan, separators=(",", ":"))
    # The pipeline recomputes sha256 over the exact KAI_OPS_EXECUTION_PLAN text
    # it receives (see Jenkinsfile.auto-remediation's "Govern request" stage:
    # it writes the raw parameter to disk and hashes that file) and rejects the
    # build unless the caller's own digest matches - a tamper-evidence check
    # that this parameter was not altered between being approved and being
    # submitted. Skipping it here (as this script previously did) always fails
    # with "the submitted execution plan digest does not match the approved
    # plan", regardless of whether the plan itself is otherwise valid.
    plan_digest = f"sha256:{hashlib.sha256(execution_plan_json.encode()).hexdigest()}"
    params = {
        "KAI_OPS_INCIDENT_ID": incident_id,
        "KAI_OPS_APPROVAL_ID": str(uuid.uuid4()),
        "KAI_OPS_APPLICATION_ID": "kaiops-local-e2e",
        "KAI_OPS_TARGET": service,
        "KAI_OPS_SERVICE": service,
        "KAI_OPS_ENVIRONMENT": "local",
        "KAI_OPS_NAMESPACE": "default",
        "KAI_OPS_RESOLUTION_ID": "restart_service",
        "KAI_OPS_DRY_RUN": str(not execute).lower(),
        "KAI_OPS_EXECUTION_PLAN": execution_plan_json,
        "KAI_OPS_PLAN_DIGEST": plan_digest,
    }
    async with httpx.AsyncClient(auth=(username, token), timeout=30.0) as client:
        headers: dict[str, str] = {}
        crumb_response = await client.get(f"{endpoint}/crumbIssuer/api/json")
        if crumb_response.status_code == 200:
            crumb = crumb_response.json()
            headers[str(crumb.get("crumbRequestField") or "Jenkins-Crumb")] = str(crumb.get("crumb") or "")
        response = await client.post(f"{endpoint}/job/kaiops-auto-remediation/buildWithParameters", params=params, headers=headers)
        response.raise_for_status()
        queue_url = urljoin(f"{endpoint}/", str(response.headers.get("location") or ""))
        if not queue_url:
            raise RuntimeError("Jenkins did not return a queue URL")
        build_url = ""
        for _ in range(60):
            queue = (await client.get(f"{queue_url.rstrip('/')}/api/json")).json()
            if queue.get("cancelled"):
                raise RuntimeError("Jenkins cancelled the queued verification")
            build_url = str((queue.get("executable") or {}).get("url") or "")
            if build_url:
                break
            await asyncio.sleep(1)
        if not build_url:
            raise TimeoutError("Jenkins verification did not leave the queue")
        result = ""
        for _ in range(180):
            build = (await client.get(f"{build_url.rstrip('/')}/api/json")).json()
            result = str(build.get("result") or "")
            if not build.get("building") and result:
                break
            await asyncio.sleep(1)
        if result != "SUCCESS":
            raise RuntimeError(f"Jenkins verification finished with {result or 'unknown status'}: {build_url}")
        artifact_response = await client.get(f"{build_url.rstrip('/')}/artifact/kaiops-result.json")
        artifact_response.raise_for_status()
        artifact = artifact_response.json()
        if artifact.get("dry_run") is not (not execute):
            raise RuntimeError("Jenkins result mode does not match the submitted execution mode")
        if execute:
            if any(artifact.get(key) is not True for key in ("preflight_passed", "executed", "recovery_validated")):
                raise RuntimeError("Jenkins result lacks live execution and recovery evidence")
        elif (artifact.get("dry_run_validated") is not True or artifact.get("executed") is not False
              or artifact.get("recovery_validated") is not False or artifact.get("executed_script_count") != 0):
            raise RuntimeError("Jenkins dry run incorrectly claims execution or recovery")
        return {"build_url": build_url, "incident_id": incident_id, "service": service, "dry_run": not execute, "result": artifact}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--service", default="context-agent")
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args()
    print(json.dumps(asyncio.run(verify(service=args.service, execute=args.execute)), indent=2))


if __name__ == "__main__":
    main()
