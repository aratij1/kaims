from __future__ import annotations

import argparse
import json
import os
import time
from datetime import UTC, datetime, timedelta
from urllib.error import HTTPError
from urllib.request import Request, urlopen


CONTEXT_FIELDS = {
    "id",
    "created_at",
    "trace_id",
    "metadata",
    "tenant_id",
    "incident_id",
    "alert",
    "deployment",
    "related_incidents",
    "runbook",
    "dependency_services",
    "recent_changes",
    "cmdb",
    "cloud",
    "kubernetes",
    "observability",
}


def request_json(url: str, *, method: str = "GET", payload: object | None = None, token: str = "", timeout: int = 30):
    body = json.dumps(payload).encode() if payload is not None else None
    headers = {"Accept": "application/json"}
    if body is not None:
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = Request(url, data=body, headers=headers, method=method)
    try:
        with urlopen(request, timeout=timeout) as response:
            raw = response.read().decode()
            return response.status, json.loads(raw) if raw else {}
    except HTTPError as exc:
        raw = exc.read().decode(errors="replace")
        try:
            detail = json.loads(raw)
        except json.JSONDecodeError:
            detail = raw
        return exc.code, detail


def unwrap(payload):
    return payload.get("data", payload) if isinstance(payload, dict) else payload


def summarize_context_evidence(context: object, snapshot: object | None = None) -> dict[str, object]:
    context_map = context if isinstance(context, dict) else {}
    metadata = context_map.get("metadata") if isinstance(context_map.get("metadata"), dict) else {}
    snapshot_map = snapshot if isinstance(snapshot, dict) else context_map.get("snapshot")
    snapshot_map = snapshot_map if isinstance(snapshot_map, dict) else {}
    source_manifest = (
        snapshot_map.get("source_manifest")
        if isinstance(snapshot_map.get("source_manifest"), dict)
        else {}
    )
    collected_sources: list[str] = []
    evidence_count = 0
    for source, detail in source_manifest.items():
        detail_map = detail if isinstance(detail, dict) else {}
        try:
            result_count = int(detail_map.get("result_count") or detail_map.get("fresh_count") or 0)
        except (TypeError, ValueError):
            result_count = 0
        if result_count > 0:
            collected_sources.append(str(source))
            evidence_count += result_count
    discovery_evidence = metadata.get("discovery_evidence")
    context_evidence = metadata.get("context_evidence")
    evidence_present = bool(discovery_evidence or context_evidence or evidence_count)
    return {
        "evidence_present": evidence_present,
        "evidence_count": evidence_count,
        "collected_sources": sorted(collected_sources),
        "context_complete": metadata.get("context_complete") is True,
        "context_source": metadata.get("context_source"),
        "snapshot_quality": snapshot_map.get("quality_score"),
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Probe alert arrival through incident RCA without relying on host port forwarding"
    )
    parser.add_argument("--gateway", default="http://api-gateway:8000")
    parser.add_argument("--monitoring", default="http://monitoring-adapter:8000")
    parser.add_argument("--alertmanager", default="http://alertmanager:9093")
    parser.add_argument("--resolution", default="http://resolution-agent:8000")
    parser.add_argument("--username", default="admin")
    parser.add_argument("--password", default=os.getenv("ADMIN_USER_PASSWORD", "Admin@123456"))
    parser.add_argument("--wait-seconds", type=int, default=240)
    parser.add_argument(
        "--recover-missing-analysis",
        action="store_true",
        help="Explicitly exercise direct resolution recovery; excludes natural-delivery verification.",
    )
    parser.add_argument(
        "--include-live-remediation",
        action="store_true",
        help="Approve the recommendation and allow configured remediation side effects.",
    )
    parser.add_argument(
        "--complete-diagnostic",
        action="store_true",
        help="Close an explicitly diagnostic/watch-only outcome without executing a corrective operation.",
    )
    parser.add_argument(
        "--manual-close-inconclusive",
        action="store_true",
        help="Use the authenticated administrator closure path when evidence policy leaves the incident inconclusive.",
    )
    args = parser.parse_args()
    selected_closure_modes = sum(
        bool(value)
        for value in (
            args.include_live_remediation,
            args.complete_diagnostic,
            args.manual_close_inconclusive,
        )
    )
    if selected_closure_modes > 1:
        parser.error(
            "choose only one of --include-live-remediation, --complete-diagnostic, or --manual-close-inconclusive"
        )

    suffix = datetime.now(UTC).strftime("%Y%m%d%H%M%S")
    name = f"ServiceDown-E2E-{suffix}"
    service = "discovery-mcp"
    # E2E-* environments intentionally share one deduplication family in the
    # product. Use a run-scoped review environment here so each probe exercises
    # a new incident from ingestion through closure instead of attaching to a
    # still-open incident from an earlier test run.
    environment = f"review-{suffix}"
    now = datetime.now(UTC)
    stages: dict[str, object] = {"name": name}

    status, login = request_json(
        f"{args.gateway}/auth/login",
        method="POST",
        payload={"username": args.username, "password": args.password, "device": "e2e-lifecycle-probe"},
    )
    token = str(login.get("access_token") or "") if isinstance(login, dict) else ""
    stages["login"] = {"ok": status == 200 and bool(token), "status": status}
    if not token:
        print(json.dumps(stages, indent=2))
        return 2

    alert = [{
        "labels": {
            "alertname": name,
            "service": service,
            "severity": "critical",
            "application": "KaiOps",
            "project_name": "KaiOps",
            "environment": environment,
        },
        "annotations": {"summary": name, "description": f"{service} is unreachable; endpoint down"},
        "startsAt": now.isoformat(),
        "endsAt": (now + timedelta(minutes=10)).isoformat(),
        "generatorURL": "http://prometheus:9090/graph?g0.expr=vector(1)",
    }]
    status, response = request_json(f"{args.alertmanager}/api/v2/alerts", method="POST", payload=alert)
    stages["alertmanager"] = {"ok": 200 <= status < 300, "status": status}
    if not 200 <= status < 300:
        stages["alertmanager"]["response"] = response
        print(json.dumps(stages, indent=2))
        return 3

    deadline = time.time() + args.wait_seconds
    row = None
    while time.time() < deadline and row is None:
        status, payload = request_json(f"{args.gateway}/alerts/all?limit=5000", token=token, timeout=45)
        rows = unwrap(payload).get("rows", []) if status == 200 else []
        row = next((item for item in rows if item.get("name") == name), None)
        if row is None:
            time.sleep(2)
    stages["live_stream"] = {"ok": row is not None, "alert_id": row.get("id") if row else None}
    if row is None:
        print(json.dumps(stages, indent=2))
        return 4

    alert_id = row["id"]
    processed = None
    while time.time() < deadline:
        status, payload = request_json(
            f"{args.monitoring}/alerts/{alert_id}/processed-result?tenant_id=default",
            timeout=45,
        )
        if status == 200:
            processed = payload
            processed_context = processed.get("context") or {}
            if (
                processed_context
                and (processed.get("recommendation") or {}).get("id")
                and summarize_context_evidence(processed_context).get("evidence_present")
            ):
                break
        time.sleep(2)

    incident = (processed or {}).get("incident") or {}
    context = (processed or {}).get("context") or {}
    recommendation = (processed or {}).get("recommendation") or {}
    context_evidence = summarize_context_evidence(context)
    stages["incident"] = {"ok": bool(incident.get("id")), "incident_id": incident.get("id")}
    stages["context"] = {
        "ok": bool(context) and bool(context_evidence["evidence_present"]),
        **context_evidence,
    }
    if args.recover_missing_analysis and context and not recommendation.get("id"):
        # The processed read model adds presentation-only fields such as
        # ``snapshot``. Resolution accepts the strict Context event contract,
        # so only forward schema fields when exercising the recovery path.
        resolution_context = {key: value for key, value in context.items() if key in CONTEXT_FIELDS}
        resolution_context["incident_id"] = incident.get("id")
        resolution_context["tenant_id"] = context.get("tenant_id") or "default"
        resolution_context["alert"] = context.get("alert") or (processed or {}).get("alert")
        status, recommendation_payload = request_json(
            f"{args.resolution.rstrip('/')}/resolve?publish_events=true",
            method="POST",
            payload=resolution_context,
            timeout=180,
        )
        stages["rca_regeneration"] = {"ok": status == 200, "status": status}
        if status == 200 and isinstance(recommendation_payload, dict):
            recommendation = recommendation_payload
        else:
            stages["rca_regeneration"]["response"] = recommendation_payload
    stages["rca"] = {
        "ok": bool(recommendation.get("id")),
        "recommendation_id": recommendation.get("id"),
        "natural_delivery": bool(recommendation.get("id")) and "rca_regeneration" not in stages,
        "analysis_status": (recommendation.get("metadata") or {}).get("rca_status"),
    }
    impact = (recommendation.get("metadata") or {}).get("impact_analysis") or {}
    stages["impact"] = {
        "ok": bool(impact) and isinstance(impact.get("observed_impact"), str),
        "assessment_present": bool(impact),
        "observed_impact": impact.get("observed_impact"),
        "confidence": impact.get("confidence_score"),
    }
    report_row: dict = {}
    report_deadline = time.time() + min(args.wait_seconds, 120)
    while incident.get("id") and time.time() < report_deadline:
        status, report_payload = request_json(
            f"{args.gateway}/incidents/metadata?limit=1&incident_id={incident.get('id')}&include_enrichment=true",
            token=token,
            timeout=45,
        )
        report_rows = unwrap(report_payload).get("rows", []) if status == 200 else []
        report_row = report_rows[0] if report_rows else {}
        report_context = report_row.get("context") or {}
        report_evidence = summarize_context_evidence(report_context, report_row.get("context_snapshot"))
        if (
            report_context
            and report_row.get("context_snapshot")
            and report_row.get("recommendation")
            and report_evidence.get("evidence_present")
        ):
            break
        time.sleep(2)
    report_context = report_row.get("context") or {}
    report_evidence = summarize_context_evidence(report_context, report_row.get("context_snapshot"))
    stages["report_ui_context"] = {
        "ok": bool(
            report_context
            and report_row.get("context_snapshot")
            and report_row.get("recommendation")
            and report_evidence.get("evidence_present")
        ),
        **report_evidence,
        "recommendation_present": bool(report_row.get("recommendation")),
    }
    execution_plan = (recommendation.get("metadata") or {}).get("execution_plan") or {}
    executable_plan = execution_plan.get("execution_ready") is True and bool(execution_plan.get("commands"))
    diagnostic_plan = (
        execution_plan.get("execution_ready") is False
        and bool(execution_plan.get("readiness_blocks") or execution_plan.get("diagnostic_only"))
    )
    stages["execution_plan"] = {
        "ok": executable_plan or diagnostic_plan,
        "playbook_id": ((execution_plan.get("playbook") or {}).get("id")),
        "execution_ready": execution_plan.get("execution_ready"),
        "mode": "executable" if executable_plan else "diagnostic" if diagnostic_plan else "invalid",
        "readiness_blocks": execution_plan.get("readiness_blocks") or [],
    }
    if stages["rca"]["ok"] and args.include_live_remediation:
        status, approval = request_json(
            f"{args.gateway}/approval/approve",
            method="POST",
            token=token,
            payload={
                "incident_id": incident.get("id"),
                "recommendation_id": recommendation.get("id"),
                "approver": "admin",
                "channel": "web",
                "comment": "approved by end-to-end lifecycle probe",
            },
            timeout=60,
        )
        stages["approval"] = {"ok": status == 200, "status": status}
        if status != 200:
            stages["approval"]["response"] = approval

        approved = unwrap(approval) if isinstance(approval, dict) else {}
        if stages["approval"]["ok"] and executable_plan:
            commands = [str(item) for item in execution_plan.get("commands", []) if str(item).strip()]
            scripts = [str(item) for item in execution_plan.get("scripts", []) if str(item).strip()]
            connector = ((execution_plan.get("connection") or {}).get("connector") or {})
            execution_payload = {
                "id": approved.get("id"),
                "incident_id": incident.get("id"),
                "recommendation_id": recommendation.get("id"),
                "decision": "approved",
                "approver": "admin",
                "channel": "web",
                "comment": "execute exact plan approved by end-to-end lifecycle probe",
                "modified_action": "\n".join(commands + scripts),
                "metadata": {
                    "recommended_action": recommendation.get("recommended_action"),
                    "recommended_commands": commands + [f"script: {item}" for item in scripts],
                    "execution_plan": execution_plan,
                    "rollback_plan": execution_plan.get("rollback_commands") or [],
                    "service": service,
                    "environment": environment,
                    "remediation_target": service,
                    "connection_profile": {
                        "application": "KaiOps",
                        "service": service,
                        "environment": environment,
                        "namespace": "default",
                        "endpoint_url": "http://jenkins:8080",
                        "connection_type": "jenkins",
                        "executor_type": "jenkins",
                        "job_name": "kaiops-auto-remediation",
                        "timeout_seconds": 1200,
                        "credential_ref": connector.get("secret_ref") or "vault://kaiops/local/jenkins#api-token",
                        "allowed_operations": connector.get("allowed_operations") or [],
                    },
                },
            }
            status, execution = request_json(
                f"{args.gateway}/remediation/execute",
                method="POST",
                token=token,
                payload=execution_payload,
                timeout=180,
            )
            submitted = unwrap(execution) if isinstance(execution, dict) else {}
            stages["execution_submission"] = {
                "ok": status in {200, 202} and bool(submitted.get("id")),
                "status": status,
                "action_id": submitted.get("id"),
                "action_status": submitted.get("status"),
            }
            if not stages["execution_submission"]["ok"]:
                stages["execution_submission"]["response"] = execution
        elif stages["approval"]["ok"]:
            stages["execution_submission"] = {
                "ok": False,
                "status": 409,
                "response": "approved recommendation did not contain an execution-ready catalog plan",
            }

    if stages["rca"]["ok"] and args.complete_diagnostic:
        if not diagnostic_plan:
            stages["diagnostic_completion"] = {
                "ok": False,
                "status": 409,
                "response": "recommendation is not an explicitly diagnostic-only plan",
            }
        else:
            status, completion_payload = request_json(
                f"{args.gateway}/remediation/diagnostic/complete",
                method="POST",
                token=token,
                payload={"incident_id": incident.get("id")},
                timeout=60,
            )
            completed_action = unwrap(completion_payload) if isinstance(completion_payload, dict) else {}
            stages["diagnostic_completion"] = {
                "ok": (
                    status == 200
                    and str(completed_action.get("action_type") or "").lower() == "diagnostic_completion"
                    and str(completed_action.get("status") or "").lower() == "skipped"
                ),
                "status": status,
                "action_id": completed_action.get("id"),
                "action_status": completed_action.get("status"),
            }
            if not stages["diagnostic_completion"]["ok"]:
                stages["diagnostic_completion"]["response"] = completion_payload

    if stages["rca"]["ok"] and args.manual_close_inconclusive:
        status, closure_payload = request_json(
            f"{args.gateway}/incidents/{incident.get('id')}/manual-close",
            method="POST",
            token=token,
            payload={
                "comment": (
                    "E2E review completed: evidence is inconclusive, corrective execution remained blocked, "
                    "and the synthetic incident is administratively closed without claiming technical recovery."
                )
            },
            timeout=60,
        )
        closed = unwrap(closure_payload) if isinstance(closure_payload, dict) else {}
        stages["manual_closure"] = {
            "ok": (
                status == 200
                and str(closed.get("status") or "").lower() in {"closed", "already_closed"}
                and closed.get("technical_recovery_verified") is not True
            ),
            "status": status,
            "closure_kind": closed.get("closure_kind"),
            "technical_recovery_verified": closed.get("technical_recovery_verified"),
        }
        if not stages["manual_closure"]["ok"]:
            stages["manual_closure"]["response"] = closure_payload

    closure_triggered = (
        stages.get("execution_submission", {}).get("ok")
        or stages.get("diagnostic_completion", {}).get("ok")
        or stages.get("manual_closure", {}).get("ok")
    )
    if closure_triggered:
        expected_action_status = (
            ""
            if args.manual_close_inconclusive
            else "skipped"
            if args.complete_diagnostic
            else "succeeded"
        )
        completion = 0
        final_status = ""
        action_status = ""
        closure_complete = False
        incident_status = ""
        closure_deadline = time.time() + args.wait_seconds
        while time.time() < closure_deadline:
            status, payload = request_json(
                f"{args.gateway}/incidents/{incident.get('id')}/stage-completeness", token=token, timeout=45
            )
            if status == 200:
                stage_data = unwrap(payload)
                completion = int(((stage_data.get("stage_completion") or {}).get("percentage")) or 0)
                incident_status = str(stage_data.get("status") or "").lower()
                closure_stage = next(
                    (item for item in stage_data.get("stages", []) if item.get("stage") == "closure_completed"),
                    {},
                )
                closure_complete = closure_stage.get("state") == "complete"
            status, payload = request_json(f"{args.gateway}/alerts/all?limit=5000", token=token, timeout=45)
            rows = unwrap(payload).get("rows", []) if status == 200 else []
            final_row = next((item for item in rows if item.get("id") == alert_id), None)
            final_status = str((final_row or {}).get("status") or "")
            if expected_action_status:
                status, payload = request_json(
                    f"{args.gateway}/remediation/actions/by-incident/{incident.get('id')}/latest",
                    token=token,
                    timeout=45,
                )
                if status == 200:
                    action_status = str((unwrap(payload) or {}).get("status") or "").lower()
            if (
                completion == 100
                and closure_complete
                and (not expected_action_status or action_status == expected_action_status)
                and incident_status in {"closed", "resolved"}
            ):
                break
            time.sleep(2)
        stages["remediation_and_closure"] = {
            "ok": (
                completion == 100
                and closure_complete
                and (not expected_action_status or action_status == expected_action_status)
                and incident_status in {"closed", "resolved"}
            ),
            "completion": completion,
            "alert_status": final_status,
            "incident_status": incident_status,
            "closure_stage_complete": closure_complete,
            "action_status": action_status,
        }

    required = ("live_stream", "incident", "context", "report_ui_context", "rca", "impact", "execution_plan")
    if args.include_live_remediation:
        required += ("approval", "execution_submission", "remediation_and_closure")
    if args.complete_diagnostic:
        required += ("diagnostic_completion", "remediation_and_closure")
    if args.manual_close_inconclusive:
        required += ("manual_closure", "remediation_and_closure")
    stages["result"] = "pass" if all(stages.get(key, {}).get("ok") for key in required) else "fail"
    print(json.dumps(stages, indent=2, default=str))
    return 0 if stages["result"] == "pass" else 5


if __name__ == "__main__":
    raise SystemExit(main())
