"""Review a pinned incident cohort; fresh analysis never closes or remediates incidents."""

import argparse
import asyncio
import json
import os
from uuid import UUID
import httpx
from sqlalchemy import select
from common.database import (
    create_engine,
    create_session_factory,
    IncidentRecord,
    ContextSnapshotRecord,
    AnalysisRequestRecord,
    AuditLogRecord,
    RcaReportRecord,
    IncidentInvestigationBindingRecord,
    ExecutionPlanRecord,
    ActionRecord,
    ApprovalRecord,
)
from common.config import get_settings


async def run(args):
    engine = create_engine(get_settings())
    factory = create_session_factory(engine)
    try:
        async with factory() as s, httpx.AsyncClient(base_url="http://127.0.0.1:8000", timeout=60) as client:
            token = None
            if args.submit:
                response = await client.post(
                    "/auth/login", json={"username": "admin", "password": os.getenv("ADMIN_USER_PASSWORD", "")}
                )
                response.raise_for_status()
                token = response.json()["access_token"]
            for iid in args.ids.split(","):
                i = await s.get(IncidentRecord, UUID(iid))
                if not i or i.tenant_id != args.tenant:
                    raise ValueError("Incident outside selected tenant")
                snap = await s.scalar(
                    select(ContextSnapshotRecord)
                    .where(ContextSnapshotRecord.tenant_id == args.tenant, ContextSnapshotRecord.incident_id == iid)
                    .order_by(ContextSnapshotRecord.snapshot_version.desc())
                    .limit(1)
                )
                p = snap.payload if snap else {}
                m = p.get("metadata") or {}
                buckets = m.get("context_evidence") or {}
                alert_id = (p.get("alert") or {}).get("id")
                row = {
                    "incident_id": iid,
                    "ticket": i.ticket_id,
                    "service": i.service,
                    "title": i.title,
                    "environment": i.environment,
                    "status": i.status,
                    "snapshot_version": snap.snapshot_version if snap else None,
                    "snapshot_time": str(snap.collected_at) if snap else None,
                    "alert_started_at": (p.get("alert") or {}).get("starts_at"),
                    "context_quality": m.get("context_quality"),
                    "alert_id": alert_id,
                    "sources": {k: len(v) for k, v in buckets.items() if isinstance(v, list)},
                }
                latest = await s.scalar(
                    select(AnalysisRequestRecord)
                    .where(
                        AnalysisRequestRecord.tenant_id == args.tenant,
                        AnalysisRequestRecord.incident_id == i.id,
                        *(
                            [AnalysisRequestRecord.request_id.in_([UUID(x) for x in args.requests.split(",") if x])]
                            if args.requests
                            else []
                        ),
                    )
                    .order_by(AnalysisRequestRecord.created_at.desc())
                    .limit(1)
                )
                if latest:
                    binding = await s.scalar(
                        select(IncidentInvestigationBindingRecord).where(
                            IncidentInvestigationBindingRecord.analysis_request_id == latest.request_id
                        )
                    )
                    audit = await s.get(AuditLogRecord, latest.recommendation_id) if latest.recommendation_id else None
                    rec = audit.payload if audit else {}
                    meta = rec.get("metadata") or {}
                    analysis = meta.get("rca_analysis") or {}
                    row["analysis"] = {
                        "request_id": str(latest.request_id),
                        "status": latest.status,
                        "reason": latest.terminal_reason,
                        "created_at": str(latest.created_at),
                        "completed_at": str(latest.completed_at),
                        "rca_version": binding.rca_version if binding else None,
                        "bound_snapshot_id": str(binding.context_snapshot_id) if binding else None,
                        "bound_evidence_count": len(binding.evidence_ids or []) if binding else 0,
                        "rca_status": meta.get("rca_status"),
                        "root_cause": rec.get("root_cause"),
                        "missing_evidence": analysis.get("missing_evidence"),
                    }
                plans = (
                    await s.execute(
                        select(
                            ExecutionPlanRecord.id,
                            ExecutionPlanRecord.execution_ready,
                            ExecutionPlanRecord.readiness_blocks,
                            ExecutionPlanRecord.rca_version,
                        ).where(ExecutionPlanRecord.tenant_id == args.tenant, ExecutionPlanRecord.incident_id == i.id)
                    )
                ).all()
                row["execution_plans"] = [dict(x._mapping) for x in plans]
                actions = (
                    await s.execute(
                        select(ActionRecord.id, ActionRecord.status, ActionRecord.recommendation_id).where(
                            ActionRecord.tenant_id == args.tenant, ActionRecord.incident_id == i.id
                        )
                    )
                ).all()
                row["actions"] = [dict(x._mapping) for x in actions]
                approvals = (
                    await s.execute(
                        select(ApprovalRecord.id, ApprovalRecord.decision, ApprovalRecord.recommendation_id).where(
                            ApprovalRecord.tenant_id == args.tenant, ApprovalRecord.incident_id == i.id
                        )
                    )
                ).all()
                row["approvals"] = [dict(x._mapping) for x in approvals]
                reports = (
                    await s.scalars(
                        select(RcaReportRecord).where(
                            RcaReportRecord.tenant_id == args.tenant, RcaReportRecord.incident_id == i.id
                        )
                    )
                ).all()
                row["recovery"] = [
                    {
                        "health_restored": (r.payload or {}).get("health_restored"),
                        "alerts_cleared": (r.payload or {}).get("alerts_cleared"),
                        "root_cause": r.root_cause,
                        "action_taken": (r.payload or {}).get("action_taken"),
                    }
                    for r in reports
                ]
                if args.submit:
                    if i.status in ("closed", "resolved", "cancelled", "recovered"):
                        row["replay"] = {"status": "terminal_read_only"}
                    elif not alert_id:
                        row["replay"] = {"status": "missing_alert_link"}
                    else:
                        try:
                            response = await client.post(
                                "/analysis/alerts/" + alert_id + "/regenerate",
                                json={"mode": "fresh"},
                                headers={"Authorization": "Bearer " + token},
                            )
                            response.raise_for_status()
                            result = response.json()
                            row["replay"] = result.get("data", result)
                        except httpx.HTTPStatusError as exc:
                            row["replay"] = {
                                "status": "http_error",
                                "http_status": exc.response.status_code,
                                "detail": exc.response.text[:500],
                            }
                        except httpx.RequestError as exc:
                            row["replay"] = {"status": "transport_error", "type": type(exc).__name__}
                print(json.dumps(row, default=str), flush=True)
    finally:
        await engine.dispose()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tenant", default="default")
    parser.add_argument("--ids", required=True)
    parser.add_argument("--submit", action="store_true")
    parser.add_argument("--requests", default="")
    asyncio.run(run(parser.parse_args()))
