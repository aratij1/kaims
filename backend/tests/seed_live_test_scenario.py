import asyncio
import json
import os
import sys
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

sys.path.insert(0, "/app/src/common")
sys.path.insert(0, "/app/src")
sys.path.insert(0, r"c:\Users\arati.joshi\Documents\new kaims\kaims-latest\kaims-latest\backend\src\common")
sys.path.insert(0, r"c:\Users\arati.joshi\Documents\new kaims\kaims-latest\kaims-latest\backend\src")

DB_URL = os.getenv("DATABASE_URL", "mysql+aiomysql://kaiops:kaiops@mysql:3306/kaiops")

async def seed_test_scenario():
    print("=" * 80)
    print("SEEDING 2 TEST ALERTS FOR HANDS-ON UI VERIFICATION")
    print("=" * 80)
    
    engine = create_async_engine(DB_URL, echo=False)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    
    async with session_factory() as session:
        from common.database import (
            IncidentRecord,
            IncidentProjectionRecord,
            ContextSnapshotRecord,
            ApprovalRecord,
            CanonicalEvidenceRecord,
            GovernedRagDocumentRecord
        )
        from common.repository import ContextEnrichmentRepository
        from common.context_enrichment_contract import build_evidence_requirements

        tenant_id = "default"
        now = datetime.now(UTC)

        # ---------------------------------------------------------------------
        # SCENARIO 1: Known Incident with Existing Runbook -> Ready for Approval
        # ---------------------------------------------------------------------
        inc1_id = uuid4()
        plan1_uuid = uuid4()
        rec1_uuid = uuid4()
        snap1_uuid = uuid4()

        known_runbook = (
            "# Runbook: mysql-exporter Access Denied\n"
            "Service: mysql-exporter\n"
            "Remediation:\n"
            "Execute grant fix and restart exporter:\n"
            "`mysql -e \"GRANT REPLICATION CLIENT ON *.* TO 'exporter'@'%'; FLUSH PRIVILEGES;\"`\n"
            "`kubectl rollout restart deployment/mysql-exporter -n prod`"
        )

        inc1 = IncidentRecord(
            id=inc1_id,
            tenant_id=tenant_id,
            title="BROWSER-DEMO: MySQLExporterReplicationClientDenied",
            severity="critical",
            status="pending_approval",
            service="mysql-exporter",
            environment="prod",
            payload={
                "alert_ids": ["alert-mysql-001"],
                "timeline": [{"event": "incident.opened", "timestamp": now.isoformat()}],
                "ticket_id": "JIRA-MYSQL-101",
                "jira_qualification": {"qualified": True, "reason": "Deduplicated critical alert"},
                "recommendation": {
                    "id": str(rec1_uuid),
                    "summary": "Access denied; missing REPLICATION CLIENT privilege for mysql-exporter.",
                    "root_cause": "User 'exporter'@'%' lacks REPLICATION CLIENT privilege required for slave_status check.",
                    "impact": "MySQL exporter metrics collection failing for 10 minutes in prod.",
                    "confidence": 0.95,
                    "metadata": {
                        "execution_plan": {
                            "plan_id": str(plan1_uuid),
                            "plan_fingerprint": f"sha256:{'1'*64}",
                            "playbook_id": "grant-replication-client",
                            "remediation_target": "mysql-exporter",
                            "risk_tier": "low",
                            "commands": ["kubectl rollout restart deployment/mysql-exporter -n prod"],
                            "preflight_commands": ["kubectl get deployment/mysql-exporter -n prod"],
                            "rollback_commands": ["kubectl rollout undo deployment/mysql-exporter -n prod"],
                        }
                    }
                }
            }
        )
        session.add(inc1)
        await session.flush()

        # Add to Approvals table
        app1 = ApprovalRecord(
            id=uuid4(),
            tenant_id=tenant_id,
            incident_id=inc1_id,
            recommendation_id=rec1_uuid,
            plan_id=plan1_uuid,
            plan_fingerprint=f"sha256:{'1'*64}",
            decision="awaiting_approval",
            approver="admin",
            payload={"risk_tier": "low", "service": "mysql-exporter"}
        )
        session.add(app1)

        # ---------------------------------------------------------------------
        # SCENARIO 2: Unknown Incident without Runbook -> Waiting For Human
        # ---------------------------------------------------------------------
        inc2_id = uuid4()
        snap2_uuid = uuid4()

        inc2 = IncidentRecord(
            id=inc2_id,
            tenant_id=tenant_id,
            title="BROWSER-DEMO: InvoiceWorkerQueueStall",
            severity="critical",
            status="waiting_for_human",
            service="invoice-worker",
            environment="prod",
            payload={
                "alert_ids": ["alert-invoice-002"],
                "timeline": [{"event": "incident.opened", "timestamp": now.isoformat()}],
                "ticket_id": "JIRA-INVOICE-202",
                "jira_qualification": {"qualified": True, "reason": "Deduplicated critical alert"},
            }
        )
        session.add(inc2)
        await session.flush()

        # Add context snapshot
        snap2 = ContextSnapshotRecord(
            snapshot_id=snap2_uuid,
            tenant_id=tenant_id,
            incident_id=str(inc2_id),
            source_incident_id=str(inc2_id),
            alert_signature="sig-invoice-worker",
            subject_fingerprint="s" * 64,
            context_fingerprint="c" * 64,
            snapshot_stage="final",
            snapshot_version=1,
            evidence_ids=["ev-inv-1"],
            evidence_checksums={"ev-inv-1": "2" * 64},
            contract_version="kaiops.context.v2",
            quality_score=0.5,
            reusable=False,
            source_manifest={"telemetry": {"connector": "alert-receiver"}},
            payload={
                "tenant_id": tenant_id,
                "incident_id": str(inc2_id),
                "alert": {
                    "id": "alert-invoice-002",
                    "name": "InvoiceWorkerQueueStall",
                    "service": "invoice-worker",
                    "severity": "critical",
                    "description": "invoice-worker consumer group lag exceeded 1200 messages for 10m in prod",
                    "environment": "prod",
                },
                "runbook": "",
                "metadata": {"context_snapshot_id": str(snap2_uuid), "document_available": False},
            },
            collected_at=now,
            expires_at=now + timedelta(hours=1),
        )
        session.add(snap2)

        # Build evidence requirement for unknown incident
        enrichment_repo = ContextEnrichmentRepository(session)
        reqs = build_evidence_requirements(
            tenant_id=tenant_id,
            incident_id=inc2_id,
            rca_version=1,
            missing_evidence=[
                {
                    "category": "runbook",
                    "question": "Provide runbook, observed symptoms, root cause, and remediation steps for invoice-worker queue stall.",
                    "reason": "No approved runbook was retrieved for invoice-worker in production.",
                    "collection_mode": "human_required",
                    "candidate_connectors": [],
                }
            ],
            now=now,
        )
        await enrichment_repo.upsert_context_evidence_requirements(reqs)
        assignment = await enrichment_repo.resolve_human_evidence_responder(
            tenant_id=tenant_id, incident_id=inc2_id
        )
        human_req = await enrichment_repo.create_human_evidence_request(
            tenant_id=tenant_id,
            incident_id=inc2_id,
            requirement_id=reqs[0].requirement_id,
            expected_responder=assignment["identity"],
            assignment_source=assignment["source"],
            due_at=now + timedelta(hours=1),
            acceptable_format="Verified runbook observation",
            evidence_already_checked=[],
            hypothesis_impact=reqs[0].reason,
            automatic_fallback=True,
        )

        await session.commit()

        print("✓ SUCCESS! Seeding complete.")
        print(f"  1. Known Incident (Pending Approval): {inc1_id} (Service: mysql-exporter)")
        print(f"  2. Unknown Incident (Waiting For Human): {inc2_id} (Service: invoice-worker)")

if __name__ == "__main__":
    asyncio.run(seed_test_scenario())
