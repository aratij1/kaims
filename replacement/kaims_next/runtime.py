"""Opt-in replacement onboarding API and RabbitMQ workers; no legacy cutover."""
import asyncio
import hashlib
from datetime import datetime,timezone,timedelta
import json
import os
import secrets
from contextlib import asynccontextmanager,suppress
from pathlib import Path
from typing import Literal

import aio_pika
from fastapi import FastAPI,Header,HTTPException,Query
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel,Field
from sqlalchemy import create_engine,select,func,or_
from sqlalchemy.exc import NoResultFound

from .consumer import StageConsumer
from .discovery import DocumentDiscovery
from .handoff import Handoff,metadata,applications
from .rabbitmq import topology,recovery_routes
from .workers import OnboardingWorker
from .incidents import IncidentStore, IncidentWorker, incidents
from .telemetry import TelemetryCollector
from .overview import overview
from .live_alerts import live_alerts
from .intake import AlertIntake
from .registration import revise
from .alert_inbox import snapshot as alert_snapshot
from .resolution import ResolutionWorker
from .feedback import submit as submit_feedback, list_feedback
from .governance import assign as assign_role, snapshot as governance_snapshot


class DocumentSource(BaseModel):
    id: str = Field(min_length=1,max_length=128,pattern=r"^[a-zA-Z0-9_.-]+$")
    root: str = Field(min_length=1,max_length=128)
    path: str = Field(default=".",max_length=4096)
    required: bool = True


class Registration(BaseModel):
    application_id: str = Field(min_length=1,max_length=128,pattern=r"^[a-zA-Z0-9_.-]+$")
    document_sources: list[DocumentSource] = Field(default_factory=list,max_length=20)
    services: list[str] = Field(default_factory=list,max_length=100)
    telemetry_sources: list[str] = Field(default_factory=list,max_length=12)


class RegistrationUpdate(Registration):
    expected_version: int = Field(ge=1)


class ResolutionDecision(BaseModel):
    plan_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    decision: Literal["approve","reject"]


class RoleAssignment(BaseModel):
    role: Literal["incident_commander","communications_lead","operations_lead"]
    subject: str = Field(min_length=1, max_length=256)


class FeedbackRequest(BaseModel):
    decision: Literal["helpful","incorrect","incomplete"]
    reason_category: str = Field(default="", max_length=64)
    corrected_cause: str = Field(default="", max_length=4000)
    missing_evidence: str = Field(default="", max_length=4000)
    comment: str = Field(default="", max_length=4000)


class ReinvestigationRequest(BaseModel):
    mode: Literal["recollect","reanalyze"] = "recollect"
    expected_result_ref: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")


class IncidentRequest(BaseModel):
    incident_id: str = Field(min_length=1,max_length=128,pattern=r"^[a-zA-Z0-9_.-]+$")
    service: str = Field(min_length=1,max_length=128)
    window_start: str = Field(max_length=64)
    window_end: str = Field(max_length=64)


def create_app():
    token=os.environ.get("NEXT_API_TOKEN","")
    tenant=os.environ.get("NEXT_TENANT_ID","")
    if len(token)<32 or not tenant:
        raise RuntimeError("Set NEXT_TENANT_ID and a NEXT_API_TOKEN of at least 32 characters")
    database=os.environ.get("NEXT_DATABASE_URL","sqlite:///replacement-state.db")
    engine=create_engine(database,pool_pre_ping=True)
    metadata.create_all(engine)
    store=Handoff(engine)
    roots=json.loads(Path(os.environ["NEXT_DOCUMENT_ROOTS_FILE"]).read_text())
    worker=OnboardingWorker(store,DocumentDiscovery(roots))
    incident_store=IncidentStore(store)
    telemetry_file=os.environ.get("NEXT_TELEMETRY_SOURCES_FILE")
    endpoints=json.loads(Path(telemetry_file).read_text()) if telemetry_file else {}
    policy_file=os.environ.get("NEXT_RESOLUTION_POLICIES_FILE")
    policies=json.loads(Path(policy_file).read_text()) if policy_file else {}
    incident_worker=IncidentWorker(incident_store,TelemetryCollector(endpoints),policies)
    resolution_worker=ResolutionWorker(incident_store,policies)
    rabbit_url=os.environ["NEXT_RABBITMQ_URL"]
    namespace=os.environ.get("NEXT_RABBITMQ_NAMESPACE","kaims-next-v1")

    async def transport(app):
        while True:
            connection=None
            try:
                connection=await aio_pika.connect_robust(rabbit_url,timeout=10)
                bindings={"discovery":"application.discovery.requested","context":"application.context.requested",
                          "context-ready":"application.context.ready","context-blocked":"application.context.blocked",
                          "incident-collection":"incident.collection.requested","incident-analysis":"incident.analysis.requested",
                          "resolution-planning":"incident.resolution.requested","resolution-authorization":"incident.authorization.requested","resolution-execution":"incident.execution.requested",
                          "resolution-verification":"incident.verification.requested"}
                channel,publish,queues=await topology(connection,namespace,bindings)
                for name in bindings:
                    retry,quarantine,_=await recovery_routes(channel,namespace,name,bindings[name])
                    consumer=StageConsumer(worker if name in ("discovery","context") else resolution_worker if name.startswith("resolution-") else incident_worker,retry,quarantine,timeout=35)
                    async def receive(message,consumer=consumer):
                        try:
                            await consumer.handle(message)
                        except asyncio.CancelledError:
                            raise
                        except Exception:
                            # Failure to persist/transfer keeps the original delivery.
                            await asyncio.sleep(1)
                            if not message.processed: await message.nack(requeue=True)
                    await queues[name].consume(receive)
                app.state.broker_ready=True
                while not connection.is_closed:
                    await store.dispatch(publish)
                    await asyncio.sleep(1)
            except asyncio.CancelledError:
                raise
            except Exception as error:
                print(json.dumps({"transport_unavailable":type(error).__name__}),flush=True)
            finally:
                app.state.broker_ready=False
                if connection is not None: await connection.close()
            await asyncio.sleep(5)

    intake=AlertIntake(incident_store,endpoints)
    intake_apps=sorted(set(filter(None,(item.strip() for item in os.environ.get("NEXT_AUTO_INCIDENT_APPLICATIONS","").split(",")))))
    poll_seconds=max(15,int(os.environ.get("NEXT_INCIDENT_POLL_SECONDS","30")))
    intake_status={"enabled":bool(intake_apps),"applications":intake_apps,"poll_seconds":poll_seconds,"last_checks":{}}

    async def poll_alerts():
        while True:
            for application_id in intake_apps:
                try: intake_status["last_checks"][application_id]=await intake.scan(tenant,application_id)
                except asyncio.CancelledError:raise
                except Exception as error:
                    intake_status["last_checks"][application_id]={"status":"failed","reason":type(error).__name__}
            await asyncio.sleep(poll_seconds)

    diagnostic_status={"enabled":any(p.get("automatic_until") for p in policies.values()),"last_checks":{}}
    async def diagnostic_intake():
        while True:
            for key,policy in policies.items():
                if not policy.get("automatic_until"):continue
                scope_tenant,application_id,service=key.split("/")
                if scope_tenant!=tenant:continue
                try:
                    if datetime.fromisoformat(policy["automatic_until"])<=datetime.now(timezone.utc):
                        diagnostic_status["last_checks"][key]={"status":"authorization_expired"};continue
                    observed=resolution_worker.observation(await resolution_worker.request(policy,"diagnostic"),service)
                    diagnostic_status["last_checks"][key]={"status":"healthy" if observed["healthy"] else "unhealthy","observed_at":observed["observed_at"]}
                    if observed["healthy"] or observed["failure_code"]!=policy["failure_code"]:continue
                    identity=hashlib.sha256(json.dumps([key,observed["failure_code"],observed["revision"]]).encode()).hexdigest()[:32]
                    incident_id="diagnostic-"+identity
                    try:incident_store.get(tenant,application_id,incident_id);continue
                    except NoResultFound:pass
                    now=datetime.now(timezone.utc)
                    incident_store.admit(tenant,application_id,incident_id,{"service":service,
                        "window_start":(now-timedelta(minutes=2)).isoformat(),"window_end":now.isoformat(),
                        "origin":{"kind":"service_diagnostic","name":policy.get("alert_name","Service diagnostic failed"),
                            "severity":"critical","observed_at":observed["observed_at"],"failure_code":observed["failure_code"]}})
                except asyncio.CancelledError:raise
                except Exception as error:diagnostic_status["last_checks"][key]={"status":"failed","reason":type(error).__name__}
            await asyncio.sleep(5)

    @asynccontextmanager
    async def lifespan(app):
        app.state.broker_ready=False
        task=asyncio.create_task(transport(app))
        diagnostic_task=asyncio.create_task(diagnostic_intake()) if diagnostic_status["enabled"] else None
        intake_task=asyncio.create_task(poll_alerts()) if intake_apps else None
        try: yield
        finally:
            if diagnostic_task:
                diagnostic_task.cancel()
                with suppress(asyncio.CancelledError):await diagnostic_task
            if intake_task:
                intake_task.cancel()
                with suppress(asyncio.CancelledError): await intake_task
            task.cancel()
            with suppress(asyncio.CancelledError): await task
            engine.dispose()

    app=FastAPI(title="KaiMS replacement - incident pipeline preview",lifespan=lifespan)
    static=Path(__file__).parent/"static"
    ui_revision=hashlib.sha256((static/"app.js").read_bytes()+(static/"app.css").read_bytes()+(static/"index.html").read_bytes()).hexdigest()[:12]
    app.mount("/ui",StaticFiles(directory=static),name="ui")

    @app.middleware("http")
    async def response_headers(request,call_next):
        response=await call_next(request)
        response.headers["Cache-Control"]="no-store"
        response.headers["X-Content-Type-Options"]="nosniff"
        response.headers["Referrer-Policy"]="no-referrer"
        response.headers["Content-Security-Policy"]="default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
        return response

    @app.get("/",include_in_schema=False)
    def home(): return HTMLResponse((static/"index.html").read_text(encoding="utf-8").replace("/ui/app.js", "/ui/app.js?v="+ui_revision).replace("/ui/app.css", "/ui/app.css?v="+ui_revision))

    def authorize(authorization):
        if not secrets.compare_digest(authorization or "","Bearer "+token):
            raise HTTPException(401,"Invalid authorization")

    @app.get("/healthz")
    def health():
        return {"status":"running","ui_revision":ui_revision,"broker_ready":getattr(app.state,"broker_ready",False),
                "qualification":"incident_pipeline_preview","incident_resolution_available":bool(policies),
                "automatic_remediation_scopes":resolution_worker.automatic_scopes(tenant),
                "resolution_scope":"Configured service policies only; scoped authorization or preview tenant approval"}

    @app.get("/source-catalog")
    def catalog(authorization:str|None=Header(default=None)):
        authorize(authorization)
        return {"document_roots":sorted(roots),"telemetry_sources":[
            {"id":key,"type":value.get("type","normalized")} for key,value in sorted(endpoints.items())]}

    @app.get("/alerts")
    async def alerts_inbox(after:str="",application_id:str="",authorization:str|None=Header(default=None)):
        authorize(authorization)
        return await alert_snapshot(store,tenant,endpoints,after,application_id)

    @app.get("/incident-intake")
    def incident_intake_status(authorization:str|None=Header(default=None)):
        authorize(authorization)
        return {**intake_status,"diagnostic_intake":diagnostic_status}

    @app.get("/workspace")
    def workspace(authorization:str|None=Header(default=None)):
        authorize(authorization)
        with engine.connect() as c:
            apps=dict(c.execute(select(applications.c.state,func.count()).where(applications.c.tenant_id==tenant).group_by(applications.c.state)).all())
            states=dict(c.execute(select(incidents.c.state,func.count()).where(incidents.c.tenant_id==tenant).group_by(incidents.c.state)).all())
        return {"applications":sum(apps.values()),"context_ready":apps.get("context_ready",0),
            "incidents":sum(states.values()),"incident_states":states,
            "in_progress":sum(states.get(s,0) for s in ("waiting_for_context","collection_queued","analysis_queued","resolution_queued","execution_queued","verification_queued")),
            "blocked_or_failed":sum(states.get(s,0) for s in ("context_blocked","failed","resolution_failed")),
            "capabilities":{"versioned_registration_updates":True,"automatic_remediation":bool(resolution_worker.automatic_scopes(tenant)),
                            "automatic_remediation_scopes":resolution_worker.automatic_scopes(tenant),
                            "approval_workflow":bool(policies),"qualified_service_health":False}}

    @app.get("/incidents")
    def inbox_view(q:str=Query(default="",max_length=128),state:str="",offset:int=Query(default=0,ge=0,le=100000),
                   limit:int=Query(default=50,ge=1,le=100),authorization:str|None=Header(default=None)):
        authorize(authorization)
        conditions=[incidents.c.tenant_id==tenant]
        if state: conditions.append(incidents.c.state==state)
        if q: conditions.append(or_(incidents.c.incident_id.contains(q,autoescape=True),incidents.c.application_id.contains(q,autoescape=True)))
        with engine.connect() as c:
            rows=c.execute(select(incidents.c.application_id,incidents.c.incident_id,incidents.c.state,incidents.c.request).where(*conditions)
                .order_by(incidents.c.application_id,incidents.c.incident_id).offset(offset).limit(limit+1)).mappings().all()
        return {"items":[{**dict(row),"request":json.loads(row["request"])} for row in rows[:limit]],"next":offset+limit if len(rows)>limit else None}

    @app.get("/applications")
    def list_applications(after:str="",limit:int=Query(default=50,ge=1,le=100),authorization:str|None=Header(default=None)):
        authorize(authorization)
        with engine.connect() as c:
            rows=c.execute(select(applications.c.application_id,applications.c.state,applications.c.version).where(
                applications.c.tenant_id==tenant,applications.c.application_id>after).order_by(applications.c.application_id).limit(limit+1)).mappings().all()
        return {"items":[dict(row) for row in rows[:limit]],"next":rows[limit-1]["application_id"] if len(rows)>limit else None}

    @app.get("/applications/{application_id}/incidents")
    def list_incidents(application_id:str,after:str="",limit:int=Query(default=50,ge=1,le=100),authorization:str|None=Header(default=None)):
        authorize(authorization)
        try: store.application(tenant,application_id)
        except NoResultFound as error: raise HTTPException(404,"Application not found") from error
        with engine.connect() as c:
            rows=c.execute(select(incidents.c.incident_id,incidents.c.state,incidents.c.request).where(
                incidents.c.tenant_id==tenant,incidents.c.application_id==application_id,incidents.c.incident_id>after
            ).order_by(incidents.c.incident_id).limit(limit+1)).mappings().all()
        return {"items":[{**dict(row),"application_id":application_id,"request":json.loads(row["request"])} for row in rows[:limit]],
                "next":rows[limit-1]["incident_id"] if len(rows)>limit else None}

    @app.post("/applications",status_code=202)
    def onboard(payload:Registration,authorization:str|None=Header(default=None)):
        authorize(authorization)
        try:
            source_ids=[source.id for source in payload.document_sources]
            if any(not isinstance(s,str) or not s for s in source_ids) or len(set(source_ids))!=len(source_ids):
                raise ValueError("Document sources require unique nonempty IDs")
            if len(set(payload.telemetry_sources)) != len(payload.telemetry_sources):
                raise ValueError("Telemetry sources must be unique")
            if any(not item or len(item)>128 for item in payload.services+payload.telemetry_sources):
                raise ValueError("Services and source IDs must contain 1 to 128 characters")
            store.onboard(tenant,payload.application_id,payload.model_dump(exclude={"application_id"}))
            return store.application(tenant,payload.application_id)
        except ValueError as error: raise HTTPException(409,str(error)) from error

    @app.put("/applications/{application_id}",status_code=202)
    def update_registration(application_id:str,payload:RegistrationUpdate,authorization:str|None=Header(default=None)):
        authorize(authorization)
        if payload.application_id != application_id:
            raise HTTPException(422,"Application ID cannot be changed")
        config=payload.model_dump(exclude={"application_id","expected_version"})
        try:
            ids=[source.id for source in payload.document_sources]
            if len(set(ids)) != len(ids): raise ValueError("Document source IDs must be unique")
            for values in [payload.services,payload.telemetry_sources]:
                if len(set(values)) != len(values) or any(not v.strip() or len(v)>128 for v in values):
                    raise ValueError("Service and source names must be unique and contain 1 to 128 characters")
            if any(source.root not in roots for source in payload.document_sources):
                raise ValueError("Select a configured document root")
            if any(source not in endpoints for source in payload.telemetry_sources):
                raise ValueError("Select configured telemetry sources")
            for source in payload.document_sources:
                root=Path(roots[source.root]).resolve()
                if not (root/source.path).resolve().is_relative_to(root):
                    raise ValueError("Document path must stay within its configured root")
            revise(store,tenant,application_id,payload.expected_version,config)
            return store.application(tenant,application_id)
        except NoResultFound as error: raise HTTPException(404,"Application not found") from error
        except ValueError as error: raise HTTPException(409,str(error)) from error

    @app.get("/applications/{application_id}/live-alerts")
    async def application_alerts(application_id:str,authorization:str|None=Header(default=None)):
        authorize(authorization)
        try: config=store.application(tenant,application_id)["config"]
        except NoResultFound as error: raise HTTPException(404,"Application not found") from error
        return await live_alerts(config,endpoints)

    @app.get("/applications/{application_id}/monitoring-status")
    async def application_monitoring_status(application_id:str,authorization:str|None=Header(default=None)):
        """Return a fresh, bounded monitoring snapshot for the application.

        Monitoring connectivity is intentionally separate from service-health qualification:
        a source can be connected while no health policy has been approved.
        """
        authorize(authorization)
        try:
            config=store.application(tenant,application_id)["config"]
        except NoResultFound as error:
            raise HTTPException(404,"Application not found") from error
        snapshot=await live_alerts(config,endpoints)
        configured=[source_id for source_id in config.get("telemetry_sources",[]) if source_id in endpoints]
        outcomes={row.get("source_id"):row for row in snapshot.get("source_outcomes",[])}
        sources=[]
        for source_id in configured:
            endpoint=endpoints[source_id]
            outcome=outcomes.get(source_id,{})
            source_type=endpoint.get("type","normalized")
            if source_type=="prometheus":
                connectivity=outcome.get("status","not_checked")
            else:
                # Live alert collection is Prometheus-only; these connectors remain
                # configured for context collection and are checked during investigations.
                connectivity="configured_not_probed"
            sources.append({"id":source_id,"type":source_type,"configuration":"configured",
                            "connectivity":connectivity,"last_checked":snapshot.get("checked_at"),
                            "alerting":source_type=="prometheus" and endpoint.get("collect_alerts",True)})
        prometheus=[row for row in sources if row["alerting"]]
        ready={"collected","no_matches","partial"}
        if not configured:
            status="not_configured"
        elif prometheus and all(row["connectivity"] in ready for row in prometheus):
            status="connected"
        else:
            status="partial"
        return {"enabled":bool(configured),"status":status,"checked_at":snapshot.get("checked_at"),
                "sources":sources,"alerts":len(snapshot.get("alerts",[])),
                "scope_note":snapshot.get("scope_note"),
                "health_note":"Connectivity does not qualify service health; a health policy must be explicitly approved."}

    @app.get("/applications/{application_id}/overview")
    def application_overview(application_id:str,authorization:str|None=Header(default=None)):
        authorize(authorization)
        try: return overview(store,tenant,application_id,endpoints)
        except NoResultFound as error: raise HTTPException(404,"Application not found") from error

    @app.get("/applications/{application_id}")
    def application(application_id:str,authorization:str|None=Header(default=None)):
        authorize(authorization)
        try: return store.application(tenant,application_id)
        except NoResultFound as error: raise HTTPException(404,"Application not found") from error

    @app.post("/applications/{application_id}/incidents",status_code=202)
    def admit(application_id:str,payload:IncidentRequest,authorization:str|None=Header(default=None)):
        authorize(authorization)
        try:
            incident_store.admit(tenant,application_id,payload.incident_id,payload.model_dump(exclude={"incident_id"}))
            return incident_store.get(tenant,application_id,payload.incident_id)
        except NoResultFound as error: raise HTTPException(404,"Application not found") from error
        except ValueError as error: raise HTTPException(409,str(error)) from error

    @app.post("/applications/{application_id}/incidents/{incident_id}/decision",status_code=202)
    def resolution_decision(application_id:str,incident_id:str,payload:ResolutionDecision,authorization:str|None=Header(default=None)):
        authorize(authorization)
        try:
            resolution_worker.approve(tenant,application_id,incident_id,payload.plan_digest,payload.decision)
            return incident_store.get(tenant,application_id,incident_id)
        except NoResultFound as error: raise HTTPException(404,"Incident not found") from error
        except ValueError as error: raise HTTPException(409,str(error)) from error

    @app.post("/applications/{application_id}/incidents/{incident_id}/reinvestigate",status_code=202)
    def reinvestigate(application_id:str,incident_id:str,payload:ReinvestigationRequest,authorization:str|None=Header(default=None)):
        authorize(authorization)
        try:
            incident_store.reinvestigate(tenant,application_id,incident_id,payload.expected_result_ref,payload.mode)
            return incident_store.get(tenant,application_id,incident_id)
        except NoResultFound as error: raise HTTPException(404,"Incident not found") from error
        except ValueError as error: raise HTTPException(409,str(error)) from error

    @app.post("/applications/{application_id}/incidents/{incident_id}/assignments", status_code=201)
    def incident_assignment(application_id:str, incident_id:str, payload:RoleAssignment, authorization:str|None=Header(default=None)):
        actor=authorize(authorization)
        try:
            incident_store.get(tenant, application_id, incident_id)
            return assign_role(engine,tenant,application_id,incident_id,payload.role,payload.subject,actor or "preview-operator")
        except NoResultFound as error: raise HTTPException(404,"Incident not found") from error
        except ValueError as error: raise HTTPException(422,str(error)) from error

    @app.get("/applications/{application_id}/incidents/{incident_id}/governance")
    def incident_governance(application_id:str, incident_id:str, authorization:str|None=Header(default=None)):
        authorize(authorization)
        try:
            incident_store.get(tenant, application_id, incident_id)
            return {"multi_user":False,"roles":["incident_commander","communications_lead","operations_lead"],**governance_snapshot(engine,tenant,application_id,incident_id)}
        except NoResultFound as error: raise HTTPException(404,"Incident not found") from error

    @app.post("/applications/{application_id}/incidents/{incident_id}/feedback", status_code=201)
    def incident_feedback(application_id:str, incident_id:str, payload:FeedbackRequest, authorization:str|None=Header(default=None)):
        authorize(authorization)
        try:
            incident_store.get(tenant, application_id, incident_id)
            return submit_feedback(engine, tenant, application_id, incident_id, payload.model_dump())
        except NoResultFound as error: raise HTTPException(404,"Incident not found") from error
        except ValueError as error: raise HTTPException(422,str(error)) from error

    @app.get("/applications/{application_id}/incidents/{incident_id}/feedback")
    def incident_feedback_list(application_id:str, incident_id:str, authorization:str|None=Header(default=None)):
        authorize(authorization)
        try:
            incident_store.get(tenant, application_id, incident_id)
            return {"items":list_feedback(engine, tenant, application_id, incident_id)}
        except NoResultFound as error: raise HTTPException(404,"Incident not found") from error

    @app.get("/applications/{application_id}/incidents/{incident_id}")
    def incident(application_id:str,incident_id:str,include_evidence:bool=True,authorization:str|None=Header(default=None)):
        authorize(authorization)
        try:
            result=incident_store.get(tenant,application_id,incident_id)
            if not include_evidence and isinstance(result.get("result"),dict):
                stage=result["result"]
                if "records" in stage:
                    stage["record_count"]=len(stage.pop("records"))
            return result
        except NoResultFound as error: raise HTTPException(404,"Incident not found") from error

    @app.get("/applications/{application_id}/artifacts/{artifact_id}")
    def artifact(application_id:str,artifact_id:str,authorization:str|None=Header(default=None)):
        authorize(authorization)
        try: return store.artifact(tenant,application_id,artifact_id)
        except NoResultFound as error: raise HTTPException(404,"Artifact not found") from error

    return app
