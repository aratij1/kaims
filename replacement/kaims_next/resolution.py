"""Governed HTTP resolution contracts for explicitly configured service policies."""
import asyncio, hashlib, json
from datetime import datetime, timezone, timedelta
from uuid import UUID
import httpx
from sqlalchemy import select, insert, update, Table, Column, String, Text
from .handoff import metadata, artifacts, inbox, encode, write_transaction
from .incidents import incidents, instant

approvals = Table("next_resolution_approvals",metadata,
    Column("tenant_id",String(128),primary_key=True),Column("application_id",String(128),primary_key=True),
    Column("incident_id",String(128),primary_key=True),Column("plan_digest",String(64),primary_key=True),
    Column("decision",String(32),nullable=False),Column("decided_at",String(64),nullable=False),
    Column("authority",String(128),nullable=False))


def digest(value):return hashlib.sha256(encode(value).encode()).hexdigest()


def policy_key(tenant,application,service):return "/".join((tenant,application,service))


class ResolutionWorker:
    topics={"incident.resolution.requested":"resolution-planning",
            "incident.execution.requested":"resolution-execution",
            "incident.authorization.requested":"resolution-authorization",
            "incident.verification.requested":"resolution-verification"}
    expected={"resolution-planning":"resolution_queued","resolution-authorization":"awaiting_approval","resolution-execution":"execution_queued","resolution-verification":"verification_queued"}

    def __init__(self,store,policies,transport=None):
        self.store,self.policies,self.transport=store,policies,transport
        from urllib.parse import urlsplit
        if not isinstance(policies,dict):raise ValueError("Resolution policies must be a mapping")
        for key,policy in policies.items():
            if len(key.split("/"))!=3 or not isinstance(policy,dict):raise ValueError("Invalid policy scope")
            for field in ("action","description","cause","impact","failure_code"):
                if not isinstance(policy.get(field),str) or not 1<=len(policy[field])<=2048:raise ValueError("Invalid resolution policy field")
            for field in ("diagnostic_url","execution_url"):
                url=urlsplit(policy.get(field,""))
                if url.scheme not in {"http","https"} or not url.hostname or url.username or url.password:
                    raise ValueError("Invalid server-owned connector URL")

    def policy(self,tenant,application,service):
        return self.policies.get(policy_key(tenant,application,service))

    def automatic_scopes(self, tenant):
        now=datetime.now(timezone.utc)
        return sorted(key for key,policy in self.policies.items() if key.split('/')[0]==tenant
                      and policy.get('automatic_until') and instant(policy['automatic_until'])>now)

    async def request(self,policy,kind,body=None,key=None):
        headers=dict(policy.get("headers",{}))
        if key:headers["Idempotency-Key"]=key
        async with httpx.AsyncClient(transport=self.transport,timeout=5,follow_redirects=False,trust_env=False) as client:
            async with client.stream("POST" if body is not None else "GET",policy[kind+"_url"],headers=headers,json=body) as response:
                response.raise_for_status();raw=bytearray()
                async for chunk in response.aiter_bytes():
                    raw.extend(chunk)
                    if len(raw)>65536:raise RuntimeError("Connector response exceeds contract limit")
        try:data=json.loads(raw)
        except (ValueError,UnicodeError) as error:raise RuntimeError("Invalid connector JSON") from error
        if not isinstance(data,dict):raise RuntimeError("Connector returned an invalid contract")
        return data

    def observation(self,data,service,after=None):
        now=datetime.now(timezone.utc)
        try:
            observed=instant(data["observed_at"])
            if data["service"]!=service or type(data["healthy"]) is not bool:
                raise ValueError()
            if observed<now-timedelta(seconds=60) or observed>now+timedelta(seconds=5) or (after and observed<instant(after)):
                raise ValueError()
            if not isinstance(data.get("revision"),int) or isinstance(data["revision"],bool):raise ValueError()
            return {key:data.get(key) for key in ("service","healthy","failure_code","observed_at","revision","last_action")}
        except (KeyError,ValueError,TypeError):raise RuntimeError("Invalid, stale, or incorrectly scoped diagnostic observation")

    def approve(self,tenant,application,incident,plan_digest,decision,authorization_event=None):
        if decision not in {"approve","reject"}:raise ValueError("Invalid decision")
        with write_transaction(self.store.engine) as c:
            self.store.lock_app(c,tenant,application)
            row=c.execute(select(incidents).where(*self.store.scope(tenant,application,incident))).mappings().one()
            if authorization_event and c.execute(select(inbox.c.event_id).where(inbox.c.consumer=="resolution-authorization",
                inbox.c.event_id==authorization_event["event_id"])).first():return False
            prior=c.execute(select(approvals).where(approvals.c.tenant_id==tenant,approvals.c.application_id==application,
                approvals.c.incident_id==incident,approvals.c.plan_digest==plan_digest)).mappings().first()
            if prior:
                if prior["decision"]!=decision:raise ValueError("This plan already has a different decision")
                return False
            if row["state"]!="awaiting_approval":raise ValueError("Incident is not awaiting approval")
            source=json.loads(c.execute(select(artifacts.c.content).where(artifacts.c.tenant_id==tenant,
                artifacts.c.application_id==application,artifacts.c.artifact_id==row["result_ref"])).scalar_one())
            plan=source["resolution"]["plan"]
            if digest(plan)!=plan_digest:raise ValueError("Plan changed; refresh before deciding")
            if instant(plan["expires_at"])<=datetime.now(timezone.utc):raise ValueError("Plan approval has expired")
            policy=self.policy(tenant,application,plan["service"])
            if not policy or digest(policy)!=plan["policy_digest"]:raise ValueError("Resolution policy changed")
            if authorization_event:
                if not policy.get("automatic_until") or instant(policy["automatic_until"])<=datetime.now(timezone.utc):
                    raise ValueError("Automatic authorization expired")
                c.execute(insert(inbox).values(consumer="resolution-authorization",event_id=authorization_event["event_id"]))
            c.execute(insert(approvals).values(tenant_id=tenant,application_id=application,incident_id=incident,
                plan_digest=plan_digest,decision=decision,decided_at=datetime.now(timezone.utc).isoformat(),authority="preauthorized_policy" if authorization_event else "preview_tenant_operator"))
            c.execute(update(incidents).where(*self.store.scope(tenant,application,incident)).values(
                state="execution_queued" if decision=="approve" else "resolution_rejected"))
            if decision=="approve":self.store.emit(c,row,"incident.execution.requested",[row["result_ref"]])
        return True

    async def handle(self,envelope):
        if envelope.get("schema_version")!=1:raise ValueError("Unsupported event schema")
        UUID(envelope["event_id"]);instant(envelope["created_at"])
        consumer=self.topics[envelope["topic"]]
        if self.store.store.consumed(consumer,envelope["event_id"]):return False
        tenant,application,incident=(envelope[k] for k in ("tenant_id","application_id","incident_id"))
        row=self.store.get(tenant,application,incident)
        ref,=envelope["artifact_refs"]
        if row["state"]!=self.expected[consumer] or row["result_ref"]!=ref:raise ValueError("Stale resolution event")
        result=self.store.store.artifact(tenant,application,ref)
        service=row["request"]["service"];policy=self.policy(tenant,application,service)
        if not policy:raise RuntimeError("No configured resolution policy")
        app=self.store.store.application(tenant,application)
        if service not in app["config"].get("services",[]):raise RuntimeError("Resolution target is no longer registered")
        if consumer=="resolution-planning":
            observation=self.observation(await self.request(policy,"diagnostic"),service)
            if observation["healthy"] or observation["failure_code"]!=policy["failure_code"]:
                result["resolution"]={"status":"blocked","reason":"Current diagnostic does not confirm this policy's repair condition","diagnostic":observation}
                return self.store.complete(envelope,consumer,"resolution_queued","assessed",result)
            now=datetime.now(timezone.utc)
            plan={"service":service,"action":policy["action"],"description":policy["description"],
                "policy_digest":digest(policy),"assessment_ref":ref,"diagnostic":observation,
                "expires_at":(now+timedelta(minutes=10)).isoformat(),"created_at":now.isoformat()}
            result["rca"]={**result["rca"],"status":"current_condition_confirmed","confirmed_cause":policy["cause"],
                "summary":policy["cause"],"diagnostic":observation,
                "qualification":"Current configured diagnostic confirms this condition; it does not establish the cause throughout the historical incident window."}
            result["impact"]={**result["impact"],"status":"current_service_failure_confirmed", "summary":policy["impact"],"diagnostic":observation}
            result["resolution"]={"status":"awaiting_approval","plan":plan,"plan_digest":digest(plan),
                "authorization_mode":"preauthorized_policy" if policy.get("automatic_until") else "operator",
                "reason":"Automatic authorization requested under the time-limited service policy." if policy.get("automatic_until") else "Approve the displayed plan before execution. Authorization uses the preview tenant token."}
            return self.store.complete(envelope,consumer,"resolution_queued","awaiting_approval",result,
                "incident.authorization.requested" if policy.get("automatic_until") else None)
        plan=result["resolution"]["plan"]
        if digest(plan)!=result["resolution"]["plan_digest"] or digest(policy)!=plan["policy_digest"]:
            raise RuntimeError("Approved plan or policy changed")
        if consumer=="resolution-authorization":
            try:return self.approve(tenant,application,incident,digest(plan),"approve",envelope)
            except ValueError as error:raise RuntimeError(str(error)) from error
        with self.store.engine.connect() as c:
            approval=c.execute(select(approvals.c.decision,approvals.c.authority).where(approvals.c.tenant_id==tenant,
                approvals.c.application_id==application,approvals.c.incident_id==incident,
                approvals.c.plan_digest==digest(plan))).first()
        if not approval or approval.decision!="approve":raise RuntimeError("Missing bound approval")
        if consumer=="resolution-execution":
            if approval.authority=="preauthorized_policy" and (not policy.get('automatic_until')
                    or instant(policy['automatic_until'])<=datetime.now(timezone.utc)):
                raise RuntimeError("Automatic execution authorization expired")
            if instant(plan["expires_at"])<=datetime.now(timezone.utc):raise RuntimeError("Approved plan expired")
            key=digest({"tenant":tenant,"application":application,"incident":incident,"plan":digest(plan)})
            response=await self.request(policy,"execution",{"action":plan["action"],"service":service,
                "expected_revision":plan["diagnostic"]["revision"]},key)
            if response.get("service")!=service or response.get("action_id")!=key or response.get("status")!="executed":
                raise RuntimeError("Execution receipt is invalid; action outcome uncertain")
            result["resolution"]={**result["resolution"],"status":"verifying","action_id":key,
                "executed_at":datetime.now(timezone.utc).isoformat(),"reason":"Execution acknowledged; fresh recovery observations required"}
            return self.store.complete(envelope,consumer,"execution_queued","verification_queued",result,"incident.verification.requested")
        observations=[]
        for _ in range(2):
            observation=self.observation(await self.request(policy,"diagnostic"),service,after=result["resolution"]["executed_at"])
            if not observation["healthy"] or observation.get("failure_code") or observation["last_action"]!=result["resolution"]["action_id"]:
                raise RuntimeError("Recovery is not verified")
            if observations and instant(observation["observed_at"])<=instant(observations[-1]["observed_at"]):
                raise RuntimeError("Repeated stale recovery sample")
            observations.append(observation)
            if len(observations)<2:await asyncio.sleep(1)
        result["resolution"]={**result["resolution"],"status":"recovered","verification":observations,
            "reason":"Two fresh healthy observations confirmed the configured service recovery condition"}
        return self.store.complete(envelope,consumer,"verification_queued","recovered",result)

    async def fail(self,envelope,reason):
        consumer=self.topics[envelope["topic"]]
        row=self.store.get(envelope["tenant_id"],envelope["application_id"],envelope["incident_id"])
        result=row["result"] or {}
        result["resolution"]={**result.get("resolution",{}),"status":"failed","reason":reason,
            "failed_stage":consumer,"outcome_uncertain":consumer=="resolution-execution"}
        return self.store.complete(envelope,consumer,self.expected[consumer],"resolution_failed",result)
