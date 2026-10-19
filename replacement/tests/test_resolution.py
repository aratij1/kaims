import asyncio,json
from datetime import datetime,timezone,timedelta
import httpx,pytest
from sqlalchemy import select
from test_incidents import setup,baseline,pending,REQUEST,RECORD
from kaims_next.incidents import IncidentWorker
from kaims_next.telemetry import TelemetryCollector
from kaims_next.resolution import ResolutionWorker,digest
from kaims_next.handoff import outbox

POLICY={"action":"repair","description":"Repair fixture","cause":"Test maintenance enabled","impact":"Fixture service rejects requests while maintenance is enabled",
    "failure_code":"maintenance_enabled","diagnostic_url":"http://fixture.test/diagnostic","execution_url":"http://fixture.test/repair"}

async def prepared(tmp_path,automatic=False):
    store,inc,onboarding=setup(tmp_path)
    inc.admit("t","a","i",REQUEST)
    await baseline(store,onboarding);inc.release(pending(store,"application.context.ready"))
    policies={"t/a/gateway":dict(POLICY)}
    if automatic:policies["t/a/gateway"]["automatic_until"]=(datetime.now(timezone.utc)+timedelta(minutes=10)).isoformat()
    collector=TelemetryCollector({"metrics":{"url":"http://fixture.test/metrics"}},transport=httpx.MockTransport(lambda r:httpx.Response(200,json={"records":[RECORD]})))
    analysis=IncidentWorker(inc,collector,policies)
    await analysis.handle(pending(store,"incident.collection.requested"));await analysis.handle(pending(store,"incident.analysis.requested"))
    state={"healthy":False,"action":None,"executions":0,"calls":0,"receipts":{}}
    def handle(req):
        if req.method=="POST":
            state["calls"]+=1;key=req.headers["Idempotency-Key"]
            if key not in state["receipts"]:
                assert json.loads(req.content)["expected_revision"]==1
                state.update(healthy=True,action=key,executions=state["executions"]+1)
                state["receipts"][key]={"service":"gateway","status":"executed","action_id":key}
            return httpx.Response(200,json=state["receipts"][key])
        return httpx.Response(200,json={"service":"gateway","healthy":state["healthy"],"failure_code":None if state["healthy"] else "maintenance_enabled",
            "observed_at":datetime.now(timezone.utc).isoformat(),"last_action":state["action"],"revision":2 if state["healthy"] else 1})
    worker=ResolutionWorker(inc,policies,httpx.MockTransport(handle))
    assert inc.get("t","a","i")["state"]=="resolution_queued"
    assert await worker.handle(pending(store,"incident.resolution.requested"))
    assert not await worker.handle(pending(store,"incident.resolution.requested"))
    return store,inc,worker,state


def test_full_resolution_and_duplicate_execution_receipt(tmp_path):
    async def run():
        store,inc,worker,state=await prepared(tmp_path)
        row=inc.get("t","a","i");plan=row["result"]["resolution"]["plan_digest"]
        assert row["state"]=="awaiting_approval" and state["executions"]==0
        with pytest.raises(ValueError):worker.approve("t","a","i","0"*64,"approve")
        assert worker.approve("t","a","i",plan,"approve")
        assert not worker.approve("t","a","i",plan,"approve")
        execution=pending(store,"incident.execution.requested")
        original=inc.complete
        def lost_commit(*args,**kwargs):raise RuntimeError("Simulated crash after connector receipt")
        inc.complete=lost_commit
        with pytest.raises(RuntimeError):await worker.handle(execution)
        inc.complete=original
        assert await worker.handle(execution)
        assert not await worker.handle(execution)
        assert state["calls"]==2 and state["executions"]==1
        assert await worker.handle(pending(store,"incident.verification.requested"))
        row=inc.get("t","a","i")
        assert row["state"]=="recovered"
        assert len(row["result"]["resolution"]["verification"])==2
        assert row["result"]["rca"]["status"]=="current_condition_confirmed"
    asyncio.run(run())


def test_rejection_and_changed_policy_prevent_execution(tmp_path):
    async def run():
        store,inc,worker,state=await prepared(tmp_path)
        plan=inc.get("t","a","i")["result"]["resolution"]["plan_digest"]
        worker.policies["t/a/gateway"]["action"]="different"
        with pytest.raises(ValueError,match="policy changed"):worker.approve("t","a","i",plan,"approve")
        worker.policies["t/a/gateway"]["action"]="repair"
        worker.approve("t","a","i",plan,"reject")
        assert inc.get("t","a","i")["state"]=="resolution_rejected"
        assert state["executions"]==0
        with pytest.raises(ValueError):worker.approve("t","a","i",plan,"approve")
    asyncio.run(run())


def test_unhealthy_verification_never_recovers(tmp_path):
    async def run():
        store,inc,worker,state=await prepared(tmp_path)
        plan=inc.get("t","a","i")["result"]["resolution"]["plan_digest"]
        worker.approve("t","a","i",plan,"approve")
        await worker.handle(pending(store,"incident.execution.requested"))
        state["healthy"]=False
        envelope=pending(store,"incident.verification.requested")
        with pytest.raises(RuntimeError,match="not verified"):await worker.handle(envelope)
        await worker.fail(envelope,"verification_exhausted")
        assert inc.get("t","a","i")["state"]=="resolution_failed"
    asyncio.run(run())


def test_diagnostic_requires_fresh_scoped_boolean_observations():
    worker=ResolutionWorker(None,{})
    valid={"service":"gateway","healthy":False,"failure_code":"maintenance_enabled","observed_at":datetime.now(timezone.utc).isoformat(),"revision":1}
    assert worker.observation(valid,"gateway")["healthy"] is False
    for patch in [{"service":"foreign"},{"healthy":"false"},{"observed_at":"2020-01-01T00:00:00Z"},{"revision":True}]:
        with pytest.raises(RuntimeError):worker.observation({**valid,**patch},"gateway")


def test_preauthorized_plan_uses_durable_authorization_stage(tmp_path):
    async def run():
        store,inc,worker,state=await prepared(tmp_path,automatic=True)
        from kaims_next.resolution import approvals
        authorization=pending(store,"incident.authorization.requested")
        assert await worker.handle(authorization)
        assert not await worker.handle(authorization)
        with store.engine.connect() as c:assert c.execute(select(approvals.c.authority)).scalar_one()=="preauthorized_policy"
        await worker.handle(pending(store,"incident.execution.requested"))
        await worker.handle(pending(store,"incident.verification.requested"))
        assert inc.get("t","a","i")["state"]=="recovered" and state["executions"]==1
    asyncio.run(run())


def test_automatic_authority_is_rechecked_immediately_before_execution(tmp_path, monkeypatch):
    async def run():
        store,inc,worker,state=await prepared(tmp_path,automatic=True)
        await worker.handle(pending(store,"incident.authorization.requested"))
        import kaims_next.resolution as module
        expired_at=datetime.fromisoformat(worker.policies['t/a/gateway']['automatic_until'])+timedelta(seconds=1)
        class FutureClock(datetime):
            @classmethod
            def now(cls,tz=None):return expired_at
        monkeypatch.setattr(module,'datetime',FutureClock)
        with pytest.raises(RuntimeError,match='authorization expired'):
            await worker.handle(pending(store,'incident.execution.requested'))
        assert state['executions']==0
        assert worker.automatic_scopes('t')==[]
    asyncio.run(run())
