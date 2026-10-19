import pytest

from remediation_engine.plugins import jenkins_result_proves_outcome


def result(*, dry_run):
    return {"result": "SUCCESS", "dry_run": dry_run, "dry_run_validated": dry_run,
            "preflight_passed": not dry_run, "executed": not dry_run,
            "recovery_validated": not dry_run, "executed_script_count": 0 if dry_run else 2}


def test_validated_dry_run_does_not_establish_live_recovery():
    receipt = result(dry_run=True)
    assert jenkins_result_proves_outcome(receipt, dry_run=True, script_count=2)
    assert not jenkins_result_proves_outcome(receipt, dry_run=False, script_count=2)


@pytest.mark.parametrize("field,value", [("executed", True), ("recovery_validated", True),
                                       ("executed_script_count", 2), ("dry_run_validated", False)])
def test_dry_run_rejects_false_execution_proof(field, value):
    receipt = result(dry_run=True)
    receipt[field] = value
    assert not jenkins_result_proves_outcome(receipt, dry_run=True, script_count=2)


@pytest.mark.parametrize("field,value", [("dry_run", True), ("preflight_passed", False),
                                       ("executed", False), ("recovery_validated", False),
                                       ("executed_script_count", 1)])
def test_live_recovery_requires_all_execution_proofs(field, value):
    receipt = result(dry_run=False)
    assert jenkins_result_proves_outcome(receipt, dry_run=False, script_count=2)
    receipt[field] = value
    assert not jenkins_result_proves_outcome(receipt, dry_run=False, script_count=2)

@pytest.mark.asyncio
async def test_large_execution_plan_is_posted_in_body_not_request_uri(monkeypatch):
    import httpx
    from urllib.parse import parse_qs
    from uuid import uuid4
    from common.models import RemediationAction, RemediationStatus
    from remediation_engine.plugins import JenkinsRollbackPlugin
    payload = '{"plan":"' + 'x' * 30000 + '"}'
    calls = []
    def handle(request):
        if request.url.path.endswith('crumbIssuer/api/json'):
            return httpx.Response(404)
        calls.append(request)
        assert not request.url.query
        assert parse_qs(request.content.decode())['KAI_OPS_EXECUTION_PLAN'] == [payload]
        return httpx.Response(201, headers={'Location':'http://jenkins/queue/item/42/'})
    factory = httpx.AsyncClient
    monkeypatch.setattr(httpx, 'AsyncClient', lambda **kw: factory(transport=httpx.MockTransport(handle), **kw))
    monkeypatch.setenv('JENKINS_USERNAME', 'test-user')
    monkeypatch.setenv('JENKINS_API_TOKEN', 'test-token')
    monkeypatch.setattr(JenkinsRollbackPlugin, '_execution_plan_envelope', lambda self, action: (payload,'sha256:digest',1))
    action = RemediationAction(tenant_id='tenant-a', incident_id=uuid4(), action_type='restart_service', target='demo-proxy',
        parameters={'connection_profile': {'endpoint_url':'http://jenkins', 'job_name':'recovery',
                     'credential_ref':'secret://test'}})
    action = await JenkinsRollbackPlugin().dispatch(action)
    assert action.status == RemediationStatus.EXECUTOR_ACCEPTED
    assert len(calls) == 1

@pytest.mark.asyncio
async def test_reobserving_completed_jenkins_build_preserves_stability_clock(monkeypatch):
    import httpx
    from datetime import UTC,datetime,timedelta
    from uuid import uuid4
    from common.models import RemediationAction,RemediationStatus
    from remediation_engine.plugins import JenkinsRollbackPlugin
    completed=datetime.now(UTC)-timedelta(minutes=10)
    action=RemediationAction(tenant_id='tenant-a',incident_id=uuid4(),approval_id=uuid4(),
        action_type='restart_service',target='demo-proxy',status=RemediationStatus.SUCCEEDED,completed_at=completed,
        parameters={'execution_result':{'connector_endpoint':'http://jenkins','queue_url':'http://jenkins/queue/item/1/',
            'build_url':'http://jenkins/job/recovery/1/','approved_plan_digest':'sha256:plan','expected_script_count':0}})
    proof={'incident_id':str(action.incident_id),'approval_id':str(action.approval_id),'target':action.target,
           'plan_digest':'sha256:plan','preflight_passed':True,'executed':True,'recovery_validated':True,'executed_script_count':0}
    def handle(request):
        if request.url.path.endswith('/api/json'):return httpx.Response(200,json={'building':False,'result':'SUCCESS'})
        return httpx.Response(200,json=proof)
    factory=httpx.AsyncClient
    monkeypatch.setattr(httpx,'AsyncClient',lambda **kw: factory(transport=httpx.MockTransport(handle),**kw))
    monkeypatch.setenv('JENKINS_USERNAME','test-user');monkeypatch.setenv('JENKINS_API_TOKEN','test-token')
    observed=await JenkinsRollbackPlugin().observe(action)
    assert observed.status==RemediationStatus.SUCCEEDED
    assert observed.completed_at==completed
