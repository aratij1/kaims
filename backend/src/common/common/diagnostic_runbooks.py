"""Cold-start runbooks: diagnostic guidance, never execution authority or evidence."""
import hashlib
import json
from uuid import NAMESPACE_URL, uuid5

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from common.database import RunbookVersionRecord
from common.tenant_identity import require_tenant_id

READ_ONLY_TOOLS = frozenset({'logs.search', 'telemetry.search', 'traces.search', 'code.search',
    'topology.search', 'dependency-health.search', 'resource-health.search', 'changes.search'})


def diagnostic_template(*, tenant_id: str, application: str, service: str, environment: str,
                        alert_family: str = 'application_baseline', owner: str = 'unassigned') -> dict:
    tenant_id = require_tenant_id(tenant_id, source='diagnostic runbook')
    scope = {'tenant_id':tenant_id, 'application':application.strip(), 'service':service.strip(),
             'environment':environment.strip(), 'alert_family':alert_family.strip()}
    if not all(scope.values()):
        raise ValueError('diagnostic runbook requires a complete application/service/environment/family scope')
    signal = alert_family.lower()
    tools = ['logs.search', 'telemetry.search']
    if any(word in signal for word in ('down', 'unavailable', 'availability')):
        tools += ['topology.search', 'dependency-health.search', 'resource-health.search']
    elif any(word in signal for word in ('latency', '5xx', 'error', 'timeout')):
        tools += ['traces.search', 'code.search']
    elif any(word in signal for word in ('disk', 'memory', 'cpu')):
        tools += ['resource-health.search']
    elif alert_family == 'application_baseline':
        tools += ['topology.search']
    signature = hashlib.sha256(json.dumps(scope, sort_keys=True).encode()).hexdigest()
    payload = {**scope, 'runbook_id':str(uuid5(NAMESPACE_URL, 'kaims:diagnostic-runbook:'+signature)),
        'version':1, 'issue_signature':signature, 'name':f'Diagnose {alert_family} for {service}',
        'owner':owner, 'service_scope':[service], 'catalog_stage':'diagnostic_bootstrap',
        'diagnostic_only':True, 'diagnostic_eligible':True, 'execution_eligible':False,
        'context_eligible':False, 'review_state':'unverified_diagnostic_guidance',
        'generation_policy':'scoped-diagnostic-template-v1', 'readonly_tools':tools,
        'diagnostic_steps':[
            'Bind all observations to the affected service, environment and incident window.',
            'Test the observed failure against a healthy peer or last known-good baseline.',
            'Use source citations to test competing causes; record unknowns and contradictions.',
        ],
        'impact_checks':['Measure affected operations, error rate, latency and affected dependencies during the incident window.',
                         'Distinguish observed technical impact from unverified customer or business impact.'],
        'resolution_requirements':['Bind a registered corrective capability to the verified affected target.',
            'Evaluate policy and obtain human approval when required.',
            'Verify independent post-action health and stability; use a bound rollback on failure.'],
        'remediation_steps':[], 'validation_steps':[], 'rollback_steps':[],
        'risk_level':'low', 'required_approval':'mandatory'}
    payload['content_sha256'] = hashlib.sha256(json.dumps(payload,sort_keys=True).encode()).hexdigest()
    return payload


async def ensure_diagnostic_runbook(session, **scope) -> dict:
    payload = diagnostic_template(**scope)
    from uuid import UUID
    runbook_id = UUID(payload['runbook_id'])
    statement = select(RunbookVersionRecord).where(RunbookVersionRecord.runbook_id==runbook_id,
        RunbookVersionRecord.tenant_id==payload['tenant_id']).order_by(RunbookVersionRecord.version.desc()).limit(1)
    existing = await session.scalar(statement)
    if existing is None:
        try:
            async with session.begin_nested():
                session.add(RunbookVersionRecord(runbook_id=runbook_id,version=1,tenant_id=payload['tenant_id'],
                    issue_signature=payload['issue_signature'],approval_status='draft',owner=payload['owner'],
                    risk_level='low',required_approval='mandatory',content=payload))
                await session.flush()
        except IntegrityError:
            # A current/locking read sees a concurrent winner even under
            # MySQL REPEATABLE READ after the initial absence check.
            existing = await session.scalar(statement.with_for_update())
            if existing is None:
                raise
    if existing is not None:
        # Do not silently override an operator-disabled version.
        content = dict(existing.content or {})
        if existing.approval_status in {'disabled','deprecated','rejected'}:
            return {**payload,'diagnostic_eligible':False,'readonly_tools':[],'status':existing.approval_status}
        return content
    return payload


def diagnostic_tools(plan: object, *, tenant_id: str, service: str, environment: str) -> list[str]:
    if not isinstance(plan,dict) or plan.get('diagnostic_only') is not True or plan.get('diagnostic_eligible') is not True:
        return []
    if any(str(plan.get(key) or '') != value for key,value in
           [('tenant_id',tenant_id),('service',service),('environment',environment)]):
        return []
    tools = plan.get('readonly_tools')
    return list(dict.fromkeys(tool for tool in tools if isinstance(tool,str) and tool in READ_ONLY_TOOLS))[:6] if isinstance(tools,list) else []
