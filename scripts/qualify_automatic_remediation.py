"""Prove scoped unattended recovery using a disposable HTTP target and real RabbitMQ."""
from __future__ import annotations

import argparse
import json
import re
import secrets
import subprocess
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--project', default='kaims-auto-qualification-' + datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S'))
    parser.add_argument('--port', type=int, default=18503)
    args = parser.parse_args()
    if not re.fullmatch(r'kaims-auto-qualification-[a-z0-9-]+', args.project) or not 1024 <= args.port <= 65535:
        parser.error('Require a qualification project name and nonprivileged port')
    existing = subprocess.run(['docker', 'ps', '-aq', '--filter',
        f'label=com.docker.compose.project={args.project}'], cwd=ROOT, capture_output=True, text=True, check=True)
    if existing.stdout.strip():
        raise RuntimeError('Qualification project already exists; use a fresh project to avoid resetting evidence')
    config = ROOT / '.tmp/auto-qualification' / args.project
    config.mkdir(parents=True, exist_ok=True)
    token, password = secrets.token_hex(32), secrets.token_hex(24)
    env_file = config / 'runtime.env'
    env_file.write_text(f'AUTO_QUAL_TOKEN={token}\nAUTO_QUAL_BROKER_PASSWORD={password}\nAUTO_QUAL_PORT={args.port}\n'
                        f'AUTO_QUAL_CONFIG_DIR={config.as_posix()}\n')
    expires = (datetime.now(timezone.utc) + timedelta(minutes=15)).isoformat()
    policy = {'qualification/pipeline-validation/validation-service': {
        'action': 'disable_test_maintenance', 'description': 'Disable the disposable fixture maintenance flag',
        'cause': 'The fixture maintenance flag is enabled', 'impact': 'The fixture returns HTTP 503 while maintenance is enabled',
        'failure_code': 'maintenance_enabled', 'diagnostic_url': 'http://target:8080/diagnostic',
        'execution_url': 'http://target:8080/repair', 'automatic_until': expires,
    }}
    for name, value in [('policy', policy), ('roots', {'qualification-docs': '/qualification-documents'}),
                        ('telemetry', {'metrics': {'url': 'http://target:8080/evidence'}})]:
        (config / f'{name}.json').write_text(json.dumps(value))
    compose = ['docker', 'compose', '-p', args.project, '--env-file', str(env_file),
               '-f', str(ROOT / 'deploy/automation-validation/compose.yaml')]
    output = ROOT / 'artifacts/automatic-remediation' / args.project
    output.mkdir(parents=True, exist_ok=True)

    def run(command, timeout=120):
        completed = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=timeout)
        with (output / 'deployment.log').open('a', encoding='utf-8') as log:
            log.write(completed.stdout + completed.stderr)
        if completed.returncode:
            raise RuntimeError('Qualification command failed; see deployment.log')
        return completed.stdout

    if run(['docker', 'ps', '-aq', '--filter', f'label=com.docker.compose.project={args.project}']).strip():
        raise RuntimeError('Qualification project already exists; use a fresh project to avoid resetting evidence')
    print('Building isolated qualification runtime', flush=True)
    run(compose + ['build', 'api'], 180)
    run(compose + ['up', '-d', '--wait', '--wait-timeout', '120'], 150)
    base = f'http://127.0.0.1:{args.port}'

    def call(path, payload=None):
        req = Request(base + path, data=json.dumps(payload).encode() if payload is not None else None,
                      headers={'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'})
        with urlopen(req, timeout=10) as response:
            return json.load(response)

    deadline = time.monotonic() + 180
    while True:
        try:
            if call('/healthz').get('broker_ready'):
                break
        except (URLError, OSError):
            pass
        if time.monotonic() >= deadline:
            raise RuntimeError('Qualification runtime did not become ready')
        time.sleep(2)
    diagnostic = json.loads(run(compose + ['exec', '-T', 'target', 'python', '-c',
        "import json,urllib.request; print(urllib.request.urlopen('http://127.0.0.1:8080/diagnostic').read().decode())"]))
    assert diagnostic['healthy'] is False and diagnostic['failure_code'] == 'maintenance_enabled'
    initial_http = int(run(compose + ['exec', '-T', 'target', 'python', '-c',
        "import urllib.request,urllib.error\ntry: print(urllib.request.urlopen('http://127.0.0.1:8080/health').status)\nexcept urllib.error.HTTPError as e: print(e.code)"]).strip())
    assert initial_http == 503
    print('Observed actual unhealthy target; registering reviewed context', flush=True)
    call('/applications', {'application_id': 'pipeline-validation', 'services': ['validation-service'],
                           'telemetry_sources': ['metrics'], 'document_sources': [
                               {'id': 'repair-runbook', 'root': 'qualification-docs', 'path': '.', 'required': True}]})
    deadline = time.monotonic() + 180
    recovered = None
    while time.monotonic() < deadline:
        rows = call('/incidents').get('items', [])
        # The observer, not the test runner, admits and authorizes the incident.
        for row in rows:
            if row.get('application_id') == 'pipeline-validation':
                candidate = call('/applications/pipeline-validation/incidents/' + row['incident_id'])
                if candidate['state'] == 'recovered':
                    recovered = candidate
                    break
                if candidate['state'] in {'failed', 'resolution_failed', 'context_blocked'}:
                    raise RuntimeError('Automatic qualification failed: ' + candidate['state'])
        if recovered:
            break
        time.sleep(2)
    if not recovered:
        raise RuntimeError('Target did not recover automatically before the deadline')
    result = recovered['result']['resolution']
    assert len(result['verification']) == 2 and all(v['healthy'] for v in result['verification'])
    counts = json.loads(run(compose + ['exec', '-T', 'target', 'python', '-c',
        "import sqlite3,json; c=sqlite3.connect('/state/target.db'); print(json.dumps({'actions':c.execute('SELECT COUNT(*) FROM actions').fetchone()[0],'faulty':c.execute('SELECT faulty FROM state WHERE id=1').fetchone()[0]}))"]))
    assert counts == {'actions': 1, 'faulty': 0}, counts
    final_http = int(run(compose + ['exec', '-T', 'target', 'python', '-c',
        "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:8080/health').status)"]).strip())
    assert final_http == 200
    db_proof = json.loads(run(compose + ['exec', '-T', 'api', 'python', '-c',
        "import sqlite3,json; c=sqlite3.connect('/state/workflow.db'); print(json.dumps({'approval_authority':c.execute('SELECT authority FROM next_resolution_approvals').fetchone()[0],'consumed_events':c.execute('SELECT COUNT(*) FROM next_inbox').fetchone()[0]}))"]))
    assert db_proof['approval_authority'] == 'preauthorized_policy', db_proof
    report = {'project': args.project, 'url': base, 'scope': 'isolated qualification runtime using existing resolution workers',
              'initial_diagnostic': diagnostic, 'initial_health_http':initial_http,'final_health_http':final_http,
              'incident': recovered, 'target_state': counts, 'durable_proof': db_proof,
              'automatic_until': expires, 'human_approval_clicks': 0, 'manual_repair_calls': 0,
              'production_services_modified': False, 'result': 'passed'}
    (output / 'result.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'result': 'passed', 'project': args.project, 'report': str(output / 'result.json')}), flush=True)


if __name__ == '__main__':
    main()
