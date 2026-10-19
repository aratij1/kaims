"""Bounded live KaiMS outage check; always restore the approval service."""
import json
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

REMOTE = r"""
import json,urllib.request
from pathlib import Path

def get(url):
    return json.load(urllib.request.urlopen(url,timeout=15))
r={}
r['prometheus']=[a for a in get('http://prometheus:9090/api/v1/alerts')['data']['alerts'] if a['labels'].get('job')=='kaiops-approval-service']
r['alertmanager']=[a for a in get('http://alertmanager:9093/api/v2/alerts') if a['labels'].get('job')=='kaiops-approval-service']
r['intake']=[]
root=Path('/app/ingested_alerts')
for folder in [root/'input',root/'processed'/__import__('datetime').datetime.now(__import__('datetime').timezone.utc).strftime('%Y/%m/%d')]:
    for p in folder.glob('*kaiopsservicedown*'):
        d=json.loads(p.read_text());a=d.get('alert',{});labels=a.get('labels',{})
        if labels.get('job')=='kaiops-approval-service':
            r['intake'].append({'received_at':d.get('received_at'),'status':labels.get('alert_status'),'alert_id':a.get('id')})
print(json.dumps(r))
"""

def snapshot():
    result=subprocess.run(['docker','exec','-i','kaims-monitoring-adapter-1','python','-'],input=REMOTE,text=True,capture_output=True,timeout=50,check=True)
    return json.loads(result.stdout)

def main():
    report={'started_at':datetime.now(timezone.utc).isoformat(),'target':'kaims-approval-service-1','observations':[]}
    output=Path(__file__).with_name('e2e-kaims-'+datetime.now(timezone.utc).strftime('%Y%m%d')+'.json')
    def record():
        row={'at':datetime.now(timezone.utc).isoformat(),**snapshot()};report['observations'].append(row);output.write_text(json.dumps(report,indent=2));return row
    state=json.loads(subprocess.check_output(['docker','inspect','kaims-approval-service-1']))[0]['State']
    if not state['Running']:raise RuntimeError('Approval service must be running before this test')
    initial=record()
    if initial['prometheus']:raise RuntimeError('Approval service already has active alerts; refusing overlapping test')
    try:
        subprocess.run(['docker','stop','kaims-approval-service-1'],check=True,timeout=45)
        print('Approval service stopped; waiting for firing alert and new intake.',flush=True)
        deadline=time.monotonic()+150
        while time.monotonic()<deadline:
            row=record()
            firing=any(a['state']=='firing' for a in row['prometheus'])
            captured=any(a['status']=='firing' and a['received_at']>report['started_at'] for a in row['intake'])
            if firing and captured:
                report['firing_captured']=True;break
            time.sleep(10)
    finally:
        subprocess.run(['docker','start','kaims-approval-service-1'],check=True,timeout=45)
        print('Approval service restored; waiting for resolved notification.',flush=True)
    deadline=time.monotonic()+180
    while time.monotonic()<deadline:
        row=record()
        if not row['prometheus'] and any(a['status']=='resolved' and a['received_at']>report['started_at'] for a in row['intake']):
            report['resolved_captured']=True;break
        time.sleep(10)
    report['finished_at']=datetime.now(timezone.utc).isoformat()
    output.write_text(json.dumps(report,indent=2))
    print(json.dumps({k:v for k,v in report.items() if k!='observations'}),flush=True)
    if not report.get('firing_captured') or not report.get('resolved_captured'):raise SystemExit(1)

if __name__=='__main__':main()
