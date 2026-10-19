"""Local test connector: inspect/start ONE pinned validation container; no arbitrary Docker API."""
import hashlib,json,secrets,sqlite3,subprocess,sys,threading
from datetime import datetime,timezone
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from pathlib import Path

CONFIG=json.loads(Path(sys.argv[1]).read_text())
TARGET=CONFIG["container_id"]
if len(TARGET)!=64 or any(c not in "0123456789abcdef" for c in TARGET):raise RuntimeError("Require pinned container ID")
DB=Path(sys.argv[1]).with_suffix('.db')
LOCK=threading.Lock()
def now():return datetime.now(timezone.utc).isoformat()
def run(args):return subprocess.check_output(["docker",*args],text=True,timeout=20)
def inspect():
    data=json.loads(run(["inspect",TARGET]))[0]
    labels=data["Config"].get("Labels",{})
    if data["Id"]!=TARGET or labels.get("com.docker.compose.project")!="kaims-next-preview" or labels.get("com.docker.compose.service")!="validation-target":
        raise RuntimeError("Container is outside allowed target")
    return data

def diagnostic():
    state=inspect()["State"]
    revision=int(hashlib.sha256(json.dumps([state["Running"],state["StartedAt"],state["FinishedAt"]]).encode()).hexdigest()[:12],16)
    healthy=False
    if state["Running"]:
        try:
            healthy=run(["exec",TARGET,"python","-c","import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:8080/health',timeout=2).status)"]).strip()=="200"
        except (subprocess.SubprocessError,OSError):pass
    with sqlite3.connect(DB) as c:
        row=c.execute("SELECT action_id FROM actions WHERE receipt IS NOT NULL ORDER BY rowid DESC LIMIT 1").fetchone()
    return {"service":"validation-service","healthy":healthy,"failure_code":None if healthy else "container_stopped" if not state["Running"] else "service_unhealthy",
        "revision":revision,"last_action":row[0] if row else None,"observed_at":now()}

class Handler(BaseHTTPRequestHandler):
    def log_message(self,*args):pass
    def send(self,status,body):
        raw=json.dumps(body).encode();self.send_response(status);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
    def authorized(self):return secrets.compare_digest(self.headers.get('Authorization',''),'Bearer '+CONFIG['token'])
    def do_GET(self):
        if not self.authorized():return self.send(401,{"error":"unauthorized"})
        if self.path!='/diagnostic':return self.send(404,{"error":"unknown endpoint"})
        try:return self.send(200,diagnostic())
        except Exception:return self.send(503,{"error":"diagnostic unavailable"})
    def do_POST(self):
        if not self.authorized():return self.send(401,{"error":"unauthorized"})
        if self.path!='/execute':return self.send(404,{"error":"unknown endpoint"})
        key=self.headers.get('Idempotency-Key','')
        try:
            length=int(self.headers.get('Content-Length','0'))
            if not 0<length<=4096 or len(key)!=64:raise ValueError()
            payload=json.loads(self.rfile.read(length))
            if payload.get('service')!='validation-service' or payload.get('action')!='start_validation_container':raise ValueError()
            encoded=json.dumps(payload,sort_keys=True)
        except (ValueError,TypeError):return self.send(400,{"error":"unsupported execution contract"})
        with LOCK:
            try:
                with sqlite3.connect(DB) as c:
                    prior=c.execute('SELECT body,receipt FROM actions WHERE action_id=?',(key,)).fetchone()
                    if prior:
                        if prior[0]!=encoded:return self.send(409,{"error":"idempotency conflict"})
                        if prior[1]:return self.send(200,json.loads(prior[1]))
                    else:
                        before=diagnostic()
                        if before['failure_code']!='container_stopped' or before['revision']!=payload.get('expected_revision'):
                            return self.send(409,{"error":"target changed"})
                        c.execute('INSERT INTO actions(action_id,body,receipt,start_calls) VALUES(?,?,NULL,0)',(key,encoded));c.commit()
                    if not inspect()['State']['Running']:
                        c.execute('UPDATE actions SET start_calls=start_calls+1 WHERE action_id=?',(key,));c.commit()
                        run(['start',TARGET])
                    receipt={'service':'validation-service','status':'executed','action_id':key}
                    c.execute('UPDATE actions SET receipt=? WHERE action_id=?',(json.dumps(receipt),key));c.commit()
                return self.send(200,receipt)
            except Exception:return self.send(503,{"error":"execution outcome uncertain"})

if __name__=='__main__':
    inspect()
    with sqlite3.connect(DB) as c:c.execute('CREATE TABLE IF NOT EXISTS actions(action_id TEXT PRIMARY KEY,body TEXT,receipt TEXT,start_calls INTEGER)')
    ThreadingHTTPServer(('0.0.0.0',CONFIG['port']),Handler).serve_forever()
