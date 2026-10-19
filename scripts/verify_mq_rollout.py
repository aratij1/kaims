"""Read-only broker audit after the approved pipeline rollout."""
import json
import subprocess
from pathlib import Path

source=Path("scripts/audit_pipeline_stages.py").read_text(encoding="utf-8")
source=source.split("    engine = create_async_engine")[0]+"    print(json.dumps(output,default=str))\n\nasyncio.run(main())\n"
result=subprocess.run(["docker","exec","-i","kaims-api-gateway-1","python","-"],input=source,text=True,capture_output=True)
if result.returncode: raise RuntimeError(result.stderr[-1000:])
audit=json.loads(result.stdout)
Path("docs/architecture/mq-deployed-broker-audit-2026-09-13.json").write_text(json.dumps(audit,indent=2))
missing=[]
for queue in audit["queues"]:
    if queue["name"].endswith(".dlq") and not any(binding["destination"]==queue["name"] and binding["routing_key"]==queue["name"] for binding in audit["bindings"]):
        missing.append(queue["name"])
summary={"queue_count":len(audit["queues"]),"missing_isolated_dlq_bindings":missing,
 "active_ready":sum(q.get("messages_ready",0) or 0 for q in audit["queues"] if not q["name"].endswith(".dlq")),
 "active_unacknowledged":sum(q.get("messages_unacknowledged",0) or 0 for q in audit["queues"] if not q["name"].endswith(".dlq")),
 "deadletters_retained":sum(q.get("messages_ready",0) or 0 for q in audit["queues"] if q["name"].endswith(".dlq"))}
print(json.dumps(summary))
Path("docs/architecture/mq-deployed-broker-summary-2026-09-13.json").write_text(json.dumps(summary,indent=2))
assert not missing, "Some deployed consumers lack isolated DLQ routing"
