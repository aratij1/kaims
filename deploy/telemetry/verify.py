"""Read-only Telemetry checks; run inside a KaiMS container with Python."""
import json
from datetime import datetime, timezone
from urllib.parse import urlencode
from urllib.request import Request, urlopen


def request(url, payload=None):
    body = None if payload is None else json.dumps(payload).encode()
    req = Request(url, data=body, headers={"Content-Type": "application/json"})
    with urlopen(req, timeout=30) as response:
        return json.load(response)


def query(expression, base="http://host.docker.internal:19090"):
    result = request(base + "/api/v1/query?" + urlencode({"query": expression}))
    return result.get("data", {}).get("result", [])


report = {"checked_at": datetime.now(timezone.utc).isoformat()}
checks = {
    "application_probe": lambda: query('probe_success{job="telemetry-application"}', 'http://prometheus:9090'),
    "jaeger_probe": lambda: query('probe_success{job="telemetry-jaeger"}', "http://prometheus:9090"),
    "collector_uptime": lambda: query('{__name__=~"otelcol_process_uptime.*"}'),
    "accepted_spans": lambda: query('{__name__=~"otelcol_receiver_accepted_spans.*"}'),
    "prometheus_alerts": lambda: request("http://host.docker.internal:19090/api/v1/alerts"),
    "alertmanager_alerts": lambda: [a for a in request("http://alertmanager:9093/api/v2/alerts") if a.get("labels", {}).get("project") == "telemetry"],
    "discovery": lambda: request("http://discovery-mcp:8000/mcp", {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "topology.search", "arguments": {"project": "telemetry", "limit": 50}}}),
}
for name, check in checks.items():
    try:
        report[name] = check()
    except Exception as exc:
        report[name] = {"error": str(exc)}
try:
    rows = request("http://monitoring-adapter:8000/alerts/all?limit=5000&compact=true").get("rows", [])
    alerts = [a for a in rows if a.get("labels", {}).get("project") == "telemetry" or str(a.get("name", "")).startswith("Telemetry")]
    report["captured_alerts"] = [{k: a.get(k) for k in ("id", "name", "created_at", "starts_at", "ends_at", "service", "labels")} for a in alerts]
    report["incidents"] = []
    for a in alerts[:10]:
        try:
            data = request("http://monitoring-adapter:8000/alerts/" + a["id"] + "/processed-result?tenant_id=default")
            incident = data.get("incident") or {}
            report["incidents"].append({"alert_id": a["id"], "incident": {k: incident.get(k) for k in ("id", "status", "metadata")}, "context_present": bool(data.get("context"))})
        except Exception as exc:
            report["incidents"].append({"alert_id": a["id"], "error": str(exc)})
except Exception as exc:
    report["captured_alerts"] = {"error": str(exc)}
try:
    import os
    from pathlib import Path
    root = Path(os.getenv("LANDING_PAD_INPUT_DIR", "/app/ingested_alerts/input")).parent / "processed"
    today = datetime.now(timezone.utc)
    folder = root / today.strftime("%Y") / today.strftime("%m") / today.strftime("%d")
    report["intake_observations"] = []
    for path in sorted(folder.glob("*telemetry*")):
        data = json.loads(path.read_text())
        alert = data.get("alert", {})
        report["intake_observations"].append({"file": str(path), "received_at": data.get("received_at"), "name": alert.get("name"), "status": alert.get("labels", {}).get("alert_status"), "ends_at": alert.get("annotations", {}).get("endsAt")})
    evidence = request("http://discovery-mcp:8000/mcp", {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "telemetry.search", "arguments": {"project": "telemetry", "service": "frontend", "limit": 8}}})
    report["telemetry_discovery_sources"] = evidence.get("result", {}).get("sources", [])
except Exception as exc:
    report["evidence_error"] = str(exc)
print(json.dumps(report, indent=2))
