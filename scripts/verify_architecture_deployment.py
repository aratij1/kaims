"""Read-only live verification of the reviewed service images and HTTP probes."""
import json
from pathlib import Path
import subprocess


def main():
    path = Path("docs/architecture/architecture-review-deployment-2026-09-12.json")
    manifest = json.loads(path.read_text())
    services = list(manifest["services"])
    rows = json.loads(subprocess.check_output(["docker", "inspect", *["kaims-" + s + "-1" for s in services]]))
    states = []
    for row in rows:
        service = row["Config"]["Labels"]["com.docker.compose.service"]
        expected = manifest["images"][manifest["services"][service]]["image_id"]
        states.append({"service": service, "running": row["State"]["Running"], "restarts": row["RestartCount"], "health": row["State"].get("Health", {}).get("Status"), "image_matches": row["Image"] == expected})
    remote = """import concurrent.futures,json,urllib.request,urllib.error
services=SERVICES

def probe(service):
    result={'service':service}
    for endpoint in ('healthz','readyz'):
        try:
            with urllib.request.urlopen('http://'+service+':8000/'+endpoint,timeout=8) as response:
                result[endpoint]=response.status
        except urllib.error.HTTPError as error:
            result[endpoint]=error.code
        except Exception as error:
            result[endpoint]=type(error).__name__
    return result
with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
    print(json.dumps(list(pool.map(probe,services))))
""".replace("SERVICES", repr([s for s in services if s != "temporal-pilot-worker"]))
    probes = json.loads(subprocess.check_output(["docker", "exec", "kaims-monitoring-adapter-1", "python", "-c", remote]))
    result = {"containers": states, "http_probes": probes}
    manifest["live_verification"] = result
    path.write_text(json.dumps(manifest, indent=2))
    print(json.dumps(result))
    assert all(s["running"] and s["restarts"] == 0 and s["image_matches"] and s["health"] in (None, "healthy") for s in states)
    assert all(p["healthz"] == 200 and p["readyz"] == 200 for p in probes)

if __name__ == "__main__":
    main()
