"""Apply the final reviewed transport files to built service images and verify deployment."""
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

FILES = ["rabbitmq.py", "message_processing.py", "config.py"]

def run(args):
    result = subprocess.run(args, capture_output=True, text=True, env=dict(os.environ, DOCKER_BUILDKIT="0"))
    if result.returncode:
        raise RuntimeError(result.stderr[-2000:] + result.stdout[-1000:])
    return result.stdout

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--deploy", action="store_true", help="Deploy previously built and hash-verified service images; explicit rollout approval required")
    options = parser.parse_args()
    manifest_path = Path("docs/architecture/architecture-review-deployment-2026-09-12.json")
    manifest = json.loads(manifest_path.read_text())
    if options.deploy:
        for path, expected in manifest.get("files", {}).items():
            source = Path(path)
            if not source.is_file() or hashlib.sha256(source.read_bytes()).hexdigest() != expected:
                raise RuntimeError("Prepared pipeline source changed; rebuild before rollout: " + path)
        for name in FILES:
            expected = manifest.get("latest_transport_patch", {}).get(name)
            actual = hashlib.sha256((Path("backend/src/common/common") / name).read_bytes()).hexdigest()
            if expected != actual:
                raise RuntimeError("Prepared transport source changed; rebuild before rollout: " + name)
        for image in dict.fromkeys(manifest["services"].values()):
            actual = run(["docker", "image", "inspect", image, "--format", "{{.Id}}"] ).strip()
            if actual != manifest["images"][image]["image_id"]:
                raise RuntimeError("Prepared image changed; rebuild before rollout: " + image)
        rollout(manifest)
        return
    with tempfile.TemporaryDirectory(prefix="kaims-rabbitmq-review-") as folder:
        root = Path(folder)
        for name in FILES:
            shutil.copyfile(Path("backend/src/common/common") / name, root / name)
        for image in dict.fromkeys(manifest["services"].values()):
            base = run(["docker", "image", "inspect", image, "--format", "{{.Id}}"] ).strip()
            (root / "Dockerfile").write_text("FROM " + image + "\nCOPY " + " ".join(FILES) + " /app/backend/src/common/common/\nRUN python -c \"import common.rabbitmq; import common.message_processing; from common.config import Settings; Settings()\"\n")
            run(["docker", "build", "-t", image, str(root)])
            manifest["images"][image]["image_id"] = run(["docker", "image", "inspect", image, "--format", "{{.Id}}"] ).strip()
            print("Patched " + image, flush=True)
    for name in FILES:
        path = "backend/src/common/common/" + name
        manifest["files"][path] = hashlib.sha256(Path(path).read_bytes()).hexdigest()
    manifest.pop("live_verification", None)
    manifest["latest_transport_patch"] = {name: manifest["files"]["backend/src/common/common/"+name] for name in FILES}
    manifest_path.write_text(json.dumps(manifest, indent=2))
    if not options.deploy:
        print("Build-only complete. No containers restarted. Use --deploy only after rollout approval.", flush=True)
        return

def rollout(manifest):
    results = []
    # Rolling service replacement avoids stopping the whole pipeline together.
    for service in manifest["services"]:
        run(["docker", "compose", "up", "-d", "--no-deps", service])
        ready = False
        for attempt in range(30):
            row = json.loads(run(["docker", "inspect", "kaims-"+service+"-1"]))[0]
            health = row["State"].get("Health", {}).get("Status")
            if row["State"]["Running"] and health in (None,"healthy"):
                ready = True
                break
            time.sleep(2)
        results.append({"service":service,"healthy":ready,"image":row["Image"]})
        Path("docs/architecture/rabbitmq-rollout-2026-09-13.json").write_text(json.dumps(results,indent=2))
        if not ready:
            raise RuntimeError("Service did not become healthy: "+service)
        print("Healthy " + service, flush=True)

if __name__ == "__main__":
    main()
