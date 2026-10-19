"""Build the reviewed shared pipeline code on the current local service runtimes."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import subprocess
import tempfile

SERVICES = ["discovery-mcp", "monitoring-adapter", "monitoring-ingestion-worker", "alert-intelligence", "orchestrator", "context-agent", "resolution-agent", "approval-service", "remediation-engine", "closure-service", "api-gateway", "model-router", "validation-agent", "audit-service", "notification-service", "connector-hub", "discovery-service", "application-onboarding", "knowledge-development-worker", "rule-generation-agent", "prometheus-config-service", "metrics-validation-agent", "dashboard-generator", "evaluation-service", "cloud-operations", "temporal-pilot-worker"]
FILES = sorted(str(path).replace("\\", "/") for source_root in (Path("backend/src"), Path("ai-workbench/src"))
               for path in source_root.rglob("*")
               if path.is_file() and "__pycache__" not in path.parts
               and path.suffix in {".py", ".json", ".yaml", ".yml", ".txt", ".md", ".j2", ".toml", ".sql"}) + ["scripts/verify_broker_delivery.py"]


def run(args):
    result = subprocess.run(args, capture_output=True, text=True, env=dict(os.environ, DOCKER_BUILDKIT="0"))
    if result.returncode:
        raise RuntimeError(result.stderr[-1500:] + result.stdout[-1500:])
    return result.stdout


def main():
    selected = sys.argv[1:] or SERVICES
    if any(service not in SERVICES for service in selected):
        raise ValueError("unknown review service")
    rows = json.loads(run(["docker", "inspect", *["kaims-" + name + "-1" for name in selected]]))
    hashes = {name: hashlib.sha256(Path(name).read_bytes()).hexdigest() for name in FILES}
    patch_hash = hashlib.sha256(json.dumps(hashes, sort_keys=True).encode()).hexdigest()
    manifest = {"files": hashes, "patch_sha256": patch_hash, "services": {}, "images": {}}
    with tempfile.TemporaryDirectory(prefix="kaims-architecture-review-") as directory:
        root = Path(directory)
        for source in FILES:
            target = root / "app" / source
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
        for row in rows:
            service = row["Config"]["Labels"]["com.docker.compose.service"]
            assert row["Config"]["Labels"]["com.docker.compose.project"] == "kaims"
            image = row["Config"]["Image"]
            manifest["services"][service] = image
            if image in manifest["images"]:
                continue
            base = image.rsplit(":", 1)[0] if ":" in image.rsplit("/", 1)[-1] else image
            rollback = base + ":before-architecture-review-20260912"
            if subprocess.run(["docker", "image", "inspect", rollback], capture_output=True).returncode:
                run(["docker", "tag", image, rollback])
            (root / "Dockerfile").write_text("FROM " + rollback + "\nCOPY app/ /app/\nRUN python -c \"import common.repository; import importlib; from pathlib import Path; importlib.import_module('app') if Path('app.py').is_file() else None\"\nLABEL io.kaims.review.patch-sha256=" + patch_hash + "\n")
            run(["docker", "build", "-t", image, str(root)])
            manifest["images"][image] = {"rollback": rollback, "image_id": run(["docker", "image", "inspect", image, "--format", "{{.Id}}"]).strip()}
            print("Built " + service, flush=True)
    output = Path("docs/architecture/architecture-review-deployment-2026-09-12.json")
    if selected != SERVICES and output.exists():
        previous = json.loads(output.read_text())
        previous["services"].update(manifest["services"])
        previous["images"].update(manifest["images"])
        previous["files"].update(manifest["files"])
        previous["latest_patch_sha256"] = patch_hash
        previous["latest_patch_services"] = selected
        previous.pop("live_verification", None)
        manifest = previous
    output.write_text(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
