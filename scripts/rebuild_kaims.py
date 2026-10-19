"""Recreate only KaiMS application images; never delete Docker volumes."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "artifacts" / "kaims-image-rebuild" / "result.json"


def command(arguments, *, timeout=180, capture=False):
    result = subprocess.run(
        arguments, cwd=ROOT, capture_output=capture, text=True,
        encoding="utf-8", timeout=timeout,
        env={**os.environ, "COMPOSE_PARALLEL_LIMIT": "1"},
    )
    if result.returncode:
        raise RuntimeError(f"{arguments[0]} operation failed (exit {result.returncode})")
    return result.stdout if capture else ""


def main():
    report = {"status": "preflight", "removed_images": [], "volumes_deleted": False}
    try:
        free = shutil.disk_usage(ROOT).free
        report["workspace_drive_free_bytes"] = free
        if free < 10 * 1024**3:
            raise RuntimeError("At least 10 GiB free space is required before removing/rebuilding images.")
        if os.name == "nt":
            settings_path = Path(os.environ["APPDATA"]) / "Docker" / "settings-store.json"
            docker_root = Path(os.environ["LOCALAPPDATA"]) / "Docker" / "wsl"
            if settings_path.exists():
                docker_settings = json.loads(settings_path.read_text(encoding="utf-8-sig"))
                docker_root = Path(docker_settings.get("CustomWslDistroDir") or docker_root)
            storage_free = shutil.disk_usage(docker_root.anchor).free
            report["docker_storage_drive_free_bytes"] = storage_free
            if storage_free < 10 * 1024**3:
                raise RuntimeError("Docker storage drive needs at least 10 GiB free before rebuilding images.")
        command(["docker", "info", "--format", "{{.ServerVersion}}"], timeout=20, capture=True)
        config = json.loads(command(["docker", "compose", "config", "--format", "json"], capture=True))
        project = config["name"]
        builds = {name: service for name, service in config["services"].items() if service.get("build")}
        image_for = lambda name: builds[name].get("image") or f"{project}-{name}"
        expected = {image_for(name).split(":")[0] for name in builds}
        inventory = command(["docker", "image", "ls", "--format", "{{json .}}"], capture=True)
        targets = sorted({f"{row['Repository']}:{row['Tag']}"
                          for row in map(json.loads, inventory.splitlines())
                          if row["Tag"] != "<none>" and
                          (row["Repository"].startswith(("kaims-", "kaims_")) or row["Repository"] in expected)})
        report.update(project=project, planned_images=targets)
        REPORT.parent.mkdir(parents=True, exist_ok=True)
        REPORT.write_text(json.dumps(report, indent=2), encoding="utf-8")
        containers = command(["docker", "ps", "-aq", "--filter", f"label=com.docker.compose.project={project}"], capture=True).split()
        # Old validation containers may not have Compose labels, but still
        # reference the KaiMS images the user asked us to replace.
        target_repositories = {target.rsplit(":", 1)[0] for target in targets}
        container_inventory = command(["docker", "ps", "-a", "--format", "{{json .}}"], capture=True)
        for row in map(json.loads, container_inventory.splitlines()):
            image = row.get("Image", "")
            repository = image.rsplit(":", 1)[0] if ":" in image.rsplit("/", 1)[-1] else image
            if repository in target_repositories:
                containers.append(row["ID"])
        containers = sorted(set(containers))
        if containers:
            print(f"Stopping {len(containers)} saved {project} containers; volumes are retained.", flush=True)
            command(["docker", "container", "stop", *containers], timeout=600)
            # No -v: preserve named and anonymous data volumes.
            command(["docker", "container", "rm", *containers], timeout=600)
        for target in targets:
            # No --force: a reference from another project blocks removal.
            command(["docker", "image", "rm", target])
            report["removed_images"].append(target)
        groups = {}
        for name, service in builds.items():
            signature = json.dumps(service["build"], sort_keys=True)
            if signature not in groups:
                command(["docker", "compose", "build", name], timeout=7200)
                groups[signature] = image_for(name)
            elif groups[signature] != image_for(name):
                command(["docker", "tag", groups[signature], image_for(name)])
        report["rebuilt_services"] = sorted(builds)
        command(["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
                 str(ROOT / "scripts" / "start-kaims.ps1"), "-Profile", "lean",
                 "-DockerCommandTimeoutSeconds", "900", "-ReadyTimeoutSeconds", "600"], timeout=2400)
        report["status"] = "ready"
    except Exception as exc:
        report.update(status="blocked", reason=str(exc))
        raise
    finally:
        REPORT.parent.mkdir(parents=True, exist_ok=True)
        REPORT.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
