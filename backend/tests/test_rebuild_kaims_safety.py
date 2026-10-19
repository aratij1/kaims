import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest


def load_script(monkeypatch, tmp_path):
    path = Path("scripts/rebuild_kaims.py")
    spec = importlib.util.spec_from_file_location("rebuild_kaims", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, "ROOT", tmp_path)
    monkeypatch.setattr(module, "REPORT", tmp_path / "report.json")
    return module


def test_full_disk_blocks_before_any_docker_mutation(monkeypatch, tmp_path):
    module = load_script(monkeypatch, tmp_path)
    monkeypatch.setattr(module.shutil, "disk_usage", lambda root: SimpleNamespace(free=0))
    monkeypatch.setattr(module, "command", lambda *args, **kwargs: pytest.fail("Docker must not be invoked"))
    with pytest.raises(RuntimeError, match="10 GiB"):
        module.main()
    report = json.loads(module.REPORT.read_text(encoding="utf-8"))
    assert report["status"] == "blocked"
    assert not report["removed_images"] and not report["volumes_deleted"]


def test_rebuild_is_project_scoped_and_preserves_volumes(monkeypatch, tmp_path):
    module = load_script(monkeypatch, tmp_path)
    monkeypatch.setattr(module.shutil, "disk_usage", lambda root: SimpleNamespace(free=20 * 1024**3))
    calls = []
    config = {"name": "kaims", "services": {
        "api-gateway": {"build": {"dockerfile": "service"}},
        "context-agent": {"build": {"dockerfile": "service"}},
        "ui": {"build": {"dockerfile": "ui"}},
        "mysql": {"image": "mysql:8"},
    }}

    def command(args, **kwargs):
        calls.append(args)
        if args[:3] == ["docker", "compose", "config"]:
            return json.dumps(config)
        if args[:3] == ["docker", "image", "ls"]:
            return "\n".join(json.dumps({"Repository": name, "Tag": "latest"})
                             for name in ["kaims-ui", "mysql", "unrelated-app"])
        if args[:3] == ["docker", "ps", "-aq"]:
            assert "label=com.docker.compose.project=kaims" in args
            return "kaims-container-id"
        if args[:3] == ["docker", "ps", "-a"]:
            return "\n".join(json.dumps(row) for row in [
                {"ID": "old-validation", "Image": "kaims-ui:latest"},
                {"ID": "unrelated-container", "Image": "unrelated-app:latest"},
            ])
        return ""

    monkeypatch.setattr(module, "command", command)
    module.main()
    assert ["docker", "image", "rm", "kaims-ui:latest"] in calls
    assert len([args for args in calls if args[:3] == ["docker", "compose", "build"]]) == 2
    assert ["docker", "tag", "kaims-api-gateway", "kaims-context-agent"] in calls
    stopped = next(args for args in calls if args[:3] == ["docker", "container", "stop"])
    assert "old-validation" in stopped and "unrelated-container" not in stopped
    assert not any("volume" in args or "--force" in args or "-v" in args for args in calls)
    assert json.loads(module.REPORT.read_text(encoding="utf-8"))["status"] == "ready"
