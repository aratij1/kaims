import json
import re
from urllib.parse import parse_qs, urlsplit

from common.orchestration.execution_plan import docker_compose_restart_plan


def test_restart_discovers_stopped_target_with_exact_compose_scope():
    plan = docker_compose_restart_plan(project="telemetry", service="frontend-proxy")
    for command in [*plan["preflight"], *plan["commands"]]:
        url = re.search(r"'([^']+/containers/json\?[^']+)'", command).group(1)
        query = parse_qs(urlsplit(url).query)
        assert query["all"] == ["true"]
        assert json.loads(query["filters"][0]) == {"label": [
            "com.docker.compose.project=telemetry",
            "com.docker.compose.service=frontend-proxy",
        ]}
    assert "/restart?t=30" in plan["commands"][0]
