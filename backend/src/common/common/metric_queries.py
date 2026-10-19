"""Named, target-bound measurements for filesystem evidence questions."""
import json
import re


def registered_signal_metric(telemetry, arguments):
    """Operator-owned attribution for signals emitted by dependent services."""
    bindings = telemetry.get("signal_metric_bindings") or {}
    binding = bindings.get(arguments.get("alert_name")) if isinstance(bindings, dict) else None
    if not isinstance(binding, dict) or any(
        not arguments.get(key) or str(arguments[key]) != str(binding.get(key))
        for key in ("service", "tenant_id", "environment")
    ):
        return None
    name = str(binding.get("metric_name") or "")
    labels = binding.get("labels")
    if not re.fullmatch(r"[a-zA-Z_:][a-zA-Z0-9_:]*", name) or not isinstance(labels, dict) or not labels:
        return None
    if any(not re.fullmatch(r"[a-zA-Z_][a-zA-Z0-9_]*", key) or not isinstance(value, str)
           for key, value in labels.items()):
        return None
    expected = {"__name__": name, **labels}
    return "{" + ",".join(key + "=" + json.dumps(value) for key, value in expected.items()) + "}", expected


def filesystem_evidence_query(labels, *, question="", alert_name=""):
    text = f"{question} {alert_name}".lower()
    if not any(word in text for word in ("filesystem", "inode", "diskspacelow", "disk space", "disk utilization")):
        return None
    if not (labels.get("job") or labels.get("instance")):
        return None  # Never widen a missing target into a fleet-wide search.
    matchers = ['__name__=~"node_filesystem_(avail_bytes|free_bytes|size_bytes|files|files_free|readonly)"']
    matchers += [f"{key}={json.dumps(str(labels[key]))}" for key in ("job", "instance", "device", "mountpoint") if labels.get(key)]
    return "{" + ",".join(matchers) + "}"
