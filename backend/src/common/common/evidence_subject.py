"""Resolve known local service naming conventions without inventing attribution."""
from __future__ import annotations

import re
from urllib.parse import urlparse


def service_identity(value: object) -> str:
    token = str(value or "").strip().lower().replace("_", "-")
    for prefix in ("robot-shop-", "kaiops-", "kaims-", "rs-"):
        if token.startswith(prefix):
            return token[len(prefix):]
    return token


def service_matches(observed: object, expected: object) -> bool:
    # Robot Shop and platform Redis/RabbitMQ instances share component names.
    # Removing their namespace must not merge distinct applications.
    observed_robot = str(observed or "").lower().startswith(("robot-shop-", "rs-"))
    expected_robot = str(expected or "").lower().startswith(("robot-shop-", "rs-"))
    if observed_robot != expected_robot:
        return False
    return bool(observed and expected and service_identity(observed) == service_identity(expected))


def metric_matches_subject(labels: dict, service: str, *, target_labels: dict | None = None,
                           query: str = "") -> bool:
    """A broad query or a caller-supplied service field is not subject evidence."""
    target = target_labels or {}
    if target.get("instance") and labels.get("instance") and labels["instance"] != target["instance"]:
        return False
    for aliases in (("operation", "http_route", "route"), ("method", "http_method"), ("tenant", "tenant_id"), ("environment", "env"), ("namespace",), ("cluster",), ("mountpoint",), ("device",)):
        expected = next((target[key] for key in aliases if target.get(key)), None)
        observed = next((labels[key] for key in aliases if labels.get(key)), None)
        if expected is not None and observed is not None and str(expected) != str(observed):
            return False
    # This platform counter describes a RabbitMQ delivery path while job
    # identifies the consumer emitting it. It does not prove a broker failure.
    if (str(service).lower() in {"rabbitmq", "kaiops-rabbitmq", "kaims-rabbitmq"}
            and labels.get("__name__") == "kaiops_dead_letter_events_total"
            and labels.get("provider") == "rabbitmq"
            and str(labels.get("job") or "").startswith("kaiops-")):
        return True
    services = [labels[key] for key in ("service", "service_name", "service.name", "exported_service") if labels.get(key)]
    if services:
        return all(service_matches(value, service) for value in services)
    for key in ("instance", "job", "container", "container_name"):
        value = labels.get(key)
        if not value:
            continue
        if target.get(key) and value == target[key]:
            return True
        host = urlparse("//" + str(value)).hostname if key == "instance" else value
        if service_matches(host, service):
            return True
    # Aggregations may drop labels. Only an exact selector for the subject
    # (not a fleet-wide regex or vector(1)) can establish their binding.
    if not labels:
        selectors = re.findall(r'(service|service_name|job|instance)\s*=\s*"([^"\\]*)"', query)
        return any(service_matches(value, service) or bool(target.get(key) and target[key] == value)
                   for key, value in selectors)
    return False
