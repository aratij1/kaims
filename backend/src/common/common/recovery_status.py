"""Current recovery measurements are independent of RCA and closure authority."""
import hashlib
import json
from datetime import UTC, datetime
from uuid import NAMESPACE_URL, uuid5


def observation_id(tenant, incident_id):
    return uuid5(NAMESPACE_URL, f"current-recovery:{tenant}:{incident_id}")


def checksum(result):
    return "sha256:" + hashlib.sha256(json.dumps(result, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()


def project_observation(payload, *, now=None):
    if not payload:
        return {"status": "not_observed"}
    result = payload.get("result") or {}
    output = {key: payload.get(key) for key in ("observation_id", "observed_at", "valid_until", "validation_checksum", "profile_digest")}
    output.update(checks=result.get("checks") or [], corrective_execution_performed=False, closes_incident=False)
    try:
        valid_until = datetime.fromisoformat(payload["valid_until"])
        valid = valid_until.tzinfo is not None and valid_until > (now or datetime.now(UTC))
    except (KeyError, ValueError, TypeError):
        valid = False
    intact = payload.get("validation_checksum") == checksum(result)
    if result.get("status") == "verified":
        checks = result.get("checks") or []
        required = {"availability", "alert_clearance", "error_rate", "latency", "dependency_health", "critical_alerts"}
        complete = required.issubset({check.get("kind") for check in checks})
        try:
            complete = complete and all(check.get("status") == "passed"
                and len(check.get("samples") or []) >= 2
                and all(sample.get("passed") is True and sample.get("result_checksum") for sample in check["samples"])
                and (datetime.fromisoformat(check["samples"][-1]["observed_at"]) - datetime.fromisoformat(check["samples"][0]["observed_at"])).total_seconds() >= 300
                for check in checks)
        except (KeyError, TypeError, ValueError):
            complete = False
        intact = intact and complete
    output["status"] = result.get("status", "unavailable") if valid and intact else "stale" if intact else "invalid"
    return output
