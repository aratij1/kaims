"""Source episode identity and timestamps; receipt time is not event onset."""
import hashlib
import json
from datetime import UTC, datetime


def source_time(value):
    if not value:
        return None
    parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if parsed.year == 1:
        return None  # Alertmanager uses a zero timestamp for an unresolved end.
    return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)


def alertmanager_delivery_key(item, labels, status):
    onset = source_time(item.get("startsAt"))
    identity = {"status": status, "fingerprint": str(item.get("fingerprint") or ""),
                "startsAt": onset.isoformat() if onset else None}
    if not identity["fingerprint"]:
        identity["labels"] = labels
    return hashlib.sha256(json.dumps(identity, sort_keys=True, default=str).encode()).hexdigest()


def alert_source_times(payload, annotations):
    result = {}
    for field, source in (("starts_at", "startsAt"), ("ends_at", "endsAt")):
        observed = source_time(payload.get(field) or annotations.get(source))
        if observed is not None:
            result[field] = observed
    return result
