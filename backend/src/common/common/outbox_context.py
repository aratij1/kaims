"""Store large context deliveries by immutable snapshot reference, not a second JSON copy."""

import hashlib
import json
from copy import deepcopy
from uuid import UUID

from common.database import ContextSnapshotRecord

REFERENCE_VERSION = "kaims.context-outbox-ref.v1"
CONTEXT_TOPICS = frozenset({"context-events", "context-initial-events", "resolution-events"})


def context_checksum(context: dict) -> str:
    return hashlib.sha256(
        json.dumps(context, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    ).hexdigest()


def same_incident(left, right) -> bool:
    try:
        return UUID(str(left)) == UUID(str(right))
    except (TypeError, ValueError):
        return False


async def compact_context(session, *, payload, tenant_id, aggregate_id, topic):
    context = payload.get("context")
    if topic not in CONTEXT_TOPICS or not isinstance(context, dict) or "context_ref" in payload:
        return payload
    if len(json.dumps(context, ensure_ascii=True)) < 65536:
        return payload
    metadata = context.get("metadata")
    try:
        snapshot_id = UUID(str(metadata.get("context_snapshot_id"))) if isinstance(metadata, dict) else None
    except (TypeError, ValueError):
        return payload
    if snapshot_id is None:
        return payload
    snapshot = await session.get(ContextSnapshotRecord, snapshot_id)
    if (
        snapshot is None
        or not isinstance(snapshot.payload, dict)
        or snapshot.tenant_id != tenant_id
        or not same_incident(snapshot.incident_id, aggregate_id)
        or context.get("tenant_id") != tenant_id
        or not same_incident(context.get("incident_id"), aggregate_id)
    ):
        return payload
    checksum = context_checksum(context)
    if context_checksum(snapshot.payload) != checksum:
        return payload  # Preserve envelopes with extra fields absent from the snapshot.
    return {
        **{key: value for key, value in payload.items() if key != "context"},
        "context_ref": {
            "schema_version": REFERENCE_VERSION,
            "snapshot_id": str(snapshot_id),
            "context_sha256": checksum,
        },
    }


async def hydrate_context(session, row):
    reference = row.payload.get("context_ref")
    if reference is None:
        return row.payload  # Existing inline deliveries remain readable.
    if (
        not isinstance(reference, dict)
        or reference.get("schema_version") != REFERENCE_VERSION
        or row.topic not in CONTEXT_TOPICS
        or "context" in row.payload
    ):
        raise ValueError("Invalid outbox context reference")
    snapshot = await session.get(ContextSnapshotRecord, UUID(str(reference.get("snapshot_id"))))
    if (
        snapshot is None
        or not isinstance(snapshot.payload, dict)
        or snapshot.tenant_id != row.tenant_id
        or not same_incident(snapshot.incident_id, row.aggregate_id)
        or snapshot.payload.get("tenant_id") != row.tenant_id
        or not same_incident(snapshot.payload.get("incident_id"), row.aggregate_id)
        or context_checksum(snapshot.payload) != reference.get("context_sha256")
    ):
        raise ValueError("Outbox context snapshot binding or checksum mismatch")
    # Snapshot expiry is not extended. Consumers retain their existing freshness
    # checks; storage references only reconstruct the original delivery.
    return {
        **{key: value for key, value in row.payload.items() if key != "context_ref"},
        "context": deepcopy(snapshot.payload),
    }
