"""Build an RCA chronology from retained evidence, never invented event times."""
from datetime import UTC, datetime


def causal_steps(value):
    if isinstance(value, str):
        return [value.strip()] if value.strip() else []
    if not isinstance(value, list):
        return []
    return [str(item).strip() for item in value if isinstance(item, str) and item.strip()][:30]


def _observed_at(row):
    for data in (row, row.get("metadata"), row.get("content")):
        if not isinstance(data, dict):
            continue
        value = data.get("observed_at") or data.get("timestamp")
        try:
            parsed = value if isinstance(value, datetime) else datetime.fromisoformat(str(value).replace("Z", "+00:00"))
            return (parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)).astimezone(UTC).isoformat()
        except (TypeError, ValueError):
            continue
    return None


def build_rca_timeline(sequence, evidence, accepted_ids=()):
    rows = {str(row.get("evidence_id") or row.get("id")): row for row in evidence
            if isinstance(row, dict) and (row.get("evidence_id") or row.get("id"))}
    accepted = set(accepted_ids)
    events, rejected = [], []
    structured = isinstance(sequence, list) and bool(sequence)
    if structured:
        for index, event in enumerate(sequence[:30]):
            if not isinstance(event, dict) or not isinstance(event.get("event"), str) or not event["event"].strip():
                rejected.append({"index": index, "reason": "INVALID_EVENT"})
                continue
            references = event.get("evidence_ids")
            references = references if isinstance(references, list) else []
            # Every citation must resolve; partial citation acceptance must not
            # make an unsupported model event appear established.
            ids = list(dict.fromkeys(value for value in references if isinstance(value, str)))
            if not ids or any(value not in rows for value in ids):
                rejected.append({"index": index, "reason": "UNRESOLVED_EVENT_EVIDENCE"})
                continue
            times = sorted(filter(None, (_observed_at(rows[value]) for value in ids)))
            role = str(event.get("causal_role") or "observation")
            events.append({"event": event["event"].strip()[:1600],
                "causal_role": role if role in {"trigger", "mechanism", "symptom", "recovery", "observation"} else "observation",
                "occurred_at": times[0] if times else None,
                "observed_until": times[-1] if len(times)>1 else None,
                "timestamp_source": "evidence_observation" if times else "not_recorded",
                "evidence_ids": ids, "rca_cited": all(value in accepted for value in ids),
                "kind": "causal_claim"})
    else:
        for key, row in rows.items():
            # A context snapshot also contains background code and topology.
            # Only current RCA citations belong in its fallback chronology.
            if key not in accepted:
                continue
            content = row.get("content") if isinstance(row.get("content"), dict) else {}
            description = row.get("summary") or content.get("message") or content.get("summary") or row.get("snippet")
            description = description if isinstance(description, str) else ""
            events.append({"event": description[:1600] or f"Recorded {row.get('category') or row.get('source') or 'evidence'} observation",
                "causal_role": "observation", "occurred_at": _observed_at(row),
                "observed_until": None, "timestamp_source": "evidence_observation" if _observed_at(row) else "not_recorded",
                "evidence_ids": [key], "rca_cited": key in accepted, "kind": "observation"})
    known = [event for event in events if event["occurred_at"]]
    unknown = [event for event in events if not event["occurred_at"]]
    known.sort(key=lambda event: event["occurred_at"])
    return {"events": (known + unknown)[:30], "ordering": "partial" if unknown else "chronological",
        "causal_sequence_recorded": structured and bool(events) and not rejected, "rejected_events": rejected,
        "missing_event_times": len(unknown),
        "note": "Event times come from source observations. Collection timestamps are not event timestamps."}
