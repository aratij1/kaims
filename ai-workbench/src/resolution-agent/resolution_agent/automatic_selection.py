"""Only an unambiguous certified exact-service recovery may be selected unattended."""
from typing import Any


def certified_option(rows: list[dict[str, Any]], *, service: str) -> dict[str, Any] | None:
    eligible = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        scope = row.get('service_scope')
        successes, failures = row.get('success_count'), row.get('failure_count')
        if (row.get('source') == 'tenant-learned-resolution-catalog'
                and isinstance(scope, list) and service.strip().lower() in scope
                and row.get('self_heal_eligible') is True and row.get('risk') == 'low'
                and type(successes) is int and successes >= 1
                and type(failures) is int and failures == 0
                and row.get('steps') and row.get('validation') and row.get('rollback')):
            eligible.append(row)
    return eligible[0] if len(eligible) == 1 else None
