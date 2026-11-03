"""Independent Prometheus observations. No executor recovery assertions are inputs."""

from __future__ import annotations

import asyncio
import json
import math
import operator
import os
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from typing import Any

import httpx
from common.models import RemediationAction
from common.recovery_observers import (
    ObserverSource,
    RecoveryObserverRegistry,
    RegisteredRecoveryCheck,
)

from closure_service.validation import _approved_plan_integrity

_COMPARE = {
    "eq": operator.eq,
    "ne": operator.ne,
    "lt": operator.lt,
    "lte": operator.le,
    "gt": operator.gt,
    "gte": operator.ge,
}


class ObservationUnavailable(ValueError):
    pass


class PrometheusRecoveryObserver:
    def __init__(self, *, transport: httpx.AsyncBaseTransport | None = None):
        self.transport = transport

    async def observe(
        self,
        action: RemediationAction,
        source: ObserverSource,
        check: RegisteredRecoveryCheck,
        *,
        now: datetime,
        window_seconds: int,
    ) -> list[dict[str, Any]]:
        completed_at = action.completed_at
        if completed_at is None or completed_at.tzinfo is None:
            raise ObservationUnavailable("execution_completion_timestamp_missing")
        return await self.observe_window(
            source, check, now=now, window_seconds=window_seconds, not_before=completed_at,
            binding={"execution_id": str(action.id),
                     "plan_fingerprint": action.parameters["execution_plan"]["plan_fingerprint"],
                     "phase": "post_state"},
        )

    async def observe_window(
        self, source: ObserverSource, check: RegisteredRecoveryCheck, *,
        now: datetime, window_seconds: int, not_before: datetime, binding: dict[str, str],
    ) -> list[dict[str, Any]]:
        """Collect real samples after a server-established execution or assessment boundary."""
        if not_before.tzinfo is None or now.tzinfo is None or not_before > now:
            raise ObservationUnavailable("observation_boundary_invalid")
        spec = check.spec
        completed_at = not_before
        step = check.step_seconds
        end = math.floor(now.timestamp() / step) * step
        # For instant selectors, wait a full lookback interval after execution.
        # Registry review must also account for any PromQL range-selector horizons.
        first = math.ceil((completed_at.timestamp() + step) / step) * step
        start = max(first, end - math.ceil(window_seconds / step) * step)
        if start > end:
            return []
        points = (end - start) // step + 1
        if points > 10000:
            raise ObservationUnavailable("observation_window_exceeds_sample_budget")
        headers = {}
        if source.bearer_token_env:
            token = os.environ.get(source.bearer_token_env, "")
            if not token:
                raise ObservationUnavailable("observer_credential_unavailable")
            headers["Authorization"] = f"Bearer {token}"
        async with httpx.AsyncClient(
            transport=self.transport,
            timeout=spec.timeout_seconds,
            follow_redirects=False,
            trust_env=False,
            headers=headers,
        ) as client:
            response = await client.get(
                source.endpoint.rstrip("/") + "/api/v1/query_range",
                params={
                    "query": check.query,
                    "start": start,
                    "end": end,
                    "step": step,
                    "timeout": f"{spec.timeout_seconds}s",
                    "lookback_delta": f"{step}s",
                    "limit": 2,
                },
            )
            response.raise_for_status()
            body = response.json()
        if not isinstance(body, dict) or body.get("status") != "success" or body.get("warnings"):
            raise ObservationUnavailable("prometheus_query_incomplete")
        data = body.get("data") or {}
        rows = data.get("result")
        if isinstance(rows, list) and len(rows) > 1 and "vector(" in check.query:
            labeled_rows = [
                row for row in rows if isinstance(row, dict) and bool(row.get("metric"))
            ]
            if len(labeled_rows) == 1:
                rows = labeled_rows
        # Registry queries must aggregate to exactly one target-scoped value.
        # No-data is unknown, never an implicit zero or successful recovery.
        if data.get("resultType") != "matrix" or not isinstance(rows, list) or len(rows) != 1:
            raise ObservationUnavailable("prometheus_requires_one_complete_series")
        values = rows[0].get("values")
        if not isinstance(values, list) or len(values) != points:
            raise ObservationUnavailable("prometheus_observation_gap")
        observations = []
        for index, sample in enumerate(values):
            if not isinstance(sample, list) or len(sample) != 2:
                raise ObservationUnavailable("prometheus_sample_invalid")
            timestamp, value = float(sample[0]), float(sample[1])
            expected_timestamp = start + index * step
            if not math.isfinite(value) or timestamp != expected_timestamp:
                raise ObservationUnavailable("prometheus_sample_stale_or_invalid")
            material = {
                **binding,
                "validator_id": spec.validator_id,
                "connector_id": spec.connector_id,
                "target_resource_id": spec.target_resource_id,
                "observed_at": datetime.fromtimestamp(timestamp, UTC).isoformat(),
                # Preserve the source decimal text in checksummed evidence.
                # MySQL JSON can shorten a double's decimal representation
                # (0.9874999999999999 -> 0.9875), invalidating a valid proof.
                # Numeric evaluation above/below still uses the parsed value.
                "measured_value": str(sample[1]),
                "expected_value": str(spec.threshold),
                "passed": _COMPARE[spec.evaluation_operator](value, float(spec.threshold)),
            }
            checksum_material = {
                **material,
                "check_reference": spec.check_reference,
                "series": rows[0].get("metric", {}),
            }
            material["result_checksum"] = (
                "sha256:"
                + sha256(json.dumps(checksum_material, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            )
            observations.append(material)
        return observations


async def collect_recovery_observations(
    action: RemediationAction,
    registry: RecoveryObserverRegistry,
    *,
    observer: PrometheusRecoveryObserver | None = None,
    now: datetime | None = None,
    grace_seconds: int = 120,
) -> RemediationAction:
    now = now or datetime.now(UTC)
    result = action.model_copy(deep=True)
    # The runtime path must replace any observations/snapshots supplied by an
    # executor or API caller with independently acquired evidence.
    result.parameters["validation_observations"] = []
    result.parameters["validator_registry_snapshot"] = []
    result.parameters["pre_state_validation_observations"] = []
    plan = result.parameters.get("execution_plan") or {}
    profile = registry.profile_for(
        tenant_id=result.tenant_id,
        environment=str(plan.get("environment") or ""),
        target=result.target,
        alert_name=str((plan.get("alert") or {}).get("name") or ""),
    )
    errors = []
    if not _approved_plan_integrity(result, plan):
        errors.append("approved_plan_integrity_failed")
    if profile is None:
        errors.append("recovery_profile_not_registered")
    elif profile.specs() != plan.get("validators"):
        errors.append("approved_validators_do_not_match_registry")
    if errors:
        result.parameters["recovery_observation_collection"] = {"status": "failed", "reason_codes": errors}
        return result
    result.parameters["validator_registry_snapshot"] = profile.specs()
    observer = observer or PrometheusRecoveryObserver()
    semaphore = asyncio.Semaphore(4)

    async def collect(check):
        async with semaphore:
            try:
                return await observer.observe(
                    result,
                    registry.source_for(check.spec),
                    check,
                    now=now,
                    window_seconds=max(
                        60, int(plan.get("stability_window_seconds") or 300), check.spec.observation_window_seconds
                    ),
                ), None
            except (httpx.HTTPError, ValueError, TypeError, KeyError, OverflowError, AttributeError):
                # Do not persist URLs, response bodies, queries, or credentials
                # in failure messages. The check reference identifies the input.
                return [], f"observer_unavailable:{check.spec.validator_id}"

    batches = await asyncio.gather(*(collect(check) for check in profile.checks))
    observations = [sample for samples, _ in batches for sample in samples]
    errors = [error for _, error in batches if error]
    complete = not errors
    for check, (samples, _) in zip(profile.checks, batches, strict=True):
        window = max(60, int(plan.get("stability_window_seconds") or 300), check.spec.observation_window_seconds)
        span = (
            (
                datetime.fromisoformat(samples[-1]["observed_at"]) - datetime.fromisoformat(samples[0]["observed_at"])
            ).total_seconds()
            if samples
            else 0
        )
        complete = complete and len(samples) >= check.spec.minimum_sample_count and span >= window
    failed_check = any(sample["passed"] is False for sample in observations)
    completed_at = action.completed_at
    window = max(
        60,
        int(plan.get("stability_window_seconds") or 300),
        *(check.spec.observation_window_seconds + 2 * check.step_seconds for check in profile.checks),
    )
    deadline = (
        completed_at + timedelta(seconds=window + max(0, grace_seconds))
        if completed_at is not None and completed_at.tzinfo is not None
        else now
    )
    status = (
        "failed"
        if failed_check
        else "complete"
        if complete
        else "failed"
        if now >= deadline
        else "unavailable"
        if errors
        else "warming_up"
    )
    if failed_check:
        errors.extend(
            sorted(
                {f"recovery_check_failed:{sample['validator_id']}" for sample in observations if not sample["passed"]}
            )
        )
    elif not complete and now >= deadline:
        errors.append("recovery_observation_deadline_exceeded")
    result.parameters["validation_observations"] = observations
    result.parameters["recovery_observation_collection"] = {
        "status": status,
        "reason_codes": errors or ([] if complete else ["recovery_window_incomplete"]),
        "observed_at": now.isoformat(),
        "deadline": deadline.isoformat(),
        "sample_count": len(observations),
    }
    return result
