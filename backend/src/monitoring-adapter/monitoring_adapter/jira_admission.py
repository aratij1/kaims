from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger("monitoring-adapter.jira-admission")


@dataclass(frozen=True)
class AdmissionDecision:
    allowed: bool
    action: str
    reason: str
    occurrence_count: int


class JiraAdmissionState:
    """Durable guardrail around Jira creates and recurring comments."""

    def __init__(
        self,
        state_path: Path,
        *,
        recurrence_window_seconds: int,
        comment_cooldown_seconds: int,
        max_new_issues_per_hour: int,
        min_occurrences: dict[str, int],
    ) -> None:
        self.state_path = state_path
        self.recurrence_window = timedelta(seconds=max(30, recurrence_window_seconds))
        self.comment_cooldown = timedelta(seconds=max(0, comment_cooldown_seconds))
        self.max_new_issues_per_hour = max(1, max_new_issues_per_hour)
        self.min_occurrences = {key: max(1, int(value)) for key, value in min_occurrences.items()}

    @staticmethod
    def _parse(value: Any) -> datetime | None:
        try:
            parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except (TypeError, ValueError):
            return None

    def _load(self) -> dict[str, Any]:
        try:
            payload = json.loads(self.state_path.read_text(encoding="utf-8"))
            return payload if isinstance(payload, dict) else {}
        except (OSError, ValueError):
            return {}

    def _save(self, payload: dict[str, Any]) -> None:
        try:
            self.state_path.parent.mkdir(parents=True, exist_ok=True)
            temporary = self.state_path.with_suffix(f"{self.state_path.suffix}.tmp")
            temporary.write_text(json.dumps(payload, separators=(",", ":")), encoding="utf-8")
            temporary.replace(self.state_path)
        except OSError:
            logger.exception("failed to persist Jira admission state")

    def evaluate(
        self,
        *,
        fingerprint: str,
        source: str,
        severity: str,
        has_open_ticket: bool,
        now: datetime | None = None,
    ) -> AdmissionDecision:
        current = now or datetime.now(timezone.utc)
        state = self._load()
        fingerprints = state.setdefault("fingerprints", {})
        item = fingerprints.setdefault(fingerprint, {})

        cutoff = current - self.recurrence_window
        occurrences = [
            parsed
            for value in item.get("occurrences", [])
            if (parsed := self._parse(value)) is not None and parsed >= cutoff
        ]
        occurrences.append(current)
        item["occurrences"] = [value.isoformat() for value in occurrences][-100:]
        occurrence_count = len(occurrences)

        if has_open_ticket:
            last_comment = self._parse(item.get("last_comment_at"))
            if last_comment is not None and current - last_comment < self.comment_cooldown:
                self._save(state)
                return AdmissionDecision(False, "suppressed", "comment cooldown active", occurrence_count)
            item["last_comment_at"] = current.isoformat()
            self._save(state)
            return AdmissionDecision(True, "comment", "existing Jira issue", occurrence_count)

        required = 1 if severity.lower() == "critical" else self.min_occurrences.get(source, 1)
        if occurrence_count < required:
            self._save(state)
            return AdmissionDecision(
                False,
                "deferred",
                f"waiting for {required} occurrences in recurrence window",
                occurrence_count,
            )

        hour_cutoff = current - timedelta(hours=1)
        creations = [
            parsed
            for value in state.get("created_at", [])
            if (parsed := self._parse(value)) is not None and parsed >= hour_cutoff
        ]
        if len(creations) >= self.max_new_issues_per_hour:
            self._save(state)
            return AdmissionDecision(False, "rate_limited", "hourly Jira creation limit reached", occurrence_count)

        creations.append(current)
        state["created_at"] = [value.isoformat() for value in creations]
        item["last_created_at"] = current.isoformat()
        self._save(state)
        return AdmissionDecision(True, "create", "admitted", occurrence_count)

    def evaluate_for_discovery(
        self,
        *,
        fingerprint: str,
        source: str,
        severity: str,
        episode_start: str | None = None,
        now: datetime | None = None,
    ) -> AdmissionDecision:
        """Cheap pre-LLM gate that never reserves Jira creation capacity.

        Jira creation limits and comment cooldowns belong after Discovery.
        This gate only bundles recurring noisy signals before spending model
        tokens; critical signals pass immediately.
        """
        current = now or datetime.now(timezone.utc)
        state = self._load()
        discoveries = state.setdefault("discovery_fingerprints", {})
        item = discoveries.setdefault(fingerprint, {})
        onset = self._parse(episode_start)
        prior_onset = self._parse(item.get("episode_start"))
        if onset is not None:
            if prior_onset is not None and onset < prior_onset:
                return AdmissionDecision(False, "suppressed", "older alert episode", 0)
            if prior_onset is None or onset > prior_onset:
                item.clear()
                item["episode_start"] = onset.isoformat()
        cutoff = current - self.recurrence_window
        occurrences = [
            parsed
            for value in item.get("occurrences", [])
            if (parsed := self._parse(value)) is not None and parsed >= cutoff
        ]
        occurrences.append(current)
        item["occurrences"] = [value.isoformat() for value in occurrences][-100:]
        occurrence_count = len(occurrences)
        required = 1 if severity.lower() == "critical" else self.min_occurrences.get(source, 1)
        if occurrence_count < required:
            self._save(state)
            return AdmissionDecision(
                False,
                "deferred",
                f"waiting for {required} occurrences before Discovery",
                occurrence_count,
            )
        last_discovery = self._parse(item.get("last_discovery_at"))
        if last_discovery is not None and current - last_discovery < self.comment_cooldown:
            self._save(state)
            return AdmissionDecision(False, "suppressed", "Discovery cooldown active", occurrence_count)
        item["last_discovery_at"] = current.isoformat()
        self._save(state)
        return AdmissionDecision(True, "discover", "admitted for Discovery", occurrence_count)
