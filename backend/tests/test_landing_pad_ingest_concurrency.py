"""Alert-ingestion scaling for a 10,000-alert burst: the global
asyncio.Lock that used to serialize ALL landing-pad file processing is
replaced by an atomic per-file claim (so different files/webhooks never
contend), a shared bounded semaphore (so total in-flight work stays capped
regardless of how many files/rows are involved), and per-row failure
isolation (so one bad row in a big CSV no longer silently drops every row
after it).
"""

from __future__ import annotations

import asyncio
import importlib.util
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest


class _DummyProducer:
    async def publish(self, *_args, **_kwargs) -> None:
        return None


def load_monitoring_app_module(name: str = "monitoring_adapter_app_ingest_concurrency"):
    module_path = Path("backend/src/monitoring-adapter/app.py")
    spec = importlib.util.spec_from_file_location(name, module_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def monitoring_app(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("LANDING_PAD_INPUT_DIR", str(tmp_path / "input"))
    module = load_monitoring_app_module()
    module.LANDING_PAD_INPUT_DIR = tmp_path / "input"
    module.LANDING_PAD_PROCESSED_DIR = tmp_path / "processed"
    module.LANDING_PAD_FAILED_DIR = tmp_path / "failed"
    module.LANDING_PAD_INPUT_REPLAYED_DIR = tmp_path / "input_replayed"
    module.LANDING_PAD_INPUT_FAILED_DIR = tmp_path / "input_failed"
    module.LANDING_PAD_ADDITIONAL_INPUT_DIRS = []
    module.app.state.producer = _DummyProducer()
    return module


def _write_csv(path: Path, service_names: list[str]) -> None:
    header = '"Issue ID","Service","Alert Name","Severity","Environment"'
    rows = "\n".join(
        f'"KAI-{index}","{service}","Alert {index}","High","Production"'
        for index, service in enumerate(service_names, start=1)
    )
    path.write_text(f"{header}\n{rows}\n", encoding="utf-8")


async def test_claim_race_exactly_one_winner(monitoring_app, tmp_path: Path) -> None:
    module = monitoring_app
    source = tmp_path / "incoming.json"
    source.write_text("{}", encoding="utf-8")

    results = await asyncio.gather(*(module._claim_landing_pad_input_file(source) for _ in range(20)))
    winners = [r for r in results if r is not None]

    assert len(winners) == 1
    claimed_path, original_parent = winners[0]
    assert claimed_path.is_file()
    assert original_parent == tmp_path
    assert not source.exists()


async def test_bad_row_does_not_block_siblings(monitoring_app, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    module = monitoring_app
    csv_path = tmp_path / "tickets.csv"
    _write_csv(csv_path, [f"svc-{i}" for i in range(1, 6)])

    original_publish = module._publish_ingested_alert

    async def flaky_publish(alert):
        if alert.service == "svc-3":
            raise RuntimeError("simulated publish failure")
        await original_publish(alert)

    monkeypatch.setattr(module, "_publish_ingested_alert", flaky_publish)

    claimed = await module._claim_landing_pad_input_file(csv_path)
    assert claimed is not None
    claimed_path, original_parent = claimed
    result = await module._process_landing_pad_input_file_unlocked(claimed_path, original_parent=original_parent)

    assert result["status"] == "processed_partial"
    assert result["row_count"] == 5
    assert len(result["row_failures"]) == 1
    assert len(result["alerts"]) == 4
    assert Path(result["archived_path"]).is_relative_to(module.LANDING_PAD_INPUT_REPLAYED_DIR)

    processed_files = list(module.LANDING_PAD_PROCESSED_DIR.rglob("*.json"))
    failed_files = list(module.LANDING_PAD_FAILED_DIR.rglob("*.json"))
    assert len(processed_files) == 4
    assert len(failed_files) == 1


async def test_all_rows_fail_archives_to_input_failed(monitoring_app, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    module = monitoring_app
    csv_path = tmp_path / "tickets.csv"
    _write_csv(csv_path, ["svc-1", "svc-2"])

    async def always_fail(_alert):
        raise RuntimeError("simulated publish failure")

    monkeypatch.setattr(module, "_publish_ingested_alert", always_fail)

    claimed = await module._claim_landing_pad_input_file(csv_path)
    assert claimed is not None
    claimed_path, original_parent = claimed
    result = await module._process_landing_pad_input_file_unlocked(claimed_path, original_parent=original_parent)

    assert result["status"] == "failed_all_rows"
    assert result["alerts"] == []
    assert len(result["row_failures"]) == 2
    assert Path(result["archived_path"]).is_relative_to(module.LANDING_PAD_INPUT_FAILED_DIR)


def test_stale_claim_is_recovered_fresh_claim_is_not(monitoring_app) -> None:
    module = monitoring_app
    claim_dir = module.LANDING_PAD_INPUT_DIR / ".claiming"
    claim_dir.mkdir(parents=True, exist_ok=True)

    stale = claim_dir / "abcd1234_old-alert.json"
    stale.write_text("{}", encoding="utf-8")
    stale_time = (datetime.now(timezone.utc) - timedelta(minutes=module.LANDING_PAD_CLAIM_STALE_MINUTES + 5)).timestamp()
    os.utime(stale, (stale_time, stale_time))

    fresh = claim_dir / "ef567890_fresh-alert.json"
    fresh.write_text("{}", encoding="utf-8")

    recovered = module._recover_stale_claims()

    assert recovered == 1
    assert not stale.exists()
    assert (module.LANDING_PAD_INPUT_DIR / "old-alert.json").is_file()
    assert fresh.is_file()  # untouched: not old enough to be recovered


async def test_semaphore_bounds_global_concurrency_across_files(monitoring_app, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    module = monitoring_app
    module._LANDING_PAD_INGEST_SEMAPHORE = asyncio.Semaphore(5)

    concurrency = {"current": 0, "max": 0}
    tracker_lock = asyncio.Lock()

    async def tracked_publish(_alert):
        async with tracker_lock:
            concurrency["current"] += 1
            concurrency["max"] = max(concurrency["max"], concurrency["current"])
        await asyncio.sleep(0.02)
        async with tracker_lock:
            concurrency["current"] -= 1

    monkeypatch.setattr(module, "_publish_ingested_alert", tracked_publish)

    paths = []
    for file_index in range(3):
        csv_path = tmp_path / f"tickets-{file_index}.csv"
        _write_csv(csv_path, [f"svc-{file_index}-{i}" for i in range(8)])
        paths.append(csv_path)

    await asyncio.gather(*(module._process_landing_pad_input_file(path) for path in paths))

    assert concurrency["max"] <= 5
    assert concurrency["max"] > 1


async def test_alertmanager_webhook_parallel_path_matches_sequential_semantics(monitoring_app, monkeypatch: pytest.MonkeyPatch) -> None:
    module = monitoring_app
    original_write = module._write_alert_to_landing_pad_input

    def flaky_write(mapped_payload, raw_alert):
        if mapped_payload.get("service") == "svc-3":
            raise RuntimeError("simulated disk failure")
        return original_write(mapped_payload, raw_alert)

    monkeypatch.setattr(module, "_write_alert_to_landing_pad_input", flaky_write)

    payload = {
        "status": "firing",
        "commonLabels": {},
        "commonAnnotations": {},
        "alerts": [
            {
                "status": "firing",
                # Exercise admitted investigation work; warnings intentionally
                # remain live-alert observations without entering this path.
                "labels": {"alertname": f"Alert{i}", "service": f"svc-{i}", "severity": "high"},
                "annotations": {"summary": f"summary {i}"},
                "fingerprint": f"fp-{i}",
            }
            for i in range(1, 6)
        ]
        + [
            {"status": "resolved", "labels": {"alertname": "ResolvedAlert", "service": "svc-resolved"}, "annotations": {}},
            "not-a-dict",
        ],
    }

    response = await module.ingest_alertmanager_webhook(payload=payload)

    assert response["received"] == 7
    assert response["ingested"] == 4
    assert response["observed"] == 1
    assert response["skipped"] == 2
    assert len(response["alerts"]) == 4
    assert response["observed_rows"][0]["status"] == "resolved"
    assert response["observed_rows"][0]["investigation_started"] is False
    assert any(
        row.get("name") == "ResolvedAlert" and row.get("alert_status") == "resolved"
        for row in module.RECENT_INGESTION_EVENTS
    )
    reasons = [str(row.get("reason")) for row in response["skipped_rows"]]
    assert any("landing pad ingestion failed" in reason for reason in reasons)
    assert any(reason == "non-object alert item" for reason in reasons)


@pytest.mark.parametrize("marker", [{"synthetic": "true"}, {"synthetic": "1"}, {"event_authenticity": "synthetic"}, {"event_mode": "simulation"}])
async def test_alertmanager_quarantines_synthetic_signals_before_investigation(monitoring_app, monkeypatch, marker):
    monkeypatch.setattr(monitoring_app, "_claim_alertmanager_delivery", lambda key: True)
    result = await monitoring_app.ingest_alertmanager_webhook(payload={"alerts": [{
        "status": "firing", "labels": {"alertname": "ServiceDown", "service": "fault-lab", "severity": "critical", **marker},
    }]})
    assert result["ingested"] == 0
    assert result["skipped_rows"][0]["authenticity"] == "synthetic"
    assert not list(monitoring_app.LANDING_PAD_INPUT_DIR.glob("*.json"))
