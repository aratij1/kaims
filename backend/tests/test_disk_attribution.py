import importlib.util
import json
from pathlib import Path

import pytest

from common.disk_attribution import search_disk_observations, seal

ROOT = Path(__file__).parents[2]
spec = importlib.util.spec_from_file_location("host_disk_collector", ROOT / "scripts/disk_attribution.py")
collector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collector)


@pytest.fixture
def snapshot(tmp_path):
    scope = {"tenant_id": "t", "environment": "prod", "host_id": "host-a",
             "instance": "node:9100", "device": "D:", "mountpoint": "/mnt/host/d"}
    payload = {"schema": "kaiops.disk-attribution.v1", "scope": scope,
        "window_start": "2026-10-17T10:00:00Z", "window_end": "2026-10-17T10:00:10Z",
        "coverage": {"events_lost": "unknown"}, "records": [{"observed_at": "2026-10-17T10:00:05Z",
            "pid": 42, "path": "disk.vhdx", "observation_kind": "kernel_file_write_request"}]}
    path = tmp_path / "disk-20261017.json"
    path.write_text(json.dumps(seal(payload)), encoding="utf-8")
    arguments = {"tenant_id": "t", "environment": "prod", "service": "node-exporter",
        "target_labels": {k: scope[k] for k in ("instance", "device", "mountpoint")},
        "start_time": "2026-10-17T09:59:00Z", "end_time": "2026-10-17T10:01:00Z"}
    return tmp_path, path, payload, arguments


def test_exact_source_event_is_cited_without_promoting_cause(snapshot):
    root, _, _, arguments = snapshot
    result = search_disk_observations(root, arguments)
    row, = result["evidence"]
    assert row["pid"] == 42
    assert row["causal_claim"] == "not_established"
    assert row["observed_at"] == "2026-10-17T10:00:05Z"
    assert "sha256=" in row["source_reference"]
    assert row["coverage"]["events_lost"] == "unknown"


@pytest.mark.parametrize("field", ["tenant_id", "environment", "instance", "device", "mountpoint"])
def test_does_not_cross_target_or_tenant(snapshot, field):
    root, _, _, arguments = snapshot
    (arguments if field in ("tenant_id", "environment") else arguments["target_labels"])[field] = "different"
    assert not search_disk_observations(root, arguments)["evidence"]


def test_no_historical_backfill_from_present_measurements(snapshot):
    root, _, _, arguments = snapshot
    arguments.update(start_time="2026-10-16T09:00:00Z", end_time="2026-10-16T11:00:00Z")
    assert search_disk_observations(root, arguments)["provider_status"] == "no_matching_history"


def test_checksum_tampering_is_rejected(snapshot):
    root, path, _, arguments = snapshot
    changed = json.loads(path.read_text()); changed["records"][0]["pid"] = 666
    path.write_text(json.dumps(changed))
    result = search_disk_observations(root, arguments)
    assert not result["evidence"] and result["rejected"] == 1


@pytest.mark.parametrize("field", ["start_time", "end_time"])
def test_missing_or_naive_time_is_not_current_evidence(snapshot, field):
    root, _, _, arguments = snapshot
    arguments[field] = "2026-10-17T10:00:00"
    assert search_disk_observations(root, arguments)["provider_status"] == "observation_window_required"


def test_collector_retention_does_not_remove_other_files(tmp_path):
    (tmp_path / "operator-notes.json").write_text("keep")
    for i in range(125):
        (tmp_path / f"disk-20261016T{i:06}.json").write_text("{}")
    collector.save(tmp_path, {"records": []})
    assert len(list(tmp_path.glob("disk-*.json"))) == 120
    assert (tmp_path / "operator-notes.json").read_text() == "keep"


def test_windows_file_object_reuse_does_not_attribute_next_file():
    def event(event_id, **data):
        return {"event_id": event_id, "pid": 20, "observed_at": "2026-10-17T10:00:05Z", "data": data}
    events = [event(12, FileObject="0x1", OpenPath="\\Device\\HarddiskVolume4\\a.log"),
              event(16, FileObject="0x1", IoSize="4096"), event(14, FileObject="0x1"),
              event(16, FileObject="0x1", IoSize="8192")]
    rows, unresolved = collector.windows_records(events, {"native_volume": "\\Device\\HarddiskVolume4"}, {})
    assert unresolved == 1
    row, = rows
    assert row["requested_write_bytes"] == 4096
    assert not row["allocation_growth_proven"]
    assert row["causal_claim"] == "not_established"


def test_windows_same_prefix_different_volume_is_excluded():
    event = {"event_id": 16, "pid": 20, "observed_at": "2026-10-17T10:00:05Z",
             "data": {"FileName": "\\Device\\HarddiskVolume40\\data", "IoSize": "1024"}}
    assert not collector.windows_records([event], {"native_volume": "\\Device\\HarddiskVolume4"}, {})[0]


def test_windows_manifest_uppercase_size_and_filekey_name_are_supported():
    events = [{"event_id": 10, "pid": 4, "observed_at": "2026-10-17T10:00:04Z",
               "data": {"FileKey": "0x2", "FileName": "\\Device\\HarddiskVolume4\\data"}},
              {"event_id": 16, "pid": 30, "observed_at": "2026-10-17T10:00:05Z",
               "data": {"FileObject": "0x1", "FileKey": "0x2", "IOSize": "0x1000"}}]
    row, = collector.windows_records(events, {"native_volume": "\\Device\\HarddiskVolume4"}, {})[0]
    assert row["requested_write_bytes"] == 4096 and row["pid"] == 30
    assert "process" not in row


def test_windows_async_context_cannot_be_misattributed_to_header_process():
    event = {"event_id": 16, "pid": 4, "header_tid": 10, "observed_at": "2026-10-17T10:00:05Z",
             "data": {"FileName": "\\Device\\HarddiskVolume4\\data", "IssuingThreadId": "20", "IOSize": "1024"}}
    rows, unresolved = collector.windows_records([event], {"native_volume": "\\Device\\HarddiskVolume4"}, {})
    assert not rows and unresolved == 1


def test_windows_rundown_resolves_a_file_opened_before_capture():
    event = {"event_id": 16, "pid": 4, "header_tid": 10, "observed_at": "2026-10-17T10:00:05Z",
             "data": {"FileKey": "0xAB", "IssuingThreadId": "10", "IOSize": "4096"}}
    rows, unresolved = collector.windows_records([event], {"native_volume": "\\Device\\HarddiskVolume4"}, {},
        {"0xab": "\\Device\\HarddiskVolume4\\docker_data.vhdx"})
    assert unresolved == 0
    row, = rows
    assert row["path"].endswith("docker_data.vhdx") and row["requested_write_bytes"] == 4096


def test_linux_holders_are_not_promoted_to_writers_and_pids_cannot_be_reused():
    base = {"files": {"1:2": {"allocated_bytes": 4096}},
            "processes": {20: {"start_ticks": "1", "write_bytes": 100}}}
    after = {"observed_at": "2026-10-17T10:00:05Z", "files": {"1:2": {
        "allocated_bytes": 8192, "deleted": False, "holders": [20]}},
        "processes": {20: {"start_ticks": "2", "write_bytes": 1000}}}
    row, = collector.linux_records(base, after)
    assert row["allocated_bytes_delta"] == 4096
    assert row["holders"] == []
    assert row["writer_attribution"] == "not_established"


def test_linux_deleted_open_file_is_reported_even_without_growth():
    after = {"observed_at": "2026-10-17T10:00:05Z", "files": {"1:2": {
        "allocated_bytes": 8192, "deleted": True, "holders": []}}, "processes": {}}
    row, = collector.linux_records({"files": {}, "processes": {}}, after)
    assert row["observation_kind"] == "deleted_open_file"
    assert row["allocated_bytes_delta"] is None


def test_missing_linux_task_io_accounting_is_unknown_not_zero():
    process = {"pid": 20, "start_ticks": "1", "write_bytes": None}
    before = {"files": {"1:2": {"allocated_bytes": 4096}}, "processes": {20: process}}
    after = {"observed_at": "2026-10-17T10:00:05Z", "files": {"1:2": {
        "allocated_bytes": 8192, "deleted": False, "holders": [20]}}, "processes": {20: process}}
    row, = collector.linux_records(before, after)
    assert row["holders"][0]["write_bytes_delta"] is None


def test_disk_observation_survives_canonical_evidence_admission(snapshot):
    from datetime import UTC, datetime
    from common.context_enrichment_contract import EvidenceRequirement, normalize_connector_response
    from common.models import Incident
    from uuid import uuid4
    root, _, _, arguments = snapshot
    incident = Incident(tenant_id="t", service="node-exporter", title="Disk growth")
    now = datetime(2026, 10, 17, 10, 0, 20, tzinfo=UTC)
    requirement = EvidenceRequirement(requirement_id=uuid4(), tenant_id="t", incident_id=incident.id,
        rca_version=1, category="logs", question="Which process wrote to the affected disk?",
        reason="Determine the storage consumer", priority="high", collection_mode="automatic",
        candidate_connectors=["discovery-mcp"], created_at=now, updated_at=now)
    result = normalize_connector_response(raw_response=search_disk_observations(root, arguments),
        requirement=requirement, incident=incident, connector="discovery-mcp", collected_at=now)
    assert not result.rejected
    record, = result.records
    assert record.content["pid"] == 42
    assert record.content["causal_claim"] == "not_established"
    assert record.source_reference.startswith("host-disk://")


@pytest.mark.asyncio
async def test_disk_evidence_reaches_logs_discovery_before_exporter_logs(snapshot, monkeypatch):
    root, _, _, arguments = snapshot
    spec = importlib.util.spec_from_file_location("discovery_disk_test", ROOT / "backend/src/discovery-mcp/app.py")
    discovery = importlib.util.module_from_spec(spec); spec.loader.exec_module(discovery)
    monkeypatch.setenv("DISCOVERY_MCP_DISK_OBSERVATIONS_ROOT", str(root))
    monkeypatch.setattr(discovery, "_search_text_files", lambda *a: [])
    async def logs(*a):
        return [{"uri": "docker://exporter", "source": "log", "snippet": "exporter started"}]
    monkeypatch.setattr(discovery, "_search_docker_logs", logs)
    result = await discovery._call_logs_tool(arguments)
    assert result["evidence"][0]["source"] == "host_disk"
    assert result["sources"]["host_disk"] == 1
