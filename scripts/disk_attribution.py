"""Host-side bounded collector. No file contents, command lines, or cleanup actions.

Windows: consume manifest ETW metadata captured by collect-disk-attribution.ps1.
Linux: native fanotify modification events identify the kernel-observed process
and inode. If unavailable, /proc sampling never claims a holder is the writer.
Run on the monitored host, not an ordinary application container.
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import stat
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend/src/common"))
from common.disk_attribution import seal


def utc():
    return datetime.now(UTC).isoformat()


def linux_snapshot(mount: str, *, proc: Path = Path("/proc"), max_processes=2048, max_fds=8192):
    """Use device identity, not a path-prefix guess across namespaces/bind mounts."""
    started = time.monotonic()
    device = os.stat(mount).st_dev
    files, processes, denied, fds, truncated = {}, {}, 0, 0, False
    with os.scandir(proc) as entries:
        for entry in entries:
            if not entry.name.isdigit():
                continue
            if len(processes) >= max_processes or fds >= max_fds or time.monotonic() - started > 3:
                truncated = True
                break
            pid = int(entry.name)
            base = Path(entry.path)
            try:
                raw = (base / "stat").read_text()
                # comm may contain spaces and parentheses; field 22 is starttime.
                identity = raw[raw.rfind(")") + 2:].split()[19]
                try:
                    io = dict(line.split(":", 1) for line in (base / "io").read_text().splitlines())
                except OSError:
                    # CONFIG_TASK_IO_ACCOUNTING may be disabled (including WSL).
                    # Inode allocation/open-file evidence is still available.
                    io = {}
                processes[pid] = {"pid": pid, "start_ticks": identity,
                    "name": (base / "comm").read_text().strip()[:128],
                    "write_bytes": int(io["write_bytes"]) if "write_bytes" in io else None,
                    "cancelled_write_bytes": int(io["cancelled_write_bytes"]) if "cancelled_write_bytes" in io else None}
                with os.scandir(base / "fd") as descriptors:
                    for descriptor in descriptors:
                        fds += 1
                        if fds > max_fds or time.monotonic() - started > 3:
                            truncated = True
                            break
                        try:
                            st = os.stat(descriptor.path)
                            if st.st_dev != device or not stat.S_ISREG(st.st_mode):
                                continue
                            key = f"{st.st_dev}:{st.st_ino}"
                            item = files.setdefault(key, {"identity": key, "path": os.readlink(descriptor.path)[:1024],
                                "size_bytes": st.st_size, "allocated_bytes": st.st_blocks * 512,
                                "deleted": st.st_nlink == 0, "holders": []})
                            if pid not in item["holders"] and len(item["holders"]) < 16:
                                item["holders"].append(pid)
                        except OSError:
                            denied += 1
                final_stat = (base / "stat").read_text()
                if final_stat[final_stat.rfind(")") + 2:].split()[19] != identity:
                    processes.pop(pid, None)  # PID reused/exited while sampled.
            except (OSError, ValueError, IndexError):
                denied += 1
    return {"observed_at": utc(), "files": files, "processes": processes,
            "coverage": {"denied_or_exited": denied, "truncated": truncated, "descriptors_scanned": fds}}


def linux_records(before, after):
    records = []
    for key, item in after["files"].items():
        old = before["files"].get(key)
        delta = item["allocated_bytes"] - old["allocated_bytes"] if old else None
        if not item["deleted"] and not (delta and delta > 0):
            continue
        holders = []
        for pid in item["holders"]:
            current, previous = after["processes"].get(pid), before["processes"].get(pid)
            if not current or not previous or current["start_ticks"] != previous["start_ticks"]:
                continue
            counter_delta = (max(0, current["write_bytes"] - previous["write_bytes"])
                             if current["write_bytes"] is not None and previous["write_bytes"] is not None else None)
            holders.append({**current, "write_bytes_delta": counter_delta,
                            "counter_scope": "all_filesystems_not_this_file"})
        records.append({**item, "observed_at": after["observed_at"], "holders": holders,
            "allocated_bytes_delta": delta, "observation_kind": "deleted_open_file" if item["deleted"] else "open_file_allocation_growth",
            "writer_attribution": "not_established", "causal_claim": "not_established"})
    return sorted(records, key=lambda r: r.get("allocated_bytes_delta") or r["allocated_bytes"], reverse=True)[:100]


def windows_records(events, scope, processes, seed_names=None):
    """ETW manifest event IDs, names and writer PID come from source events.

    Keep request semantics: FileIo/Write reports requested bytes, not successful
    allocation or a proven cause. Do not infer ownership from block-I/O flushes.
    """
    names = {str(key).casefold(): str(value) for key, value in list((seed_names or {}).items())[:2048]}
    rows = {}
    unresolved = 0
    for event in events:
        data = {str(key).casefold(): value for key, value in (event.get("data") or {}).items()}
        event_id = int(event.get("event_id", 0))
        objects = [str(data[key]).casefold() for key in ("fileobject", "filekey") if data.get(key)]
        filename = str(data.get("filename") or data.get("openpath") or "")
        if filename and len(names) < 32768:
            for obj in objects:
                names[obj] = filename
        if event_id in (11, 14):  # name deletion/close: pointers can be reused
            for obj in objects:
                names.pop(obj, None)
            continue
        if event_id != 16:
            continue
        filename = filename or next((names[obj] for obj in objects if obj in names), "")
        # Native device paths have an exact QueryDosDevice-derived volume prefix.
        prefix = scope["native_volume"].rstrip("\\") + "\\"
        if not filename.casefold().startswith(prefix.casefold()):
            unresolved += not bool(filename)
            continue
        pid = int(event.get("pid", 0))
        issuing_thread = data.get("issuingthreadid") or data.get("ttid")
        if issuing_thread is not None and event.get("header_tid") is not None:
            value = str(issuing_thread)
            if int(value, 16 if value.lower().startswith("0x") else 10) != int(event["header_tid"]):
                unresolved += 1
                continue  # Asynchronous context: header PID cannot identify the issuer.
        if pid <= 0 or pid == 4294967295:
            unresolved += 1
            continue
        key = (pid, filename)
        if key not in rows and len(rows) >= 2048:
            unresolved += 1
            continue
        row = rows.setdefault(key, {"pid": pid, "path": filename[:1024], "requested_write_bytes": 0,
            "write_requests": 0, "first_observed_at": event["observed_at"], "observed_at": event["observed_at"],
            "observation_kind": "kernel_file_write_request", "writer_attribution": "kernel_event_pid",
            "allocation_growth_proven": False, "causal_claim": "not_established"})
        size = str(data.get("iosize") or "0")
        row["requested_write_bytes"] += int(size, 16 if size.lower().startswith("0x") else 10)
        row["write_requests"] += 1
        row["observed_at"] = event["observed_at"]
        # Only attach a name when both snapshots agree on process start identity.
        identity = processes.get(str(pid)) or {}
        if identity.get("stable_identity"):
            row["process"] = identity
    return sorted(rows.values(), key=lambda r: r["requested_write_bytes"], reverse=True)[:100], unresolved


def save(root: Path, payload: dict):
    root.mkdir(parents=True, exist_ok=True)
    path = root / ("disk-" + datetime.now(UTC).strftime("%Y%m%dT%H%M%S%f") + ".json")
    raw = json.dumps(seal(payload), ensure_ascii=False, separators=(",", ":"))
    if len(raw.encode()) > 512_000:
        raise ValueError("snapshot size limit exceeded")
    temporary = path.with_suffix(".tmp")
    temporary.write_text(raw, encoding="utf-8")
    temporary.replace(path)
    # Only this collector's fixed-pattern regular files in its resolved directory.
    for old in sorted(root.glob("disk-*.json"), reverse=True)[120:]:
        if not old.is_symlink() and old.resolve().parent == root.resolve():
            old.unlink()
    return path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--windows-input", type=Path)
    parser.add_argument("--backend", choices=("auto", "procfs", "fanotify"), default="auto")
    parser.add_argument("--interval", type=int, default=5, choices=range(1, 31))
    args = parser.parse_args()
    scope = json.loads(args.config.read_text(encoding="utf-8-sig"))
    for key in ("tenant_id", "environment", "host_id", "instance", "device", "mountpoint", "host_mount"):
        if not scope.get(key):
            raise ValueError(f"missing registered scope: {key}")
    if scope["host_id"].casefold() != socket.gethostname().casefold():
        raise ValueError("registered host does not match collector host")
    if args.windows_input:
        raw = json.loads(args.windows_input.read_text(encoding="utf-8-sig"))
        records, unresolved = windows_records(raw["events"], scope, raw.get("processes") or {}, raw.get("file_names"))
        begin, end = raw["window_start"], raw["window_end"]
        coverage = {**raw.get("coverage", {}), "unresolved_write_events": unresolved,
                    "historical_before_collector_start": False}
        source = "windows_etw"
        volume = raw.get("volume") or {}
        for row in records:
            measurements = (raw.get("tracked_files") or {}).get(row["path"].casefold())
            if measurements:
                row["file_measurements"] = measurements
        for path, measurements in list((raw.get("tracked_files") or {}).items())[:32]:
            records.append({"observation_kind": "tracked_file_allocation", "path": path,
                "observed_at": end, "file_measurements": measurements,
                "writer_attribution": "not_established", "causal_claim": "not_established"})
    else:
        if sys.platform != "linux":
            raise ValueError("Windows requires the ETW capture script")
        volume_before = os.statvfs(scope["host_mount"])
        kernel_error = None
        source = "linux_fanotify"
        if args.backend != "procfs":
            try:
                from disk_fanotify import observe
                records, begin, end, coverage = observe(scope["host_mount"], args.interval)
            except (OSError, AttributeError) as exc:
                if args.backend == "fanotify":
                    raise
                kernel_error = str(exc)
        if args.backend == "procfs" or kernel_error:
            before = linux_snapshot(scope["host_mount"])
            time.sleep(args.interval)
            after = linux_snapshot(scope["host_mount"])
            records = linux_records(before, after)
            begin, end = before["observed_at"], after["observed_at"]
            coverage = {"before": before["coverage"], "after": after["coverage"],
                        "writer_collection": "unavailable", "writer_collection_error": kernel_error,
                        "short_lived_or_closed_files": "not_covered", "historical_before_collector_start": False}
            source = "linux_procfs"
        volume_after = os.statvfs(scope["host_mount"])
        volume = {"available_before": volume_before.f_bavail * volume_before.f_frsize,
                  "available_after": volume_after.f_bavail * volume_after.f_frsize}
    if volume:
        records.append({"observation_kind": "volume_capacity", "observed_at": end,
                        "measurements": volume, "causal_claim": "not_established"})
    path = save(args.output, {"schema": "kaiops.disk-attribution.v1", "scope": scope,
        "window_start": begin, "window_end": end, "source": source,
        "coverage": coverage, "volume": volume, "records": records})
    print(json.dumps({"path": str(path), "records": len(records), "coverage": coverage}))


if __name__ == "__main__":
    main()
