"""Linux native modification attribution; no BCC installation or file contents.

Run in the monitored host PID/mount namespace with fanotify permission. A kernel
modification event identifies its process and inode, but is not an exact write
byte count, full coverage (mmap is excluded), or proof of an incident's cause.
"""
import ctypes
import os
import select
import stat
import struct
import time
from datetime import UTC, datetime


def observe(mount, seconds, *, ready=None):
    native = ctypes.CDLL(None, use_errno=True)
    native.fanotify_init.argtypes = [ctypes.c_uint, ctypes.c_uint]
    native.fanotify_init.restype = ctypes.c_int
    native.fanotify_mark.argtypes = [ctypes.c_int, ctypes.c_uint, ctypes.c_uint64, ctypes.c_int, ctypes.c_char_p]
    native.fanotify_mark.restype = ctypes.c_int
    # CLOEXEC|NONBLOCK, notification-only; opened event FDs are read-only.
    handle = native.fanotify_init(3, os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_LARGEFILE", 0))
    if handle < 0:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code))
    rows, count, overflow, truncated = {}, 0, False, False
    device = os.stat(mount).st_dev
    begin = datetime.now(UTC).isoformat()
    try:
        # ADD|FILESYSTEM, MODIFY only. CLOSE_WRITE alone does not prove a write.
        if native.fanotify_mark(handle, 0x101, 0x2, -100, os.fsencode(mount)):
            code = ctypes.get_errno()
            raise OSError(code, os.strerror(code))
        if ready:
            ready()
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline and count < 8192:
            if not select.select([handle], [], [], max(0, deadline - time.monotonic()))[0]:
                break
            data = os.read(handle, 65536)
            offset = 0
            while offset + 24 <= len(data):
                length, version, _, metadata_length, mask, event_fd, pid = struct.unpack_from("=IBBHQii", data, offset)
                if length < 24 or offset + length > len(data) or version != 3 or metadata_length < 24:
                    raise ValueError("Unsupported or truncated fanotify metadata")
                offset += length
                count += 1
                if mask & 0x4000:
                    overflow = True
                if event_fd < 0:
                    continue
                try:
                    value = os.fstat(event_fd)
                    if not mask & 0x2 or value.st_dev != device or not stat.S_ISREG(value.st_mode):
                        continue
                    key = (pid, value.st_dev, value.st_ino)
                    if key not in rows and len(rows) >= 2048:
                        truncated = True
                        continue
                    now = datetime.now(UTC).isoformat()
                    item = rows.setdefault(key, {"pid": pid, "device_id": value.st_dev, "inode": value.st_ino,
                        "path": os.readlink(f"/proc/self/fd/{event_fd}")[:1024],
                        "first_allocated_bytes": value.st_blocks * 512,
                        "first_observed_at": now, "modification_notifications": 0,
                        "observation_kind": "kernel_filesystem_modification",
                        "writer_attribution": "kernel_modifying_process_pid",
                        "process_identity": "kernel_event_pid_only_name_not_inferred",
                        "causal_claim": "not_established"})
                    item.update(observed_at=now, allocated_bytes=value.st_blocks * 512,
                                size_bytes=value.st_size, deleted=value.st_nlink == 0)
                    item["modification_notifications"] += 1
                    item["allocated_bytes_delta_since_first_event"] = value.st_blocks * 512 - item["first_allocated_bytes"]
                finally:
                    os.close(event_fd)
        end = datetime.now(UTC).isoformat()
    finally:
        os.close(handle)  # Removes marks and queued event FDs, including exceptions.
    return sorted(rows.values(), key=lambda r: r["allocated_bytes"], reverse=True)[:80], begin, end, {
        "writer_collection": "enabled", "backend": "fanotify", "queue_overflow": overflow,
        "event_limit_reached": count >= 8192, "record_limit_reached": truncated,
        "events_received": count, "timestamp_semantics": "receipt_time",
        "write_bytes": "not_measured", "mmap_and_msync": "not_covered",
        "historical_before_collector_start": False}
