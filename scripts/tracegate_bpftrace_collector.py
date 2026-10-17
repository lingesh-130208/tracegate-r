#!/usr/bin/env python3
"""TraceGate-R targeted eBPF runtime collector for LinuxONE/s390x.

Collects real syscall events using bpftrace and current-process TCP sockets by
matching /proc/<pid>/fd socket inodes to /proc/<pid>/net/tcp{,6}. It submits one
snapshot per run to the local TraceGate-R API. Unmeasured feature values remain
None. The event is intentionally review-gated because parity with the QUT-DV25
feature-extraction pipeline is not yet independently validated, and package
installation dependency features are unavailable for an arbitrary PID.

Paths observed by openat/openat2 probes are classified in memory only; raw paths
are never sent to the API or written to disk.
"""
from __future__ import annotations

import argparse
import collections
import ipaddress
import json
import os
import posixpath
try:
    import pwd  # POSIX account database; unavailable on Windows.
except ImportError:  # Keep the pure parsing/unit-test module importable on Windows.
    pwd = None  # type: ignore[assignment]
import queue
import re
import signal
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Iterable

API_DEFAULT = "http://127.0.0.1:8001"
BPFTRACE = "/usr/bin/bpftrace"

# The groups are deliberately mutually exclusive: a syscall name has one
# primary group. Raw syscall events not in this selected, documented set are
# included in the miscellaneous total, not dropped from the total count.
SYSCALL_GROUPS: dict[str, set[str]] = {
    "io": {
        "read", "readv", "pread64", "preadv", "preadv2", "write", "writev",
        "pwrite64", "pwritev", "pwritev2", "ioctl", "poll", "ppoll", "select",
        "pselect6", "epoll_wait", "epoll_pwait", "epoll_pwait2", "sendfile",
        "splice", "copy_file_range", "fsync", "fdatasync", "sync", "syncfs",
        "sync_file_range", "lseek", "llseek",
    },
    "file": {
        "open", "openat", "openat2", "creat", "close", "close_range", "unlink",
        "unlinkat", "rename", "renameat", "renameat2", "mkdir", "mkdirat", "rmdir",
        "link", "linkat", "symlink", "symlinkat", "mknod", "mknodat", "truncate",
        "ftruncate", "fallocate", "chmod", "fchmod", "fchmodat", "chown", "fchown",
        "fchownat", "lchown", "utimensat", "dup", "dup2", "dup3", "fcntl",
    },
    "memory": {
        "mmap", "mmap2", "munmap", "mprotect", "mremap", "brk", "madvise",
        "mlock", "munlock", "mlockall", "munlockall", "mincore", "process_madvise",
    },
    "network": {
        "socket", "connect", "accept", "accept4", "bind", "listen", "shutdown",
        "sendto", "recvfrom", "sendmsg", "recvmsg", "sendmmsg", "recvmmsg",
        "getsockopt", "setsockopt", "getpeername", "getsockname",
    },
    "process_management": {
        "clone", "clone3", "fork", "vfork", "execve", "execveat", "wait4", "waitid",
        "exit", "exit_group", "kill", "tkill", "tgkill", "pidfd_open",
        "pidfd_send_signal", "pidfd_getfd",
    },
    "time": {
        "clock_gettime", "clock_getres", "gettimeofday", "time", "nanosleep",
        "clock_nanosleep", "timer_create", "timer_settime", "timer_delete",
        "timerfd_create", "timerfd_settime", "getitimer", "setitimer", "times", "alarm",
        "sched_yield",
    },
    "ipc": {
        "pipe", "pipe2", "eventfd", "eventfd2", "futex", "futex_waitv", "mq_open",
        "mq_unlink", "mq_timedsend", "mq_timedreceive", "msgget", "msgsnd", "msgrcv",
        "semget", "semop", "semtimedop", "shmget", "shmat", "shmdt", "memfd_create",
        "socketpair",
    },
    "filesystem": {
        "stat", "lstat", "newfstatat", "statx", "access", "faccessat", "faccessat2",
        "getdents", "getdents64", "statfs", "fstatfs", "getcwd", "chdir", "fchdir",
        "readlink", "readlinkat",
    },
    "security": {
        "getuid", "geteuid", "getgid", "getegid", "setuid", "setgid", "setreuid",
        "setregid", "setresuid", "setresgid", "setgroups", "setfsuid", "setfsgid",
        "capget", "capset", "prctl", "ptrace", "seccomp", "keyctl", "add_key",
        "request_key", "mount", "umount2", "pivot_root", "chroot", "setns", "unshare",
    },
}

FEATURE_GROUPS = {
    "io": ("SysCall__IO_Operations", "SysCall__Unique_IO_Operations"),
    "file": ("SysCall__File_Operations", "SysCall__Unique_File_Operations"),
    "memory": ("SysCall__Memory_Operations", "SysCall__Unique_Memory_Operations"),
    "network": ("SysCall__Network_Operations", "SysCall__Unique_Network_Operations"),
    "process_management": (
        "SysCall__Process_Management_Operations", "SysCall__Unique_Process_Management_Operations"
    ),
    "time": ("SysCall__Time_Operations", "SysCall__Unique_Time_Operations"),
    "ipc": ("SysCall__IPC_Operations", "SysCall__Unique_IPC_Operations"),
    "filesystem": ("SysCall__Filesystem_Operations", "SysCall__Unique_Filesystem_Operations"),
    "security": ("SysCall__Security_Operations", "SysCall__Unique_Security_Operations"),
}

DIRECTORY_FEATURES = {
    "root": "Opensnoop__Root_DIR_Installation",
    "temporary": "Opensnoop__Temporary_DIR_Installation",
    "home": "Opensnoop__Home_DIR_Installation",
    "user": "Opensnoop__User_Access",
    "sys": "Opensnoop__Sys_Access",
    "etc": "Opensnoop__Etc_DIR_Installation",
    "other": "Opensnoop__Other_DIR_Installation",
}

# Keyword matching is local only; paths themselves never leave the collector.
PYTHON_KEYWORDS = ("python", ".py", "site-packages", "dist-packages", "pyvenv")
INSTALL_KEYWORDS = (
    "pip", "wheel", ".whl", "site-packages", "dist-packages", "setup.py",
    "pyproject.toml", "pkg-info", "metadata", "conda",
)


def parse_io(text: str) -> dict[str, int]:
    result: dict[str, int] = {}
    for line in text.splitlines():
        k, sep, v = line.partition(":")
        if not sep:
            continue
        try:
            result[k.strip()] = int(v.strip())
        except ValueError:
            continue
    return result


def io_delta(before: dict[str, int], after: dict[str, int], key: str) -> int | None:
    if key not in before or key not in after:
        return None
    # A process restart/PID reuse is handled separately; counter reset is never
    # allowed to create negative activity.
    return max(0, after[key] - before[key])


def classify_path(path: str, home: str) -> str | None:
    """Classify a resolved absolute path; None means it couldn't be resolved."""
    if not path or not path.startswith("/"):
        return None
    p = posixpath.normpath(path)
    if p == "/root" or p.startswith("/root/"):
        return "root"
    if p == "/tmp" or p.startswith("/tmp/") or p == "/var/tmp" or p.startswith("/var/tmp/") or p == "/dev/shm" or p.startswith("/dev/shm/"):
        return "temporary"
    if p == "/home" or p.startswith("/home/") or (home and (p == home or p.startswith(home.rstrip("/") + "/"))):
        return "home"
    if p.startswith("/sys/") or p == "/sys":
        return "sys"
    if p.startswith("/etc/") or p == "/etc":
        return "etc"
    if p.startswith("/usr/lib/python") or p.startswith("/usr/local/lib/python"):
        return "user"
    return "other"


def resolve_open_path(pid: int, dfd: int, raw_path: str, cwd: str | None = None) -> str | None:
    raw_path = raw_path.strip("\x00\r\n")
    if not raw_path:
        return None
    if posixpath.isabs(raw_path):
        return posixpath.normpath(raw_path)
    if dfd == -100:  # AT_FDCWD
        base = cwd
        if base is None:
            try:
                base = os.readlink(f"/proc/{pid}/cwd")
            except OSError:
                return None
    else:
        try:
            base = os.readlink(f"/proc/{pid}/fd/{dfd}")
        except OSError:
            return None
    if not base or not posixpath.isabs(base):
        return None
    return posixpath.normpath(posixpath.join(base, raw_path))


def parse_proc_tcp_line(line: str, family: int) -> tuple[str, int, str, int, str, str] | None:
    """Parse a /proc/<pid>/net/tcp{,6} row to local/remote endpoint + state + inode."""
    cols = line.split()
    if len(cols) < 10 or cols[0].rstrip(":").isdecimal() is False:
        return None
    try:
        local_hex, local_port_hex = cols[1].split(":", 1)
        remote_hex, remote_port_hex = cols[2].split(":", 1)
        if family == 4:
            local_ip = str(ipaddress.IPv4Address(int(local_hex, 16).to_bytes(4, sys.byteorder)))
            remote_ip = str(ipaddress.IPv4Address(int(remote_hex, 16).to_bytes(4, sys.byteorder)))
        else:
            # procfs prints each 32-bit IPv6 word in native-endian hex.
            local_raw = b"".join(int(local_hex[i:i+8], 16).to_bytes(4, sys.byteorder) for i in range(0, 32, 8))
            remote_raw = b"".join(int(remote_hex[i:i+8], 16).to_bytes(4, sys.byteorder) for i in range(0, 32, 8))
            local_ip = str(ipaddress.IPv6Address(local_raw))
            remote_ip = str(ipaddress.IPv6Address(remote_raw))
        return local_ip, int(local_port_hex, 16), remote_ip, int(remote_port_hex, 16), cols[3], cols[9]
    except (ValueError, OverflowError):
        return None


def parse_socket_table(text: str, family: int, socket_inodes: set[str]) -> set[tuple[str, int, str, int, str]]:
    found: set[tuple[str, int, str, int, str]] = set()
    for line in text.splitlines()[1:]:
        row = parse_proc_tcp_line(line, family)
        if row and row[5] in socket_inodes:
            found.add((row[0], row[1], row[2], row[3], row[4]))
    return found


def bucket_paths(path_events: Iterable[tuple[int, str]], home: str) -> dict[str, int]:
    counts = {name: 0 for name in DIRECTORY_FEATURES}
    counts["total_paths"] = 0
    counts["python_keywords"] = 0
    counts["install_keywords"] = 0
    for _, path in path_events:
        counts["total_paths"] += 1
        if not path:
            continue
        low = path.casefold()
        if any(word in low for word in PYTHON_KEYWORDS):
            counts["python_keywords"] += 1
        if any(word in low for word in INSTALL_KEYWORDS):
            counts["install_keywords"] += 1
        bucket = classify_path(path, home)
        if bucket:
            counts[bucket] += 1
    return counts


def build_features(
    schema: list[str], io_before: dict[str, int], io_after: dict[str, int],
    fd_count: int | None, raw_count: int, raw_ids: set[int],
    syscall_counts: collections.Counter[str], path_events: list[tuple[int, str]],
    open_errors: int | None, tcp_rows: set[tuple[str, int, str, int, str]],
    python_related: bool, home: str, traced_probes: set[str],
    mapped_syscall_ids: set[int] | None = None,
) -> tuple[dict[str, int | None], set[str]]:
    features: dict[str, int | None] = {name: None for name in schema}
    available_groups: set[str] = set()
    def put(name: str, value: int | None) -> None:
        if name in features:
            features[name] = value
    # /proc/<pid>/io gives real read/write syscall counts over the sampling window.
    put("Filetop__Total_Reads", io_delta(io_before, io_after, "syscr"))
    put("Filetop__Total_Writes", io_delta(io_before, io_after, "syscw"))
    # rchar/wchar are byte counters, not the dataset's validated Filetop-derived
    # transfer feature units. Leave those model fields missing rather than mix units.

    pcount = bucket_paths(path_events, home)
    paths_instrumented = bool({"openat", "openat2"}.intersection(traced_probes))
    put("Opensnoop__Total_Paths", pcount["total_paths"] if paths_instrumented else None)
    put("Opensnoop__Total_Error", open_errors)
    put("Opensnoop__Total__File_Descriptor", fd_count)
    put("Opensnoop__Python_Related_Keywords", pcount["python_keywords"] if paths_instrumented else None)
    put("Opensnoop__Install_Package_Keywords", pcount["install_keywords"] if paths_instrumented else None)
    for bucket, feature in DIRECTORY_FEATURES.items():
        put(feature, pcount[bucket] if paths_instrumented else None)

    put("SysCall__Total_System_Calls", raw_count)
    put("SysCall__Unique_System_Calls", len(raw_ids))
    for group, (total_name, unique_name) in FEATURE_GROUPS.items():
        members = SYSCALL_GROUPS[group]
        probed_members = members.intersection(traced_probes)
        observed_member_names = members.intersection(syscall_counts.keys())
        if probed_members:
            # 0 is meaningful because these syscall probes were attached for the window.
            put(total_name, sum(syscall_counts[name] for name in observed_member_names))
            put(unique_name, len(observed_member_names))
            available_groups.add(group)
        else:
            put(total_name, None)
            put(unique_name, None)

    # The total can be measured independently; unassigned selected/other raw calls
    # are not fabricated into an unknown category.
    assigned_syscalls = sum(
        count for name, count in syscall_counts.items()
        if any(name in group_set for group_set in SYSCALL_GROUPS.values())
    )
    put("SysCall__Miscellaneous_Operations", max(0, raw_count - assigned_syscalls) if raw_count is not None else None)
    # Numeric syscall IDs emitted by named tracepoint probes are mapped to their
    # observed category. Any raw syscall IDs not matched to a selected named probe
    # are an observed estimate of miscellaneous calls, not reference-pipeline parity.
    put("SysCall__Unique_Miscellaneous_Operations",
        len(raw_ids - mapped_syscall_ids) if mapped_syscall_ids is not None else None)

    if tcp_rows is not None:
        put("TCP__Total_Entries", len(tcp_rows))
        put("TCP__Python_Related_Process", int(python_related and bool(tcp_rows)))
        put("TCP__Local_IP_Address_Access", len({r[0] for r in tcp_rows}))
        put("TCP__Remote_IP_Address_Access", len({r[2] for r in tcp_rows}))
        put("TCP__Local_Port_Access", len({r[1] for r in tcp_rows}))
        put("TCP__Remote_Port_Access", len({r[3] for r in tcp_rows}))
    # Install dependency features and Unique_C-COMM remain missing by design; they
    # require package-install graph evidence and exact source-feature parity.
    return features, available_groups


def fetch_json(base: str, route: str, payload: dict[str, Any] | None = None, timeout: float = 10) -> dict[str, Any]:
    body = None if payload is None else json.dumps(payload, allow_nan=False).encode("utf-8")
    req = urllib.request.Request(base.rstrip("/") + route, data=body,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="GET" if body is None else "POST")
    with urllib.request.urlopen(req, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def proc_start_ticks(pid: int) -> str:
    raw = Path(f"/proc/{pid}/stat").read_text()
    # comm is parenthesized and may contain spaces/parentheses; split after last ')'.
    tail = raw[raw.rfind(")") + 2:].split()
    if len(tail) <= 19:
        raise RuntimeError("Could not read process start time from /proc")
    return tail[19]  # field 22 (starttime), after removing fields 1-2


def process_metadata(pid: int) -> tuple[int, str, str, str]:
    st = os.stat(f"/proc/{pid}")
    comm = Path(f"/proc/{pid}/comm").read_text().strip()
    cmdline_bytes = Path(f"/proc/{pid}/cmdline").read_bytes()
    cmdline = cmdline_bytes.replace(b"\x00", b" ").decode("utf-8", "replace").strip()
    try:
        home = os.path.expanduser("~") if pwd is None else pwd.getpwuid(st.st_uid).pw_dir
    except KeyError:
        home = ""
    return st.st_uid, comm, cmdline, home


def io_snapshot(pid: int) -> dict[str, int]:
    return parse_io(Path(f"/proc/{pid}/io").read_text())


def fd_snapshot(pid: int) -> tuple[int, set[str]]:
    count = 0
    inodes: set[str] = set()
    for fd in Path(f"/proc/{pid}/fd").iterdir():
        count += 1
        try:
            target = os.readlink(fd)
        except OSError:
            continue
        match = re.fullmatch(r"socket:\[(\d+)\]", target)
        if match:
            inodes.add(match.group(1))
    return count, inodes


def tcp_snapshot(pid: int, inodes: set[str]) -> set[tuple[str, int, str, int, str]]:
    rows: set[tuple[str, int, str, int, str]] = set()
    if not inodes:
        return rows
    for filename, family in ((f"/proc/{pid}/net/tcp", 4), (f"/proc/{pid}/net/tcp6", 6)):
        try:
            text = Path(filename).read_text()
        except OSError:
            continue
        rows.update(parse_socket_table(text, family, inodes))
    return rows


def discover_probes() -> tuple[set[str], set[str], bool, str]:
    result = subprocess.run(["sudo", "-n", BPFTRACE, "-l", "tracepoint:syscalls:sys_enter_*"],
        capture_output=True, text=True, timeout=20, check=False)
    if result.returncode != 0:
        raise RuntimeError("Cannot list syscall tracepoints through passwordless sudo: " + (result.stderr.strip()[:800] or result.stdout.strip()[:800]))
    names: set[str] = set()
    for line in result.stdout.splitlines():
        m = re.fullmatch(r"tracepoint:syscalls:sys_enter_([A-Za-z0-9_]+)", line.strip())
        if m:
            names.add(m.group(1))
    exits_result = subprocess.run(["sudo", "-n", BPFTRACE, "-l", "tracepoint:syscalls:sys_exit_*"],
        capture_output=True, text=True, timeout=20, check=False)
    exits: set[str] = set()
    if exits_result.returncode == 0:
        for line in exits_result.stdout.splitlines():
            m = re.fullmatch(r"tracepoint:syscalls:sys_exit_([A-Za-z0-9_]+)", line.strip())
            if m:
                exits.add(m.group(1))
    raw = subprocess.run(["sudo", "-n", BPFTRACE, "-l", "tracepoint:raw_syscalls:sys_enter"],
        capture_output=True, text=True, timeout=15, check=False)
    raw_available = raw.returncode == 0 and "tracepoint:raw_syscalls:sys_enter" in raw.stdout
    if not names:
        raise RuntimeError("No tracepoint:syscalls:sys_enter_* probes were found on this host")
    return names, exits, raw_available, result.stderr.strip()


def build_bpf_program(pid: int, available: set[str], exits_available: set[str], raw_available: bool) -> tuple[str, set[str], bool]:
    selected = set().union(*SYSCALL_GROUPS.values())
    selected.update({"openat", "openat2"})
    traced = selected.intersection(available)
    lines: list[str] = []
    if raw_available:
        lines.append(f'tracepoint:raw_syscalls:sys_enter /pid == {pid}/ {{ printf("TG|%d|RAW|%ld\\n", pid, args.id); }}')
    else:
        # Total/unique syscall features can't be represented faithfully without raw events.
        raise RuntimeError("The raw_syscalls:sys_enter tracepoint is unavailable; refusing a misleading total-system-call count")
    for name in sorted(traced):
        probe = f"tracepoint:syscalls:sys_enter_{name}"
        if name in ("openat", "openat2"):
            lines.append(f'{probe} /pid == {pid}/ {{ printf("TG|%d|CALL|{name}|%d\\n", pid, args.__syscall_nr); printf("TG|%d|OPEN|%d|%s\\n", pid, args.dfd, str(args.filename)); }}')
        else:
            lines.append(f'{probe} /pid == {pid}/ {{ printf("TG|%d|CALL|{name}|%d\\n", pid, args.__syscall_nr); }}')
    error_probes: set[str] = set()
    open_traced = {name for name in ("openat", "openat2") if name in traced}
    for name in sorted(open_traced.intersection(exits_available)):
        exit_probe = f"tracepoint:syscalls:sys_exit_{name}"
        lines.append(f'{exit_probe} /pid == {pid} && args.ret < 0/ {{ printf("TG|%d|OPENERR|{name}\\n", pid); }}')
        error_probes.add(name)
    # If only one of openat/openat2 exit probes exists, don't present the partial
    # error counter as complete for both open syscall variants.
    errors_complete = bool(open_traced) and open_traced.issubset(error_probes)
    return "\n".join(lines) + "\n", traced, errors_complete


def parse_bpf_line(line: str, pid: int, raw_ids: set[int], raw_total: list[int], syscall_counts: collections.Counter[str], path_events: list[tuple[int, str]], open_errors: list[int], mapped_syscall_ids: set[int] | None = None) -> None:
    parts = line.rstrip("\r\n").split("|", 4)
    if len(parts) < 4 or parts[0] != "TG":
        return
    try:
        event_pid = int(parts[1])
    except ValueError:
        return
    if event_pid != pid:
        return
    if parts[2] == "RAW":
        raw_total[0] += 1
        try:
            raw_ids.add(int(parts[3]))
        except ValueError:
            pass
    elif parts[2] == "CALL":
        name = parts[3]
        syscall_counts[name] += 1
        if mapped_syscall_ids is not None and len(parts) >= 5:
            try:
                mapped_syscall_ids.add(int(parts[4]))
            except ValueError:
                pass
    elif parts[2] == "OPEN" and len(parts) >= 5:
        try:
            dfd = int(parts[3])
        except ValueError:
            dfd = -100
        # Resolve immediately while cwd/dirfd still exists; retain no raw path
        # string if resolution fails.
        resolved = resolve_open_path(pid, dfd, parts[4])
        path_events.append((dfd, resolved or ""))
    elif parts[2] == "OPENERR":
        open_errors[0] += 1


def capture(pid: int, duration: int, interval: float, api: str, package_ref: str | None) -> dict[str, Any]:
    if pid <= 1 or not 2 <= duration <= 120 or not 0.25 <= interval <= 5:
        raise ValueError("PID must be >1, duration 2-120 seconds, interval 0.25-5 seconds")
    proc = Path(f"/proc/{pid}")
    if not proc.exists():
        raise ProcessLookupError(f"PID {pid} does not exist")
    uid, comm, cmdline, home = process_metadata(pid)
    if uid != os.getuid():
        raise PermissionError(f"Target PID {pid} belongs to UID {uid}; this collector only traces processes owned by UID {os.getuid()}")
    start_ticks = proc_start_ticks(pid)
    info = fetch_json(api, "/api/model-info")
    schema = info.get("feature_names")
    if not info.get("models_available") or not isinstance(schema, list) or len(schema) != 48:
        raise RuntimeError("API model schema is unavailable or not the expected 48-feature model")
    schema_file = Path(__file__).resolve().parent.parent / "data" / "model_feature_names.json"
    try:
        local_schema = json.loads(schema_file.read_text())
        if isinstance(local_schema, dict):
            local_schema = local_schema.get("feature_names", local_schema.get("features"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Local model feature schema is missing/invalid: {exc}") from exc
    if not isinstance(local_schema, list) or schema != local_schema:
        raise RuntimeError("Live API schema differs from the release feature schema; refusing to submit mismatched features")
    before = io_snapshot(pid)
    names, exit_names, raw_available, _ = discover_probes()
    program, traced, open_errors_instrumented = build_bpf_program(pid, names, exit_names, raw_available)
    cmd = ["sudo", "-n", BPFTRACE, "-q", "-e", program]
    try:
        tracer = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, bufsize=1, start_new_session=True)
    except OSError as exc:
        raise RuntimeError(f"Could not start bpftrace: {exc}") from exc
    events: queue.Queue[str] = queue.Queue()
    stderr_chunks: collections.deque[str] = collections.deque(maxlen=40)

    def read_stdout() -> None:
        assert tracer.stdout is not None
        for line in tracer.stdout:
            events.put(line)

    def read_stderr() -> None:
        assert tracer.stderr is not None
        for line in tracer.stderr:
            stderr_chunks.append(line.rstrip())

    out_thread = threading.Thread(target=read_stdout, daemon=True)
    err_thread = threading.Thread(target=read_stderr, daemon=True)
    out_thread.start(); err_thread.start()

    raw_ids: set[int] = set()
    mapped_syscall_ids: set[int] = set()
    raw_total = [0]
    syscall_counts: collections.Counter[str] = collections.Counter()
    path_events: list[tuple[int, str]] = []
    open_errors = [0]
    tcp_rows: set[tuple[str, int, str, int, str]] = set()
    fd_count: int | None = None
    io_after = before
    expected_start = time.monotonic() + 0.7
    while time.monotonic() < expected_start:
        if tracer.poll() is not None:
            raise RuntimeError("bpftrace exited before capture started: " + " | ".join(stderr_chunks)[-1500:])
        time.sleep(0.05)
    deadline = time.monotonic() + duration
    try:
        while time.monotonic() < deadline:
            if tracer.poll() is not None:
                raise RuntimeError("bpftrace exited during capture: " + " | ".join(stderr_chunks)[-1500:])
            if proc_start_ticks(pid) != start_ticks:
                raise RuntimeError("PID was reused during capture; event discarded")
            try:
                fd_count, inodes = fd_snapshot(pid)
                tcp_rows.update(tcp_snapshot(pid, inodes))
                io_after = io_snapshot(pid)
            except (FileNotFoundError, ProcessLookupError):
                raise RuntimeError("Target process exited during capture; start a new capture for the current PID")
            try:
                line = events.get(timeout=min(interval, max(0.05, deadline - time.monotonic())))
                parse_bpf_line(line, pid, raw_ids, raw_total, syscall_counts, path_events, open_errors, mapped_syscall_ids)
                while True:
                    parse_bpf_line(events.get_nowait(), pid, raw_ids, raw_total, syscall_counts, path_events, open_errors, mapped_syscall_ids)
            except queue.Empty:
                pass
    finally:
        try:
            tracer.send_signal(signal.SIGINT)
            tracer.wait(timeout=4)
        except Exception:
            try:
                tracer.kill()
            except Exception:
                pass
        out_thread.join(timeout=1); err_thread.join(timeout=1)
    # Drain remaining complete records, after bpftrace flushes its output.
    while True:
        try:
            parse_bpf_line(events.get_nowait(), pid, raw_ids, raw_total, syscall_counts, path_events, open_errors, mapped_syscall_ids)
        except queue.Empty:
            break
    stderr_text = " | ".join(stderr_chunks)
    if re.search(r"\b(?:lost|dropped)\s+\d+\s+(?:events|records|samples)\b", stderr_text, re.IGNORECASE):
        raise RuntimeError("bpftrace reported lost output events; sample discarded before submission")
    after_ticks = proc_start_ticks(pid)
    if after_ticks != start_ticks:
        raise RuntimeError("Target PID identity changed before submit; event discarded")
    io_after = io_snapshot(pid)
    fd_count, final_inodes = fd_snapshot(pid)
    tcp_rows.update(tcp_snapshot(pid, final_inodes))

    raw_count = raw_total[0]
    features, instrumented_groups = build_features(
        schema, before, io_after, fd_count, raw_count, raw_ids, syscall_counts,
        path_events, open_errors[0] if open_errors_instrumented else None,
        tcp_rows, ("python" in (comm + " " + cmdline).casefold()), home, traced, mapped_syscall_ids,
    )
    missing = sorted(k for k, v in features.items() if v is None)
    alerts = [
        "BPFTRACE_RUNTIME_CAPTURE",
        "QUT_DV25_FEATURE_EXTRACTION_PARITY_NOT_VALIDATED",
        "INSTALL_DEPENDENCY_TRACE_UNAVAILABLE_FOR_GENERIC_PID",
        "TCP_UNIQUE_C_COMM_FEATURE_MAPPING_UNVERIFIED",
        "SYSCALL_GROUP_COUNTS_FROM_AVAILABLE_KERNEL_PROBES",
    ]
    if missing:
        alerts.append(f"FEATURE_VECTOR_INCOMPLETE:{len(missing)}")
    if not raw_count:
        alerts.append("NO_RAW_SYSCALL_EVENTS_OBSERVED")
    if not path_events:
        alerts.append("NO_OPENAT_PATH_EVENTS_OBSERVED")
    if not tcp_rows and not syscall_counts.keys().isdisjoint(SYSCALL_GROUPS["network"]):
        alerts.append("NO_ACTIVE_TCP_SOCKET_ENTRY_OBSERVED_DURING_SAMPLE")
    evidence = {
        "file_activity": "present" if io_delta(before, io_after, "syscr") is not None and io_delta(before, io_after, "syscw") is not None else "missing",
        "process_execution": "present",
        "system_calls": "present" if raw_count > 0 else "missing",
        # This field describes whether network telemetry was actually observed,
        # not just whether the corresponding tracepoint could be attached.
        "network_behavior": "present" if (sum(syscall_counts[name] for name in SYSCALL_GROUPS["network"]) + len(tcp_rows)) > 0 else "missing",
    }
    event_id = f"bpftrace-{pid}-{time.time_ns()}"
    payload = {
        "event_id": event_id,
        "package_ref": package_ref or f"bpftrace-pid-{pid}-{comm[:40]}",
        "features": features,
        "evidence": evidence,
        "integrity_alerts": alerts,
    }
    prediction = fetch_json(api, "/api/predict", payload, timeout=20)
    audit = fetch_json(api, "/api/audit?limit=200")
    saved_ids = {e.get("event_id") for e in audit.get("events", []) if isinstance(e, dict)}
    if event_id not in saved_ids:
        raise RuntimeError("Prediction response succeeded but the new event was not found in the audit endpoint")
    missing_count = sum(value is None for value in features.values())
    return {
        "event_id": event_id,
        "pid": pid,
        "process_comm": comm,
        "duration_seconds": duration,
        "syscall_events_observed": raw_count,
        "unique_raw_syscall_ids": len(raw_ids),
        "named_syscall_types_observed": len(syscall_counts),
        "file_open_events_observed": len(path_events),
        "tcp_socket_tuples_observed": len(tcp_rows),
        "measured_feature_count": 48 - missing_count,
        "missing_feature_count": missing_count,
        "missing_features": missing,
        "syscall_categories_instrumented": sorted(instrumented_groups),
        "decision": prediction.get("decision"),
        "ensemble_probability_provisional": prediction.get("model_probabilities", {}).get("ensemble"),
        "api_latency_ms": prediction.get("latency_ms"),
        "audit_record_verified": True,
        "integrity_alerts": alerts,
        "note": "Real targeted kernel events were captured. Model score remains provisional until QUT-DV25 feature-extraction parity and missing install-time features are validated; the evidence gate should retain REVIEW_REQUIRED.",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pid", required=True, type=int, help="PID owned by the current Linux user")
    parser.add_argument("--duration", type=int, default=10, help="capture duration, 2-120 seconds (default 10)")
    parser.add_argument("--interval", type=float, default=0.5, help="/proc TCP/FD sample interval, 0.25-5 seconds")
    parser.add_argument("--api", default=API_DEFAULT, help="local TraceGate-R API base URL")
    parser.add_argument("--package-ref", default=None, help="optional event/package label")
    args = parser.parse_args()
    try:
        output = capture(args.pid, args.duration, args.interval, args.api, args.package_ref)
        print(json.dumps(output, ensure_ascii=False, indent=2))
        if output["syscall_events_observed"] <= 0:
            return 2
        return 0
    except Exception as exc:
        print(json.dumps({"collector_status": "FAILED", "error_type": type(exc).__name__, "detail": str(exc)[:1200]}, indent=2), file=sys.stderr)
        return 1

if __name__ == "__main__":
    raise SystemExit(main())
