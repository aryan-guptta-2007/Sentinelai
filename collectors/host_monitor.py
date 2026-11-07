#!/usr/bin/env python3
"""Watch this host's resources, listening ports and processes. Runs on Linux and Windows.

New processes are found by comparing PID lists every couple of seconds, which is cheap
and catches anything that lives longer than that. A process that starts and exits
between two looks is missed. Only kernel-level tracing would see those.
"""

from __future__ import annotations

import ipaddress
import os
import socket
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

if __package__ in (None, ""):  # allow `python collectors/host_monitor.py`
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import psutil

from collectors.process_checks import Indicators, ProcessFacts, inspect, load_indicators
from common.runtime import (
    METRIC_FIELDS,
    Paths,
    append_bytes,
    append_jsonl,
    atomic_write_json,
    exit_with_supervisor,
    get_paths,
    harden_process,
    load_config,
    make_logger,
    now_iso,
    read_json,
)
from responder.system import process_key

log_message = make_logger("host_monitor", "collectors.log")

SUSTAINED_SCANS = 2  # one busy sample is normal, two in a row are a pattern
DEFAULT_EPHEMERAL_START = 49152
HOST = socket.gethostname()


def emit(paths: Paths, event_type: str, **fields: Any) -> None:
    append_jsonl(paths.events, {"ts": now_iso(), "src": "host_monitor", "type": event_type, "host": HOST, **fields})


# -------------------------------------------------------------------------- metrics
class MetricsSampler:
    def __init__(self, paths: Paths):
        self.paths = paths
        self.last_net = psutil.net_io_counters()
        self.last_time = time.monotonic()
        psutil.cpu_percent(interval=None)  # the first reading only sets the baseline
        self._prepare_file()

    def _prepare_file(self) -> None:
        """A file from an older version has different columns, so it is set aside."""
        path = self.paths.metrics
        header = ",".join(METRIC_FIELDS)
        try:
            with path.open("r", encoding="utf-8", errors="replace") as handle:
                current = handle.readline().strip()
        except OSError:
            current = ""
        if current and current != header:
            os.replace(path, path.with_name(f"{path.name}.old"))
            current = ""
        if not current:
            append_bytes(path, (header + "\n").encode("utf-8"))

    def sample(self, connections: int) -> str:
        memory = psutil.virtual_memory()
        try:
            load1, load5, load15 = psutil.getloadavg()
        except (OSError, AttributeError, RuntimeError):
            load1 = load5 = load15 = 0.0

        counters = psutil.net_io_counters()
        now = time.monotonic()
        seconds = max(now - self.last_time, 0.001)
        received = max(counters.bytes_recv - self.last_net.bytes_recv, 0) * 8 / 1000 / seconds
        sent = max(counters.bytes_sent - self.last_net.bytes_sent, 0) * 8 / 1000 / seconds
        self.last_net, self.last_time = counters, now

        return ",".join(
            [
                now_iso(),
                f"{psutil.cpu_percent(interval=None):.2f}",
                f"{(memory.total - memory.available) / 1048576:.0f}",
                f"{memory.total / 1048576:.0f}",
                f"{load1:.2f}",
                f"{load5:.2f}",
                f"{load15:.2f}",
                str(len(psutil.pids())),
                str(connections),
                f"{received:.1f}",
                f"{sent:.1f}",
            ]
        )

    def record(self, connections: int) -> None:
        append_bytes(self.paths.metrics, (self.sample(connections) + "\n").encode("utf-8"))


# ------------------------------------------------------------------------ listeners
def ephemeral_start() -> int:
    """Where the kernel starts handing out temporary client ports."""
    try:
        return int(Path("/proc/sys/net/ipv4/ip_local_port_range").read_text("ascii").split()[0])
    except (OSError, ValueError, IndexError):
        return DEFAULT_EPHEMERAL_START


def is_exposed(address: str) -> bool:
    """A loopback listener cannot be reached from outside. Desktop software opens them
    all day, so reporting them would bury everything else."""
    try:
        return not ipaddress.ip_address(address.split("%", 1)[0]).is_loopback
    except ValueError:
        return True


def process_identity(pid: Optional[int], cache: Dict[int, Tuple[str, str]]) -> Tuple[str, str]:
    if not pid:
        return "", ""
    if pid not in cache:
        try:
            process = psutil.Process(pid)
            name = process.name()
            try:
                exe = process.exe()
            except psutil.Error:
                exe = ""
            cache[pid] = (name, exe)
        except psutil.Error:
            cache[pid] = ("", "")
    return cache[pid]


def snapshot_listeners(connections: List[Any], first_ephemeral: int, ignored: Set[str]) -> Dict[str, Dict[str, Any]]:
    current: Dict[str, Dict[str, Any]] = {}
    identities: Dict[int, Tuple[str, str]] = {}
    for item in connections:
        if not item.laddr:
            continue
        is_tcp = item.type == socket.SOCK_STREAM
        if is_tcp and item.status != psutil.CONN_LISTEN:
            continue
        if not is_tcp and (item.raddr or item.laddr.port >= first_ephemeral):
            continue  # a UDP socket on a temporary port is a client, not a service

        proto = "tcp" if is_tcp else "udp"
        key = f"{proto}|{item.laddr.port}|{item.laddr.ip}"
        if key in current:
            continue  # forked workers share one socket
        name, exe = process_identity(item.pid, identities)
        if process_key(name) in ignored:
            continue
        current[key] = {
            "proto": proto, "port": item.laddr.port, "ip": item.laddr.ip,
            "pid": item.pid or 0, "proc": name, "exe": exe,
        }
    return current


def listener_changes(
    previous: Dict[str, Dict[str, Any]], current: Dict[str, Dict[str, Any]]
) -> List[Dict[str, Any]]:
    changed = []
    for key, entry in current.items():
        known = previous.get(key)
        if known is None:
            changed.append(entry)
        # A restart only changes the PID. A different program on the port is what matters.
        elif known.get("proc") and entry["proc"] and known["proc"] != entry["proc"]:
            changed.append(entry)
    return changed


class ListenerWatcher:
    def __init__(self, paths: Paths, config: Dict[str, Any]):
        self.paths = paths
        self.state = paths.state_dir / "listening_ports.json"
        saved = read_json(self.state, None)
        self.previous: Optional[Dict[str, Dict[str, Any]]] = saved if isinstance(saved, dict) else None
        self.first_ephemeral = ephemeral_start()
        names = config.get("network", {}).get("ignored_listeners", [])
        self.ignored = {process_key(name) for name in names}

    def scan(self, connections: List[Any]) -> None:
        current = snapshot_listeners(connections, self.first_ephemeral, self.ignored)
        if self.previous is None:
            # Nothing recorded yet, so whatever is listening now is the starting point.
            log_message(f"baseline recorded ({len(current)} listeners)")
        else:
            for entry in listener_changes(self.previous, current):
                self._report(entry)
        if current != self.previous:
            atomic_write_json(self.state, current)
        self.previous = current

    def _report(self, entry: Dict[str, Any]) -> None:
        meta = {
            "proto": entry["proto"], "bind_ip": entry["ip"], "exposed": is_exposed(entry["ip"]),
        }
        if entry["proc"]:
            meta["proc"] = entry["proc"]
        if entry["exe"]:
            meta["exe"] = entry["exe"]
        fields: Dict[str, Any] = {"port": entry["port"], "meta": meta}
        if entry["pid"]:
            fields["pid"] = entry["pid"]
        # The bind address goes in meta. It must never look like an attacker's IP.
        emit(self.paths, "new_port", **fields)
        log_message(f"new listener {entry['proto']} {entry['ip']}:{entry['port']} proc={entry['proc']}")


# ------------------------------------------------------------------------ processes
def stdio_is_socket(pid: int) -> bool:
    """A shell whose input and output are a network socket is a remote control channel."""
    if not sys.platform.startswith("linux"):
        return False
    try:
        return all(os.readlink(f"/proc/{pid}/fd/{fd}").startswith("socket:") for fd in (0, 1))
    except OSError:
        return False


def link_target(pid: int) -> str:
    """psutil hides the " (deleted)" marker, so the link is read directly."""
    if not sys.platform.startswith("linux"):
        return ""
    try:
        return os.readlink(f"/proc/{pid}/exe")
    except OSError:
        return ""


def gather_facts(process: psutil.Process) -> Optional[ProcessFacts]:
    try:
        with process.oneshot():
            name = process.name()
            try:
                exe = process.exe()
            except psutil.Error:
                exe = ""
            try:
                cmdline = process.cmdline()
            except psutil.Error:
                cmdline = []
            try:
                user = process.username().rsplit("\\", 1)[-1]
            except psutil.Error:
                user = ""
            try:
                parent_process = process.parent()
                parent = parent_process.name() if parent_process else ""
            except psutil.Error:
                parent = ""
    except psutil.Error:
        return None

    link = link_target(process.pid)
    return ProcessFacts(
        pid=process.pid,
        name=name,
        exe=exe,
        cmdline=cmdline,
        user=user,
        parent=parent,
        exe_deleted=link.endswith(" (deleted)"),
        from_memory=link.startswith("/memfd:"),
        socket_stdio=stdio_is_socket(process.pid),
        platform="linux" if sys.platform.startswith("linux") else sys.platform,
    )


class ProcessWatcher:
    def __init__(self, paths: Paths, config: Dict[str, Any], indicators: Indicators):
        self.paths = paths
        self.indicators = indicators
        section = config.get("collectors", {})
        self.cpu_threshold = float(section.get("cpu_threshold", 80))
        self.mem_threshold = float(section.get("mem_threshold", 70))
        self.cores = psutil.cpu_count() or 1
        self.known: Dict[int, psutil.Process] = {}
        self.reported: Set[Tuple[int, float, str]] = set()
        self.busy_scans: Dict[int, int] = {}
        self.own_pids = {os.getpid(), os.getppid()}

    def scan_new(self) -> None:
        """Look at anything that appeared since the last call."""
        pids = set(psutil.pids())
        gone = [item for item in self.known if item not in pids]
        for pid in gone:
            del self.known[pid]
            self.busy_scans.pop(pid, None)
        if gone:
            self.reported = {key for key in self.reported if key[0] in pids}
        for pid in pids - set(self.known):
            try:
                process = psutil.Process(pid)
            except psutil.Error:
                continue
            self.known[pid] = process
            try:
                process.cpu_percent(interval=None)  # sets the baseline for later scans
            except psutil.Error:
                pass  # protected system processes refuse this, and that is fine
            if pid not in self.own_pids:
                self._check(process)

    def _check(self, process: psutil.Process) -> None:
        facts = gather_facts(process)
        if facts is None:
            return
        for finding in inspect(facts, self.indicators):
            self._report(process, facts, finding)

    def _report(self, process: psutil.Process, facts: ProcessFacts, finding: Dict[str, Any]) -> None:
        try:
            started = process.create_time()
        except psutil.Error:
            started = 0.0
        key = (facts.pid, started, finding["type"])
        if key in self.reported:
            return
        self.reported.add(key)

        meta = {"proc": facts.name, "exe": facts.exe, **finding["meta"]}
        meta.setdefault("parent", facts.parent)
        fields = {"pid": facts.pid, "user": facts.user, "msg": facts.name, "meta": meta}
        emit(self.paths, finding["type"], **fields)
        log_message(f"flagged {finding['type']} pid={facts.pid} proc={facts.name}")

    def scan_resources(self) -> None:
        """CPU here is measured between scans, so a burst in an old process still counts."""
        for pid, process in list(self.known.items()):
            if pid in self.own_pids:
                continue
            try:
                cpu = process.cpu_percent(interval=None) / self.cores
                memory = process.memory_percent()
            except psutil.Error:
                continue

            flags = []
            if cpu >= self.cpu_threshold:
                flags.append("cpu")
            if memory >= self.mem_threshold:
                flags.append("mem")
            if not flags:
                self.busy_scans.pop(pid, None)
                continue
            self.busy_scans[pid] = self.busy_scans.get(pid, 0) + 1
            if self.busy_scans[pid] == SUSTAINED_SCANS:
                self._report_resources(process, flags, cpu, memory)

    def _report_resources(self, process: psutil.Process, flags: List[str], cpu: float, memory: float) -> None:
        facts = gather_facts(process)
        if facts is None:
            return
        self._report(
            process,
            facts,
            {"type": "suspicious_proc", "meta": {"flags": flags, "cpu": round(cpu, 1), "mem": round(memory, 1)}},
        )


def inet_connections() -> List[Any]:
    try:
        return psutil.net_connections(kind="inet")
    except (psutil.Error, OSError, RuntimeError) as exc:
        log_message(f"cannot list connections: {exc}")
        return []


def main() -> int:
    harden_process()
    exit_with_supervisor()
    config = load_config()
    paths = get_paths(config).ensure()
    section = config.get("collectors", {})
    interval = float(section.get("interval_sec", 30))
    fast = float(section.get("process_interval_sec", 2))
    follow = bool(config["modes"].get("follow_files", True))
    watch_listen = bool(config.get("network", {}).get("watch_listen", True))

    metrics = MetricsSampler(paths)
    listeners = ListenerWatcher(paths, config)
    processes = ProcessWatcher(paths, config, load_indicators(config))
    log_message(f"started (interval={interval}s processes={fast}s)")

    next_slow = 0.0
    while True:
        processes.scan_new()
        now = time.monotonic()
        if now >= next_slow:
            next_slow = now + interval
            connections = inet_connections()
            metrics.record(len(connections))
            if watch_listen:
                listeners.scan(connections)
            processes.scan_resources()
        if not follow:
            return 0
        time.sleep(fast)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        pass
