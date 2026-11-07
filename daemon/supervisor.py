#!/usr/bin/env python3
"""Start every SentinelAI component, restart crashes, and shut down cleanly."""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, IO, List, Optional

import psutil

from common.maintenance import run_maintenance
from common.runtime import (
    CODE_ROOT,
    SUPERVISOR_ENV,
    InstanceLock,
    Paths,
    atomic_write_json,
    get_paths,
    harden_paths,
    harden_process,
    load_config,
    make_logger,
    now_iso,
    read_json,
    run_mode,
)

log_message = make_logger("supervisor", "supervisor.log")

EXIT_UNAVAILABLE = 3  # a component's way of saying "nothing to do on this host"
MAX_BACKOFF_SEC = 60
STABLE_AFTER_SEC = 60
STOP_GRACE_SEC = 5
STATUS_EVERY_SEC = 5
MAINTENANCE_EVERY_SEC = 3600


@dataclass
class Component:
    name: str
    argv: List[str]
    process: Optional[subprocess.Popen] = None
    output: Optional[IO[bytes]] = None
    started_at: float = 0.0
    restarts: int = 0
    backoff: float = 1.0
    next_start: float = 0.0
    state: str = "pending"
    detail: str = field(default="")


def python_component(name: str, module: str) -> Component:
    return Component(name, [sys.executable, "-m", module])


def build_components(
    config: Dict[str, Any], collectors: bool = True, dashboard: bool = True
) -> List[Component]:
    components = [
        python_component("rule_engine", "analyzer.rule_engine"),
        python_component("anomaly_detector", "analyzer.anomaly_detector"),
        python_component("responder", "responder.responder"),
    ]
    components.append(python_component("notifier", "reporter.notifier"))
    if dashboard:
        components.append(python_component("dashboard", "reporter.web_dashboard"))
    if collectors:
        components.append(python_component("log_monitor", "collectors.log_monitor"))
        components.append(python_component("host_monitor", "collectors.host_monitor"))
        components.append(python_component("file_monitor", "collectors.file_monitor"))
    return components


def component_env() -> Dict[str, str]:
    return {**os.environ, "PYTHONUNBUFFERED": "1", SUPERVISOR_ENV: str(os.getpid())}


def another_instance(paths: Paths) -> Optional[int]:
    """Return the PID of a live supervisor for this data directory, if any."""
    state = read_json(paths.supervisor, {})
    pid = state.get("pid") if isinstance(state, dict) else None
    if not isinstance(pid, int) or pid == os.getpid():
        return None
    try:
        command = " ".join(psutil.Process(pid).cmdline())
    except psutil.Error:
        return None
    return pid if "sentinel" in command.lower() else None


class Supervisor:
    def __init__(self, config: Dict[str, Any], components: List[Component]):
        self.config = config
        self.paths = get_paths(config).ensure()
        self.components = components
        self.env = component_env()
        self.stopping = False
        self.started = now_iso()
        self.instance = InstanceLock(self.paths.state_dir / ".supervisor.lock")

    def request_stop(self, *_: Any) -> None:
        self.stopping = True

    def _spawn(self, item: Component) -> None:
        if item.output is None:
            item.output = (self.paths.logs_dir / f"{item.name}.out.log").open("ab")
        kwargs: Dict[str, Any] = {}
        if os.name == "posix":
            kwargs["start_new_session"] = True  # own group, so pipelines die together
        else:
            kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
        item.process = subprocess.Popen(
            item.argv,
            cwd=CODE_ROOT,
            env=self.env,
            stdin=subprocess.DEVNULL,
            stdout=item.output,
            stderr=subprocess.STDOUT,
            **kwargs,
        )
        item.started_at = time.time()
        item.state = "running"
        item.detail = ""
        log_message(f"started {item.name} pid={item.process.pid}")

    def _check(self, item: Component, now: float) -> None:
        if item.state in ("unavailable", "finished"):
            return
        if item.process is None:
            if now >= item.next_start:
                self._spawn(item)
            return

        code = item.process.poll()
        if code is None:
            if now - item.started_at > STABLE_AFTER_SEC:
                item.backoff = 1.0
            return

        item.process = None
        if code == EXIT_UNAVAILABLE:
            item.state = "unavailable"
            item.detail = "nothing to do on this host"
            log_message(f"{item.name} unavailable on this host")
        elif code == 0 and not self.config["modes"].get("follow_files", True):
            item.state = "finished"
        else:
            item.restarts += 1
            item.state = "restarting"
            item.detail = f"exit code {code}"
            item.next_start = now + item.backoff
            log_message(f"{item.name} exited code={code}, retry in {item.backoff:.0f}s")
            item.backoff = min(item.backoff * 2, MAX_BACKOFF_SEC)

    def write_status(self, running: bool = True) -> None:
        components = {
            item.name: {
                "state": item.state if running else "stopped",
                "pid": item.process.pid if item.process and running else None,
                "restarts": item.restarts,
                "detail": item.detail,
            }
            for item in self.components
        }
        atomic_write_json(
            self.paths.supervisor,
            {
                "pid": os.getpid() if running else None,
                "mode": run_mode(self.config),
                "started": self.started,
                "updated": now_iso(),
                "components": components,
            },
        )

    def _stop_all(self) -> None:
        for item in self.components:
            if item.process and item.process.poll() is None:
                self._signal(item.process, signal.SIGTERM)
        deadline = time.time() + STOP_GRACE_SEC
        for item in self.components:
            if item.process:
                try:
                    item.process.wait(timeout=max(0.1, deadline - time.time()))
                except subprocess.TimeoutExpired:
                    self._signal(item.process, signal.SIGKILL if os.name == "posix" else signal.SIGTERM)
                    try:
                        item.process.wait(timeout=STOP_GRACE_SEC)
                    except subprocess.TimeoutExpired:
                        log_message(f"{item.name} did not stop")
            if item.output:
                item.output.close()

    @staticmethod
    def _signal(process: subprocess.Popen, signum: int) -> None:
        try:
            if os.name == "posix":
                os.killpg(process.pid, signum)
            else:
                process.terminate()
        except (ProcessLookupError, PermissionError):
            pass

    def _maintain(self) -> None:
        try:
            rotated = run_maintenance(self.config, self.paths)
            if rotated:
                log_message(f"rotated {', '.join(rotated)}")
        except Exception as exc:  # housekeeping must never take the stack down
            log_message(f"maintenance failed: {exc!r}")

    def run(self, duration: Optional[float] = None) -> int:
        # Holding this lock, not a PID file, is what makes two starts at once safe.
        if not self.instance.acquire():
            other = another_instance(self.paths)
            print(f"SentinelAI is already running{f' (pid {other})' if other else ''}.", file=sys.stderr)
            return 1

        harden_paths(self.paths)
        signal.signal(signal.SIGINT, self.request_stop)
        signal.signal(signal.SIGTERM, self.request_stop)
        if hasattr(signal, "SIGBREAK"):
            signal.signal(signal.SIGBREAK, self.request_stop)

        log_message(f"supervisor started mode={run_mode(self.config)}")
        deadline = time.time() + duration if duration else None
        last_status = 0.0
        next_maintenance = time.monotonic() + MAINTENANCE_EVERY_SEC
        try:
            while not self.stopping:
                now = time.time()
                if deadline and now >= deadline:
                    break
                for item in self.components:
                    self._check(item, now)
                if now - last_status >= STATUS_EVERY_SEC or last_status == 0.0:
                    self.write_status()
                    last_status = now
                if time.monotonic() >= next_maintenance:
                    next_maintenance = time.monotonic() + MAINTENANCE_EVERY_SEC
                    threading.Thread(target=self._maintain, name="maintenance", daemon=True).start()
                if all(item.state in ("unavailable", "finished") for item in self.components):
                    break
                time.sleep(0.25)
        finally:
            self._stop_all()
            self.write_status(running=False)
            self.instance.release()
            log_message("supervisor stopped")
        return 0


def run_stack(
    collectors: bool = True, dashboard: bool = True, duration: Optional[float] = None
) -> int:
    harden_process()
    config = load_config()
    return Supervisor(config, build_components(config, collectors, dashboard)).run(duration)
