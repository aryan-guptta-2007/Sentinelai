#!/usr/bin/env python3
"""Follow the host's authentication log and write events.

It reads the journal where systemd is running, because the journal can tell a real
sshd line from a forged one. Otherwise it reads auth.log or secure, and on Windows the
event logs. Its position is saved, so what happens during a restart is still seen, and
events keep the time from the log, so a catch-up cannot be mistaken for a live attack.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

if __package__ in (None, ""):  # allow `python collectors/log_monitor.py`
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from collectors import windows_events
from collectors.auth_parsers import JOURNAL_PROGRAMS, journal_entry_events, line_events
from common.runtime import (
    Follower,
    Paths,
    append_jsonl,
    append_jsonl_batch,
    atomic_write_json,
    exit_with_supervisor,
    get_paths,
    harden_process,
    load_config,
    make_logger,
    now_iso,
    read_json,
)

log_message = make_logger("log_monitor", "collectors.log")

WINDOWS = os.name == "nt"
EXIT_UNAVAILABLE = 3  # tells the supervisor there is nothing to read on this host
AUTH_LOG_CANDIDATES = ("/var/log/auth.log", "/var/log/secure")
FILE_POLL_SEC = 0.25
WINDOWS_POLL_SEC = 5.0
WINDOWS_RETRY_DENIED_SEC = 600.0
CURSOR_SAVE_EVERY_SEC = 2.0


def pick_source(config: Dict[str, Any]) -> Tuple[str, Optional[str]]:
    """Return which source to read, and the file if it is a file."""
    section = config.get("collectors", {})
    choice = str(section.get("auth_source", "auto"))
    override = os.environ.get("AUTH_LOG") or str(section.get("auth_log") or "")
    if choice == "none":
        return "none", None
    if WINDOWS:
        return "windows", None

    systemd = Path("/run/systemd/system").is_dir() and shutil.which("journalctl")
    if not override and (choice == "journal" or (choice == "auto" and systemd)):
        return "journal", None
    for candidate in ([override] if override else list(AUTH_LOG_CANDIDATES)):
        if os.access(candidate, os.R_OK):
            return "file", candidate
    return "none", None


def report_cleared_log(paths: Paths, source: str) -> None:
    append_jsonl(
        paths.events,
        {
            "ts": now_iso(),
            "src": "log_monitor",
            "type": "log_cleared",
            "msg": f"{source} shrank while being read",
            "meta": {"log": source, "source_log": "auth"},
        },
    )
    log_message(f"{source} shrank while being read")


def follow_file(path: str, paths: Paths, follow: bool) -> None:
    log_message(f"following {path}")
    # Nothing in an existing log is news on the first run. After that, the saved
    # position means lines written during downtime are read on return.
    follower = Follower(Path(path), "log_monitor", paths.state_dir, FILE_POLL_SEC, start_at_end=True)
    while True:
        batch: List[Dict[str, Any]] = []
        for line in follower.read_available():
            for event in line_events(line):
                batch.append(event)
                if len(batch) >= 200:
                    append_jsonl_batch(paths.events, batch)
                    batch.clear()
        if batch:
            append_jsonl_batch(paths.events, batch)
            batch.clear()
        if follower.truncated:
            follower.truncated = False
            report_cleared_log(paths, path)
        if not follow:
            return
        time.sleep(FILE_POLL_SEC)


def journal_command(cursor: Optional[str]) -> List[str]:
    argv = ["journalctl", "--follow", "--output=json", "--no-pager"]
    # --follow implies --lines=10, which would quietly cap a catch-up after downtime.
    argv += [f"--after-cursor={cursor}", "--lines=all"] if cursor else ["--lines=0"]
    for program in JOURNAL_PROGRAMS:
        argv += ["-t", program]
    return argv


def follow_journal(paths: Paths) -> None:
    state = paths.state_dir / "journal_cursor.json"
    saved = read_json(state, {})
    cursor = saved.get("cursor") if isinstance(saved, dict) else None
    log_message("following the systemd journal")

    process = subprocess.Popen(
        journal_command(cursor),
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    assert process.stdout is not None
    last_save = 0.0
    try:
        for raw in process.stdout:
            try:
                entry = json.loads(raw)
            except ValueError:
                continue
            for event in journal_entry_events(entry):
                append_jsonl(paths.events, event)
            cursor = entry.get("__CURSOR", cursor)
            if time.monotonic() - last_save >= CURSOR_SAVE_EVERY_SEC:
                atomic_write_json(state, {"cursor": cursor})
                last_save = time.monotonic()
    finally:
        if cursor:
            atomic_write_json(state, {"cursor": cursor})
        process.kill()
    raise RuntimeError("journalctl stopped")


class WindowsLogReader:
    def __init__(self, paths: Paths):
        self.paths = paths
        self.state = paths.state_dir / "windows_events.json"
        saved = read_json(self.state, {})
        self.positions: Dict[str, int] = saved if isinstance(saved, dict) else {}
        self.denied: Dict[str, float] = {}

    def _start(self, channel: str) -> bool:
        """Begin at the newest record, so history is not reported as new."""
        code, record = windows_events.latest_record(channel)
        if code == windows_events.ACCESS_DENIED:
            self._deny(channel)
            return False
        if code != 0:
            return False
        self.positions[channel] = record
        return True

    def _deny(self, channel: str) -> None:
        if channel not in self.denied:
            log_message(f"cannot read the {channel} log: run as Administrator to collect it")
        self.denied[channel] = time.monotonic()

    def poll(self) -> None:
        for channel, event_ids in windows_events.CHANNELS.items():
            denied_at = self.denied.get(channel)
            if denied_at is not None:
                if time.monotonic() - denied_at < WINDOWS_RETRY_DENIED_SEC:
                    continue
                del self.denied[channel]
            if channel not in self.positions and not self._start(channel):
                continue

            code, records = windows_events.read_since(channel, event_ids, self.positions[channel])
            if code == windows_events.ACCESS_DENIED:
                self._deny(channel)
                continue
            batch = []
            for record in records:
                event = windows_events.to_sentinel_event(record)
                if event:
                    batch.append(event)
                self.positions[channel] = max(self.positions[channel], record.record_id)
            if batch:
                append_jsonl_batch(self.paths.events, batch)
        atomic_write_json(self.state, self.positions)

    def readable(self) -> List[str]:
        return [name for name in windows_events.CHANNELS if name not in self.denied]


def follow_windows(paths: Paths, follow: bool) -> int:
    reader = WindowsLogReader(paths)
    while True:
        reader.poll()
        if not reader.readable():
            log_message("no Windows event log can be read")
            return EXIT_UNAVAILABLE
        if not follow:
            return 0
        time.sleep(WINDOWS_POLL_SEC)


def main() -> int:
    harden_process()
    exit_with_supervisor()
    config = load_config()
    paths = get_paths(config).ensure()
    follow = bool(config["modes"].get("follow_files", True))

    source, path = pick_source(config)
    if source == "windows":
        return follow_windows(paths, follow)
    if source == "journal":
        follow_journal(paths)
    elif source == "file" and path:
        follow_file(path, paths, follow)
    else:
        log_message("no readable auth log or journal on this host")
        return EXIT_UNAVAILABLE
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        pass
