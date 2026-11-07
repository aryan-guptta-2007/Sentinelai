#!/usr/bin/env python3
"""Watch the files and registry keys attackers change to keep access.

An SSH key, a cron job or a startup entry shows up in no process list and no login log,
so this is often the only trace left of how someone planned to come back. The first run
records a baseline silently. After that, every change is reported with what it was.
"""

from __future__ import annotations

import glob
import hashlib
import os
import socket
import stat as stat_module
import sys
import time
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple

if __package__ in (None, ""):  # allow `python collectors/file_monitor.py`
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import yaml

from common.runtime import (
    ConfigError,
    Paths,
    append_jsonl,
    atomic_write_json,
    exit_with_supervisor,
    get_paths,
    harden_process,
    load_config,
    make_logger,
    now_iso,
    read_json,
    root_dir,
)

log_message = make_logger("file_monitor", "collectors.log")

EXIT_UNAVAILABLE = 3
HASH_LIMIT_BYTES = 16 * 1024 * 1024
FULL_HASH_EVERY = 60  # scans between hashing everything, which catches a forged timestamp
HOST = socket.gethostname()
CATEGORIES = {
    "identity", "sudoers", "ssh_config", "ssh_keys", "cron", "service", "preload", "pam",
    "startup", "hosts",
}


def load_watch_list(path: Optional[Path] = None) -> List[Dict[str, str]]:
    source = path or root_dir() / "config" / "integrity.yml"
    try:
        document = yaml.safe_load(source.read_text(encoding="utf-8-sig")) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise ConfigError(f"{source.name}: {' '.join(str(exc).split())}") from exc
    if not isinstance(document, dict):
        raise ConfigError(f"{source.name}: must be a mapping")

    entries = document.get("windows" if os.name == "nt" else "linux") or []
    for entry in entries:
        if not isinstance(entry, dict) or not ({"path", "registry"} & set(entry)):
            raise ConfigError(f"{source.name}: each entry needs a path or registry key")
        if entry.get("category") not in CATEGORIES:
            raise ConfigError(f"{source.name}: unknown category {entry.get('category')!r}")
    return entries


def expand(entry: Dict[str, str]) -> Iterator[str]:
    """List the real files an entry stands for right now."""
    pattern = os.path.expandvars(entry["path"])
    for match in glob.glob(pattern) or [pattern]:
        if os.path.isdir(match):
            try:
                names = sorted(os.listdir(match))
            except OSError:
                continue
            for name in names:
                full = os.path.join(match, name)
                if os.path.isfile(full):
                    yield full
        else:
            yield match


def fingerprint(path: str, previous: Optional[Dict[str, Any]], rehash: bool) -> Optional[Dict[str, Any]]:
    """Describe a file. Unchanged metadata reuses the old hash unless a full pass is due."""
    try:
        info = os.stat(path)
    except OSError:
        return None
    if not stat_module.S_ISREG(info.st_mode):
        return None

    record: Dict[str, Any] = {
        "size": info.st_size,
        "mtime": info.st_mtime_ns,
        "mode": stat_module.S_IMODE(info.st_mode),
        "uid": getattr(info, "st_uid", 0),
    }
    unchanged = previous is not None and all(previous.get(k) == record[k] for k in ("size", "mtime"))
    if unchanged and not rehash and previous is not None:
        record["sha256"] = previous.get("sha256")
    elif info.st_size <= HASH_LIMIT_BYTES:
        try:
            with open(path, "rb") as handle:
                record["sha256"] = hashlib.sha256(handle.read()).hexdigest()
        except OSError:
            record["sha256"] = previous.get("sha256") if previous else None
    else:
        record["sha256"] = None
    return record


def registry_values(key_path: str) -> Dict[str, str]:
    """Read every value under a key. Empty if the key does not exist."""
    import winreg  # Windows only, and only reached for registry entries

    hive_name, _, sub_key = key_path.partition("\\")
    hive = {"HKLM": winreg.HKEY_LOCAL_MACHINE, "HKCU": winreg.HKEY_CURRENT_USER}[hive_name]
    values: Dict[str, str] = {}
    try:
        with winreg.OpenKey(hive, sub_key) as key:
            index = 0
            while True:
                try:
                    name, data, _ = winreg.EnumValue(key, index)
                except OSError:
                    break
                values[name] = str(data)
                index += 1
    except OSError:
        pass
    return values


def snapshot(
    entries: List[Dict[str, str]], baseline: Dict[str, Dict[str, Any]], rehash: bool
) -> Dict[str, Dict[str, Any]]:
    current: Dict[str, Dict[str, Any]] = {}
    for entry in entries:
        category = entry["category"]
        if "registry" in entry:
            for name, data in registry_values(entry["registry"]).items():
                label = f"registry:{entry['registry']}\\{name}"
                digest = hashlib.sha256(data.encode("utf-8", "replace")).hexdigest()
                current[label] = {"sha256": digest, "category": category, "value": data[:300]}
            continue
        for path in expand(entry):
            record = fingerprint(path, baseline.get(path), rehash)
            if record is not None:
                record["category"] = category
                current[path] = record
    return current


def compare(
    baseline: Dict[str, Dict[str, Any]], current: Dict[str, Dict[str, Any]]
) -> List[Tuple[str, str, Dict[str, Any]]]:
    """Return (path, change, record) for everything that differs."""
    changes: List[Tuple[str, str, Dict[str, Any]]] = []
    for path, record in current.items():
        before = baseline.get(path)
        if before is None:
            changes.append((path, "added", record))
        elif before.get("sha256") != record.get("sha256"):
            changes.append((path, "modified", record))
        elif before.get("mode") != record.get("mode") or before.get("uid") != record.get("uid"):
            changes.append((path, "permissions", record))
    for path, record in baseline.items():
        if path not in current:
            changes.append((path, "removed", record))
    return changes


class FileMonitor:
    def __init__(self, paths: Paths, entries: List[Dict[str, str]]):
        self.paths = paths
        self.entries = entries
        self.state = paths.state_dir / "file_baseline.json"
        saved = read_json(self.state, None)
        self.baseline: Optional[Dict[str, Dict[str, Any]]] = saved if isinstance(saved, dict) else None
        self.scans = 0

    def scan(self) -> None:
        self.scans += 1
        rehash = self.scans % FULL_HASH_EVERY == 0
        current = snapshot(self.entries, self.baseline or {}, rehash)
        if self.baseline is None:
            log_message(f"baseline recorded ({len(current)} items)")
            self.baseline = current
            atomic_write_json(self.state, current)
            return

        changes = compare(self.baseline, current)
        for path, change, record in changes:
            self._report(path, change, record)
        if changes or current != self.baseline:
            self.baseline = current
            atomic_write_json(self.state, current)

    def _report(self, path: str, change: str, record: Dict[str, Any]) -> None:
        meta = {"path": path, "change": change, "category": record.get("category", ""),
                "sha256": record.get("sha256") or ""}
        if record.get("value"):
            meta["value"] = record["value"]
        append_jsonl(
            self.paths.events,
            {
                "ts": now_iso(), "src": "file_monitor", "type": "file_change", "host": HOST,
                "msg": f"{path} {change}", "meta": meta,
            },
        )
        log_message(f"{change}: {path}")


def main() -> int:
    harden_process()
    exit_with_supervisor()
    config = load_config()
    paths = get_paths(config).ensure()
    entries = load_watch_list()
    if not entries:
        return EXIT_UNAVAILABLE
    interval = float(config.get("collectors", {}).get("integrity_interval_sec", 60))
    follow = bool(config["modes"].get("follow_files", True))

    monitor = FileMonitor(paths, entries)
    log_message(f"started (interval={interval}s, {len(entries)} entries)")
    while True:
        monitor.scan()
        if not follow:
            return 0
        time.sleep(interval)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        pass
