"""Append-only record of every response decision, linked with a hash chain.

Each entry carries the hash of the one before it, so editing or removing an entry
breaks the chain and ``sentinel.py audit`` reports where. The chain proves integrity
against anyone who cannot rewrite the whole file. An attacker with root can recompute
it, so for that threat the entries also need to leave the host.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, Iterator, List, Optional, Tuple

from common.runtime import (
    Paths,
    append_jsonl,
    atomic_write_json,
    file_lock,
    read_json,
    read_recent_jsonl,
)

GENESIS = "0" * 64
LOCK_TIMEOUT_SEC = 30.0


def entry_hash(entry: Dict[str, Any]) -> str:
    body = {key: value for key, value in entry.items() if key != "hash"}
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class AuditLog:
    def __init__(self, paths: Paths):
        self.paths = paths
        self.lock_path = paths.state_dir / ".audit.lock"

    def _tip(self) -> Tuple[str, int]:
        """The file is the truth. The head file only matters once the log has rotated."""
        recent = read_recent_jsonl(self.paths.audit, limit=1, max_bytes=65536)
        if recent:
            return str(recent[-1].get("hash", GENESIS)), int(recent[-1].get("seq", 0))
        head = read_json(self.paths.audit_head, {})
        if isinstance(head, dict):
            return str(head.get("hash", GENESIS)), int(head.get("seq", 0))
        return GENESIS, 0

    def append(self, entry: Dict[str, Any]) -> Dict[str, Any]:
        with file_lock(self.lock_path, timeout=LOCK_TIMEOUT_SEC):
            previous, sequence = self._tip()
            record = {**entry, "seq": sequence + 1, "prev": previous}
            record["hash"] = entry_hash(record)
            append_jsonl(self.paths.audit, record)
            atomic_write_json(self.paths.audit_head, {"hash": record["hash"], "seq": record["seq"]})
        return record


def read_actions(paths: Paths, limit: int = 1000) -> List[Dict[str, Any]]:
    return read_recent_jsonl(paths.audit, limit)


def _records(paths: Paths) -> Iterator[Tuple[int, Optional[Dict[str, Any]]]]:
    sources = [paths.audit.with_name(f"{paths.audit.name}.1"), paths.audit]
    for source in sources:
        try:
            with source.open("rb") as handle:
                for number, raw in enumerate(handle, 1):
                    if raw.strip():
                        try:
                            record = json.loads(raw)
                        except ValueError:
                            yield number, None
                            continue
                        yield number, record if isinstance(record, dict) else None
        except OSError:
            continue


def verify_audit(paths: Paths) -> Tuple[bool, int, str]:
    """Walk the chain. Returns (intact, entries checked, what went wrong)."""
    checked = 0
    previous: Optional[str] = None
    expected_seq: Optional[int] = None
    for number, record in _records(paths):
        if record is None:
            return False, checked, f"line {number} is not a valid entry"
        if entry_hash(record) != record.get("hash"):
            return False, checked, f"entry {record.get('seq')} was altered"
        if previous is not None and record.get("prev") != previous:
            return False, checked, f"entry {record.get('seq')} does not follow the one before it"
        if expected_seq is not None and record.get("seq") != expected_seq:
            return False, checked, f"expected entry {expected_seq}, found {record.get('seq')}"
        previous = record["hash"]
        expected_seq = int(record.get("seq", 0)) + 1
        checked += 1

    head = read_json(paths.audit_head, {})
    if isinstance(head, dict) and head.get("hash") and head["hash"] != (previous or GENESIS):
        if checked or head.get("seq"):
            return False, checked, f"the log should end at entry {head.get('seq')}: entries are missing"
    return True, checked, ""
