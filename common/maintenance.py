"""Keep disk use bounded without needing cron. The supervisor calls this once an hour.

Data files are rotated by renaming, never by copying and truncating, so nothing written
during a rotation can fall into a gap. Readers finish the renamed file before moving on.
"""

from __future__ import annotations

import gzip
import os
import shutil
import time
from pathlib import Path
from typing import Any, Dict, List

from common.runtime import METRIC_FIELDS, Paths

MEGABYTE = 1024 * 1024
DATA_FILES = ("events", "alerts", "threats", "audit", "dead_letters")


def archive_dir(paths: Paths) -> Path:
    return paths.data_dir / "archive"


def compress(source: Path, folder: Path) -> None:
    folder.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d_%H%M%S", time.gmtime())
    target = folder / f"{source.name}.{stamp}.gz"
    with source.open("rb") as reader, gzip.open(target, "wb") as writer:
        shutil.copyfileobj(reader, writer)
    source.unlink()


def rotate_file(path: Path, limit_bytes: int, folder: Path) -> bool:
    """Rename a file that has grown too big, keeping the copy readers may still need."""
    try:
        if path.stat().st_size < limit_bytes:
            return False
        previous = path.with_name(f"{path.name}.1")
        if previous.exists():
            compress(previous, folder)
        os.replace(path, previous)
        return True
    except OSError:
        return False  # Windows refuses while a reader has it open, so this waits for next time


def trim_metrics(path: Path, max_rows: int) -> bool:
    """The anomaly model needs recent history, so old rows go rather than the whole file."""
    try:
        lines = path.read_bytes().splitlines(keepends=True)
    except OSError:
        return False
    if len(lines) <= max_rows:
        return False
    header = ",".join(METRIC_FIELDS).encode("utf-8") + b"\n"
    temporary = path.with_name(f"{path.name}.tmp")
    try:
        temporary.write_bytes(header + b"".join(lines[-max_rows // 2:]))
        os.replace(temporary, path)
        return True
    except OSError:
        temporary.unlink(missing_ok=True)
        return False


def trim_output_log(path: Path, limit_bytes: int) -> None:
    """Child processes hold these open, so they can only be emptied in place."""
    try:
        if path.stat().st_size >= limit_bytes:
            with path.open("r+b") as handle:
                handle.truncate(0)
    except OSError:
        pass


def delete_old(folder: Path, days: float) -> int:
    cutoff = time.time() - days * 86400
    removed = 0
    try:
        for item in folder.iterdir():
            if item.is_file() and item.stat().st_mtime < cutoff:
                item.unlink()
                removed += 1
    except OSError:
        pass
    return removed


def run_maintenance(config: Dict[str, Any], paths: Paths) -> List[str]:
    section = config.get("retention", {})
    data_limit = int(float(section.get("max_data_mb", 100)) * MEGABYTE)
    log_limit = int(float(section.get("max_log_mb", 20)) * MEGABYTE)
    folder = archive_dir(paths)

    rotated = []
    for name in DATA_FILES:
        path = getattr(paths, name)
        if rotate_file(path, data_limit, folder):
            rotated.append(path.name)
    for path in paths.logs_dir.glob("*.log"):
        if path.name.endswith(".out.log"):
            trim_output_log(path, log_limit)
        elif rotate_file(path, log_limit, folder):
            rotated.append(path.name)
    if trim_metrics(paths.metrics, int(section.get("max_metric_rows", 50000))):
        rotated.append(paths.metrics.name)
    delete_old(folder, float(section.get("archive_days", 14)))
    return rotated
