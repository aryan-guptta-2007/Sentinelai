"""Paths, configuration, time handling, locks and durable JSONL I/O.

Nothing here touches the filesystem at import time, so modules can be imported
by tests or read-only containers without side effects. Locations are resolved
on each call, which lets ``SENTINELAI_HOME`` and friends redirect a whole run.
"""

from __future__ import annotations

import contextlib
import datetime as dt
import json
import os
import secrets
import tempfile
import threading
import time
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, Optional, Tuple

VERSION = "2.0.0"
CODE_ROOT = Path(__file__).resolve().parents[1]
RUN_MODES = ("dry-run", "enforce")
SUPERVISOR_ENV = "SENTINELAI_SUPERVISOR_PID"
TOKEN_ENV = "SENTINELAI_DASHBOARD_TOKEN"
OFFSET_SAVE_EVERY = 200  # lines between saves of a reader's position
METRIC_FIELDS = [
    "ts", "cpu_pct", "mem_used_mb", "mem_total_mb", "load1", "load5", "load15",
    "procs", "conns", "net_in_kbps", "net_out_kbps",
]


class ConfigError(ValueError):
    """Raised when a configuration file cannot be used."""


# --------------------------------------------------------------------------- paths
@dataclass(frozen=True)
class Paths:
    root: Path
    config_dir: Path
    data_dir: Path
    logs_dir: Path

    @property
    def state_dir(self) -> Path:
        return self.data_dir / "state"

    @property
    def events(self) -> Path:
        return self.data_dir / "events.jsonl"

    @property
    def alerts(self) -> Path:
        return self.data_dir / "alerts.jsonl"

    @property
    def threats(self) -> Path:
        return self.data_dir / "threats.jsonl"

    @property
    def audit(self) -> Path:
        return self.data_dir / "audit.jsonl"

    @property
    def dead_letters(self) -> Path:
        return self.data_dir / "dead_letters.jsonl"

    @property
    def metrics(self) -> Path:
        return self.data_dir / "resource_metrics.csv"

    @property
    def evidence_dir(self) -> Path:
        return self.data_dir / "evidence"

    @property
    def commands_dir(self) -> Path:
        return self.data_dir / "commands"

    @property
    def blocked(self) -> Path:
        return self.state_dir / "blocked_ips.json"

    @property
    def locked_users(self) -> Path:
        return self.state_dir / "locked_users.json"

    @property
    def audit_head(self) -> Path:
        return self.state_dir / "audit_head.json"

    @property
    def supervisor(self) -> Path:
        return self.state_dir / "supervisor.json"

    @property
    def dashboard_token(self) -> Path:
        return self.state_dir / "dashboard_token.json"

    @property
    def reports_dir(self) -> Path:
        return self.root / "reporter-output" / "reports"

    def ensure(self) -> "Paths":
        for path in (self.data_dir, self.logs_dir, self.state_dir):
            path.mkdir(parents=True, exist_ok=True)
        return self


def root_dir() -> Path:
    override = os.environ.get("SENTINELAI_HOME")
    return Path(override).resolve() if override else CODE_ROOT


def load_config() -> Dict[str, Any]:
    path = root_dir() / "config" / "sentinelai.toml"
    try:
        return tomllib.loads(path.read_text(encoding="utf-8-sig"))
    except OSError as exc:
        raise ConfigError(f"{path}: {exc}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"{path.name}: {exc}") from exc


def get_paths(config: Optional[Dict[str, Any]] = None) -> Paths:
    cfg = config if config is not None else load_config()
    root = root_dir()
    section = cfg.get("paths", {})
    data = os.environ.get("SENTINELAI_DATA_DIR") or section.get("data_dir", "data")
    logs = os.environ.get("SENTINELAI_LOGS_DIR") or section.get("logs_dir", "logs")
    return Paths(root, root / "config", root / data, root / logs)


_paths_cache: Dict[Tuple[Optional[str], ...], Paths] = {}


def cached_paths() -> Paths:
    """Resolve paths once per environment, for code that runs on every log line."""
    key = tuple(
        os.environ.get(name)
        for name in ("SENTINELAI_HOME", "SENTINELAI_DATA_DIR", "SENTINELAI_LOGS_DIR")
    )
    if key not in _paths_cache:
        _paths_cache[key] = get_paths()
    return _paths_cache[key]


def run_mode(config: Dict[str, Any]) -> str:
    """Return the effective mode. Anything unrecognised fails safe to dry-run."""
    mode = os.environ.get("SENTINELAI_RUN_MODE") or config.get("modes", {}).get("run_mode")
    return mode if mode in RUN_MODES else "dry-run"


# ------------------------------------------------------------------- file protection
def harden_process() -> None:
    """Keep everything this process creates private.

    Events hold usernames, and people regularly type a password into the username
    prompt, so none of this may be readable by other local accounts.
    """
    if os.name == "posix":
        os.umask(0o077)


def _harden_windows(folder: Path) -> None:
    """Folders outside the user profile inherit "Users can modify" from their parent, and
    a responder running as Administrator acts on what is in them. Well-known SIDs are
    used because the names of these groups change with the language of Windows.

    This must only touch the folder. Everything inside inherits from it, and running it
    over each file (/T) strips the inherited entries while the inheritable grants do not
    apply to files, which leaves files nobody can open.
    """
    import getpass
    import subprocess

    grants = ["*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F", f"{getpass.getuser()}:(OI)(CI)F"]
    try:
        subprocess.run(
            ["icacls", str(folder), "/inheritance:r", *[item for g in grants for item in ("/grant:r", g)], "/Q"],
            capture_output=True,
            timeout=60,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        pass


def harden_paths(paths: Paths) -> None:
    """Tighten what already exists, so upgrading a host closes the same gap."""
    if os.name != "posix":
        for folder in (paths.data_dir, paths.logs_dir):
            if folder.exists():
                _harden_windows(folder)
        return
    take_ownership = os.geteuid() == 0
    for folder in (paths.data_dir, paths.logs_dir):
        if not folder.exists():
            continue
        for current, directories, files in os.walk(folder):
            base = Path(current)
            for name, mode in [(d, 0o700) for d in directories] + [(f, 0o600) for f in files]:
                _protect(base / name, mode, take_ownership)
        _protect(folder, 0o700, take_ownership)


def _protect(path: Path, mode: int, take_ownership: bool) -> None:
    try:
        if take_ownership:
            os.chown(path, 0, 0, follow_symlinks=False)
        if not path.is_symlink():
            os.chmod(path, mode)
    except OSError:
        pass


def unsafe_data_dir(paths: Paths) -> Optional[str]:
    """Explain why the data files cannot be trusted, or return None if they can.

    The responder acts on these files with full privileges, so anyone else who can
    write them could make it kill or lock whatever they choose.
    """
    if os.name != "posix":
        return None
    for path in (paths.data_dir, paths.state_dir, paths.threats):
        try:
            info = path.stat()
        except OSError:
            continue
        if info.st_uid != os.geteuid():
            return f"{path} belongs to uid {info.st_uid}, not this process"
        if info.st_mode & 0o022:
            return f"{path} can be written by other accounts"
    return None


# ---------------------------------------------------------------------------- time
def utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def now_iso() -> str:
    return utc_now().strftime("%Y-%m-%dT%H:%M:%SZ")


def to_iso(moment: dt.datetime) -> str:
    return moment.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_ts(value: Any) -> Optional[dt.datetime]:
    """Parse an ISO timestamp into an aware UTC datetime, or None if unusable."""
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def event_epoch(event: Dict[str, Any]) -> float:
    parsed = parse_ts(event.get("ts"))
    return parsed.timestamp() if parsed else time.time()


# ----------------------------------------------------------------------- lifecycle
def exit_with_supervisor(poll_sec: float = 1.0) -> None:
    """Stop this process if the supervisor dies without shutting it down.

    A supervisor that is killed or loses its console cannot stop its children, and an
    orphaned responder would keep acting with nobody watching it. Components started
    by hand have no supervisor, so this does nothing for them.
    """
    raw = os.environ.get(SUPERVISOR_ENV)
    if not raw:
        return

    import psutil

    try:
        supervisor = psutil.Process(int(raw))
    except (ValueError, psutil.Error):
        os._exit(0)

    def alive() -> bool:
        try:
            return supervisor.is_running() and supervisor.status() != psutil.STATUS_ZOMBIE
        except psutil.Error:
            return False

    def watch() -> None:
        while alive():
            time.sleep(poll_sec)
        os._exit(0)

    threading.Thread(target=watch, name="supervisor-watch", daemon=True).start()


# ------------------------------------------------------------------------- logging
def make_logger(component: str, filename: str) -> Callable[[str], None]:
    def log(message: str) -> None:
        # Log text can carry attacker input, so it must stay on one line.
        clean = " ".join(str(message).split())[:1000]
        line = f"{now_iso()} [{component}] {clean}\n"
        target = cached_paths().logs_dir / filename
        try:
            with target.open("a", encoding="utf-8") as handle:
                handle.write(line)
        except FileNotFoundError:
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open("a", encoding="utf-8") as handle:
                handle.write(line)

    return log


# --------------------------------------------------------------------------- locks
if os.name == "nt":
    import msvcrt

    def _try_lock(handle: Any) -> bool:
        handle.seek(0)
        try:
            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            return True
        except OSError:
            return False

    def _unlock(handle: Any) -> None:
        handle.seek(0)
        msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)

else:
    import fcntl

    def _try_lock(handle: Any) -> bool:
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            return True
        except OSError:
            return False

    def _unlock(handle: Any) -> None:
        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


@contextlib.contextmanager
def file_lock(path: Path, timeout: float = 10.0) -> Iterator[None]:
    """Hold an exclusive lock across processes for one read-modify-write."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+b") as handle:
        deadline = time.monotonic() + timeout
        while not _try_lock(handle):
            if time.monotonic() >= deadline:
                raise TimeoutError(f"could not lock {path}")
            time.sleep(0.01)
        try:
            yield
        finally:
            _unlock(handle)


class InstanceLock:
    """Held for a process's whole life. The OS releases it if the process dies."""

    def __init__(self, path: Path):
        self.path = path
        self.handle: Any = None

    def acquire(self) -> bool:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        handle = self.path.open("a+b")
        if _try_lock(handle):
            self.handle = handle
            return True
        handle.close()
        return False

    def release(self) -> None:
        if self.handle is not None:
            _unlock(self.handle)
            self.handle.close()
            self.handle = None


# ----------------------------------------------------------------------- file I/O
def atomic_write_json(path: Path, payload: Any) -> None:
    """Write JSON so a crash can never leave a half-written state file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
        for attempt in range(5):
            try:
                os.replace(tmp, path)
                return
            except PermissionError:  # Windows: a reader briefly holds the target open
                if attempt == 4:
                    raise
                time.sleep(0.05 * (attempt + 1))
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def read_json(path: Path, default: Any) -> Any:
    try:
        text = path.read_text(encoding="utf-8-sig")
        return json.loads(text) if text.strip() else default
    except (OSError, ValueError):
        return default


def dashboard_token(paths: Paths) -> str:
    """Return the dashboard's access token, creating it the first time."""
    configured = os.environ.get(TOKEN_ENV)
    if configured:
        return configured

    def saved_token() -> Optional[str]:
        saved = read_json(paths.dashboard_token, {})
        return saved.get("token") if isinstance(saved, dict) else None

    # Reading needs no lock, which matters in a container with the data mounted read-only.
    token = saved_token()
    if token:
        return str(token)
    with file_lock(paths.state_dir / ".token.lock"):
        token = saved_token()
        if not token:
            token = secrets.token_urlsafe(32)
            atomic_write_json(paths.dashboard_token, {"token": token})
    return str(token)


def _append(path: Path, data: bytes) -> None:
    try:
        handle = path.open("ab")
    except FileNotFoundError:
        path.parent.mkdir(parents=True, exist_ok=True)
        handle = path.open("ab")
    with handle:
        handle.write(data)


def append_bytes(path: Path, data: bytes) -> None:
    """Append with one write, so concurrent writers cannot interleave."""
    if os.name == "nt":
        # Windows emulates append with a seek, so two writers can overwrite each other.
        with file_lock(path.with_name(f".{path.name}.lock")):
            _append(path, data)
    else:
        _append(path, data)


def append_jsonl(path: Path, record: Dict[str, Any]) -> None:
    append_bytes(path, (json.dumps(record, separators=(",", ":")) + "\n").encode("utf-8"))


def append_jsonl_batch(path: Path, records: list[Dict[str, Any]]) -> None:
    if not records:
        return
    data = ("\n".join(json.dumps(record, separators=(",", ":")) for record in records) + "\n").encode("utf-8")
    append_bytes(path, data)


def read_recent_jsonl(path: Path, limit: int = 5000, max_bytes: int = 16 * 1024 * 1024) -> list[dict]:
    """Return the newest records without loading an arbitrarily large file."""
    try:
        size = path.stat().st_size
        with path.open("rb") as handle:
            start = max(0, size - max_bytes)
            handle.seek(start)
            blob = handle.read()
    except OSError:
        return []

    lines = blob.split(b"\n")
    if start > 0:
        lines = lines[1:]  # the first line is probably cut in half
    lines = [line for line in lines if line.strip()]
    items: list[dict] = []
    for raw in lines[-limit:] if limit else lines:
        try:
            obj = json.loads(raw.decode("utf-8", errors="replace"))
        except ValueError:
            continue
        if isinstance(obj, dict):
            items.append(obj)
    return items


def deliver(
    raw: str,
    handler: Callable[[Dict[str, Any]], Any],
    log: Callable[[str], None],
    dead_letters: Path,
) -> None:
    """Hand one JSONL record to its consumer.

    A record that cannot be processed would otherwise be retried forever and hold up
    everything behind it, so it is set aside for inspection. Disk errors are not the
    record's fault, so they are raised and the line is retried after a restart.
    """
    if not raw.strip():
        return
    try:
        record = json.loads(raw)
        if not isinstance(record, dict):
            raise ValueError("record is not an object")
        handler(record)
    except OSError:
        raise
    except Exception as exc:
        log(f"set aside a bad record ({exc!r}): {raw[:200]}")
        append_bytes(dead_letters, (raw + "\n").encode("utf-8"))


class Follower:
    """Tail a line-based file with at-least-once delivery.

    The read position is saved per consumer, so lines written while a component was
    down are picked up when it returns. Only complete lines are delivered. When a file
    is rotated by renaming, the rest of the old file is read first, so nothing written
    just before the rotation is lost. ``truncated`` is set if a file shrinks in place,
    which is how a cleared log looks.

    A consumer that dies between saves sees up to ``OFFSET_SAVE_EVERY`` lines again.
    Every stage tolerates that: alerts have cooldowns and actions are idempotent.
    """

    def __init__(
        self,
        path: Path,
        consumer: str,
        state_dir: Path,
        poll_sec: float = 0.25,
        start_at_end: bool = False,
    ):
        self.path = path
        self.poll_sec = poll_sec
        self.state_file = state_dir / f"offset_{consumer}.json"
        self.truncated = False
        saved = read_json(self.state_file, None)
        if isinstance(saved, dict):
            self.offset = int(saved.get("offset", 0))
            self.inode = saved.get("inode")
        else:
            self.offset, self.inode = 0, None
            if start_at_end:
                self._skip_existing()

    def _skip_existing(self) -> None:
        """On the very first run, history is not news."""
        try:
            info = self.path.stat()
        except OSError:
            return
        self.offset, self.inode = info.st_size, info.st_ino
        self._save()

    def _save(self) -> None:
        atomic_write_json(self.state_file, {"offset": self.offset, "inode": self.inode})

    def _read_lines(self, path: Path) -> Iterator[str]:
        unsaved = 0
        try:
            with path.open("rb") as handle:
                handle.seek(self.offset)
                while True:
                    raw = handle.readline()
                    if not raw.endswith(b"\n"):
                        break  # the writer has not finished this line yet
                    yield raw.decode("utf-8", errors="replace").rstrip("\r\n")
                    self.offset += len(raw)
                    unsaved += 1
                    if unsaved >= OFFSET_SAVE_EVERY:
                        self._save()
                        unsaved = 0
        finally:
            if unsaved:
                self._save()

    def _rotated_copy(self) -> Optional[Path]:
        candidate = self.path.with_name(f"{self.path.name}.1")
        try:
            return candidate if candidate.stat().st_ino == self.inode else None
        except OSError:
            return None

    def read_available(self) -> Iterator[str]:
        """Yield each complete unread line, saving progress as lines are handled."""
        try:
            info = self.path.stat()
        except OSError:
            return

        if self.inode not in (None, info.st_ino):
            rotated = self._rotated_copy()
            if rotated is not None:
                yield from self._read_lines(rotated)
            self.offset = 0
        elif info.st_size < self.offset:
            self.truncated = True
            self.offset = 0
        self.inode = info.st_ino
        if info.st_size == self.offset:
            return
        yield from self._read_lines(self.path)

    def follow(self, should_stop: Callable[[], bool] = lambda: False) -> Iterator[str]:
        while not should_stop():
            yield from self.read_available()
            time.sleep(self.poll_sec)
