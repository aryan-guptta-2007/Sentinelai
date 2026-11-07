#!/usr/bin/env python3
"""SentinelAI responder: acts on threats, or records what it would do in dry-run.

Untrusted values from logs reach this module, so every target is validated with a
strict parser and external commands only ever receive argument lists. No shell or
generated source code is involved.
"""

from __future__ import annotations

import collections
import getpass
import hashlib
import ipaddress
import os
import re
import sys
import time
from pathlib import Path
from typing import Any, Callable, Deque, Dict, List, Optional, Set, Tuple

if __package__ in (None, ""):  # allow `python responder/responder.py`
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import psutil

from common.audit import AuditLog
from common.runtime import (
    Follower,
    Paths,
    atomic_write_json,
    deliver,
    exit_with_supervisor,
    file_lock,
    get_paths,
    harden_process,
    load_config,
    make_logger,
    now_iso,
    parse_ts,
    read_json,
    run_mode,
    unsafe_data_dir,
)
from responder import system
from responder.accounts import Accounts
from responder.firewall import Firewall
from responder.system import IPAddress, IPNetwork, parse_ip, process_key, read_list

log_message = make_logger("responder", "responder.log")

SWEEP_EVERY_SEC = 15
RECONCILE_EVERY_SEC = 60
GATEWAY_REFRESH_SEC = 300
LOCK_TIMEOUT_SEC = 30.0
EVIDENCE_HASH_LIMIT = 64 * 1024 * 1024
OFFENDER_MEMORY_SEC = 30 * 86400
USERNAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,31}\$?$")
ALWAYS_PROTECTED_USERS = {"root", "system", "administrator", "local service", "network service"}
ALWAYS_PROTECTED_PROCESSES = {
    "system", "smss", "csrss", "wininit", "winlogon", "services", "lsass", "svchost",
    "init", "systemd", "kthreadd",
}
DEFAULT_ALLOWED_NETWORKS = ("127.0.0.0/8", "::1/128")


def local_addresses() -> Set[IPAddress]:
    return system.local_addresses()


def load_allowed_networks(path: Path) -> List[IPNetwork]:
    networks = [ipaddress.ip_network(net) for net in DEFAULT_ALLOWED_NETWORKS]
    for entry in read_list(path):
        try:
            networks.append(ipaddress.ip_network(entry, strict=False))
        except ValueError:
            log_message(f"ignoring invalid allow-list entry: {entry}")
    return networks


def threat_time(threat: Dict[str, Any]) -> Optional[float]:
    """When this actually happened.

    The oldest stamp wins. A backlog replayed after downtime is scored afresh, so its
    newer stamps say nothing about how old the event is.
    """
    alert = threat.get("alert") or {}
    event = alert.get("event") or {}
    stamps = [parse_ts(item.get("ts")) for item in (event, alert, threat)]
    known = [stamp.timestamp() for stamp in stamps if stamp is not None]
    return min(known) if known else None


class Responder:
    def __init__(self, config: Dict[str, Any], paths: Paths):
        section = config.get("responder", {})
        self.paths = paths
        self.dry_run = run_mode(config) != "enforce"
        self.block_timeout = int(section.get("block_timeout_sec", 3600))
        self.max_block = int(section.get("max_block_sec", 7 * 86400))
        self.max_age = int(section.get("max_threat_age_sec", 300))
        self.rate_limit = int(section.get("max_actions_per_minute", 30))
        self.act_on_protected = bool(section.get("kill_protected_users", False))
        self.protected_processes = ALWAYS_PROTECTED_PROCESSES | {
            process_key(name) for name in section.get("protected_processes", [])
        }
        self.firewall = Firewall(str(section.get("firewall", "auto")))
        self.accounts = Accounts()
        self.audit = AuditLog(paths)
        self.state_lock = paths.state_dir / ".responder.lock"
        self.recent: Dict[str, Deque[float]] = collections.defaultdict(collections.deque)
        self.allowed_networks: List[IPNetwork] = []
        self.protected_users: Set[str] = set(ALWAYS_PROTECTED_USERS)
        self.list_stamp: Optional[Tuple[Any, ...]] = None
        self.operators = self._operators()
        self.gateways: Set[IPAddress] = set()
        self.gateways_read = 0.0
        self.reload_lists()

        problem = unsafe_data_dir(paths)
        if problem and not self.dry_run:
            self.dry_run = True
            log_message(f"refusing to enforce, staying in dry-run: {problem}")

    @staticmethod
    def _operators() -> Set[str]:
        """The account running this, and whoever used sudo to start it.

        Locking one of these would shut the person in charge out of their own machine,
        which on a laptop means every process they own being killed as well.
        """
        names = {os.environ.get("SUDO_USER", "")}
        try:
            names.add(getpass.getuser())
        except (KeyError, OSError):
            pass
        return {name.lower() for name in names if name}

    # -------------------------------------------------------------------- lists
    def _list_paths(self) -> Tuple[Path, Path]:
        folder = self.paths.config_dir
        return folder / "allowlist_ips.txt", folder / "allowlist_users.txt"

    def _list_stamp(self) -> Tuple[Any, ...]:
        stamps = []
        for path in self._list_paths():
            try:
                stamps.append(path.stat().st_mtime_ns)
            except OSError:
                stamps.append(None)
        return tuple(stamps)

    def reload_lists(self) -> bool:
        """Read the allow-lists if they changed. An operator adding their own address
        during an incident must not have to restart anything."""
        stamp = self._list_stamp()
        if stamp == self.list_stamp:
            return False
        self.list_stamp = stamp
        addresses, users = self._list_paths()
        self.allowed_networks = load_allowed_networks(addresses)
        self.protected_users = ALWAYS_PROTECTED_USERS | {user.lower() for user in read_list(users)}
        return True

    def release_allow_listed(self) -> List[str]:
        """Lift blocks on anything that has since been allow-listed."""
        released = []
        for key in list(self._blocked()):
            address = parse_ip(key)
            if address and self._allow_listed(address):
                ok, detail = self.unblock(key)
                log_message(f"allow-listed, released ip={key}: {detail}")
                if ok:
                    released.append(key)
        return released

    # ----------------------------------------------------------------- dispatch
    def handle(self, threat: Dict[str, Any]) -> List[Dict[str, Any]]:
        plan = threat.get("plan") or []
        if not plan:
            alert = threat.get("alert") or {}
            log_message(f"no action for threat_ts={threat.get('ts')} type={alert.get('type')}")
            return []

        handlers: Dict[str, Callable[[str, Dict[str, Any]], Tuple[str, str]]] = {
            "block_ip": self.block_ip,
            "kill_process": self.kill_process,
            "lock_user": self.lock_user,
        }
        stale = self._is_stale(threat)
        simulated = ((threat.get("alert") or {}).get("event") or {}).get("src") == "simulator"
        entries = []
        for step in plan:
            action = str(step.get("action")) if isinstance(step, dict) else "invalid"
            target = str(step.get("target") or "") if isinstance(step, dict) else ""
            if action not in handlers:
                status, detail = "refused", f"unknown action {action!r}"
            elif stale:
                status, detail = "skipped", "threat too old to act on safely"
            elif simulated and not self.dry_run:
                status, detail = "dry_run", "simulated event, nothing was done"
            elif self._over_rate_limit(action):
                status, detail = "skipped", f"more than {self.rate_limit} {action} in a minute"
            else:
                status, detail = handlers[action](target, threat)
            entries.append(self._record(threat, action, target, status, detail))
        return entries

    def _is_stale(self, threat: Dict[str, Any]) -> bool:
        happened = threat_time(threat)
        return happened is None or time.time() - happened > self.max_age

    def _over_rate_limit(self, action: str) -> bool:
        """A flood of bad data must not turn into a flood of real actions."""
        recent = self.recent[action]
        now = time.monotonic()
        while recent and now - recent[0] > 60:
            recent.popleft()
        if len(recent) >= self.rate_limit:
            return True
        recent.append(now)
        return False

    def _record(self, threat, action, target, status, detail) -> Dict[str, Any]:
        alert = threat.get("alert") or {}
        entry = self.audit.append(
            {
                "ts": now_iso(),
                "threat_ts": threat.get("ts", ""),
                "action": action,
                "target": target,
                "status": status,
                "detail": detail,
                "dry_run": self.dry_run,
                "notes": alert.get("type", ""),
                "rule_id": alert.get("rule_id", ""),
                "incident": threat.get("incident", ""),
                "score": threat.get("threat_score"),
            }
        )
        log_message(f"{action} target={target} status={status} detail={detail}")
        return entry

    def _operator_record(self, action: str, target: str, detail: str) -> None:
        self.audit.append(
            {
                "ts": now_iso(), "action": action, "target": target, "status": "applied",
                "detail": detail, "dry_run": self.dry_run, "notes": "operator",
            }
        )

    # ----------------------------------------------------------------- block_ip
    def _state(self) -> Dict[str, Any]:
        data = read_json(self.paths.blocked, {})
        return data if isinstance(data, dict) else {}

    def _blocked(self) -> Dict[str, Any]:
        blocked = self._state().get("blocked", {})
        return blocked if isinstance(blocked, dict) else {}

    def _save(self, blocked: Dict[str, Any], offenders: Optional[Dict[str, Any]] = None) -> None:
        current = self._state().get("offenders", {})
        kept = offenders if offenders is not None else current
        atomic_write_json(self.paths.blocked, {"blocked": blocked, "offenders": kept})

    def _allow_listed(self, address: IPAddress) -> bool:
        return any(address in net for net in self.allowed_networks if net.version == address.version)

    def ip_refusal(self, address: IPAddress) -> Optional[str]:
        if address.is_loopback or address.is_unspecified or address.is_multicast:
            return "address is not a routable source"
        if self._allow_listed(address):
            return "allow-listed"
        if address in local_addresses():
            return "address belongs to this host"
        if address in self._gateways():
            return "address is this host's gateway"
        return None

    def _gateways(self) -> Set[IPAddress]:
        if time.monotonic() - self.gateways_read > GATEWAY_REFRESH_SEC or not self.gateways_read:
            self.gateways = system.default_gateways()
            self.gateways_read = time.monotonic()
        return self.gateways

    def _ban_length(self, offenders: Dict[str, Any], key: str) -> Tuple[int, Dict[str, Any]]:
        """Each return doubles the ban, so a persistent attacker stops being worth the noise."""
        now = time.time()
        kept = {
            ip: info for ip, info in offenders.items()
            if isinstance(info, dict) and now - float(info.get("last", 0)) < OFFENDER_MEMORY_SEC
        }
        strikes = int(kept.get(key, {}).get("strikes", 0))
        kept[key] = {"strikes": strikes + 1, "last": int(now)}
        if self.block_timeout <= 0:
            return self.block_timeout, kept
        return min(self.block_timeout * 2 ** min(strikes, 20), self.max_block), kept

    def block_ip(self, target: str, threat: Dict[str, Any]) -> Tuple[str, str]:
        address = parse_ip(target)
        if address is None:
            return "refused", "not a valid IP address"
        refusal = self.ip_refusal(address)
        if refusal:
            return "skipped", refusal

        with file_lock(self.state_lock, timeout=LOCK_TIMEOUT_SEC):
            state = self._state()
            blocked = self._blocked()
            key = str(address)
            current = blocked.get(key)
            active = isinstance(current, dict) and current.get("expires", 0) > time.time()
            # A dry-run entry must never stand in for a real block after switching to enforce.
            if active and bool(current.get("dry_run")) == self.dry_run:
                if self.dry_run:
                    return "skipped", "already blocked"
                # The saved state is only a record. A reboot or firewall reload can empty
                # the kernel's table, so a repeat offender is put back rather than trusted.
                remaining = int(current["expires"] - time.time())
                ok, message = self.firewall.block(address, remaining)
                return ("skipped", "already blocked") if ok else ("failed", message)

            offenders = state.get("offenders", {})
            length, offenders = self._ban_length(offenders if isinstance(offenders, dict) else {}, key)
            if self.dry_run:
                status, detail = "dry_run", f"would block for {length}s"
            else:
                ok, message = self.firewall.block(address, length)
                if not ok:
                    return "failed", message
                status, detail = "applied", f"blocked for {length}s via {self.firewall.backend}"

            blocked[key] = {
                "expires": int(time.time()) + length,
                "blocked_at": now_iso(),
                "dry_run": self.dry_run,
                "reason": (threat.get("alert") or {}).get("reason", ""),
                "strikes": offenders[key]["strikes"],
            }
            self._save(blocked, offenders)
        return status, detail

    def reconcile(self) -> List[str]:
        """Put back real blocks the kernel has lost, after a reboot or firewall reload."""
        if self.dry_run:
            return []
        now = time.time()
        active = {
            key: entry for key, entry in self._blocked().items()
            if isinstance(entry, dict) and not entry.get("dry_run") and entry.get("expires", 0) > now
        }
        if not active:
            return []
        present = self.firewall.present()
        restored = []
        for key, entry in active.items():
            address = parse_ip(key)
            if address is None or (present is not None and key in present):
                continue
            ok, detail = self.firewall.block(address, int(entry["expires"] - now))
            if ok:
                restored.append(key)
            else:
                log_message(f"could not restore block ip={key}: {detail}")
        if restored:
            log_message(f"restored blocks the firewall had lost: {', '.join(restored)}")
        return restored

    def sweep_expired(self) -> List[str]:
        """Remove lapsed blocks. Failed removals stay listed so they are retried."""
        with file_lock(self.state_lock, timeout=LOCK_TIMEOUT_SEC):
            blocked = self._blocked()
            now = time.time()
            removed = []
            for key, entry in list(blocked.items()):
                if entry.get("expires", 0) > now:
                    continue
                address = parse_ip(key)
                if address and not entry.get("dry_run"):
                    ok, detail = self.firewall.unblock(address)
                    if not ok:
                        log_message(f"failed to expire block ip={key}: {detail}")
                        continue
                del blocked[key]
                removed.append(key)
            if removed:
                self._save(blocked)
                log_message(f"expired blocks: {', '.join(removed)}")
        return removed

    def unblock(self, target: str) -> Tuple[bool, str]:
        address = parse_ip(target)
        if address is None:
            return False, "not a valid IP address"
        with file_lock(self.state_lock, timeout=LOCK_TIMEOUT_SEC):
            blocked = self._blocked()
            entry = blocked.get(str(address))
            if entry is None:
                return False, "address is not blocked"
            if not entry.get("dry_run"):
                ok, detail = self.firewall.unblock(address)
                if not ok:
                    return False, detail
            del blocked[str(address)]
            self._save(blocked)
        self._operator_record("unblock_ip", str(address), "unblocked")
        log_message(f"unblocked ip={address}")
        return True, "unblocked"

    # ------------------------------------------------------------- kill_process
    def sentinel_pids(self) -> Set[int]:
        pids = {os.getpid()}
        try:
            pids.update(parent.pid for parent in psutil.Process().parents())
        except psutil.Error:
            pass
        state = read_json(self.paths.supervisor, {})
        if isinstance(state, dict):
            if isinstance(state.get("pid"), int):
                pids.add(state["pid"])
            for info in (state.get("components") or {}).values():
                if isinstance(info, dict) and isinstance(info.get("pid"), int):
                    pids.add(info["pid"])
        return pids

    @staticmethod
    def _expected_names(threat: Dict[str, Any]) -> Set[str]:
        event = (threat.get("alert") or {}).get("event") or {}
        meta = event.get("meta") if isinstance(event.get("meta"), dict) else {}
        return {process_key(value) for value in (meta.get("proc"), meta.get("exe")) if value}

    def _identity_problem(self, process: psutil.Process, threat: Dict[str, Any]) -> Optional[str]:
        """A PID can be reused after the alert, so confirm it is the same process."""
        expected = self._expected_names(threat)
        if not expected:
            return "alert does not identify the process"

        names = {process_key(process.name())}
        try:
            exe = process.exe()
            if exe:
                names.add(process_key(exe))
        except psutil.Error:
            pass
        if not expected & names:
            return "PID now belongs to a different process"

        event = (threat.get("alert") or {}).get("event") or {}
        seen = parse_ts(event.get("ts"))
        if seen and process.create_time() > seen.timestamp() + 2:
            return "process started after the alert (PID reused)"
        return None

    def _capture_evidence(self, process: psutil.Process, threat: Dict[str, Any]) -> Optional[str]:
        """Record what the process was before it is gone for good."""
        record: Dict[str, Any] = {"captured": now_iso(), "pid": process.pid}
        reads: Dict[str, Callable[[], Any]] = {
            "name": process.name,
            "exe": process.exe,
            "cmdline": process.cmdline,
            "cwd": process.cwd,
            "user": process.username,
            "started": process.create_time,
            "parents": lambda: [parent.name() for parent in process.parents()],
            "connections": lambda: [
                {"local": str(item.laddr), "remote": str(item.raddr), "status": item.status}
                for item in process.net_connections(kind="inet")
            ],
        }
        for name, read in reads.items():
            try:
                record[name] = read()
            except (psutil.Error, OSError, RuntimeError):
                record[name] = None

        exe = record.get("exe")
        if exe:
            try:
                if os.path.getsize(exe) <= EVIDENCE_HASH_LIMIT:
                    with open(exe, "rb") as handle:
                        record["sha256"] = hashlib.sha256(handle.read()).hexdigest()
            except OSError:
                record["sha256"] = None

        record["alert"] = (threat.get("alert") or {}).get("reason", "")
        path = self.paths.evidence_dir / f"{int(time.time())}-{process.pid}.json"
        try:
            atomic_write_json(path, record)
        except OSError as exc:
            log_message(f"could not save evidence: {exc}")
            return None
        return path.name

    def kill_process(self, target: str, threat: Dict[str, Any]) -> Tuple[str, str]:
        if not target.isascii() or not target.isdigit():
            return "refused", "not a valid PID"
        pid = int(target)
        if pid <= 1:
            return "refused", "system PID"
        ours = self.sentinel_pids()
        if pid in ours:
            return "refused", "SentinelAI process"

        try:
            process = psutil.Process(pid)
            if process_key(process.name()) in self.protected_processes:
                return "refused", "protected process"
            owner = process.username().rsplit("\\", 1)[-1].lower()
            if owner in self.protected_users and not self.act_on_protected:
                return "refused", f"owned by protected user {owner}"
            problem = self._identity_problem(process, threat)
            if problem:
                return "refused", problem
        except psutil.NoSuchProcess:
            if self.dry_run:
                return "dry_run", "would kill (process is not running now)"
            return "skipped", "process is not running"
        except psutil.AccessDenied as exc:
            return "failed", f"cannot inspect process: {exc}"

        evidence = self._capture_evidence(process, threat)
        saved = f", evidence in {evidence}" if evidence else ""
        if self.dry_run:
            return "dry_run", f"would kill{saved}"

        try:
            # A shell left behind by a killed parent keeps the attacker's foothold.
            family = [item for item in process.children(recursive=True) if item.pid not in ours]
        except (psutil.Error, OSError, RuntimeError):
            family = []
        family = [process, *family]
        for member in family:
            try:
                member.terminate()
            except psutil.NoSuchProcess:
                pass
            except (psutil.Error, OSError, RuntimeError) as exc:
                if member is process:
                    return "failed", str(exc)
        _, survivors = psutil.wait_procs(family, timeout=3)
        for member in survivors:
            try:
                member.kill()
            except psutil.NoSuchProcess:
                pass
            except (psutil.Error, OSError, RuntimeError) as exc:
                return "failed", str(exc)
        psutil.wait_procs(survivors, timeout=3)
        return "applied", f"process killed{saved}"

    # ---------------------------------------------------------------- lock_user
    def _locked(self) -> Dict[str, Any]:
        data = read_json(self.paths.locked_users, {})
        return data if isinstance(data, dict) else {}

    def end_sessions(self, name: str) -> int:
        """A locked account's live sessions would otherwise carry on regardless."""
        ours = self.sentinel_pids()
        ended = 0
        for process in psutil.process_iter(["username"]):
            owner = str(process.info.get("username") or "").rsplit("\\", 1)[-1].lower()
            if owner != name.lower() or process.pid in ours or process.pid <= 1:
                continue
            try:
                process.kill()
                ended += 1
            except psutil.Error:
                continue
        return ended

    def lock_user(self, target: str, threat: Dict[str, Any]) -> Tuple[str, str]:
        if not USERNAME_RE.match(target):
            return "refused", "not a valid username"
        name = target.lower()
        if name in ALWAYS_PROTECTED_USERS:
            return "refused", "system account"
        if name in self.operators:
            return "refused", "the account running SentinelAI"
        if name in self.protected_users and not self.act_on_protected:
            return "refused", "protected user"
        if self.dry_run:
            return "dry_run", "would lock the account and end its sessions"

        with file_lock(self.state_lock, timeout=LOCK_TIMEOUT_SEC):
            locked = self._locked()
            if target in locked:
                ended = self.end_sessions(target)
                return "skipped", f"already locked, ended {ended} processes"
            ok, detail, prior = self.accounts.lock(target)
            if not ok:
                return "failed", detail
            locked[target] = {
                "locked_at": now_iso(),
                "prior": prior,
                "reason": (threat.get("alert") or {}).get("reason", ""),
            }
            atomic_write_json(self.paths.locked_users, locked)
        ended = self.end_sessions(target)
        return "applied", f"account locked, ended {ended} processes"

    def unlock_user(self, target: str) -> Tuple[bool, str]:
        if not USERNAME_RE.match(target):
            return False, "not a valid username"
        with file_lock(self.state_lock, timeout=LOCK_TIMEOUT_SEC):
            locked = self._locked()
            entry = locked.get(target)
            if entry is None:
                return False, "account was not locked by SentinelAI"
            ok, detail = self.accounts.unlock(target, entry.get("prior") or {})
            if not ok:
                return False, detail
            del locked[target]
            atomic_write_json(self.paths.locked_users, locked)
        self._operator_record("unlock_user", target, "unlocked")
        log_message(f"unlocked user={target}")
        return True, "unlocked"

    # -------------------------------------------------------------- housekeeping
    def maintain(self) -> None:
        if self.reload_lists():
            self.release_allow_listed()
        self.sweep_expired()


def main() -> None:
    harden_process()
    exit_with_supervisor()
    config = load_config()
    paths = get_paths(config).ensure()
    responder = Responder(config, paths)
    follow = bool(config["modes"].get("follow_files", True))
    mode = "dry-run" if responder.dry_run else "ENFORCE"
    log_message(f"started mode={mode} firewall={responder.firewall.backend}")
    responder.reconcile()

    paths.threats.touch(exist_ok=True)
    follower = Follower(paths.threats, "responder", paths.state_dir)
    last_sweep = last_reconcile = time.monotonic()
    while True:
        for raw in follower.read_available():
            deliver(raw, responder.handle, log_message, paths.dead_letters)

        now = time.monotonic()
        if now - last_sweep >= SWEEP_EVERY_SEC:
            responder.maintain()
            last_sweep = now
        if now - last_reconcile >= RECONCILE_EVERY_SEC:
            responder.reconcile()
            last_reconcile = now
        if not follow:
            responder.maintain()
            return
        time.sleep(follower.poll_sec)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
