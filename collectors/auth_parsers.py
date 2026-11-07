"""Turn authentication log lines into events.

Everything in these lines is hostile until proven otherwise. The rules that keep it safe:

* A line counts only if the program field names the program that really logs it. A
  `sudo` line whose command contains "Failed password ... from 8.8.8.8" is not an sshd
  failure, and treating it as one lets a local user get any address blocked.
* Patterns are anchored at both ends. sshd writes the source address after the username,
  and the username belongs to the attacker, so a login attempted as
  "x from 8.8.8.8 port 1" must not read as coming from 8.8.8.8. Greedy matching gives
  the address sshd itself wrote at the end of the line.
* Plain log files can still be forged by anyone who can write to syslog, for example with
  `logger -t sshd`. The journal records who really wrote a line, so `journal_entry_events`
  checks that and is preferred wherever it is available.
"""

from __future__ import annotations

import datetime as dt
import re
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

from common.runtime import to_iso, utc_now

MAX_MESSAGE = 500
MAX_REPEATS = 100
ADDR = r"(?P<ip>[0-9a-fA-F:.]+)"
PROGRAM = r"(?P<program>[A-Za-z0-9_.-]+)(?:\[(?P<pid>\d+)\])?"

TRADITIONAL_LINE = re.compile(
    rf"^(?P<month>[A-Z][a-z]{{2}})\s+(?P<day>\d{{1,2}})\s+(?P<clock>\d\d:\d\d:\d\d)\s+"
    rf"(?P<host>\S+)\s+{PROGRAM}:\s?(?P<message>.*)$"
)
ISO_LINE = re.compile(
    rf"^(?P<stamp>\d{{4}}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:?\d\d))\s+"
    rf"(?P<host>\S+)\s+{PROGRAM}:\s?(?P<message>.*)$"
)

REPEATED = re.compile(r"^message repeated (?P<count>\d+) times: \[\s*(?P<inner>.*)\]$")
FAILED = re.compile(
    rf"^Failed (?P<method>\S+) for (?P<invalid>invalid user )?(?P<user>.*) "
    rf"from {ADDR} port (?P<port>\d+)(?: ssh2)?$"
)
ACCEPTED = re.compile(
    rf"^Accepted (?P<method>\S+) for (?P<user>\S+) from {ADDR} port (?P<port>\d+)(?: ssh2)?(?:: .*)?$"
)
INVALID_USER = re.compile(rf"^Invalid user (?P<user>.*) from {ADDR}(?: port (?P<port>\d+))?$")
MAX_ATTEMPTS = re.compile(
    rf"^error: maximum authentication attempts exceeded for (?:invalid user )?(?P<user>.*) "
    rf"from {ADDR} port (?P<port>\d+)(?: ssh2)?(?: \[preauth\])?$"
)
PREAUTH_CLOSE = re.compile(
    rf"^(?:Connection closed by|Disconnected from|Connection reset by) "
    rf"(?:authenticating|invalid) user (?P<user>.*) {ADDR} port (?P<port>\d+) \[preauth\]$"
)
SCANNER = re.compile(
    rf"^(?:Did not receive identification string from {ADDR}(?: port (?P<port>\d+))?"
    rf"|Unable to negotiate with {ADDR.replace('ip', 'ip2')} port (?P<port2>\d+):.*)$"
)

SUDO_LINE = re.compile(r"^\s*(?P<user>[^\s:]+) : (?P<rest>.*)$")
SUDO_ATTEMPTS = re.compile(r"^(?P<count>\d+) incorrect password attempts? ;")
SUDO_DENIED = re.compile(r"^(?:user NOT in sudoers|user NOT authorized on host|command not allowed) ;")
SUDO_RAN = re.compile(r"^TTY=\S+ ; PWD=.* ; USER=(?P<as_user>\S+) ; (?:.* ; )?COMMAND=(?P<command>.*)$")

SU_FAILED = re.compile(
    r"^pam_unix\(su(?:-l)?:auth\): authentication failure;.*\bruser=(?P<ruser>\S*)\s.*\buser=(?P<user>\S+)\s*$"
)
SU_FAILED_OLD = re.compile(r"^FAILED SU \(to (?P<user>\S+)\) (?P<ruser>\S+) on ")

NEW_USER = re.compile(r"^new user: name=(?P<user>[\w.-]+)(?P<rest>.*)$")
UID_CHANGE = re.compile(r"^change user '(?P<user>[^']+)' UID from '(?P<old>\d+)' to '(?P<new>\d+)'$")
GROUP_ADD = re.compile(r"^add '(?P<user>[^']+)' to group '(?P<group>[^']+)'$")
GPASSWD_ADD = re.compile(r"^user (?P<user>\S+) added by (?P<by>\S+) to group (?P<group>\S+)$")
USER_DELETED = re.compile(r"^delete user '(?P<user>[^']+)'$")
PASSWORD_CHANGED = re.compile(r"^pam_unix\((?:passwd|chpasswd):chauthtok\): password changed for (?P<user>\S+)$")
CRONTAB_CHANGED = re.compile(r"^\((?P<user>[^)]+)\) (?P<verb>REPLACE|DELETE)\b")

SSH_PROGRAMS = {"sshd", "sshd-session"}
ROOT_ONLY_PROGRAMS = SSH_PROGRAMS | {"useradd", "usermod", "userdel", "groupmems", "gpasswd"}
JOURNAL_PROGRAMS = sorted(ROOT_ONLY_PROGRAMS | {"sudo", "su", "passwd", "chpasswd", "crontab"})


@dataclass(frozen=True)
class LogLine:
    when: dt.datetime
    host: str
    program: str
    pid: Optional[int]
    message: str


def _resolve_traditional(month: str, day: str, clock: str, now: dt.datetime) -> Optional[dt.datetime]:
    """Traditional syslog stamps have no year or zone, so they are local and this year,
    unless that puts them in the future, which means the line is from last December."""
    year = now.astimezone().year
    for candidate in (year, year - 1):
        try:
            naive = dt.datetime.strptime(f"{candidate} {month} {day} {clock}", "%Y %b %d %H:%M:%S")
        except ValueError:
            continue  # 29 February, or nonsense
        parsed = naive.astimezone(dt.timezone.utc)
        if parsed <= now + dt.timedelta(days=1):
            return parsed
    return None


def parse_syslog(line: str, now: Optional[dt.datetime] = None) -> Optional[LogLine]:
    moment = now or utc_now()
    match = ISO_LINE.match(line)
    if match:
        try:
            when = dt.datetime.fromisoformat(match["stamp"].replace("Z", "+00:00"))
        except ValueError:
            return None
    else:
        match = TRADITIONAL_LINE.match(line)
        if not match:
            return None
        resolved = _resolve_traditional(match["month"], match["day"], match["clock"], moment)
        if resolved is None:
            return None
        when = resolved

    return LogLine(
        when=min(when.astimezone(dt.timezone.utc), moment),
        host=match["host"],
        program=match["program"],
        pid=int(match["pid"]) if match["pid"] else None,
        message=match["message"],
    )


def _event(kind: str, **fields: Any) -> Dict[str, Any]:
    return {"type": kind, **{key: value for key, value in fields.items() if value not in (None, "")}}


def _ssh_event(event_type: str, match: re.Match, **meta: Any) -> Dict[str, Any]:
    groups = match.groupdict()
    port = groups.get("port")
    return _event(
        event_type,
        user=groups.get("user"),
        ip=groups.get("ip"),
        port=int(port) if port else None,
        meta={"source_log": "auth", **{k: v for k, v in meta.items() if v not in (None, "")}},
    )


def _parse_ssh_once(message: str) -> List[Dict[str, Any]]:
    match = FAILED.match(message)
    if match:
        return [_ssh_event("auth_fail", match, method=match["method"], invalid=bool(match["invalid"]) or None)]
    match = ACCEPTED.match(message)
    if match:
        return [_ssh_event("auth_success", match, method=match["method"])]
    # These appear once per connection, without any password guess. A server that only
    # accepts keys shows brute force like this and nothing else. They are kept apart from
    # auth_fail so a guess is not counted twice.
    match = INVALID_USER.match(message)
    if match:
        return [_ssh_event("auth_probe", match, kind="invalid_user")]
    match = MAX_ATTEMPTS.match(message)
    if match:
        return [_ssh_event("auth_probe", match, kind="max_attempts")]
    match = PREAUTH_CLOSE.match(message)
    if match:
        return [_ssh_event("auth_probe", match, kind="preauth_close")]
    match = SCANNER.match(message)
    if match:
        address = match["ip"] or match["ip2"]
        port = match["port"] or match["port2"]
        return [
            _event("auth_probe", ip=address, port=int(port) if port else None,
                   meta={"source_log": "auth", "kind": "scanner"})
        ]
    return []


def _parse_ssh(message: str) -> List[Dict[str, Any]]:
    repeated = REPEATED.match(message)
    if repeated:
        # syslog folds identical lines together, and each one was a separate attempt.
        return _parse_ssh_once(repeated["inner"].strip()) * min(int(repeated["count"]), MAX_REPEATS)
    return _parse_ssh_once(message)


def _parse_sudo(message: str) -> List[Dict[str, Any]]:
    line = SUDO_LINE.match(message)
    if not line:
        return []
    user, rest = line["user"], line["rest"]
    meta = {"source_log": "auth"}
    attempts = SUDO_ATTEMPTS.match(rest)
    if attempts:
        return [_event("sudo_fail", user=user, meta=meta)] * min(int(attempts["count"]), MAX_REPEATS)
    if SUDO_DENIED.match(rest):
        return [_event("sudo_denied", user=user, meta=meta)]
    ran = SUDO_RAN.match(rest)
    if ran:
        return [_event("sudo_exec", user=user, meta={**meta, "as_user": ran["as_user"], "command": ran["command"][:200]})]
    return []


def _parse_su(message: str) -> List[Dict[str, Any]]:
    match = SU_FAILED.match(message) or SU_FAILED_OLD.match(message)
    if not match:
        return []
    return [_event("su_fail", user=match["user"], meta={"source_log": "auth", "by": match["ruser"]})]


def _parse_new_user(rest: str) -> Dict[str, Any]:
    meta: Dict[str, Any] = {"source_log": "auth"}
    for field, key in (("UID", "uid"), ("GID", "gid")):
        found = re.search(rf"\b{field}=(\d+)", rest)
        if found:
            meta[key] = int(found[1])
    for field in ("home", "shell"):
        found = re.search(rf"\b{field}=([^\s,]+)", rest)
        if found:
            meta[field] = found[1]
    return meta


def _parse_accounts(message: str) -> List[Dict[str, Any]]:
    match = NEW_USER.match(message)
    if match:
        return [_event("user_add", user=match["user"], meta=_parse_new_user(match["rest"]))]
    match = UID_CHANGE.match(message)
    if match:
        meta = {"source_log": "auth", "old_uid": int(match["old"]), "new_uid": int(match["new"])}
        return [_event("user_mod", user=match["user"], meta=meta)]
    match = GROUP_ADD.match(message) or GPASSWD_ADD.match(message)
    if match:
        return [_event("group_add", user=match["user"], meta={"source_log": "auth", "group": match["group"]})]
    match = USER_DELETED.match(message)
    if match:
        return [_event("user_del", user=match["user"], meta={"source_log": "auth"})]
    return []


def _parse_password(message: str) -> List[Dict[str, Any]]:
    match = PASSWORD_CHANGED.match(message)
    return [_event("password_change", user=match["user"], meta={"source_log": "auth"})] if match else []


def _parse_crontab(message: str) -> List[Dict[str, Any]]:
    match = CRONTAB_CHANGED.match(message)
    if not match:
        return []
    return [_event("cron_change", user=match["user"], meta={"source_log": "auth", "verb": match["verb"]})]


PARSERS: Dict[str, Callable[[str], List[Dict[str, Any]]]] = {
    "sshd": _parse_ssh,
    "sshd-session": _parse_ssh,
    "sudo": _parse_sudo,
    "su": _parse_su,
    "useradd": _parse_accounts,
    "usermod": _parse_accounts,
    "userdel": _parse_accounts,
    "groupmems": _parse_accounts,
    "gpasswd": _parse_accounts,
    "passwd": _parse_password,
    "chpasswd": _parse_password,
    "crontab": _parse_crontab,
}


def _finish(events: List[Dict[str, Any]], when: dt.datetime, host: str, text: str) -> List[Dict[str, Any]]:
    stamp = to_iso(when)
    message = " ".join(text.split())[:MAX_MESSAGE]
    return [{"ts": stamp, "src": "log_monitor", "host": host, "msg": message, **item} for item in events]


def line_events(line: str, now: Optional[dt.datetime] = None) -> List[Dict[str, Any]]:
    parsed = parse_syslog(line, now)
    if parsed is None:
        return []
    parser = PARSERS.get(parsed.program)
    if parser is None:
        return []
    return _finish(parser(parsed.message), parsed.when, parsed.host, line)


def journal_message(entry: Dict[str, Any]) -> str:
    message = entry.get("MESSAGE", "")
    if isinstance(message, list):  # the journal stores text that is not valid UTF-8 as bytes
        return bytes(value for value in message if isinstance(value, int)).decode("utf-8", "replace")
    return str(message)


def journal_is_genuine(entry: Dict[str, Any]) -> bool:
    """Check who really wrote this entry.

    Any local account can claim to be sshd with `logger -t sshd`. journald records the
    sender's real uid and process name itself, so a forged line gives itself away. A
    fast-exiting process can lose _COMM, so only a name that disagrees counts against it.
    """
    program = str(entry.get("SYSLOG_IDENTIFIER", ""))
    if program in ROOT_ONLY_PROGRAMS and entry.get("_UID") != "0":
        return False
    process = entry.get("_COMM")
    if not process:
        return True
    return process in (SSH_PROGRAMS if program in SSH_PROGRAMS else {program})


def journal_entry_events(entry: Dict[str, Any], now: Optional[dt.datetime] = None) -> List[Dict[str, Any]]:
    program = str(entry.get("SYSLOG_IDENTIFIER", ""))
    parser = PARSERS.get(program)
    if parser is None or not journal_is_genuine(entry):
        return []
    moment = now or utc_now()
    try:
        when = dt.datetime.fromtimestamp(int(entry["__REALTIME_TIMESTAMP"]) / 1e6, dt.timezone.utc)
    except (KeyError, TypeError, ValueError):
        when = moment
    message = journal_message(entry)
    host = str(entry.get("_HOSTNAME", ""))
    return _finish(parser(message), min(when, moment), host, f"{program}: {message}")
