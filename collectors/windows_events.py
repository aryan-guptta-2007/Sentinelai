"""Read the Windows event logs and turn them into the same events the Linux logs give.

`wevtutil` ships with every Windows, so this needs no extra packages. The Security log
needs an elevated account. The others can be read without one, so a host that is not
elevated still gets service installs, Defender detections and cleared-log events.
"""

from __future__ import annotations

import re
import subprocess
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple

from common.runtime import parse_ts, to_iso, utc_now

NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"
ACCESS_DENIED = 5
QUERY_FAILED = -1
BATCH = 500
MAX_TEXT = 500
COMMAND_TIMEOUT_SEC = 20
CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")

CHANNELS: Dict[str, Tuple[int, ...]] = {
    "Security": (1102, 4624, 4625, 4697, 4698, 4720, 4728, 4732, 4740, 4756),
    "System": (104, 7045),
    "Microsoft-Windows-Windows Defender/Operational": (1116, 5001),
}
REMOTE_LOGON_TYPES = {"3", "10"}  # network and Remote Desktop
SYSTEM_ACCOUNTS = {"", "-", "system", "anonymous logon", "local service", "network service"}
NO_ADDRESS = {"", "-", "::1", "127.0.0.1"}


@dataclass(frozen=True)
class WindowsEvent:
    channel: str
    record_id: int
    event_id: int
    when: str
    data: Dict[str, str]
    host: str


def _child_text(system: ET.Element, name: str) -> str:
    node = system.find(f"{NS}{name}")
    return (node.text or "") if node is not None else ""


def parse_events(xml_text: str) -> List[WindowsEvent]:
    cleaned = CONTROL_CHARS.sub(" ", xml_text).strip()
    if not cleaned:
        return []
    try:
        root = ET.fromstring(cleaned if cleaned.startswith("<Events") else f"<Events>{cleaned}</Events>")
    except ET.ParseError:
        return []

    found = []
    for item in root.iter(f"{NS}Event"):
        system = item.find(f"{NS}System")
        if system is None:
            continue
        created = system.find(f"{NS}TimeCreated")
        data = {
            str(node.get("Name")): (node.text or "")
            for node in item.iter(f"{NS}Data")
            if node.get("Name")
        }
        try:
            found.append(
                WindowsEvent(
                    channel=_child_text(system, "Channel"),
                    record_id=int(_child_text(system, "EventRecordID")),
                    event_id=int(_child_text(system, "EventID")),
                    when=(created.get("SystemTime") or "") if created is not None else "",
                    data=data,
                    host=_child_text(system, "Computer"),
                )
            )
        except ValueError:
            continue
    return found


def _describe(event: WindowsEvent, summary: str) -> str:
    return " ".join(f"{event.channel} {event.event_id}: {summary}".split())[:MAX_TEXT]


def _address(raw: str) -> Optional[str]:
    return None if raw.strip() in NO_ADDRESS else raw.strip()


def _logon_failed(event: WindowsEvent) -> Dict[str, Any]:
    user = event.data.get("TargetUserName", "")
    ip = _address(event.data.get("IpAddress", ""))
    return {
        "type": "auth_fail",
        "user": user,
        "ip": ip,
        "msg": _describe(event, f"failed logon for {user} from {ip or 'this machine'}"),
        "meta": {"logon_type": event.data.get("LogonType", ""), "source_log": "security"},
    }


def _logon_succeeded(event: WindowsEvent) -> Optional[Dict[str, Any]]:
    user = event.data.get("TargetUserName", "")
    ip = _address(event.data.get("IpAddress", ""))
    # Windows logs thousands of service and machine logons. Only people arriving
    # over the network say anything about an attacker getting in.
    if (
        event.data.get("LogonType") not in REMOTE_LOGON_TYPES
        or ip is None
        or user.lower() in SYSTEM_ACCOUNTS
        or user.endswith("$")
    ):
        return None
    return {
        "type": "auth_success",
        "user": user,
        "ip": ip,
        "msg": _describe(event, f"logon by {user} from {ip}"),
        "meta": {"logon_type": event.data.get("LogonType", ""), "source_log": "security"},
    }


def _group_change(event: WindowsEvent) -> Dict[str, Any]:
    group = event.data.get("TargetUserName", "")
    member = event.data.get("MemberName", "")
    if member in ("", "-"):
        member = event.data.get("MemberSid", "")
    return {
        "type": "group_add",
        "user": member,
        "msg": _describe(event, f"{member} added to {group}"),
        "meta": {"group": group, "source_log": "security"},
    }


def _service_installed(event: WindowsEvent) -> Dict[str, Any]:
    name = event.data.get("ServiceName", "")
    path = event.data.get("ImagePath") or event.data.get("ServiceFileName", "")
    return {
        "type": "service_installed",
        "msg": _describe(event, f"service {name} installed: {path}"),
        "meta": {"service": name, "path": path[:300], "source_log": "system"},
    }


def _defender_detection(event: WindowsEvent) -> Dict[str, Any]:
    name = event.data.get("Threat Name", "")
    path = event.data.get("Path", "")
    return {
        "type": "malware_detected",
        "user": event.data.get("Detection User", ""),
        "msg": _describe(event, f"Defender detected {name} in {path}"),
        "meta": {"threat": name, "path": path[:300], "source_log": "defender"},
    }


def to_sentinel_event(event: WindowsEvent) -> Optional[Dict[str, Any]]:
    mapped: Optional[Dict[str, Any]]
    identifier = event.event_id
    if identifier == 4625:
        mapped = _logon_failed(event)
    elif identifier == 4624:
        mapped = _logon_succeeded(event)
    elif identifier == 4720:
        user = event.data.get("TargetUserName", "")
        mapped = {"type": "user_add", "user": user, "msg": _describe(event, f"account {user} created"),
                  "meta": {"source_log": "security"}}
    elif identifier in (4728, 4732, 4756):
        mapped = _group_change(event)
    elif identifier == 4740:
        user = event.data.get("TargetUserName", "")
        mapped = {"type": "account_lockout", "user": user,
                  "msg": _describe(event, f"account {user} locked out"), "meta": {"source_log": "security"}}
    elif identifier in (1102, 104):
        mapped = {"type": "log_cleared", "msg": _describe(event, "an event log was cleared"),
                  "meta": {"log": event.channel, "source_log": "windows"}}
    elif identifier in (4697, 7045):
        mapped = _service_installed(event)
    elif identifier == 4698:
        task = event.data.get("TaskName", "")
        mapped = {"type": "task_created", "msg": _describe(event, f"scheduled task {task} created"),
                  "meta": {"task": task, "source_log": "security"}}
    elif identifier == 1116:
        mapped = _defender_detection(event)
    elif identifier == 5001:
        mapped = {"type": "defender_disabled", "msg": _describe(event, "real-time protection was turned off"),
                  "meta": {"source_log": "defender"}}
    else:
        return None
    if mapped is None:
        return None

    stamp = parse_ts(event.when.replace(" ", "T"))
    moment = utc_now()
    return {
        "ts": to_iso(min(stamp, moment)) if stamp else to_iso(moment),
        "src": "log_monitor",
        "host": event.host,
        **{key: value for key, value in mapped.items() if value not in (None, "")},
    }


def query(channel: str, xpath: str, *flags: str) -> Tuple[int, str]:
    try:
        done = subprocess.run(
            ["wevtutil", "qe", channel, f"/q:{xpath}", "/f:xml", *flags],
            capture_output=True,
            timeout=COMMAND_TIMEOUT_SEC,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return QUERY_FAILED, ""  # tried again next time round
    return done.returncode, done.stdout.decode("utf-8", errors="replace")


def latest_record(channel: str) -> Tuple[int, int]:
    """Return (wevtutil exit code, newest record id) so a first run starts from now."""
    code, output = query(channel, "*", "/c:1", "/rd:true")
    if code != 0:
        return code, 0
    events = parse_events(output)
    return 0, events[0].record_id if events else 0


def read_since(channel: str, event_ids: Iterable[int], after: int) -> Tuple[int, List[WindowsEvent]]:
    wanted = " or ".join(f"EventID={identifier}" for identifier in event_ids)
    xpath = f"*[System[(EventRecordID>{int(after)}) and ({wanted})]]"
    code, output = query(channel, xpath, f"/c:{BATCH}")
    return code, parse_events(output) if code == 0 else []
