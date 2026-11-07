"""Aggregations shared by the dashboard and the static report."""

from __future__ import annotations

import collections
import datetime as dt
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from common.attack import TACTIC_NAMES, tactics_of, technique_name
from common.runtime import parse_ts, utc_now

MINUTE_STAMP = re.compile(rb'"ts":"(\d{4}-\d\d-\d\dT\d\d:\d\d)')
COUNT_HORIZON_MINUTES = 8 * 24 * 60


def severity_label(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


def within(items: List[Dict], cutoff: dt.datetime) -> List[Dict]:
    """Keep records at or after the cutoff. Undated records are dropped."""
    kept = []
    for item in items:
        stamp = parse_ts(item.get("ts"))
        if stamp is not None and stamp >= cutoff:
            kept.append(item)
    return kept


def time_buckets(
    items: List[Dict], start: dt.datetime, end: dt.datetime, buckets: int
) -> List[int]:
    """Count records per equal slice of real time between start and end."""
    counts = [0] * buckets
    span = (end - start).total_seconds() / buckets
    for item in items:
        stamp = parse_ts(item.get("ts"))
        if stamp is None or stamp < start or stamp > end:
            continue
        index = int((stamp - start).total_seconds() / span)
        counts[min(index, buckets - 1)] += 1
    return counts


def bucket_labels(start: dt.datetime, end: dt.datetime, buckets: int) -> List[str]:
    span = (end - start) / buckets
    return [(start + span * i).strftime("%Y-%m-%dT%H:%M:%SZ") for i in range(buckets)]


def top(counter: collections.Counter, limit: int = 8) -> List[Dict[str, Any]]:
    return [{"name": name, "count": count} for name, count in counter.most_common(limit)]


class MinuteCounts:
    """Count records per minute, reading only what was added since the last call.

    Totals come from here rather than from a capped read of the newest records, so a
    window with more records than the cap still shows the true number.
    """

    def __init__(self, path: Path):
        self.path = path
        self.offset = 0
        self.inode: Optional[int] = None
        self.minutes: collections.Counter = collections.Counter()

    def _count(self, path: Path, start: int) -> int:
        with path.open("rb") as handle:
            handle.seek(start)
            blob = handle.read()
        end = blob.rfind(b"\n") + 1  # a line still being written is counted next time
        for line in blob[:end].split(b"\n"):
            found = MINUTE_STAMP.search(line, 0, 160)
            if found:
                stamp = parse_ts(found[1].decode("ascii") + ":00Z")
                if stamp:
                    self.minutes[int(stamp.timestamp() // 60)] += 1
        return start + end

    def refresh(self) -> None:
        try:
            info = self.path.stat()
            if self.inode is None:
                rotated = self.path.with_name(f"{self.path.name}.1")
                if rotated.exists():
                    self._count(rotated, 0)
            elif info.st_ino != self.inode:
                self.offset = 0  # rotated: what was counted before still happened
            elif info.st_size < self.offset:
                self.offset = 0
                self.minutes.clear()
            self.inode = info.st_ino
            if info.st_size > self.offset:
                self.offset = self._count(self.path, self.offset)
        except OSError:
            return
        if self.minutes:
            horizon = max(self.minutes) - COUNT_HORIZON_MINUTES
            for minute in [item for item in self.minutes if item < horizon]:
                del self.minutes[minute]

    def buckets(self, start: dt.datetime, end: dt.datetime, count: int) -> List[int]:
        first, last = start.timestamp(), end.timestamp()
        span = (last - first) / count
        totals = [0] * count
        for minute, amount in self.minutes.items():
            moment = minute * 60
            if first - 60 < moment <= last:
                totals[max(0, min(int((moment - first) / span), count - 1))] += amount
        return totals


def describe_plan(plan: Any) -> Tuple[str, str]:
    """Return the actions and targets of a response plan as display text."""
    steps = [step for step in plan or [] if isinstance(step, dict)]
    if not steps:
        return "none", ""
    actions = ", ".join(str(step.get("action", "")) for step in steps)
    targets = ", ".join(dict.fromkeys(str(step.get("target", "")) for step in steps))
    return actions, targets


def threat_view(threat: Dict[str, Any]) -> Dict[str, Any]:
    """Flatten a stored threat into the fields people actually read."""
    alert = threat.get("alert") or {}
    event = alert.get("event") or {}
    score = int(threat.get("threat_score") or 0)
    action, target = describe_plan(threat.get("plan"))
    return {
        "ts": threat.get("ts", ""),
        "score": score,
        "severity": severity_label(score),
        "ml_score": threat.get("ml_score", 0),
        "action": action,
        "target": target,
        "type": alert.get("type", ""),
        "reason": alert.get("reason", ""),
        "mitre": alert.get("mitre") or [],
        "evidence": alert.get("evidence") or [],
        "advice": alert.get("advice", ""),
        "incident": threat.get("incident", ""),
        "source_ip": event.get("ip") or "",
        "user": event.get("user") or "",
        "notes": threat.get("notes", ""),
    }


def summarise(
    events: List[Dict],
    alerts: List[Dict],
    threats: List[Dict],
    hours: float,
    now: Optional[dt.datetime] = None,
    buckets: int = 24,
    event_counts: Optional[MinuteCounts] = None,
    alert_counts: Optional[MinuteCounts] = None,
) -> Dict[str, Any]:
    end = now or utc_now()
    start = end - dt.timedelta(hours=hours)
    events, alerts, threats = (within(x, start) for x in (events, alerts, threats))
    # Every alert becomes exactly one threat, so counting threats again adds nothing.
    # The useful number is how many of them called for a response.
    responses = [item for item in threats if item.get("plan")]
    event_series = (
        event_counts.buckets(start, end, buckets) if event_counts
        else time_buckets(events, start, end, buckets)
    )
    alert_series = (
        alert_counts.buckets(start, end, buckets) if alert_counts
        else time_buckets(alerts, start, end, buckets)
    )

    by_ip: collections.Counter = collections.Counter()
    by_mitre: collections.Counter = collections.Counter()
    by_type: collections.Counter = collections.Counter()
    by_severity: collections.Counter = collections.Counter()
    by_action: collections.Counter = collections.Counter()

    for threat in threats:
        view = threat_view(threat)
        by_severity[view["severity"]] += 1
        for step in threat.get("plan") or []:
            by_action[step.get("action", "") if isinstance(step, dict) else ""] += 1
        if view["type"]:
            by_type[view["type"]] += 1
        if view["source_ip"]:
            by_ip[view["source_ip"]] += 1
        for technique in view["mitre"]:
            by_mitre[technique] += 1

    return {
        "window_hours": hours,
        "labels": bucket_labels(start, end, buckets),
        "event_counts": event_series,
        "alert_counts": alert_series,
        "response_counts": time_buckets(responses, start, end, buckets),
        "totals": {
            "events": sum(event_series),
            "alerts": sum(alert_series),
            "threats": len(threats),
            "responses": len(responses),
        },
        "severity": {name: by_severity[name] for name in ("critical", "high", "medium", "low")},
        "actions": dict(by_action),
        "top_ips": top(by_ip),
        "top_types": top(by_type),
        "mitre": [
            {"id": item["name"], "name": technique_name(item["name"]), "count": item["count"]}
            for item in top(by_mitre, 10)
        ],
    }


def describe_span(start: Optional[dt.datetime], end: Optional[dt.datetime]) -> str:
    if start is None or end is None:
        return ""
    minutes = int((end - start).total_seconds() // 60)
    if minutes < 1:
        return "in under a minute"
    if minutes < 90:
        return f"over {minutes} minute{'s' if minutes != 1 else ''}"
    return f"over {minutes // 60} hours"


def narrate(ips: List[str], users: List[str], alerts: int, span: str, stages: List[str]) -> str:
    """Say what happened in one sentence, built only from fields already shown."""
    subject = ", ".join(ips[:3]) or (f"Account {users[0]}" if users else "Activity on this host")
    count = f"{alerts} alert{'s' if alerts != 1 else ''}"
    reach = f", reaching {', '.join(stages)}" if stages else ""
    return " ".join(f"{subject}: {count} {span}{reach}.".split())


def build_incidents(threats: List[Dict], actions: List[Dict]) -> List[Dict[str, Any]]:
    """Group threats into the incidents the scorer gave them, newest first."""
    groups: Dict[str, List[Dict]] = {}
    for threat in threats:
        key = threat.get("incident")
        if key:
            groups.setdefault(str(key), []).append(threat)
    responses: Dict[str, List[Dict]] = {}
    for action in actions:
        key = action.get("incident")
        if key:
            responses.setdefault(str(key), []).append(action)

    incidents = []
    for key, items in groups.items():
        views = [threat_view(item) for item in items]
        stamps = [stamp for stamp in (parse_ts(view["ts"]) for view in views) if stamp]
        opened = min(stamps) if stamps else None
        updated = max(stamps) if stamps else None
        techniques = list(dict.fromkeys(t for view in views for t in view["mitre"]))
        stages = [TACTIC_NAMES[tactic] for tactic in tactics_of(techniques)]
        ips = list(dict.fromkeys(view["source_ip"] for view in views if view["source_ip"]))
        users = list(dict.fromkeys(view["user"] for view in views if view["user"]))
        score = max(view["score"] for view in views)
        incidents.append(
            {
                "id": key,
                "opened": views[0]["ts"],
                "updated": views[-1]["ts"],
                "score": score,
                "severity": severity_label(score),
                "alerts": len(views),
                "ips": ips,
                "users": users,
                "stages": stages,
                "techniques": techniques,
                "summary": narrate(ips, users, len(views), describe_span(opened, updated), stages),
                "advice": list(dict.fromkeys(view["advice"] for view in views if view["advice"])),
                "timeline": [
                    {"ts": view["ts"], "severity": view["severity"], "score": view["score"],
                     "reason": view["reason"], "action": view["action"], "target": view["target"]}
                    for view in views
                ],
                "responses": [
                    {"action": item.get("action", ""), "target": item.get("target", ""),
                     "status": item.get("status", ""), "detail": item.get("detail", "")}
                    for item in responses.get(key, [])
                ],
            }
        )
    return sorted(incidents, key=lambda item: item["updated"], reverse=True)


def active_blocks(blocked: Any, now_epoch: float) -> List[Dict[str, Any]]:
    entries = blocked.get("blocked", {}) if isinstance(blocked, dict) else {}
    rows: List[Tuple[float, Dict[str, Any]]] = []
    for ip, info in entries.items():
        expires = float(info.get("expires", 0))
        if expires <= now_epoch:
            continue
        row = {
            "ip": ip,
            "expires_in": int(expires - now_epoch),
            "blocked_at": info.get("blocked_at", ""),
            "dry_run": bool(info.get("dry_run")),
            "reason": info.get("reason", ""),
        }
        rows.append((expires, row))
    return [row for _, row in sorted(rows, key=lambda pair: pair[0], reverse=True)]
