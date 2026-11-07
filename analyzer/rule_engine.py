#!/usr/bin/env python3
"""SentinelAI rule engine: turns raw events into alerts using config/rules.yml."""

from __future__ import annotations

import collections
import json
import re
import string
import sys
import time
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional, Tuple

if __package__ in (None, ""):  # allow `python analyzer/rule_engine.py`
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import yaml

from analyzer.schemas import Alert, Event
from common.runtime import (
    Follower,
    append_jsonl,
    deliver,
    event_epoch,
    exit_with_supervisor,
    get_paths,
    harden_process,
    load_config,
    make_logger,
    now_iso,
    root_dir,
)

log_message = make_logger("rule_engine", "analyzer.log")

RULE_KEYS = {
    "id", "match", "alert_type", "severity", "reason", "criteria", "mitre", "cooldown_sec",
    "respond", "evidence", "advice", "stop", "enabled",
}
CRITERIA_KEYS = {
    "count", "window_sec", "distinct", "group_by", "not_in_allowed_ports", "after_rule",
    "within_sec", "where", "privileged_port_boost", "offensive_tool",
}
CONDITION_KEYS = {"in", "not", "contains", "regex"}
STEP_KEYS = {"action", "target", "min_score"}
DEFAULT_TARGETS = {"block_ip": "ip", "kill_process": "pid", "lock_user": "user"}
# These cannot be undone by a timer, so they follow from what a rule proved and may
# never depend on the score. See the note at the top of rules.yml.
SCORE_INDEPENDENT_ACTIONS = {"kill_process", "lock_user"}
PRUNE_EVERY = 1000  # events between sweeps of idle tracking state
IDLE_HORIZON_SEC = 86400
MAX_WINDOW_ENTRIES = 10000  # a flood from one source must not grow without limit
MAX_REASON_LENGTH = 300
WARM_UP_BYTES = 8 * 1024 * 1024


class RuleError(ValueError):
    """Raised when rules.yml is invalid."""


def _check_template(rule_id: str, reason: Any) -> None:
    """Bad templates would otherwise pass here and crash on the first matching event."""
    if not isinstance(reason, str):
        raise RuleError(f"rule {rule_id}: reason must be text")
    try:
        parts = list(string.Formatter().parse(reason))
    except ValueError as exc:
        raise RuleError(f"rule {rule_id}: bad reason template: {exc}") from exc
    for _, field, spec, conversion in parts:
        if field is None:
            continue
        if not field.isidentifier() or spec or conversion:
            raise RuleError(f"rule {rule_id}: bad placeholder {{{field}}} in reason")


def _check_condition(rule_id: str, field: str, expected: Any) -> None:
    if not isinstance(expected, dict):
        return
    unknown = set(expected) - CONDITION_KEYS
    if unknown or len(expected) != 1:
        raise RuleError(f"rule {rule_id}: where {field} needs exactly one of {sorted(CONDITION_KEYS)}")
    if "in" in expected and not isinstance(expected["in"], list):
        raise RuleError(f"rule {rule_id}: where {field}: in needs a list")
    if "regex" in expected:
        try:
            re.compile(str(expected["regex"]))
        except re.error as exc:
            raise RuleError(f"rule {rule_id}: where {field}: bad regex: {exc}") from exc


def _check_response(rule_id: str, steps: Any) -> None:
    if not isinstance(steps, list):
        raise RuleError(f"rule {rule_id}: respond must be a list")
    for step in steps:
        if not isinstance(step, dict):
            raise RuleError(f"rule {rule_id}: each respond step must be a mapping")
        unknown = set(step) - STEP_KEYS
        if unknown:
            raise RuleError(f"rule {rule_id}: unknown keys {sorted(unknown)} in respond")
        action = step.get("action")
        if action not in DEFAULT_TARGETS:
            raise RuleError(f"rule {rule_id}: unknown response action {action!r}")
        if "min_score" in step:
            if action in SCORE_INDEPENDENT_ACTIONS:
                raise RuleError(
                    f"rule {rule_id}: {action} cannot use min_score, because a busy host "
                    "must never be the reason something is killed or locked"
                )
            if not 0 <= _whole_number(rule_id, "min_score", step["min_score"]) <= 100:
                raise RuleError(f"rule {rule_id}: min_score must be 0-100")


def _whole_number(rule_id: str, name: str, value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise RuleError(f"rule {rule_id}: {name} must be a whole number") from exc


def _check_rule(rule: Any, seen: set) -> None:
    if not isinstance(rule, dict):
        raise RuleError(f"each rule must be a mapping, not {rule!r}")
    rule_id = rule.get("id")
    if not rule_id or rule_id in seen:
        raise RuleError(f"missing or duplicate rule id: {rule_id!r}")
    seen.add(rule_id)
    for key in ("match", "alert_type", "severity", "reason"):
        if key not in rule:
            raise RuleError(f"rule {rule_id}: missing {key}")

    criteria = rule.get("criteria") or {}
    if not isinstance(criteria, dict):
        raise RuleError(f"rule {rule_id}: criteria must be a mapping")
    unknown = (set(rule) - RULE_KEYS) | (set(criteria) - CRITERIA_KEYS)
    if unknown:
        raise RuleError(f"rule {rule_id}: unknown keys {sorted(unknown)}")
    if not 1 <= _whole_number(rule_id, "severity", rule["severity"]) <= 10:
        raise RuleError(f"rule {rule_id}: severity must be 1-10")
    if ("count" in criteria) != ("window_sec" in criteria):
        raise RuleError(f"rule {rule_id}: count and window_sec go together")
    for name in ("count", "window_sec", "within_sec"):
        if name in criteria and _whole_number(rule_id, name, criteria[name]) < 1:
            raise RuleError(f"rule {rule_id}: {name} must be at least 1")
    if _whole_number(rule_id, "cooldown_sec", rule.get("cooldown_sec", 0)) < 0:
        raise RuleError(f"rule {rule_id}: cooldown_sec cannot be negative")

    where = criteria.get("where") or {}
    if not isinstance(where, dict):
        raise RuleError(f"rule {rule_id}: where must be a mapping")
    for field, expected in where.items():
        _check_condition(rule_id, field, expected)
    _check_template(rule_id, rule["reason"])
    _check_response(rule_id, rule.get("respond") or [])


def load_rules(path: Optional[Path] = None) -> List[Dict[str, Any]]:
    source = path or root_dir() / "config" / "rules.yml"
    try:
        document = yaml.safe_load(source.read_text(encoding="utf-8-sig")) or {}
    except OSError as exc:
        raise RuleError(f"{source}: {exc}") from exc
    except yaml.YAMLError as exc:
        raise RuleError(f"{source.name}: {' '.join(str(exc).split())}") from exc

    rules = document.get("rules") if isinstance(document, dict) else None
    if not isinstance(rules, list) or not rules:
        raise RuleError(f"{source.name}: no rules defined")

    seen: set = set()
    for rule in rules:
        _check_rule(rule, seen)
    for rule in rules:
        prior = (rule.get("criteria") or {}).get("after_rule")
        if prior and prior not in seen:
            raise RuleError(f"rule {rule['id']}: after_rule {prior!r} does not exist")
    return [rule for rule in rules if rule.get("enabled", True)]


def lookup(event: Event, dotted: str) -> Any:
    value: Any = event
    for part in dotted.split("."):
        if not isinstance(value, dict):
            return None
        value = value.get(part)
    return value


def condition_met(value: Any, expected: Any) -> bool:
    if not isinstance(expected, dict):
        return value == expected
    if "in" in expected:
        return value in expected["in"]
    if "not" in expected:
        return value != expected["not"]
    if "contains" in expected:
        return isinstance(value, (list, str)) and expected["contains"] in value
    return isinstance(value, str) and re.search(str(expected["regex"]), value) is not None


def process_name(event: Event) -> str:
    meta = event.get("meta") or {}
    if not isinstance(meta, dict):
        return ""
    return str(meta.get("proc") or meta.get("exe") or "")


def base_name(name: str) -> str:
    return name.replace("\\", "/").rsplit("/", 1)[-1].lower().removesuffix(".exe")


class RuleEngine:
    def __init__(self, rules: List[Dict[str, Any]], config: Dict[str, Any]):
        self.allowed_ports = {int(p) for p in config["network"]["allowed_ports"]}
        self.min_severity = int(config["thresholds"].get("base_severity_threshold", 1))
        section = config.get("collectors", {})
        names = [*section.get("suspicious_names", []), *section.get("malicious_names", [])]
        self.offensive_names = {str(name).lower() for name in names}
        self.windows: Dict[Tuple[str, str], Deque[Tuple[float, Any]]] = collections.defaultdict(
            lambda: collections.deque(maxlen=MAX_WINDOW_ENTRIES)
        )
        self.last_fired: Dict[Tuple[str, str], float] = {}
        self.seen_events = 0
        self.by_type: Dict[str, List[Dict[str, Any]]] = {}
        self.use_rules(rules)

    def use_rules(self, rules: List[Dict[str, Any]]) -> None:
        by_type: Dict[str, List[Dict[str, Any]]] = collections.defaultdict(list)
        for rule in rules:
            by_type[rule["match"]].append(rule)
        self.by_type = dict(by_type)

    def rule_count(self) -> int:
        return sum(len(rules) for rules in self.by_type.values())

    def evaluate(self, event: Event) -> List[Alert]:
        self.seen_events += 1
        if self.seen_events % PRUNE_EVERY == 0:
            self._prune(event_epoch(event))

        alerts: List[Alert] = []
        for rule in self.by_type.get(str(event.get("type")), ()):
            matched, alert = self._check(rule, event)
            if alert:
                alerts.append(alert)
            if matched and rule.get("stop"):
                break  # a more specific rule replaces the generic ones after it
        return alerts

    def _check(self, rule: Dict[str, Any], event: Event) -> Tuple[bool, Optional[Alert]]:
        """Return whether the rule matched, and the alert if one should be raised."""
        criteria = rule.get("criteria") or {}
        when = event_epoch(event)
        group = lookup(event, criteria.get("group_by", "type"))
        if group is None or group == "":
            return False, None
        group = str(group)
        key = (rule["id"], group)

        for field, expected in (criteria.get("where") or {}).items():
            if not condition_met(lookup(event, field), expected):
                return False, None
        if criteria.get("offensive_tool") and not self._is_offensive_tool(event):
            return False, None

        severity = int(rule["severity"])
        if "privileged_port_boost" in criteria or criteria.get("not_in_allowed_ports"):
            port = self._port(event)
            if port is None:
                return False, None
            if criteria.get("not_in_allowed_ports") and port in self.allowed_ports:
                return False, None
            if port < 1024:
                severity += int(criteria.get("privileged_port_boost", 0))

        prior = criteria.get("after_rule")
        if prior:
            fired_at = self.last_fired.get((prior, group))
            if fired_at is None or when - fired_at > int(criteria.get("within_sec", 600)):
                return False, None

        count = 1
        if "count" in criteria:
            count = self._window_count(key, criteria, event, when)
            if count < int(criteria["count"]):
                return False, None
            self.windows.pop(key, None)

        previous = self.last_fired.get(key)
        cooldown = int(rule.get("cooldown_sec", 0))
        if previous is not None and abs(when - previous) < cooldown:
            return True, None
        self.last_fired[key] = when

        severity = min(10, severity)
        if severity < self.min_severity:
            return True, None

        return True, {
            "ts": now_iso(),
            "event": event,
            "type": rule["alert_type"],
            "rule_id": rule["id"],
            "reason": self._reason(rule, event, count, criteria),
            "base_severity": severity,
            "mitre": self._techniques(rule, event),
            "evidence": list(rule.get("evidence") or []),
            "advice": str(rule.get("advice") or ""),
            "respond": [dict(step) for step in rule.get("respond") or []],
        }

    @staticmethod
    def _techniques(rule: Dict[str, Any], event: Event) -> List[str]:
        found = list(rule.get("mitre") or [])
        meta = event.get("meta")
        for technique in (meta.get("mitre") if isinstance(meta, dict) else None) or []:
            if isinstance(technique, str) and technique not in found:
                found.append(technique)
        return found

    def _window_count(self, key, criteria, event: Event, when: float) -> int:
        window = self.windows[key]
        field = criteria.get("distinct")
        window.append((when, lookup(event, field) if field else None))
        horizon = when - int(criteria["window_sec"])
        while window and window[0][0] < horizon:
            window.popleft()
        if field:
            return len({value for _, value in window if value not in (None, "")})
        return len(window)

    def _reason(self, rule, event: Event, count: int, criteria) -> str:
        values = collections.defaultdict(str, {k: v for k, v in event.items() if k != "meta"})
        meta = event.get("meta")
        if isinstance(meta, dict):
            for name, value in meta.items():
                values.setdefault(name, value)
        values["count"] = count
        values["window"] = criteria.get("window_sec", "")
        values["proc"] = process_name(event) or event.get("msg", "") or "unknown"
        reason = rule["reason"].format_map(values)

        if rule["match"] == "new_port":
            details = []
            if event.get("pid"):
                details.append(f"pid={event['pid']}")
            if process_name(event):
                details.append(f"exe={process_name(event)}")
            if details:
                reason += f" ({', '.join(details)})"
        return " ".join(reason.split())[:MAX_REASON_LENGTH]

    def _is_offensive_tool(self, event: Event) -> bool:
        return base_name(process_name(event)) in self.offensive_names

    @staticmethod
    def _port(event: Event) -> Optional[int]:
        try:
            port = int(event.get("port"))  # type: ignore[arg-type]
        except (TypeError, ValueError):
            return None
        return port if 0 <= port <= 65535 else None

    def _prune(self, now: float) -> None:
        for key in [k for k, w in self.windows.items() if not w or now - w[-1][0] > IDLE_HORIZON_SEC]:
            del self.windows[key]
        for key in [k for k, t in self.last_fired.items() if now - t > IDLE_HORIZON_SEC]:
            del self.last_fired[key]

    def warm_up(self, path: Path, end_offset: int) -> int:
        """Rebuild windows and correlation from events already processed.

        This state lives in memory, so without this a restart would forget that a
        brute force had just finished and the login that followed would look innocent.
        Alerts for these events were raised the first time round, so they are dropped.
        """
        start = max(0, end_offset - WARM_UP_BYTES)
        try:
            with path.open("rb") as handle:
                handle.seek(start)
                blob = handle.read(end_offset - start)
        except OSError:
            return 0

        lines = blob.split(b"\n")
        if start > 0:
            lines = lines[1:]  # the first line is probably cut in half
        replayed = 0
        for raw in lines:
            try:
                event = json.loads(raw)
            except ValueError:
                continue
            if isinstance(event, dict):
                self.evaluate(event)
                replayed += 1
        return replayed


def build_engine(config: Optional[Dict[str, Any]] = None) -> RuleEngine:
    return RuleEngine(load_rules(), config or load_config())


class RuleWatcher:
    """Apply edits to rules.yml while running. A bad edit leaves the old rules active."""

    CHECK_EVERY_SEC = 5.0

    def __init__(self, engine: RuleEngine, path: Optional[Path] = None):
        self.engine = engine
        self.path = path or root_dir() / "config" / "rules.yml"
        self.stamp = self._stamp()
        self.next_check = time.monotonic() + self.CHECK_EVERY_SEC

    def _stamp(self) -> Optional[int]:
        try:
            return self.path.stat().st_mtime_ns
        except OSError:
            return None

    def poll(self) -> None:
        if time.monotonic() < self.next_check:
            return
        self.next_check = time.monotonic() + self.CHECK_EVERY_SEC
        stamp = self._stamp()
        if stamp == self.stamp:
            return
        self.stamp = stamp
        try:
            self.engine.use_rules(load_rules(self.path))
            log_message(f"rules reloaded: {self.engine.rule_count()} active")
        except RuleError as exc:
            log_message(f"ignoring invalid rules.yml, keeping the old rules: {exc}")


def main() -> None:
    harden_process()
    exit_with_supervisor()
    config = load_config()
    paths = get_paths(config).ensure()
    engine = build_engine(config)
    follow = bool(config["modes"].get("follow_files", True))

    paths.events.touch(exist_ok=True)
    follower = Follower(paths.events, "rule_engine", paths.state_dir)
    replayed = engine.warm_up(paths.events, follower.offset)
    log_message(f"started with {engine.rule_count()} rules, replayed {replayed} events")
    watcher = RuleWatcher(engine)

    def handle(event: Dict[str, Any]) -> None:
        for alert in engine.evaluate(event):
            append_jsonl(paths.alerts, alert)
            log_message(f"alert type={alert['type']} sev={alert['base_severity']}")

    while True:
        for raw in follower.read_available():
            deliver(raw, handle, log_message, paths.dead_letters)
        if not follow:
            return
        watcher.poll()
        time.sleep(follower.poll_sec)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
