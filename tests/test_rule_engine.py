import copy
import json
import os
from pathlib import Path

import pytest
import yaml

from analyzer import rule_engine
from analyzer.rule_engine import RuleError, RuleWatcher, condition_met, load_rules


def auth_fail(ip="203.0.113.5", user="root", ts="2025-01-01T00:00:00Z"):
    return {"ts": ts, "type": "auth_fail", "ip": ip, "user": user}


def at(seconds):
    return f"2025-01-01T00:{seconds // 60:02d}:{seconds % 60:02d}Z"


@pytest.fixture
def engine(config):
    return rule_engine.build_engine(config)


def types(alerts):
    return [alert["type"] for alert in alerts]


def test_auth_burst_triggers(engine):
    for _ in range(4):
        assert engine.evaluate(auth_fail()) == []
    alert = engine.evaluate(auth_fail())[0]
    assert alert["type"] == "auth_burst"
    assert "203.0.113.5" in alert["reason"]


def test_new_port_alert_emitted(engine):
    event = {"ts": at(0), "type": "new_port", "port": 45000, "pid": 4242, "meta": {"exe": "/usr/bin/python"}}
    alert = engine.evaluate(event)[0]
    assert alert["type"] == "new_port_alert"
    assert "45000" in alert["reason"]


def test_burst_window_uses_event_time_not_arrival_time(engine):
    # Replaying old logs quickly must not make slow attempts look like a burst.
    for minute in range(5):
        assert engine.evaluate(auth_fail(ts=at(minute * 120))) == []


def test_cooldown_suppresses_repeat_alerts(engine):
    fired = [alert for i in range(11) for alert in engine.evaluate(auth_fail(ts=at(i)))]
    assert len(fired) == 1


def test_password_spray_counts_distinct_users(engine):
    alerts = []
    for index in range(5):
        alerts += engine.evaluate(auth_fail(user=f"u{index}", ts=at(index * 70)))
    assert types(alerts) == ["auth_spray"]
    assert alerts[0]["mitre"] == ["T1110.003"]


def test_distributed_attack_is_seen_across_addresses(engine):
    # No single address trips the per-IP rules here.
    alerts = []
    for index in range(10):
        alerts += engine.evaluate(auth_fail(ip=f"203.0.113.{index + 1}", user="admin", ts=at(index * 30)))
    assert types(alerts) == ["auth_distributed"]


def test_login_after_burst_is_a_compromise(engine):
    for index in range(5):
        engine.evaluate(auth_fail(ts=at(index)))
    success = {"ts": at(30), "type": "auth_success", "ip": "203.0.113.5", "user": "alice"}
    alert = engine.evaluate(success)[0]
    assert alert["type"] == "auth_compromise"
    assert alert["base_severity"] == 10


def test_login_after_spray_is_a_compromise(engine):
    for index in range(5):
        engine.evaluate(auth_fail(user=f"u{index}", ts=at(index * 70)))
    success = {"ts": at(500), "type": "auth_success", "ip": "203.0.113.5", "user": "u1"}
    assert types(engine.evaluate(success)) == ["auth_compromise"]


def test_login_without_burst_is_quiet(engine):
    assert engine.evaluate({"ts": at(0), "type": "auth_success", "ip": "203.0.113.9", "user": "a"}) == []


def test_login_long_after_burst_is_quiet(engine):
    for index in range(5):
        engine.evaluate(auth_fail(ts=at(index)))
    success = {"ts": "2025-01-01T02:00:00Z", "type": "auth_success", "ip": "203.0.113.5", "user": "a"}
    assert engine.evaluate(success) == []


def test_allowed_port_is_ignored(engine):
    assert engine.evaluate({"ts": at(0), "type": "new_port", "port": 443, "pid": 1}) == []


def test_unexpected_privileged_port_is_more_severe(engine):
    # Regression: ports under 1024 used to be skipped entirely.
    alert = engine.evaluate({"ts": at(0), "type": "new_port", "port": 23, "pid": 9})[0]
    assert alert["base_severity"] == 7


def test_loopback_listener_is_not_reported(engine):
    event = {"ts": at(0), "type": "new_port", "port": 9000, "pid": 9, "meta": {"proc": "app", "exposed": False}}
    assert engine.evaluate(event) == []


def test_offensive_tool_listening_is_a_backdoor_even_on_loopback(engine):
    event = {"ts": at(0), "type": "new_port", "port": 4444, "pid": 9, "meta": {"proc": "nc", "exposed": False}}
    alert = engine.evaluate(event)[0]
    assert alert["rule_id"] == "backdoor_listener"
    assert alert["base_severity"] == 10


def test_windows_tool_names_match(engine):
    event = {"ts": at(0), "type": "new_port", "port": 4444, "pid": 9, "meta": {"exe": "C:\\Tools\\NC.EXE"}}
    assert engine.evaluate(event)[0]["rule_id"] == "backdoor_listener"


def test_backdoor_rule_replaces_the_generic_one(engine):
    event = {"ts": at(0), "type": "new_port", "port": 4444, "pid": 9, "meta": {"proc": "nc"}}
    assert [a["rule_id"] for a in engine.evaluate(event)] == ["backdoor_listener"]


def test_malicious_process_alerts(engine):
    # Regression: these events used to be collected and then ignored.
    event = {"ts": at(0), "type": "suspicious_proc", "pid": 77, "meta": {"proc": "xmrig", "flags": ["malicious"]}}
    alert = engine.evaluate(event)[0]
    assert alert["rule_id"] == "malicious_process"
    assert "xmrig" in alert["reason"]


def test_resource_use_is_only_a_note(engine):
    event = {"ts": at(0), "type": "suspicious_proc", "pid": 77, "meta": {"proc": "gcc", "flags": ["cpu"]}}
    alert = engine.evaluate(event)[0]
    assert alert["rule_id"] == "resource_hog"
    assert alert["respond"] == []


def test_root_equivalent_account_beats_generic_rule(engine):
    event = {"ts": at(0), "type": "user_add", "user": "backdoor", "meta": {"uid": 0}}
    alerts = engine.evaluate(event)
    assert [a["rule_id"] for a in alerts] == ["root_equivalent_account"]
    assert alerts[0]["base_severity"] == 10


def test_specific_rule_on_cooldown_does_not_fall_through_to_generic_rule(engine):
    event = {"ts": at(0), "type": "user_add", "user": "backdoor", "meta": {"uid": 0}}
    engine.evaluate(event)
    assert engine.evaluate({**event, "ts": at(5)}) == []


def test_regular_account_uses_generic_rule(engine):
    event = {"ts": at(0), "type": "user_add", "user": "newhire", "meta": {"uid": 1001}}
    assert [a["rule_id"] for a in engine.evaluate(event)] == ["new_user_account"]


def test_privileged_group_is_flagged_and_ordinary_group_is_not(engine):
    privileged = {"ts": at(0), "type": "group_add", "user": "bob", "meta": {"group": "sudo"}}
    ordinary = {"ts": at(0), "type": "group_add", "user": "bob", "meta": {"group": "audio"}}
    assert engine.evaluate(ordinary) == []
    assert "sudo" in engine.evaluate(privileged)[0]["reason"]


def test_technique_can_come_from_the_event(engine):
    event = {"ts": at(0), "type": "malicious_command", "pid": 1, "user": "x",
             "meta": {"proc": "bash", "confidence": "high", "summary": "s", "mitre": ["T1059.004"]}}
    assert "T1059.004" in engine.evaluate(event)[0]["mitre"]


def test_braces_in_event_values_cannot_break_formatting(engine):
    event = {"ts": at(0), "type": "user_add", "user": "{__class__}{0}", "meta": {"uid": 1001}}
    assert "{__class__}{0}" in engine.evaluate(event)[0]["reason"]


def test_a_hostile_value_cannot_break_a_reason_across_lines(engine):
    event = {"ts": at(0), "type": "user_add", "user": "a\nb" + "x" * 1000, "meta": {"uid": 1001}}
    reason = engine.evaluate(event)[0]["reason"]
    assert "\n" not in reason and len(reason) <= rule_engine.MAX_REASON_LENGTH


def test_severity_below_threshold_is_dropped(config):
    changed = copy.deepcopy(config)
    changed["thresholds"]["base_severity_threshold"] = 8
    engine = rule_engine.RuleEngine(load_rules(), changed)
    assert engine.evaluate({"ts": at(0), "type": "new_port", "port": 45000, "pid": 1}) == []


def test_idle_tracking_state_is_pruned(engine):
    # Regression: one entry per source IP used to live forever.
    engine.evaluate(auth_fail(ip="203.0.113.77", ts="2025-01-01T00:00:00Z"))
    engine._prune(1735689600 + 3 * 86400)
    assert engine.windows == {}


def test_a_flood_from_one_source_cannot_grow_without_limit(engine):
    for index in range(rule_engine.MAX_WINDOW_ENTRIES + 50):
        engine._window_count(("r", "g"), {"window_sec": 60}, {}, 1000.0 + index / 1e6)
    assert len(engine.windows[("r", "g")]) == rule_engine.MAX_WINDOW_ENTRIES


@pytest.mark.parametrize(
    "value, expected, result",
    [
        (5, 5, True),
        (5, 6, False),
        ("sudo", {"in": ["sudo", "wheel"]}, True),
        ("audio", {"in": ["sudo"]}, False),
        (None, {"not": False}, True),
        (False, {"not": False}, False),
        (["name", "cpu"], {"contains": "cpu"}, True),
        (["name"], {"contains": "cpu"}, False),
        (None, {"contains": "x"}, False),
        ("/tmp/x", {"regex": "^/tmp"}, True),
        (7, {"regex": "x"}, False),
    ],
)
def test_conditions(value, expected, result):
    assert condition_met(value, expected) is result


def test_disabled_rule_is_left_out(tmp_path):
    rules = load_rules()
    rules[0]["enabled"] = False
    path = tmp_path / "rules.yml"
    path.write_text(yaml.safe_dump({"rules": rules}), encoding="utf-8")
    assert rules[0]["id"] not in {rule["id"] for rule in load_rules(path)}


@pytest.mark.parametrize(
    "mutate, message",
    [
        (lambda r: r[0].update(typo=1), "unknown keys"),
        (lambda r: r[0]["criteria"].update(windw=1), "unknown keys"),
        (lambda r: r[0].update(severity=11), "severity"),
        (lambda r: r[0].update(severity="high"), "whole number"),
        (lambda r: r[0].pop("reason"), "missing reason"),
        (lambda r: r[1].update(id=r[0]["id"]), "duplicate"),
        (lambda r: r[5]["criteria"].update(after_rule="nope"), "does not exist"),
        (lambda r: r[0].update(reason="bad {"), "reason template"),
        (lambda r: r[0].update(reason="{ip.__class__}"), "bad placeholder"),
        (lambda r: r[0].update(reason="{0}"), "bad placeholder"),
        (lambda r: r[0].update(reason="{ip!r}"), "bad placeholder"),
        (lambda r: r[0].update(cooldown_sec=-1), "negative"),
        (lambda r: r[0]["criteria"].update(count=0), "at least 1"),
        (lambda r: r[0].update(respond="block_ip"), "must be a list"),
        (lambda r: r[0].update(respond=["block_ip"]), "must be a mapping"),
        (lambda r: r[0].update(respond=[{"action": "format_disk"}]), "unknown response action"),
        (lambda r: r[0].update(respond=[{"action": "block_ip", "typo": 1}]), "unknown keys"),
        (lambda r: r[0].update(respond=[{"action": "block_ip", "min_score": 500}]), "0-100"),
        (lambda r: r[0]["criteria"].update(where={"a": {"regex": "("}}), "bad regex"),
        (lambda r: r[0]["criteria"].update(where={"a": {"nope": 1}}), "exactly one"),
        (lambda r: r[0]["criteria"].update(where={"a": {"in": "x"}}), "needs a list"),
    ],
)
def test_invalid_rules_are_rejected(tmp_path, mutate, message):
    rules = load_rules()
    mutate(rules)
    path = tmp_path / "rules.yml"
    path.write_text(yaml.safe_dump({"rules": rules}), encoding="utf-8")
    with pytest.raises(RuleError, match=message):
        load_rules(path)


@pytest.mark.parametrize(
    "content, message",
    [
        ("rules: [ {id: x\n", "rules.yml"),
        ("rules:\n  - just a string\n", "must be a mapping"),
        ("- a\n- b\n", "no rules"),
        ("rules: []\n", "no rules"),
    ],
)
def test_broken_rule_files_give_a_rule_error_not_a_crash(tmp_path, content, message):
    # Regression: these raised raw YAML and attribute errors.
    path = tmp_path / "rules.yml"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(RuleError, match=message):
        load_rules(path)


def test_every_shipped_rule_formats_without_crashing(engine):
    # Regression: reason "bad {" passed validation, then crashed on the first matching event.
    for rule in load_rules():
        engine.evaluate(
            {
                "ts": at(0), "type": rule["match"], "ip": "203.0.113.1", "user": "u", "pid": 5,
                "port": 9999, "msg": "m",
                "meta": {"proc": "p", "uid": 0, "new_uid": 0, "group": "sudo", "flags": ["malicious"],
                         "confidence": "high", "summary": "s", "parent": "x", "threat": "t",
                         "service": "s", "task": "t"},
            }
        )


def test_importing_the_engine_does_not_read_rules():
    # Regression: rules loaded at import, so `check` crashed on the file it exists to check.
    source = Path(rule_engine.__file__).read_text(encoding="utf-8")
    assert "\n_RULES = " not in source and "\nENGINE = " not in source


def write_events(paths, events):
    with paths.events.open("w", encoding="utf-8") as handle:
        for item in events:
            handle.write(json.dumps(item) + "\n")


def test_warm_up_remembers_a_burst_across_a_restart(config, paths):
    # Regression: a restart forgot the burst, so the login after it looked innocent.
    write_events(paths, [auth_fail(ts=at(index)) for index in range(5)])
    restarted = rule_engine.build_engine(config)
    assert restarted.warm_up(paths.events, paths.events.stat().st_size) == 5

    success = {"ts": at(30), "type": "auth_success", "ip": "203.0.113.5", "user": "alice"}
    assert types(restarted.evaluate(success)) == ["auth_compromise"]


def test_warm_up_stops_at_what_was_already_processed(config, paths):
    line = (json.dumps(auth_fail(ts=at(0))) + "\n").encode()
    paths.events.write_bytes(line * 4)
    assert rule_engine.build_engine(config).warm_up(paths.events, len(line) * 2) == 2


def test_warm_up_with_no_file_is_fine(config, paths):
    assert rule_engine.build_engine(config).warm_up(paths.events, 0) == 0


def watcher_for(engine, path):
    watcher = RuleWatcher(engine, path)
    watcher.CHECK_EVERY_SEC = 0
    watcher.next_check = 0
    return watcher


def test_rule_edit_applies_without_a_restart(config, tmp_path):
    path = tmp_path / "rules.yml"
    path.write_text(yaml.safe_dump({"rules": load_rules()[:3]}), encoding="utf-8")
    engine = rule_engine.RuleEngine(load_rules(path), config)
    watcher = watcher_for(engine, path)
    path.write_text(yaml.safe_dump({"rules": load_rules()[:1]}), encoding="utf-8")
    os.utime(path, (1, 1))
    watcher.poll()
    assert engine.rule_count() == 1


def test_bad_rule_edit_keeps_the_old_rules(config, tmp_path):
    path = tmp_path / "rules.yml"
    path.write_text(yaml.safe_dump({"rules": load_rules()[:3]}), encoding="utf-8")
    engine = rule_engine.RuleEngine(load_rules(path), config)
    watcher = watcher_for(engine, path)
    path.write_text("rules: [ broken", encoding="utf-8")
    os.utime(path, (1, 1))
    watcher.poll()
    assert engine.rule_count() == 3
