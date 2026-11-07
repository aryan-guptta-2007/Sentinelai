import pytest

from analyzer import rule_engine
from analyzer.anomaly_detector import Scorer
from analyzer.incidents import OPEN_FOR_SEC, IncidentTracker, context_factors
from common.attack import TECHNIQUES, TACTIC_NAMES, TACTIC_ORDER, tactics_of, technique_name
from common.runtime import now_iso, read_recent_jsonl


def alert(kind="auth_burst", ip="", user="", mitre=("T1110.001",)):
    return {"type": kind, "mitre": list(mitre), "event": {"ip": ip, "user": user}}


def test_alerts_from_one_address_are_one_incident():
    tracker = IncidentTracker()
    first = tracker.observe(alert(ip="203.0.113.5"), 1000)
    second = tracker.observe(alert(ip="203.0.113.5"), 1010)
    assert first is second and first.alerts == 2


def test_different_attackers_are_different_incidents():
    tracker = IncidentTracker()
    assert tracker.observe(alert(ip="203.0.113.5"), 1000) is not tracker.observe(alert(ip="203.0.113.6"), 1000)


def test_a_shared_account_name_does_not_join_unrelated_attackers():
    # Everyone tries root, so that alone proves nothing.
    tracker = IncidentTracker()
    first = tracker.observe(alert(ip="203.0.113.5", user="root"), 1000)
    assert tracker.observe(alert(ip="203.0.113.6", user="root"), 1000) is not first


def test_two_attackers_on_one_named_account_stay_separate():
    # Regression: seen in the demo, where two attackers merged into one incident because
    # both had touched "bob". An address is stronger identity than an account name.
    tracker = IncidentTracker()
    first = tracker.observe(alert("auth_compromise", ip="203.0.113.5", user="bob"), 1000)
    assert tracker.observe(alert(ip="203.0.113.6", user="bob"), 1010) is not first


def test_a_named_account_links_activity_with_no_address():
    tracker = IncidentTracker()
    first = tracker.observe(alert("auth_compromise", ip="203.0.113.5", user="alice"), 1000)
    later = tracker.observe(alert("sudo_abuse", user="alice", mitre=["T1548.003"]), 1100)
    assert later is first


def test_host_activity_joins_a_compromise():
    # A cron job carries no address, but right after a break-in it is not a coincidence.
    tracker = IncidentTracker()
    first = tracker.observe(alert("auth_compromise", ip="203.0.113.5", user="alice", mitre=["T1078"]), 1000)
    later = tracker.observe(alert("persistence", mitre=["T1053.003"]), 1200)
    assert later is first
    assert {"initial-access", "persistence"} <= first.tactics


def test_host_activity_stays_separate_without_a_compromise():
    tracker = IncidentTracker()
    first = tracker.observe(alert(ip="203.0.113.5"), 1000)
    assert tracker.observe(alert("persistence", mitre=["T1053.003"]), 1200) is not first


def test_an_incident_closes_when_it_goes_quiet():
    tracker = IncidentTracker()
    first = tracker.observe(alert(ip="203.0.113.5"), 1000)
    assert tracker.observe(alert(ip="203.0.113.5"), 1000 + OPEN_FOR_SEC + 1) is not first


def test_incident_ids_do_not_collide():
    tracker = IncidentTracker()
    first = tracker.observe(alert(ip="203.0.113.5"), 1000)
    second = tracker.observe(alert(ip="203.0.113.6"), 1000)
    assert first.id != second.id


def test_a_restart_keeps_an_attack_in_progress_together(paths):
    # Otherwise a restart would split one attack in two and lose the context behind its score.
    stamp = now_iso()
    threats = [{"ts": stamp, "alert": {**alert(ip="203.0.113.5"), "event": {"ip": "203.0.113.5", "ts": stamp}}}]
    tracker = IncidentTracker()
    tracker.rebuild(threats)
    assert tracker.open[0].alerts == 1
    assert tracker.observe(alert(ip="203.0.113.5")) is tracker.open[0]


def test_rebuild_skips_junk():
    tracker = IncidentTracker()
    tracker.rebuild([{"alert": "nonsense"}, "text", {"alert": {"event": {}}}])
    assert tracker.open == []


def test_one_alert_adds_no_context():
    tracker = IncidentTracker()
    assert context_factors(tracker.observe(alert(ip="203.0.113.5"), 1000)) == []


def test_several_stages_raise_the_stakes():
    tracker = IncidentTracker()
    tracker.observe(alert("auth_compromise", ip="203.0.113.5", mitre=["T1110"]), 1000)
    incident = tracker.observe(alert("persistence", ip="203.0.113.5", mitre=["T1053.003"]), 1100)
    names = {factor["name"] for factor in context_factors(incident)}
    assert names == {"attack_chain", "repeat_activity"}


def test_context_lift_stays_bounded():
    tracker = IncidentTracker()
    for index, technique in enumerate(("T1110", "T1053.003", "T1078", "T1059", "T1490", "T1571", "T1548.003")):
        incident = tracker.observe(alert(ip="203.0.113.5", mitre=[technique]), 1000 + index)
    assert all(factor["lift"] <= 0.6 for factor in context_factors(incident))


def test_scorer_stamps_each_threat_with_its_incident(config, paths):
    scorer = Scorer(config, paths)
    first = scorer.score_alert({**alert(ip="203.0.113.5"), "base_severity": 7})
    second = scorer.score_alert({**alert(ip="203.0.113.5"), "base_severity": 7})
    assert first["incident"] == second["incident"]


def test_an_attack_chain_lifts_the_score(config, paths):
    scorer = Scorer(config, paths)
    alone = scorer.score_alert({**alert(ip="203.0.113.5"), "base_severity": 5})["threat_score"]
    scorer.score_alert({**alert(ip="203.0.113.6", mitre=["T1078"]), "base_severity": 5})
    joined = scorer.score_alert({**alert(ip="203.0.113.6", mitre=["T1053.003"]), "base_severity": 5})
    assert joined["threat_score"] > alone
    assert "attack_chain" in {factor["name"] for factor in joined["factors"]}


def test_context_never_turns_a_review_rule_into_a_kill(config, paths):
    # Context raises urgency. What is destructive stays fixed by the rule that fired.
    engine = rule_engine.build_engine(config)
    scorer = Scorer(config, paths)
    for index in range(3):
        event = {"ts": now_iso(), "type": "suspicious_proc", "pid": 100 + index, "user": "x",
                 "meta": {"proc": "gcc", "flags": ["cpu"]}}
        for item in engine.evaluate(event):
            assert scorer.score_alert(item)["plan"] == []


def test_a_scorer_restart_continues_the_incident(config, paths):
    from common.runtime import append_jsonl

    first = Scorer(config, paths).score_alert({**alert(ip="203.0.113.5"), "base_severity": 7, "ts": now_iso()})
    append_jsonl(paths.threats, first)
    second = Scorer(config, paths).score_alert({**alert(ip="203.0.113.5"), "base_severity": 7, "ts": now_iso()})
    assert second["incident"] == first["incident"]
    assert read_recent_jsonl(paths.threats)


# --------------------------------------------------------------------- ATT&CK table
def test_every_technique_used_by_a_rule_is_known():
    # Otherwise a stage silently goes missing from the incident view.
    for rule in rule_engine.load_rules():
        for technique in rule.get("mitre") or []:
            assert technique in TECHNIQUES, f"{rule['id']}: {technique}"


def test_every_technique_used_by_an_indicator_is_known(config):
    from collectors.process_checks import load_indicators

    for indicator in load_indicators(config).commands:
        assert indicator.technique in TECHNIQUES, indicator.id


def test_every_tactic_has_a_name_and_a_place():
    assert set(TACTIC_NAMES) == set(TACTIC_ORDER)
    assert {tactic for _, tactic in TECHNIQUES.values()} <= set(TACTIC_ORDER)


def test_tactics_come_back_in_attack_order():
    assert tactics_of(["T1490", "T1078", "T1053.003"]) == ["initial-access", "persistence", "impact"]


@pytest.mark.parametrize("technique, name", [("T1110.001", "Password Guessing"), ("T9999", "")])
def test_technique_names(technique, name):
    assert technique_name(technique) == name
