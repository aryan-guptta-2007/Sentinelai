import datetime as dt
import random
from pathlib import Path

import pytest

from analyzer import anomaly_detector
from analyzer.anomaly_detector import Scorer, build_plan, combine_scores
from common.runtime import METRIC_FIELDS, utc_now

HEADER = ",".join(METRIC_FIELDS) + "\n"
STRESS = {"procs": 460, "conns": 900, "net_out": 40000}


def row(cpu, mem=6000, load=0.7, when=None, procs=190, conns=50, net_in=200, net_out=100):
    stamp = (when or utc_now()).strftime("%Y-%m-%dT%H:%M:%SZ")
    return f"{stamp},{cpu},{mem},16000,{load},{load},{load},{procs},{conns},{net_in},{net_out}\n"


def seed_metrics(paths, rows=200):
    rng = random.Random(7)
    with paths.metrics.open("w", encoding="utf-8") as handle:
        handle.write(HEADER)
        for _ in range(rows):
            handle.write(
                row(
                    rng.uniform(8, 22), rng.uniform(5800, 6600), rng.uniform(0.3, 1.1),
                    procs=rng.randint(180, 210), conns=rng.randint(40, 70),
                    net_in=rng.uniform(100, 400), net_out=rng.uniform(50, 200),
                )
            )


def metrics(cpu, mem=6000, load=0.7, age_sec=0, **extra):
    when = utc_now() - dt.timedelta(seconds=age_sec)
    values = row(cpu, mem, load, when, **extra).strip().split(",")
    return dict(zip(METRIC_FIELDS, values))


@pytest.fixture
def scorer(config, paths):
    return Scorer(config, paths)


def burst(**event):
    return {"type": "auth_burst", "base_severity": 7, "event": {"ip": "203.0.113.1", **event},
            "respond": [{"action": "block_ip", "min_score": 40}]}


def test_severity_sets_the_floor():
    assert combine_scores(7, 0.0) == 70


def test_lift_moves_towards_one_hundred():
    assert combine_scores(7, 0.5) == 85
    assert combine_scores(10, 0.0) == 100


def test_out_of_range_inputs_are_clamped():
    assert combine_scores(50, 9.0) == 100
    assert combine_scores(-1, -1.0) == 0


def test_plan_resolves_targets_from_the_event():
    alert = {"event": {"ip": "198.51.100.4", "user": "bob"},
             "respond": [{"action": "block_ip"}, {"action": "lock_user"}]}
    assert build_plan(alert, 90) == [
        {"action": "block_ip", "target": "198.51.100.4"},
        {"action": "lock_user", "target": "bob"},
    ]


def test_plan_uses_a_custom_target_field():
    alert = {"event": {"meta": {"remote": "203.0.113.2"}},
             "respond": [{"action": "block_ip", "target": "meta.remote"}]}
    assert build_plan(alert, 90) == [{"action": "block_ip", "target": "203.0.113.2"}]


@pytest.mark.parametrize("event", [{}, {"ip": ""}, {"pid": 0}, {"pid": "0"}])
def test_step_without_a_target_is_dropped(event):
    alert = {"event": event, "respond": [{"action": "block_ip"}, {"action": "kill_process"}]}
    assert build_plan(alert, 90) == []


def test_step_below_its_score_is_dropped():
    alert = {"event": {"ip": "203.0.113.1"}, "respond": [{"action": "block_ip", "min_score": 80}]}
    assert build_plan(alert, 79) == []
    assert build_plan(alert, 80) != []


def test_no_response_rule_gives_an_empty_plan():
    assert build_plan({"event": {"ip": "203.0.113.1"}}, 100) == []


def test_normal_metrics_score_near_zero(scorer, paths):
    # Regression: a perfectly ordinary sample used to score about 55 out of 100.
    seed_metrics(paths)
    assert scorer.ml_score(metrics(15, 6200, 0.7)) < 10


def test_extreme_metrics_score_high(scorer, paths):
    seed_metrics(paths)
    assert scorer.ml_score(metrics(98, 15500, 16, **STRESS)) >= 70


def test_network_spike_alone_is_unusual(scorer, paths):
    seed_metrics(paths)
    assert scorer.ml_score(metrics(15, 6200, 0.7, net_out=90000)) > scorer.ml_score(metrics(15, 6200, 0.7))


def test_model_is_trained_once_and_reused(scorer, paths, monkeypatch):
    seed_metrics(paths)
    scorer.ml_score(metrics(15))
    assert scorer.bundle is not None

    def fail():
        raise AssertionError("retrained on a later alert")

    monkeypatch.setattr(scorer, "train", fail)
    scorer.ml_score(metrics(15))


def test_an_old_model_is_retrained(scorer, paths):
    seed_metrics(paths)
    scorer.ml_score(metrics(15))
    first = scorer.bundle
    first["trained"] = 0
    scorer.last_attempt = 0
    scorer.ml_score(metrics(15))
    assert scorer.bundle is not first


def test_no_model_file_is_ever_read(paths):
    # Regression: a planted pickle in the data folder ran code when it was loaded.
    source = Path(anomaly_detector.__file__).read_text(encoding="utf-8")
    assert "joblib" not in source and "pickle.load" not in source
    assert not hasattr(paths, "model")


def test_stale_metrics_are_ignored(scorer, paths):
    seed_metrics(paths)
    assert scorer.ml_score(metrics(98, 15500, 16, age_sec=3600)) == 0.0


def test_alert_is_scored_against_metrics_from_when_it_fired(scorer, paths):
    # Regression: a queued alert picked up a spike that happened after it fired.
    seed_metrics(paths)
    fired = utc_now() - dt.timedelta(seconds=30)
    with paths.metrics.open("a", encoding="utf-8") as handle:
        handle.write(row(12, 6000, 0.6, when=fired - dt.timedelta(seconds=10)))
        handle.write(row(98, 15500, 16, when=utc_now(), **STRESS))

    alert = burst(ts=fired.strftime("%Y-%m-%dT%H:%M:%SZ"))
    assert scorer.score_alert(alert)["ml_score"] < 10

    alert["event"]["ts"] = utc_now().strftime("%Y-%m-%dT%H:%M:%SZ")
    assert scorer.score_alert(alert)["ml_score"] >= 70


def test_alert_older_than_all_metrics_scores_zero(scorer, paths):
    seed_metrics(paths, rows=60)
    assert scorer.score_alert(burst(ts="2020-01-01T00:00:00Z"))["ml_score"] == 0.0


def test_too_little_history_falls_back_to_heuristic(scorer, paths):
    seed_metrics(paths, rows=10)
    assert scorer.ml_score(metrics(15, 6000, 0.5)) == 0.0
    assert scorer.ml_score(metrics(99, 15500, 16)) > 50


def test_latest_metrics_reads_last_row(scorer, paths):
    seed_metrics(paths, rows=3)
    with paths.metrics.open("a", encoding="utf-8") as handle:
        handle.write(row(55.5))
    assert scorer.latest_metrics()["cpu_pct"] == "55.5"


def test_header_only_and_empty_metrics(scorer, paths):
    paths.metrics.write_text("", encoding="utf-8")
    assert scorer.latest_metrics() is None
    paths.metrics.write_text(HEADER, encoding="utf-8")
    assert scorer.latest_metrics() is None


def test_training_skips_header_and_zero_memory_rows(scorer, paths):
    paths.metrics.write_text(HEADER + row(10).replace("16000", "0"), encoding="utf-8")
    assert scorer.read_training_rows() == []


def test_threat_record_shape(scorer, paths):
    alert = burst()
    threat = scorer.score_alert(alert)
    assert threat["plan"] == [{"action": "block_ip", "target": "203.0.113.1"}]
    assert threat["alert"] is alert
    assert threat["threat_score"] == 70


def test_score_says_why_it_was_raised(scorer, paths):
    seed_metrics(paths)
    now = utc_now().strftime("%Y-%m-%dT%H:%M:%SZ")
    with paths.metrics.open("a", encoding="utf-8") as handle:
        handle.write(row(98, 15500, 16, **STRESS))
    threat = scorer.score_alert(burst(ts=now))
    assert threat["threat_score"] > 70
    assert threat["factors"][0]["name"] == "host_anomaly"


def test_bad_severity_is_an_error_not_a_silent_default(scorer):
    with pytest.raises(ValueError):
        scorer.score_alert({"base_severity": "high", "event": {}})


def sustained(scorer, sample, times):
    return [scorer.review_sample(sample) for _ in range(times)]


def test_sustained_anomaly_raises_an_event_with_no_rule_involved(scorer, paths):
    # A rule only catches what someone thought to write down.
    seed_metrics(paths)
    results = sustained(scorer, metrics(98, 15500, 16, **STRESS), 3)
    assert results[:2] == [None, None]
    assert results[2]["type"] == "host_anomaly"
    assert results[2]["meta"]["unusual"]


def test_one_odd_sample_is_ignored(scorer, paths):
    seed_metrics(paths)
    assert scorer.review_sample(metrics(98, 15500, 16, **STRESS)) is None
    assert scorer.review_sample(metrics(15, 6200, 0.7)) is None
    assert scorer.unusual_samples == 0


def test_a_long_episode_raises_one_event(scorer, paths):
    seed_metrics(paths)
    results = sustained(scorer, metrics(98, 15500, 16, **STRESS), 8)
    assert len([item for item in results if item]) == 1


def test_no_model_means_no_anomaly_events(scorer, paths):
    seed_metrics(paths, rows=5)
    assert sustained(scorer, metrics(99, 15500, 16), 5) == [None] * 5


def test_deviations_name_what_is_unusual(scorer, paths):
    seed_metrics(paths)
    scorer.ml_score(metrics(15))
    names = {item["feature"] for item in scorer.deviations(metrics(15, 6200, 0.7, net_out=90000))}
    assert "net_out_kbps" in names
