#!/usr/bin/env python3
"""SentinelAI scorer: rates alerts, decides the response plan, and watches host behaviour.

The score says how urgent an alert is. Severity sets the floor and context can only
lift it, so a quiet host never dilutes a critical alert. What gets killed or locked is
decided by the rule that fired, never by the score: a busy host is not evidence.
"""

from __future__ import annotations

import csv
import datetime as dt
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

if __package__ in (None, ""):  # allow `python analyzer/anomaly_detector.py`
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from analyzer.incidents import IncidentTracker, context_factors
from analyzer.rule_engine import DEFAULT_TARGETS, lookup
from common.runtime import (
    METRIC_FIELDS,
    Follower,
    Paths,
    append_jsonl,
    deliver,
    exit_with_supervisor,
    get_paths,
    harden_process,
    load_config,
    make_logger,
    now_iso,
    parse_ts,
    read_recent_jsonl,
    utc_now,
)

log_message = make_logger("anomaly_detector", "analyzer.log")

FEATURES = [
    "cpu_pct", "mem_ratio", "load1", "load5", "load15",
    "procs", "conns", "net_in_kbps", "net_out_kbps",
]
TAIL_BYTES = 65536
RETRY_TRAINING_SEC = 60
INCIDENT_HISTORY = 2000  # recent threats read at startup to pick up attacks in progress
SUSTAINED_SAMPLES = 3  # one odd sample is noise
DEVIATION_LIMIT = 3.0  # standard deviations from normal worth naming
BEYOND_HISTORY_SPREADS = 10.0  # how far past the highest value ever seen counts as extreme


def feature_vector(row: Dict[str, str]) -> Optional[List[float]]:
    try:
        total = float(row["mem_total_mb"])
        if total <= 0:
            return None
        return [
            float(row["cpu_pct"]),
            float(row["mem_used_mb"]) / total,
            float(row["load1"]),
            float(row["load5"]),
            float(row["load15"]),
            float(row["procs"]),
            float(row["conns"]),
            float(row["net_in_kbps"]),
            float(row["net_out_kbps"]),
        ]
    except (KeyError, TypeError, ValueError):
        return None


def heuristic_score(vector: List[float]) -> float:
    """Fallback that stays near zero on a healthy host and grows under real pressure."""
    cpu_pct, mem_ratio, load1 = vector[0], vector[1], vector[2]
    pressure = 1.5 * max(0.0, cpu_pct - 60.0) + 120.0 * max(0.0, mem_ratio - 0.8)
    return min(100.0, pressure + 4.0 * max(0.0, load1 - 4.0))


def beyond_history(vector: List[float], highs: List[float], spreads: List[float]) -> float:
    """Score how far any single measurement is past everything this host has recorded.

    An isolation forest picks a feature at random for each split, so one extreme value
    among many normal ones barely registers. A data transfer 700 times the usual size
    with everything else quiet scored 0 on the model alone, and that is what
    exfiltration looks like. Values inside the host's own history always score 0 here,
    so a nightly backup that has happened before is not an anomaly.
    """
    worst = 0.0
    for value, high, spread in zip(vector, highs, spreads):
        if value > high:
            worst = max(worst, (value - high) / max(spread, abs(high) * 0.1, 1e-6))
    return min(100.0, 100.0 * worst / BEYOND_HISTORY_SPREADS)


def combine_scores(base_severity: int, lift: float) -> int:
    """Severity sets the floor, and lift (0 to 1) moves the score towards 100."""
    floor = 10.0 * max(0, min(10, base_severity))
    return int(round(floor + (100.0 - floor) * max(0.0, min(1.0, lift))))


def build_plan(alert: Dict[str, Any], score: int) -> List[Dict[str, str]]:
    """Resolve the rule's response steps against this alert."""
    event = alert.get("event") or {}
    plan: List[Dict[str, str]] = []
    for step in alert.get("respond") or []:
        action = step["action"]
        if score < int(step.get("min_score", 0)):
            continue
        target = lookup(event, step.get("target") or DEFAULT_TARGETS[action])
        if target in (None, "", 0, "0"):
            continue
        plan.append({"action": action, "target": str(target)})
    return plan


class Scorer:
    def __init__(self, config: Dict[str, Any], paths: Paths):
        self.paths = paths
        section = config.get("ml", {})
        self.ml_weight = float(config["thresholds"].get("ml_weight", 0.4))
        self.min_rows = int(section.get("min_training_rows", 50))
        self.max_rows = int(section.get("max_training_rows", 20000))
        self.max_age = float(section.get("retrain_hours", 24)) * 3600
        self.metrics_max_age = int(section.get("metrics_max_age_sec", 300))
        self.anomaly_score = float(section.get("anomaly_alert_score", 80))
        self.bundle: Optional[Dict[str, Any]] = None
        self.last_attempt = 0.0
        self.unusual_samples = 0
        self.incidents = IncidentTracker()
        self.incidents.rebuild(read_recent_jsonl(paths.threats, INCIDENT_HISTORY))

    # ------------------------------------------------------------------ metrics
    def latest_metrics(self, at: Optional[dt.datetime] = None) -> Optional[Dict[str, str]]:
        """Return the newest metrics row, or the newest one at or before a moment.

        Alerts are scored against the host state when they fired. Scoring against the
        current state would be wrong for any alert that waited in the queue or was
        replayed after downtime. Only the end of the file is read.
        """
        try:
            with self.paths.metrics.open("rb") as handle:
                handle.seek(0, 2)
                size = handle.tell()
                handle.seek(max(0, size - TAIL_BYTES))
                lines = handle.read().decode("utf-8", errors="replace").strip().splitlines()
        except OSError:
            return None

        for line in reversed(lines):
            values = line.split(",")
            if len(values) != len(METRIC_FIELDS) or line.startswith("ts,"):
                continue
            row = dict(zip(METRIC_FIELDS, values))
            stamp = parse_ts(row["ts"])
            if at is None or (stamp is not None and stamp <= at):
                return row
        return None

    def metrics_are_fresh(self, metrics: Dict[str, str], at: Optional[dt.datetime] = None) -> bool:
        stamp = parse_ts(metrics.get("ts"))
        if stamp is None:
            return False
        return ((at or utc_now()) - stamp).total_seconds() <= self.metrics_max_age

    def read_training_rows(self) -> List[List[float]]:
        try:
            with self.paths.metrics.open("r", encoding="utf-8", errors="replace", newline="") as handle:
                rows = list(csv.DictReader(handle, fieldnames=METRIC_FIELDS))
        except OSError:
            return []
        vectors = [feature_vector(row) for row in rows[-self.max_rows:]]
        return [vector for vector in vectors if vector is not None]

    # -------------------------------------------------------------------- model
    def train(self) -> Optional[Dict[str, Any]]:
        """Fit a model on recent metrics and record how normal data scores on it.

        The model stays in memory. Training takes well under a second, and loading a
        saved one means unpickling a file, which runs whatever code the file contains.
        """
        try:
            import numpy as np  # type: ignore
            from sklearn.ensemble import IsolationForest  # type: ignore
        except ImportError as exc:  # pragma: no cover - optional dependency
            log_message(f"ML libraries unavailable, using heuristic: {exc}")
            return None

        vectors = self.read_training_rows()
        if len(vectors) < self.min_rows:
            return None

        data = np.array(vectors)
        model = IsolationForest(n_estimators=100, contamination="auto", random_state=42)
        model.fit(data)
        raw = -model.score_samples(data)

        # Scores are only meaningful relative to this host, so anchor them to the training
        # data: the 95th percentile maps to 0 and values past the most unusual sample climb.
        floor = float(np.percentile(raw, 95))
        ceiling = max(float(raw.max()) + 0.05, floor + 0.1)
        log_message(f"trained model on {len(vectors)} rows")
        return {
            "model": model,
            "floor": floor,
            "ceiling": ceiling,
            "means": data.mean(axis=0).tolist(),
            "spreads": data.std(axis=0).tolist(),
            "highs": data.max(axis=0).tolist(),
            "trained": time.time(),
            "rows": len(vectors),
        }

    def current_model(self) -> Optional[Dict[str, Any]]:
        """Return the model, retraining once it passes its configured age."""
        stale = self.bundle is None or time.time() - self.bundle["trained"] > self.max_age
        # Throttle attempts so hosts without enough data do not retry on every alert.
        if stale and time.time() - self.last_attempt > RETRY_TRAINING_SEC:
            self.last_attempt = time.time()
            self.bundle = self.train() or self.bundle
        return self.bundle

    def ml_score(self, metrics: Optional[Dict[str, str]], at: Optional[dt.datetime] = None) -> float:
        if not metrics or not self.metrics_are_fresh(metrics, at):
            return 0.0
        vector = feature_vector(metrics)
        if vector is None:
            return 0.0

        bundle = self.current_model()
        if bundle is None:
            return heuristic_score(vector)

        try:
            import numpy as np  # type: ignore

            raw = float(-bundle["model"].score_samples(np.array([vector]))[0])
        except Exception as exc:  # pragma: no cover
            log_message(f"model scoring failed: {exc}")
            return heuristic_score(vector)

        span = bundle["ceiling"] - bundle["floor"]
        forest = 100.0 * max(0.0, min(1.0, (raw - bundle["floor"]) / span))
        return max(forest, beyond_history(vector, bundle["highs"], bundle["spreads"]))

    def deviations(self, metrics: Dict[str, str]) -> List[Dict[str, Any]]:
        """Name what is unusual, so a person can see why the model objected."""
        vector = feature_vector(metrics)
        if vector is None or self.bundle is None:
            return []
        found = []
        for name, value, mean, spread in zip(
            FEATURES, vector, self.bundle["means"], self.bundle["spreads"]
        ):
            if spread > 0 and abs(value - mean) / spread >= DEVIATION_LIMIT:
                found.append({"feature": name, "value": round(value, 2), "normal": round(mean, 2)})
        found.sort(key=lambda item: -abs(item["value"] - item["normal"]))
        return found[:3]

    # ------------------------------------------------------------------ scoring
    def score_alert(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        event = alert.get("event") or {}
        severity = int(alert.get("base_severity", 5))
        fired_at = parse_ts(event.get("ts")) or parse_ts(alert.get("ts"))
        metrics = self.latest_metrics(fired_at)
        ml_score = self.ml_score(metrics, fired_at)
        incident = self.incidents.observe(alert, fired_at.timestamp() if fired_at else None)

        factors: List[Dict[str, Any]] = context_factors(incident)
        if ml_score >= 1:
            factors.append(
                {"name": "host_anomaly", "lift": self.ml_weight * ml_score / 100.0,
                 "detail": f"host behaviour scored {ml_score:.0f} out of 100"}
            )
        remaining = 1.0
        for factor in factors:
            remaining *= 1.0 - factor["lift"]
        threat_score = combine_scores(severity, 1.0 - remaining)

        return {
            "ts": now_iso(),
            "alert": alert,
            "ml_score": round(ml_score, 1),
            "threat_score": threat_score,
            "factors": factors,
            "incident": incident.id,
            "plan": build_plan(alert, threat_score),
            "notes": str(alert.get("reason") or ""),
        }

    def review_sample(self, row: Dict[str, str]) -> Optional[Dict[str, Any]]:
        """Raise an event when the host stays abnormal, whether or not any rule fired.

        Rules only catch what someone thought to write down. This catches the rest.
        """
        if self.current_model() is None:
            return None
        score = self.ml_score(row)
        if score < self.anomaly_score:
            self.unusual_samples = 0
            return None
        self.unusual_samples += 1
        if self.unusual_samples != SUSTAINED_SAMPLES:
            return None  # one event per episode

        unusual = self.deviations(row)
        names = ", ".join(item["feature"] for item in unusual) or "overall behaviour"
        return {
            "ts": now_iso(),
            "src": "anomaly_detector",
            "type": "host_anomaly",
            "msg": f"Host behaviour is unusual: {names}",
            "meta": {"score": round(score, 1), "unusual": unusual, "summary": names},
        }


def main() -> None:
    harden_process()
    exit_with_supervisor()
    config = load_config()
    paths = get_paths(config).ensure()
    scorer = Scorer(config, paths)
    follow = bool(config["modes"].get("follow_files", True))
    log_message("started")

    paths.alerts.touch(exist_ok=True)
    alerts = Follower(paths.alerts, "anomaly_detector", paths.state_dir)
    samples = Follower(paths.metrics, "anomaly_metrics", paths.state_dir, start_at_end=True)

    def handle(alert: Dict[str, Any]) -> None:
        threat = scorer.score_alert(alert)
        append_jsonl(paths.threats, threat)
        steps = ", ".join(f"{s['action']} {s['target']}" for s in threat["plan"]) or "none"
        log_message(f"threat score={threat['threat_score']} plan={steps}")

    while True:
        for raw in alerts.read_available():
            deliver(raw, handle, log_message, paths.dead_letters)
        for line in samples.read_available():
            values = line.split(",")
            if len(values) == len(METRIC_FIELDS) and not line.startswith("ts,"):
                event = scorer.review_sample(dict(zip(METRIC_FIELDS, values)))
                if event:
                    append_jsonl(paths.events, event)
        if not follow:
            return
        time.sleep(alerts.poll_sec)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
