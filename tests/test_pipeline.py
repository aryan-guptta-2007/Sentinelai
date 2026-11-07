"""End-to-end: real processes, real files, dry-run only."""

import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

import psutil
import pytest

from common.audit import read_actions
from common.runtime import append_jsonl, get_paths, now_iso, read_json, read_recent_jsonl
from daemon import supervisor
from daemon.supervisor import Component, Supervisor, build_components

REPO = Path(__file__).resolve().parents[1]


def wait_for(check, timeout=45):
    deadline = time.time() + timeout
    while time.time() < deadline:
        result = check()
        if result:
            return result
        time.sleep(0.25)
    return check()


@pytest.fixture
def isolated_env(home):
    env = dict(os.environ)
    env["SENTINELAI_RUN_MODE"] = "dry-run"
    return env


def test_full_pipeline_produces_every_action(paths, isolated_env):
    stack = subprocess.Popen(
        [sys.executable, "sentinel.py", "run", "--no-collectors", "--no-dashboard", "--duration", "60"],
        cwd=REPO,
        env=isolated_env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        subprocess.run(
            [sys.executable, "-m", "utils.simulate_events", "--scenario", "all"],
            cwd=REPO,
            env=isolated_env,
            check=True,
            timeout=40,
            stdout=subprocess.DEVNULL,
        )

        def recorded_actions():
            threats = read_recent_jsonl(paths.threats)
            actions = {step["action"] for t in threats for step in t["plan"]}
            history = read_actions(paths)
            needed = {"block_ip", "kill_process", "lock_user"}
            if needed <= actions and needed <= {h["action"] for h in history}:
                return threats, history
            return None

        result = wait_for(recorded_actions)
        assert result, f"threats: {read_recent_jsonl(paths.threats)}"
        _, history = result
        assert all(entry["dry_run"] is True for entry in history)
        assert {entry["status"] for entry in history} <= {"dry_run", "skipped", "refused"}
    finally:
        stack.terminate()
        stack.wait(timeout=20)


def test_stack_exits_within_duration(paths, isolated_env):
    done = subprocess.run(
        [sys.executable, "sentinel.py", "run", "--no-collectors", "--no-dashboard", "--duration", "3"],
        cwd=REPO,
        env=isolated_env,
        timeout=30,
        capture_output=True,
        text=True,
    )
    assert done.returncode == 0, done.stderr
    state = read_json(paths.supervisor, {})
    assert state["pid"] is None
    assert {info["state"] for info in state["components"].values()} == {"stopped"}


def crash_component(name="crasher", code=1):
    return Component(name, [sys.executable, "-c", f"import sys; sys.exit({code})"])


def run_supervisor(components, duration):
    from common.runtime import load_config

    instance = Supervisor(load_config(), components)
    instance.run(duration)
    return instance


def test_crashed_component_is_restarted(paths):
    item = crash_component()
    run_supervisor([item], 3.5)
    assert item.restarts >= 2


def test_backoff_grows_between_restarts(paths):
    item = crash_component()
    run_supervisor([item], 3.5)
    assert item.backoff >= 4


def test_unavailable_component_is_left_alone(paths):
    item = crash_component("idle", supervisor.EXIT_UNAVAILABLE)
    keeper = Component("keeper", [sys.executable, "-c", "import time; time.sleep(30)"])
    run_supervisor([item, keeper], 2)
    assert item.restarts == 0
    assert item.detail == "nothing to do on this host"


def test_children_are_stopped_on_shutdown(paths):
    item = Component("sleeper", [sys.executable, "-c", "import time; time.sleep(60)"])
    run_supervisor([item], 1.5)
    assert item.process.poll() is not None


def component_pids(paths):
    state = read_json(paths.supervisor, {})
    pids = [info.get("pid") for info in (state.get("components") or {}).values()]
    found = [pid for pid in pids if pid]
    return found if len(found) >= 3 else []


def test_components_exit_if_supervisor_is_killed(paths, isolated_env):
    # Regression: a killed supervisor left orphans running, including the responder.
    stack = subprocess.Popen(
        [sys.executable, "sentinel.py", "run", "--no-collectors", "--no-dashboard", "--duration", "60"],
        cwd=REPO,
        env=isolated_env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        pids = wait_for(lambda: component_pids(paths), timeout=20)
        assert pids
    finally:
        stack.kill()
        stack.wait(timeout=10)

    assert wait_for(lambda: not any(psutil.pid_exists(pid) for pid in pids), timeout=10)


def test_components_run_normally_without_a_supervisor(paths):
    env = {key: value for key, value in os.environ.items() if key != "SENTINELAI_SUPERVISOR_PID"}
    component = subprocess.Popen(
        [sys.executable, "-m", "analyzer.rule_engine"],
        cwd=REPO,
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        time.sleep(3)
        assert component.poll() is None
    finally:
        component.kill()
        component.wait(timeout=10)


def test_second_instance_is_refused(paths, isolated_env):
    first = subprocess.Popen(
        [sys.executable, "sentinel.py", "run", "--no-collectors", "--no-dashboard", "--duration", "20"],
        cwd=REPO,
        env=isolated_env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        assert wait_for(lambda: read_json(paths.supervisor, {}).get("pid"), timeout=15)
        second = subprocess.run(
            [sys.executable, "sentinel.py", "run", "--no-collectors", "--no-dashboard", "--duration", "3"],
            cwd=REPO,
            env=isolated_env,
            timeout=20,
            capture_output=True,
            text=True,
        )
        assert second.returncode == 1
        assert "already running" in second.stderr
    finally:
        first.terminate()
        first.wait(timeout=20)


def test_collectors_run_on_every_platform(config):
    names = [item.name for item in build_components(config)]
    assert {"log_monitor", "host_monitor", "file_monitor", "rule_engine", "responder", "notifier"} <= set(names)


def test_collectors_can_be_left_out(config):
    names = [item.name for item in build_components(config, collectors=False)]
    assert "host_monitor" not in names and "rule_engine" in names


def test_host_monitor_runs_for_real(paths, isolated_env):
    # This is the collector that gives a Windows host real coverage.
    monitor = subprocess.Popen(
        [sys.executable, "-m", "collectors.host_monitor"],
        cwd=REPO,
        env=isolated_env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    try:
        assert wait_for(
            lambda: paths.metrics.exists() and len(paths.metrics.read_text(encoding="utf-8").splitlines()) >= 2,
            timeout=20,
        ), monitor.stderr.read() if monitor.poll() is not None else "no metrics"
        assert wait_for((paths.state_dir / "listening_ports.json").exists, timeout=10)
    finally:
        monitor.kill()
        monitor.wait(timeout=10)


def test_a_bad_record_does_not_stop_the_detector(paths, isolated_env):
    # Regression: one malformed alert stopped every alert behind it, permanently.
    append_jsonl(paths.alerts, {"ts": now_iso(), "type": "auth_burst", "base_severity": "high", "event": {}})
    append_jsonl(paths.alerts, {"ts": now_iso(), "type": "auth_burst", "base_severity": 7,
                                "event": {"ip": "203.0.113.1"}, "reason": "good"})
    detector = subprocess.Popen(
        [sys.executable, "-m", "analyzer.anomaly_detector"],
        cwd=REPO,
        env=isolated_env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        assert wait_for(lambda: read_recent_jsonl(paths.threats), timeout=20)
        assert detector.poll() is None
        assert "high" in paths.dead_letters.read_text(encoding="utf-8")
    finally:
        detector.kill()
        detector.wait(timeout=10)


def test_two_starts_at_once_cannot_both_run(paths, isolated_env):
    # Regression: the check read a PID file, so two starts could both pass it.
    command = [sys.executable, "sentinel.py", "run", "--no-collectors", "--no-dashboard", "--duration", "8"]
    starts = [
        subprocess.Popen(command, cwd=REPO, env=isolated_env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        for _ in range(3)
    ]
    results = [start.communicate(timeout=30) and start.returncode for start in starts]
    assert sorted(results) == [0, 1, 1]


def test_old_model_files_are_left_unread(paths, isolated_env, home):
    # A leftover pickle from an older version must not be touched.
    shutil.rmtree(paths.data_dir / "models", ignore_errors=True)
    (paths.data_dir / "models").mkdir()
    (paths.data_dir / "models" / "iforest.pkl").write_bytes(b"not a real model")
    done = subprocess.run(
        [sys.executable, "sentinel.py", "run", "--no-collectors", "--no-dashboard", "--duration", "3"],
        cwd=REPO, env=isolated_env, timeout=30, capture_output=True, text=True,
    )
    assert done.returncode == 0, done.stderr


def test_simulate_command_accepts_scenario_option(paths, isolated_env):
    # Regression: the documented form was rejected by the argument parser.
    done = subprocess.run(
        [sys.executable, "sentinel.py", "simulate", "--scenario", "proc", "--no-baseline"],
        cwd=REPO,
        env=isolated_env,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert done.returncode == 0, done.stderr
    assert "suspicious_proc" in paths.events.read_text(encoding="utf-8")


def test_demo_leaves_no_simulator_running(home, isolated_env):
    # Regression: the simulator kept writing events after the demo had exited.
    done = subprocess.run(
        [sys.executable, "sentinel.py", "demo", "--no-dashboard", "--duration", "4"],
        cwd=REPO,
        env=isolated_env,
        capture_output=True,
        text=True,
        timeout=40,
    )
    assert done.returncode == 0, done.stderr

    def is_simulator(process):
        try:
            return "utils.simulate_events" in " ".join(process.cmdline())
        except psutil.Error:
            return False

    assert not [item for item in psutil.process_iter() if is_simulator(item)]


def test_demo_data_stays_out_of_real_data(home, paths, isolated_env):
    subprocess.run(
        [sys.executable, "sentinel.py", "demo", "--no-dashboard", "--duration", "4"],
        cwd=REPO,
        env=isolated_env,
        capture_output=True,
        timeout=40,
    )
    assert (home / "data" / "demo" / "events.jsonl").exists()
    assert not paths.events.exists()


def test_check_command_passes():
    done = subprocess.run(
        [sys.executable, "sentinel.py", "check"], cwd=REPO, capture_output=True, text=True, timeout=30
    )
    assert done.returncode == 0, done.stderr
    assert "rules" in done.stdout


def test_simulated_events_are_valid_json(paths, isolated_env):
    subprocess.run(
        [sys.executable, "-m", "utils.simulate_events", "--scenario", "proc"],
        cwd=REPO,
        env=isolated_env,
        check=True,
        timeout=30,
    )
    lines = paths.events.read_text(encoding="utf-8").splitlines()
    assert lines and all(json.loads(line) for line in lines)


def test_paths_honour_overrides(monkeypatch):
    monkeypatch.setenv("SENTINELAI_DATA_DIR", "data/demo")
    assert get_paths().data_dir.parts[-2:] == ("data", "demo")
