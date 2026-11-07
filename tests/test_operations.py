"""Audit log, housekeeping, configuration checks and the command line."""

import copy
import gzip
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest

from common import maintenance
from common.audit import GENESIS, AuditLog, entry_hash, read_actions, verify_audit
from common.maintenance import delete_old, rotate_file, run_maintenance, trim_metrics, trim_output_log
from common.runtime import METRIC_FIELDS, Follower, read_json
from common.settings import config_problems, preflight

REPO = Path(__file__).resolve().parents[1]


def action(number=1):
    return {"ts": "2026-11-07T10:00:00Z", "action": "block_ip", "target": f"203.0.113.{number}", "status": "applied"}


# ------------------------------------------------------------------------- audit
def test_entries_are_linked(paths):
    log = AuditLog(paths)
    first = log.append(action(1))
    second = log.append(action(2))
    assert first["prev"] == GENESIS
    assert second["prev"] == first["hash"]
    assert (first["seq"], second["seq"]) == (1, 2)


def test_an_intact_log_verifies(paths):
    log = AuditLog(paths)
    for number in range(5):
        log.append(action(number + 1))
    assert verify_audit(paths) == (True, 5, "")


def test_an_empty_log_verifies(paths):
    assert verify_audit(paths) == (True, 0, "")


def rewrite(paths, change):
    records = [json.loads(line) for line in paths.audit.read_text(encoding="utf-8").splitlines()]
    change(records)
    paths.audit.write_text("".join(json.dumps(item) + "\n" for item in records), encoding="utf-8")


def filled(paths, count=3):
    log = AuditLog(paths)
    for number in range(count):
        log.append(action(number + 1))


def test_an_edit_is_detected(paths):
    filled(paths)
    rewrite(paths, lambda records: records[1].update(target="198.51.100.1"))
    intact, checked, problem = verify_audit(paths)
    assert not intact and checked == 1 and "altered" in problem


def test_a_deleted_entry_is_detected(paths):
    filled(paths)
    rewrite(paths, lambda records: records.pop(1))
    assert verify_audit(paths)[0] is False


def test_removing_the_newest_entries_is_detected(paths):
    filled(paths)
    rewrite(paths, lambda records: records.pop())
    intact, _, problem = verify_audit(paths)
    assert not intact and "missing" in problem


def test_a_recalculated_edit_still_breaks_the_chain(paths):
    filled(paths)

    def forge(records):
        records[1]["target"] = "198.51.100.1"
        records[1]["hash"] = entry_hash(records[1])

    rewrite(paths, forge)
    assert verify_audit(paths)[0] is False


def test_a_corrupt_line_is_detected(paths):
    filled(paths)
    with paths.audit.open("a", encoding="utf-8") as handle:
        handle.write("not json\n")
    assert verify_audit(paths)[0] is False


def test_the_chain_continues_across_a_rotation(paths):
    log = AuditLog(paths)
    log.append(action(1))
    os.replace(paths.audit, paths.audit.with_name("audit.jsonl.1"))
    second = log.append(action(2))
    assert second["seq"] == 2
    assert verify_audit(paths) == (True, 2, "")


def test_a_crash_between_log_and_head_does_not_fork_the_chain(paths):
    log = AuditLog(paths)
    log.append(action(1))
    paths.audit_head.unlink()
    log.append(action(2))
    assert verify_audit(paths)[0] is True


def test_actions_read_newest_last(paths):
    filled(paths)
    assert [item["seq"] for item in read_actions(paths)] == [1, 2, 3]


def test_concurrent_writers_keep_one_chain(paths):
    code = (
        "from common.audit import AuditLog; from common.runtime import get_paths;"
        "log = AuditLog(get_paths());"
        "[log.append({'ts': 't', 'n': i}) for i in range(20)]"
    )
    writers = [subprocess.Popen([sys.executable, "-c", code], cwd=REPO) for _ in range(3)]
    for writer in writers:
        assert writer.wait(timeout=60) == 0
    assert verify_audit(paths) == (True, 60, "")


# ------------------------------------------------------------------- housekeeping
def test_a_small_file_is_left_alone(paths, tmp_path):
    paths.events.write_text("x\n", encoding="utf-8")
    assert rotate_file(paths.events, 1000, tmp_path) is False


def test_a_big_file_is_renamed_for_readers(paths, tmp_path):
    paths.events.write_text("x" * 100, encoding="utf-8")
    assert rotate_file(paths.events, 10, tmp_path) is True
    assert paths.events.with_name("events.jsonl.1").exists()
    assert not paths.events.exists()


def test_the_previous_copy_is_compressed_not_lost(paths, tmp_path):
    previous = paths.events.with_name("events.jsonl.1")
    previous.write_bytes(b"old data\n")
    paths.events.write_text("x" * 100, encoding="utf-8")
    rotate_file(paths.events, 10, tmp_path)
    archive = next(tmp_path.glob("*.gz"))
    assert gzip.decompress(archive.read_bytes()) == b"old data\n"


def test_a_missing_file_is_fine(paths, tmp_path):
    assert rotate_file(paths.events, 10, tmp_path) is False


def test_a_reader_loses_nothing_across_a_real_rotation(paths, tmp_path):
    # Regression: the old script copied and truncated, which lost anything not yet read.
    follower = Follower(paths.events, "t", paths.state_dir)
    paths.events.write_text("one\ntwo\n", encoding="utf-8")
    assert list(follower.read_available()) == ["one", "two"]
    with paths.events.open("a", encoding="utf-8") as handle:
        handle.write("three\n")
    assert rotate_file(paths.events, 1, tmp_path) is True
    paths.events.write_text("four\n", encoding="utf-8")
    assert list(follower.read_available()) == ["three", "four"]


def test_metrics_keep_their_header_and_recent_rows(paths):
    header = ",".join(METRIC_FIELDS)
    rows = [f"row{i}" for i in range(100)]
    paths.metrics.write_text("\n".join([header, *rows]) + "\n", encoding="utf-8")
    assert trim_metrics(paths.metrics, 50) is True
    lines = paths.metrics.read_text(encoding="utf-8").splitlines()
    assert lines[0] == header and lines[-1] == "row99"
    assert len(lines) == 26


def test_short_metrics_are_left_alone(paths):
    paths.metrics.write_text("a\nb\n", encoding="utf-8")
    assert trim_metrics(paths.metrics, 50) is False


def test_a_big_output_log_is_emptied_in_place(paths):
    log = paths.logs_dir / "x.out.log"
    log.write_text("y" * 100, encoding="utf-8")
    trim_output_log(log, 10)
    assert log.stat().st_size == 0


def test_old_archives_are_deleted(tmp_path):
    old, new = tmp_path / "old.gz", tmp_path / "new.gz"
    old.write_bytes(b"x")
    new.write_bytes(b"x")
    long_ago = time.time() - 30 * 86400
    os.utime(old, (long_ago, long_ago))
    assert delete_old(tmp_path, 14) == 1
    assert new.exists() and not old.exists()


def test_maintenance_covers_data_and_logs(paths, config):
    settings = copy.deepcopy(config)
    settings["retention"].update(max_data_mb=0.000001, max_log_mb=0.000001)
    paths.events.write_text("x" * 100, encoding="utf-8")
    (paths.logs_dir / "analyzer.log").write_text("x" * 100, encoding="utf-8")
    assert {"events.jsonl", "analyzer.log"} <= set(run_maintenance(settings, paths))


def test_maintenance_with_nothing_to_do(paths, config):
    assert run_maintenance(config, paths) == []


def test_archives_live_with_the_data(paths):
    assert maintenance.archive_dir(paths).parent == paths.data_dir


# ------------------------------------------------------------------ configuration
def test_shipped_config_is_clean(config):
    assert config_problems(config) == []


def test_preflight_is_clean():
    assert preflight() == []


@pytest.mark.parametrize(
    "change, message",
    [
        (lambda c: c.update(typo={}), "unknown section"),
        (lambda c: c["modes"].update(run_moed="x"), "unknown setting"),
        (lambda c: c["modes"].update(follow_files="yes"), "wrong type"),
        (lambda c: c["dashboard"].update(port=True), "wrong type"),
        (lambda c: c["modes"].update(run_mode="enforcee"), "must be one of"),
        (lambda c: c["responder"].update(firewall="pf"), "must be one of"),
        (lambda c: c["thresholds"].update(ml_weight=5), "between"),
        (lambda c: c["dashboard"].update(port=70000), "between"),
        (lambda c: c["network"].update(allowed_ports=[22, "http"]), "invalid port"),
        (lambda c: c["network"].pop("allowed_ports"), "required"),
    ],
)
def test_config_mistakes_are_named(config, change, message):
    broken = copy.deepcopy(config)
    change(broken)
    assert any(message in problem for problem in config_problems(broken))


# ------------------------------------------------------------------- command line
def run_cli(*arguments, home=None):
    env = dict(os.environ)
    if home:
        env["SENTINELAI_HOME"] = str(home)
    return subprocess.run(
        [sys.executable, "sentinel.py", *arguments], cwd=REPO, env=env, capture_output=True, text=True, timeout=60
    )


@pytest.fixture
def broken_home(tmp_path):
    shutil.copytree(REPO / "config", tmp_path / "config")
    return tmp_path


@pytest.mark.parametrize(
    "name, content",
    [
        ("rules.yml", "rules: [ {id: x\n"),
        ("rules.yml", "rules:\n  - {id: x, match: y}\n"),
        ("sentinelai.toml", "[modes\n"),
        ("indicators.yml", "commands:\n  - {id: a, pattern: '(', confidence: medium}\n"),
    ],
)
@pytest.mark.parametrize("command", [["check"], ["run", "--duration", "1"]])
def test_broken_files_give_a_clear_message_not_a_traceback(broken_home, name, content, command):
    # Regression: `check` crashed on the very files it exists to check, and `run` left
    # every component to crash and restart forever.
    (broken_home / "config" / name).write_text(content, encoding="utf-8")
    done = run_cli(*command, home=broken_home)
    assert done.returncode == 1
    assert "Traceback" not in done.stderr
    assert done.stderr.strip()


def test_check_names_what_this_host_can_do():
    done = run_cli("check")
    assert done.returncode == 0, done.stderr
    assert "rules" in done.stdout and "firewall" in done.stdout and "auth log" in done.stdout


def test_version_flag():
    assert "2.0.0" in run_cli("--version").stdout


def test_audit_command_reports_damage(paths):
    filled(paths)
    assert run_cli("audit").returncode == 0
    rewrite(paths, lambda records: records[0].update(target="x"))
    done = run_cli("audit")
    assert done.returncode == 1 and "altered" in done.stderr


def test_rotate_command(paths):
    assert "nothing needed" in run_cli("rotate").stdout


def test_unlock_command_explains_itself(paths):
    done = run_cli("unlock", "nobody-here")
    assert done.returncode == 1 and "not locked by SentinelAI" in done.stderr


def test_unblock_command_explains_itself(paths):
    done = run_cli("unblock", "203.0.113.5")
    assert done.returncode == 1 and "not blocked" in done.stderr


def test_state_is_never_in_the_old_format(paths):
    assert read_json(paths.blocked, {}) == {}
