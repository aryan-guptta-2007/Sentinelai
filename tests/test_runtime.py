import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from common import runtime
from common.runtime import (
    Follower,
    InstanceLock,
    append_jsonl,
    atomic_write_json,
    cached_paths,
    deliver,
    file_lock,
    harden_paths,
    load_config,
    make_logger,
    parse_ts,
    read_json,
    read_recent_jsonl,
    unsafe_data_dir,
)

REPO = Path(__file__).resolve().parents[1]


def drain(follower):
    return list(follower.read_available())


def test_parse_ts_is_always_aware():
    assert parse_ts("2025-01-01T00:00:00Z").tzinfo is not None
    assert parse_ts("2025-01-01T00:00:00").tzinfo is not None
    assert parse_ts("garbage") is None
    assert parse_ts(None) is None


def test_lines_written_before_startup_are_delivered(paths):
    # Regression: followers seeked to the end and lost anything already written.
    paths.events.write_text('{"a":1}\n', encoding="utf-8")
    assert drain(Follower(paths.events, "t", paths.state_dir)) == ['{"a":1}']


def test_lines_written_while_down_are_delivered(paths):
    paths.events.write_text("one\n", encoding="utf-8")
    assert drain(Follower(paths.events, "t", paths.state_dir)) == ["one"]

    with paths.events.open("a", encoding="utf-8") as handle:
        handle.write("two\n")
    assert drain(Follower(paths.events, "t", paths.state_dir)) == ["two"]


def test_partial_line_waits_for_newline(paths):
    # Regression: half-written lines were parsed, failed, and were lost.
    follower = Follower(paths.events, "t", paths.state_dir)
    paths.events.write_bytes(b'{"a":')
    assert drain(follower) == []
    with paths.events.open("ab") as handle:
        handle.write(b"1}\n")
    assert drain(follower) == ['{"a":1}']


def test_truncation_restarts_from_the_top(paths):
    # Regression: after log rotation the tail read nothing ever again.
    follower = Follower(paths.events, "t", paths.state_dir)
    paths.events.write_text("first line\n", encoding="utf-8")
    drain(follower)
    paths.events.write_text("x\n", encoding="utf-8")
    assert drain(follower) == ["x"]
    assert follower.truncated is True


def test_new_file_after_rename_is_not_called_truncated(paths):
    follower = Follower(paths.events, "t", paths.state_dir)
    paths.events.write_text("one\n", encoding="utf-8")
    drain(follower)
    os.replace(paths.events, paths.events.with_name("events.jsonl.1"))
    paths.events.write_text("two\n", encoding="utf-8")
    assert drain(follower) == ["two"]
    assert follower.truncated is False


def test_rotation_keeps_lines_the_reader_had_not_reached(paths):
    # Regression: copy-and-truncate rotation dropped anything not yet read.
    follower = Follower(paths.events, "t", paths.state_dir)
    paths.events.write_text("read\n", encoding="utf-8")
    drain(follower)
    with paths.events.open("a", encoding="utf-8") as handle:
        handle.write("written just before rotation\n")
    os.replace(paths.events, paths.events.with_name("events.jsonl.1"))
    paths.events.write_text("new file\n", encoding="utf-8")
    assert drain(follower) == ["written just before rotation", "new file"]


def test_rotation_survives_a_restart_of_the_reader(paths):
    follower = Follower(paths.events, "t", paths.state_dir)
    paths.events.write_text("read\n", encoding="utf-8")
    drain(follower)
    with paths.events.open("a", encoding="utf-8") as handle:
        handle.write("unread\n")
    os.replace(paths.events, paths.events.with_name("events.jsonl.1"))
    paths.events.write_text("new\n", encoding="utf-8")
    assert drain(Follower(paths.events, "t", paths.state_dir)) == ["unread", "new"]


def test_unhandled_line_is_redelivered(paths):
    paths.events.write_text("one\ntwo\n", encoding="utf-8")
    follower = Follower(paths.events, "t", paths.state_dir)
    stream = follower.read_available()
    assert next(stream) == "one"
    stream.close()  # the consumer crashed while handling "one"
    assert drain(Follower(paths.events, "t", paths.state_dir)) == ["one", "two"]


def test_progress_is_not_written_for_every_line(paths, monkeypatch):
    # Regression: one atomic file replacement per line capped throughput.
    paths.events.write_text("x\n" * 1000, encoding="utf-8")
    follower = Follower(paths.events, "t", paths.state_dir)
    saves = []
    monkeypatch.setattr(follower, "_save", lambda: saves.append(1))
    assert len(drain(follower)) == 1000
    assert len(saves) <= 1000 // runtime.OFFSET_SAVE_EVERY + 1


def test_progress_is_saved_at_the_end_of_a_batch(paths):
    paths.events.write_text("one\ntwo\n", encoding="utf-8")
    drain(Follower(paths.events, "t", paths.state_dir))
    assert drain(Follower(paths.events, "t", paths.state_dir)) == []


def test_invalid_utf8_does_not_stop_the_reader(paths):
    paths.events.write_bytes(b"bad \xff byte\nok\n")
    assert drain(Follower(paths.events, "t", paths.state_dir))[1] == "ok"


def test_missing_file_is_fine(paths):
    assert drain(Follower(paths.events, "t", paths.state_dir)) == []


def test_start_at_end_skips_history_on_the_first_run_only(paths):
    paths.events.write_text("old\n", encoding="utf-8")
    assert drain(Follower(paths.events, "t", paths.state_dir, start_at_end=True)) == []
    with paths.events.open("a", encoding="utf-8") as handle:
        handle.write("while down\n")
    # A later start is a restart, so what happened meanwhile must be read.
    assert drain(Follower(paths.events, "t", paths.state_dir, start_at_end=True)) == ["while down"]


def test_read_recent_skips_garbage_and_limits(paths):
    for index in range(5):
        append_jsonl(paths.events, {"n": index})
    with paths.events.open("a", encoding="utf-8") as handle:
        handle.write("not json\n[1,2]\n")
    assert [item["n"] for item in read_recent_jsonl(paths.events, limit=3)] == [4]
    assert len(read_recent_jsonl(paths.events, limit=100)) == 5


def test_read_recent_drops_cut_first_line(paths):
    for index in range(100):
        append_jsonl(paths.events, {"n": index})
    items = read_recent_jsonl(paths.events, limit=1000, max_bytes=50)
    assert items and items[-1]["n"] == 99
    assert all("n" in item for item in items)


def test_atomic_write_round_trip(paths):
    target = paths.state_dir / "x.json"
    atomic_write_json(target, {"a": 1})
    assert json.loads(target.read_text(encoding="utf-8")) == {"a": 1}
    assert [p.name for p in paths.state_dir.iterdir()] == ["x.json"]


def test_read_json_tolerates_empty_and_corrupt(paths):
    # The shipped state files were 0 bytes.
    target = paths.state_dir / "x.json"
    target.write_text("", encoding="utf-8")
    assert read_json(target, {"d": 1}) == {"d": 1}
    target.write_text("{broken", encoding="utf-8")
    assert read_json(target, {"d": 1}) == {"d": 1}


# ------------------------------------------------------------------- bad records
def record(item):
    return json.dumps(item)


def test_a_bad_record_is_set_aside_and_the_stream_moves_on(paths):
    # Regression: one bad alert crashed the detector, and because the line was never
    # marked as handled, it crashed again on every restart with everything stuck behind it.
    seen, logged = [], []

    def handler(item):
        seen.append(int(item["base_severity"]))

    for line in (record({"base_severity": "high"}), record({"base_severity": 7})):
        deliver(line, handler, logged.append, paths.dead_letters)
    assert seen == [7]
    assert "high" in paths.dead_letters.read_text(encoding="utf-8")
    assert logged and "bad record" in logged[0]


@pytest.mark.parametrize("line", ["not json", "[1, 2]", "7", '"text"'])
def test_things_that_are_not_records_are_set_aside(paths, line):
    deliver(line, lambda item: None, lambda message: None, paths.dead_letters)
    assert paths.dead_letters.exists()


def test_blank_lines_are_ignored(paths):
    deliver("   ", lambda item: None, lambda message: None, paths.dead_letters)
    assert not paths.dead_letters.exists()


def test_a_disk_error_is_raised_so_the_line_is_retried(paths):
    # A full disk is not the record's fault, so it must not be thrown away.
    def handler(item):
        raise OSError("no space left on device")

    with pytest.raises(OSError):
        deliver(record({"a": 1}), handler, lambda message: None, paths.dead_letters)
    assert not paths.dead_letters.exists()


# ------------------------------------------------------------------------- locks
def test_lock_is_exclusive(paths):
    target = paths.state_dir / ".x.lock"
    with file_lock(target):
        with pytest.raises(TimeoutError):
            with file_lock(target, timeout=0.1):
                pass


def test_lock_is_released(paths):
    target = paths.state_dir / ".x.lock"
    with file_lock(target):
        pass
    with file_lock(target, timeout=0.1):
        pass


def test_lock_protects_a_read_modify_write_across_threads(paths):
    target = paths.state_dir / "count.json"
    lock = paths.state_dir / ".count.lock"
    atomic_write_json(target, {"n": 0})

    def add():
        for _ in range(25):
            with file_lock(lock):
                value = read_json(target, {})["n"]
                atomic_write_json(target, {"n": value + 1})

    threads = [threading.Thread(target=add) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert read_json(target, {})["n"] == 100


def test_instance_lock_allows_one_holder(paths):
    target = paths.state_dir / ".i.lock"
    first, second = InstanceLock(target), InstanceLock(target)
    assert first.acquire() is True
    assert second.acquire() is False
    first.release()
    assert second.acquire() is True
    second.release()


def test_instance_lock_is_released_when_the_holder_dies(paths):
    target = paths.state_dir / ".i.lock"
    code = (
        "import sys; from pathlib import Path; from common.runtime import InstanceLock;"
        f"lock = InstanceLock(Path({str(target)!r})); assert lock.acquire(); print('held', flush=True);"
        "import time; time.sleep(60)"
    )
    holder = subprocess.Popen([sys.executable, "-c", code], cwd=REPO, stdout=subprocess.PIPE, text=True)
    try:
        assert holder.stdout.readline().strip() == "held"
        assert InstanceLock(target).acquire() is False
    finally:
        holder.kill()
        holder.wait()
    lock = InstanceLock(target)
    assert lock.acquire() is True
    lock.release()


def test_concurrent_writers_never_corrupt_a_line(paths):
    # Windows emulates append with a seek, so unlocked writers overwrite each other.
    code = (
        "import sys; from pathlib import Path; from common.runtime import append_jsonl;"
        f"target = Path({str(paths.events)!r});"
        "[append_jsonl(target, {'w': sys.argv[1], 'n': i, 'pad': 'x' * 200}) for i in range(100)]"
    )
    writers = [subprocess.Popen([sys.executable, "-c", code, str(i)], cwd=REPO) for i in range(4)]
    for writer in writers:
        assert writer.wait(timeout=60) == 0
    lines = paths.events.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 400
    assert len({(item["w"], item["n"]) for item in map(json.loads, lines)}) == 400


# ----------------------------------------------------------------------- logging
def test_logging_does_not_reread_the_config(paths, monkeypatch):
    # Regression: every log line parsed the TOML file again.
    log = make_logger("test", "test.log")
    cached_paths()
    calls = []
    monkeypatch.setattr(runtime, "load_config", lambda: calls.append(1) or {})
    for _ in range(20):
        log("message")
    assert calls == []


def test_a_log_line_cannot_be_split_by_hostile_text(paths):
    make_logger("test", "split.log")("one\ntwo\r\nthree")
    assert len((paths.logs_dir / "split.log").read_text(encoding="utf-8").splitlines()) == 1


def test_logging_recreates_a_missing_folder(paths):
    import shutil

    shutil.rmtree(paths.logs_dir)
    make_logger("test", "again.log")("hello")
    assert (paths.logs_dir / "again.log").exists()


# ------------------------------------------------------------------- protection
posix_only = pytest.mark.skipif(os.name != "posix", reason="POSIX file modes")


@posix_only
def test_new_files_are_private(paths):
    # Regression: data and logs were world-readable, including usernames people had
    # typed their passwords into.
    code = (
        "from pathlib import Path; from common.runtime import append_jsonl, harden_process;"
        f"harden_process(); append_jsonl(Path({str(paths.alerts)!r}), {{'a': 1}})"
    )
    subprocess.run([sys.executable, "-c", code], cwd=REPO, check=True)
    assert paths.alerts.stat().st_mode & 0o077 == 0


@posix_only
def test_existing_files_are_tightened(paths):
    paths.events.write_text("x\n", encoding="utf-8")
    os.chmod(paths.events, 0o644)
    os.chmod(paths.data_dir, 0o755)
    harden_paths(paths)
    assert paths.events.stat().st_mode & 0o077 == 0
    assert paths.data_dir.stat().st_mode & 0o077 == 0


@posix_only
def test_writable_data_directory_is_reported(paths):
    os.chmod(paths.data_dir, 0o777)
    try:
        assert "written by other accounts" in unsafe_data_dir(paths)
    finally:
        os.chmod(paths.data_dir, 0o700)


@posix_only
def test_writable_threat_file_is_reported(paths):
    paths.threats.write_text("", encoding="utf-8")
    os.chmod(paths.threats, 0o666)
    assert "written by other accounts" in unsafe_data_dir(paths)


@pytest.mark.skipif(os.name != "nt", reason="Windows ACLs")
def test_windows_folders_stop_inheriting_loose_permissions(paths):
    # Outside the user profile, a folder inherits "Users can modify" from its parent.
    paths.events.write_text("x\n", encoding="utf-8")
    (paths.state_dir / "x.json").write_text("{}", encoding="utf-8")
    harden_paths(paths)
    harden_paths(paths)  # it runs at every start
    listing = subprocess.run(["icacls", str(paths.data_dir)], capture_output=True, text=True).stdout
    assert "BUILTIN\\Users" not in listing and "Everyone" not in listing
    assert "(I)" not in listing  # nothing inherited any more

    # Regression: an earlier version left files that even their owner could not open.
    assert paths.events.read_text(encoding="utf-8") == "x\n"
    assert (paths.state_dir / "x.json").read_text(encoding="utf-8") == "{}"
    append_jsonl(paths.events, {"after": True})
    (paths.data_dir / "new.txt").write_text("new", encoding="utf-8")
    assert (paths.data_dir / "new.txt").read_text(encoding="utf-8") == "new"


def test_safe_data_directory_is_not_reported(paths):
    harden_paths(paths)
    assert unsafe_data_dir(paths) is None


def test_config_errors_are_clear(home):
    source = home / "config" / "sentinelai.toml"
    original = source.read_text(encoding="utf-8")
    source.write_text("[modes\n", encoding="utf-8")
    try:
        with pytest.raises(runtime.ConfigError, match="sentinelai.toml"):
            load_config()
    finally:
        source.write_text(original, encoding="utf-8")


def test_reading_a_section_takes_no_time_at_all_compared_with_a_flood(paths):
    # A burst must not be limited by the reader's bookkeeping.
    paths.events.write_text('{"a":1}\n' * 20000, encoding="utf-8")
    started = time.perf_counter()
    assert len(drain(Follower(paths.events, "t", paths.state_dir))) == 20000
    assert time.perf_counter() - started < 5
