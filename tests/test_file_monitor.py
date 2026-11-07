import hashlib
import os
import sys

import pytest

from analyzer import rule_engine
from collectors import file_monitor
from collectors.file_monitor import FileMonitor, compare, expand, fingerprint, load_watch_list, snapshot
from common.runtime import ConfigError, now_iso, read_recent_jsonl


def monitor_for(paths, *entries):
    return FileMonitor(paths, list(entries))


def changes(paths):
    return [(event["meta"]["path"], event["meta"]["change"]) for event in read_recent_jsonl(paths.events)]


@pytest.fixture
def watched(tmp_path):
    target = tmp_path / "authorized_keys"
    target.write_text("ssh-ed25519 AAAA admin\n", encoding="utf-8")
    return target


def entry(path, category="ssh_keys"):
    return {"path": str(path), "category": category}


def test_first_run_is_a_silent_baseline(paths, watched):
    monitor_for(paths, entry(watched)).scan()
    assert not paths.events.exists()


def test_an_unchanged_file_stays_quiet(paths, watched):
    monitor = monitor_for(paths, entry(watched))
    monitor.scan()
    monitor.scan()
    assert not paths.events.exists()


def test_a_planted_ssh_key_is_reported(paths, watched):
    # Nothing in a process list or login log shows this, and it is how attackers come back.
    monitor = monitor_for(paths, entry(watched))
    monitor.scan()
    with watched.open("a", encoding="utf-8") as handle:
        handle.write("ssh-ed25519 BBBB attacker\n")
    monitor.scan()
    event = read_recent_jsonl(paths.events)[0]
    assert (event["type"], event["meta"]["change"], event["meta"]["category"]) == ("file_change", "modified", "ssh_keys")
    assert event["meta"]["sha256"] == hashlib.sha256(watched.read_bytes()).hexdigest()


def test_a_change_is_reported_once(paths, watched):
    monitor = monitor_for(paths, entry(watched))
    monitor.scan()
    watched.write_text("changed\n", encoding="utf-8")
    monitor.scan()
    monitor.scan()
    assert len(changes(paths)) == 1


def test_a_removed_file_is_reported(paths, watched):
    monitor = monitor_for(paths, entry(watched))
    monitor.scan()
    watched.unlink()
    monitor.scan()
    assert changes(paths) == [(str(watched), "removed")]


def test_a_file_that_appears_is_reported(paths, tmp_path):
    target = tmp_path / "ld.so.preload"
    monitor = monitor_for(paths, entry(target, "preload"))
    monitor.scan()
    target.write_text("/tmp/evil.so\n", encoding="utf-8")
    monitor.scan()
    assert changes(paths) == [(str(target), "added")]


def test_a_new_file_in_a_watched_folder_is_reported(paths, tmp_path):
    folder = tmp_path / "cron.d"
    folder.mkdir()
    monitor = monitor_for(paths, entry(folder, "cron"))
    monitor.scan()
    (folder / "backdoor").write_text("* * * * * root /tmp/x\n", encoding="utf-8")
    monitor.scan()
    assert changes(paths) == [(str(folder / "backdoor"), "added")]


def test_the_baseline_survives_a_restart(paths, watched):
    monitor_for(paths, entry(watched)).scan()
    watched.write_text("changed\n", encoding="utf-8")
    monitor_for(paths, entry(watched)).scan()
    assert changes(paths) == [(str(watched), "modified")]


def test_a_forged_timestamp_is_caught_by_the_full_pass(paths, watched, monkeypatch):
    # Attackers reset mtime so a quick check sees nothing, which is why the hash is rechecked.
    monkeypatch.setattr(file_monitor, "FULL_HASH_EVERY", 2)
    monitor = monitor_for(paths, entry(watched))
    monitor.scan()
    info = os.stat(watched)
    watched.write_text("ssh-ed25519 AAAA evil!\n", encoding="utf-8")
    os.utime(watched, ns=(info.st_atime_ns, info.st_mtime_ns))
    assert os.stat(watched).st_size == info.st_size
    monitor.scan()
    assert changes(paths) == [(str(watched), "modified")]


def test_a_huge_file_is_tracked_without_being_read(tmp_path, monkeypatch):
    monkeypatch.setattr(file_monitor, "HASH_LIMIT_BYTES", 3)
    target = tmp_path / "big"
    target.write_text("too big", encoding="utf-8")
    assert fingerprint(str(target), None, False)["sha256"] is None


@pytest.mark.skipif(os.name != "posix", reason="POSIX file modes")
def test_a_permission_change_is_reported(paths, watched):
    monitor = monitor_for(paths, entry(watched))
    monitor.scan()
    os.chmod(watched, 0o666)
    monitor.scan()
    assert changes(paths) == [(str(watched), "permissions")]


def test_a_glob_covers_every_match(tmp_path):
    for name in ("alice", "bob"):
        folder = tmp_path / name / ".ssh"
        folder.mkdir(parents=True)
        (folder / "authorized_keys").write_text("x", encoding="utf-8")
    found = list(expand(entry(tmp_path / "*" / ".ssh" / "authorized_keys")))
    assert len(found) == 2


def test_a_path_that_does_not_exist_yet_is_still_watched(tmp_path):
    assert list(expand(entry(tmp_path / "nothing"))) == [str(tmp_path / "nothing")]


def test_compare_finds_each_kind_of_change():
    before = {"a": {"sha256": "1"}, "b": {"sha256": "2"}, "c": {"sha256": "3", "mode": 1}}
    after = {"a": {"sha256": "1"}, "c": {"sha256": "3", "mode": 2}, "d": {"sha256": "4"}}
    assert {(path, change) for path, change, _ in compare(before, after)} == {
        ("b", "removed"), ("c", "permissions"), ("d", "added"),
    }


def test_shipped_watch_list_loads():
    assert len(load_watch_list()) >= 5


def test_shipped_watch_list_covers_both_platforms(home):
    text = (home / "config" / "integrity.yml").read_text(encoding="utf-8")
    assert "authorized_keys" in text and "CurrentVersion\\Run" in text


@pytest.mark.parametrize(
    "content, message",
    [
        ("linux:\n  - {category: cron}\nwindows:\n  - {category: cron}\n", "path or registry"),
        ("linux:\n  - {path: /x, category: nope}\nwindows:\n  - {path: x, category: nope}\n", "unknown category"),
        ("a: [\n", "integrity.yml"),
        ("- x\n", "must be a mapping"),
    ],
)
def test_bad_watch_lists_are_rejected(tmp_path, content, message):
    path = tmp_path / "integrity.yml"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(ConfigError, match=message):
        load_watch_list(path)


@pytest.mark.skipif(sys.platform != "win32", reason="Windows registry")
def test_the_registry_can_be_read():
    assert isinstance(file_monitor.registry_values("HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"), dict)
    assert file_monitor.registry_values("HKCU\\Software\\NoSuchKeyAtAll") == {}


def test_a_new_startup_entry_is_reported(paths, monkeypatch):
    # The same path a Run key takes, without needing Windows to test it.
    values = {"Updater": "C:\\Users\\a\\good.exe"}
    monkeypatch.setattr(file_monitor, "registry_values", lambda key: dict(values))
    monitor = monitor_for(paths, {"registry": "HKCU\\Run", "category": "startup"})
    monitor.scan()
    values["Evil"] = "C:\\Temp\\evil.exe"
    monitor.scan()
    event = read_recent_jsonl(paths.events)[0]
    assert event["meta"]["path"] == "registry:HKCU\\Run\\Evil"
    assert event["meta"]["value"] == "C:\\Temp\\evil.exe"


def test_a_changed_startup_entry_is_reported(paths, monkeypatch):
    values = {"Updater": "C:\\good.exe"}
    monkeypatch.setattr(file_monitor, "registry_values", lambda key: dict(values))
    monitor = monitor_for(paths, {"registry": "HKCU\\Run", "category": "startup"})
    monitor.scan()
    values["Updater"] = "C:\\evil.exe"
    monitor.scan()
    assert read_recent_jsonl(paths.events)[0]["meta"]["change"] == "modified"


def test_snapshot_records_the_category(watched):
    current = snapshot([entry(watched, "cron")], {}, False)
    assert current[str(watched)]["category"] == "cron"


CATEGORY_RULES = {
    "ssh_keys": ("ssh_key_changed", 8),
    "sudoers": ("sudoers_changed", 8),
    "preload": ("linker_hijack", 10),
    "pam": ("pam_changed", 8),
    "ssh_config": ("ssh_config_changed", 7),
    "cron": ("cron_file_changed", 7),
    "service": ("service_file_changed", 7),
    "startup": ("startup_item_changed", 7),
    "hosts": ("hosts_file_changed", 6),
    "identity": ("identity_file_changed", 5),
}


@pytest.mark.parametrize("category", CATEGORY_RULES)
def test_every_category_has_a_rule(category, config):
    event = {"ts": now_iso(), "type": "file_change", "msg": "/x modified",
             "meta": {"path": "/x", "change": "modified", "category": category}}
    alert = rule_engine.build_engine(config).evaluate(event)[0]
    assert (alert["rule_id"], alert["base_severity"]) == CATEGORY_RULES[category]


def test_rule_categories_match_the_collector():
    assert set(CATEGORY_RULES) == file_monitor.CATEGORIES


def test_file_changes_only_ever_alert(config):
    # A changed file could be an admin at work, and undoing it is a person's decision.
    for rule in rule_engine.load_rules():
        if rule["match"] == "file_change":
            assert not rule.get("respond")
