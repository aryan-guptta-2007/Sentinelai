import copy
import datetime as dt
import json
import os
import subprocess
import sys
import time

import psutil
import pytest

from common.audit import read_actions
from common.runtime import atomic_write_json, get_paths, load_config, now_iso, read_json, to_iso, utc_now
from responder import accounts as accounts_mod
from responder import firewall as firewall_mod
from responder import responder as mod
from responder import system
from responder.firewall import Firewall
from responder.responder import Responder, threat_time
from responder.system import parse_ip


class FakeFirewall:
    backend = "fake"

    def __init__(self, ok=True, present=None):
        self.ok = ok
        self.blocked = []
        self.unblocked = []
        self.listed = present

    def block(self, address, timeout_sec):
        self.blocked.append(str(address))
        return self.ok, "" if self.ok else "firewall said no"

    def unblock(self, address):
        self.unblocked.append(str(address))
        return self.ok, "" if self.ok else "firewall said no"

    def present(self):
        return self.listed


class FakeAccounts:
    def __init__(self, ok=True):
        self.ok = ok
        self.locked = []
        self.unlocked = []

    def lock(self, name):
        self.locked.append(name)
        return self.ok, "" if self.ok else "no such user", {"expire": "", "password_locked": False}

    def unlock(self, name, prior):
        self.unlocked.append((name, prior))
        return self.ok, ""


def make(enforce=False, firewall=None, accounts=None, **section):
    config = copy.deepcopy(load_config())
    config["modes"]["run_mode"] = "enforce" if enforce else "dry-run"
    config["responder"].update(section)
    instance = Responder(config, get_paths(config).ensure())
    instance.firewall = firewall or FakeFirewall()
    instance.accounts = accounts or FakeAccounts()
    instance.gateways_read = time.monotonic()
    return instance


def threat(action, target, src="", **event):
    fields = {"ts": now_iso(), **event}
    if src:
        fields["src"] = src
    return {
        "ts": now_iso(),
        "plan": [{"action": action, "target": target}],
        "threat_score": 90,
        "alert": {"type": "test", "reason": "test", "event": fields},
    }


def handle(instance, item):
    """Most tests only care about one step."""
    return instance.handle(item)[0]


@pytest.fixture
def victim():
    process = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(60)"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    yield process
    if process.poll() is None:
        process.kill()
    process.wait()


def victim_threat(process, **overrides):
    name = psutil.Process(process.pid).name()
    return threat("kill_process", str(process.pid), meta={"proc": name}, **overrides)


def own_user():
    return psutil.Process().username().rsplit("\\", 1)[-1].lower()


# ------------------------------------------------------------------- dry run
def test_default_config_is_dry_run():
    assert make().dry_run is True


def test_unknown_mode_fails_safe():
    config = copy.deepcopy(load_config())
    config["modes"]["run_mode"] = "enforcee"
    assert Responder(config, get_paths(config).ensure()).dry_run is True


def test_environment_can_force_dry_run(monkeypatch):
    monkeypatch.setenv("SENTINELAI_RUN_MODE", "dry-run")
    assert make(enforce=True).dry_run is True


def test_dry_run_never_touches_firewall():
    # Regression: run_mode was never read, so "dry-run" really blocked.
    firewall = FakeFirewall()
    entry = handle(make(firewall=firewall), threat("block_ip", "203.0.113.7"))
    assert firewall.blocked == []
    assert entry["status"] == "dry_run" and entry["dry_run"] is True


def test_dry_run_never_kills(victim):
    # The owner guard runs first and would answer "refused" when the suite runs as root.
    entry = handle(make(kill_protected_users=True), victim_threat(victim))
    assert entry["status"] == "dry_run"
    assert victim.poll() is None


def test_dry_run_never_locks():
    accounts = FakeAccounts()
    assert handle(make(accounts=accounts), threat("lock_user", "mallory"))["status"] == "dry_run"
    assert accounts.locked == []


def test_simulated_events_never_cause_real_actions():
    # The simulator can run beside a live stack and uses ordinary-looking usernames.
    firewall, accounts = FakeFirewall(), FakeAccounts()
    instance = make(enforce=True, firewall=firewall, accounts=accounts)
    block = handle(instance, threat("block_ip", "203.0.113.7", src="simulator"))
    lock = handle(instance, threat("lock_user", "alice", src="simulator"))
    assert block["status"] == lock["status"] == "dry_run"
    assert firewall.blocked == [] and accounts.locked == []


# ------------------------------------------------------------------ the plan
def test_every_step_of_a_plan_runs():
    firewall, accounts = FakeFirewall(), FakeAccounts()
    item = threat("block_ip", "203.0.113.7")
    item["plan"].append({"action": "lock_user", "target": "mallory"})
    entries = make(enforce=True, firewall=firewall, accounts=accounts).handle(item)
    assert [entry["status"] for entry in entries] == ["applied", "applied"]
    assert firewall.blocked == ["203.0.113.7"] and accounts.locked == ["mallory"]


def test_root_compromise_still_blocks_the_attacker():
    # Regression: the only plan was lock_user root, which is refused, so the attacker's
    # address was left alone after they had brute-forced root.
    firewall = FakeFirewall()
    item = threat("block_ip", "203.0.113.7")
    item["plan"].append({"action": "lock_user", "target": "root"})
    entries = make(enforce=True, firewall=firewall).handle(item)
    assert firewall.blocked == ["203.0.113.7"]
    assert [entry["status"] for entry in entries] == ["applied", "refused"]


def test_a_failed_step_does_not_stop_the_rest():
    accounts = FakeAccounts()
    item = threat("block_ip", "203.0.113.7")
    item["plan"].append({"action": "lock_user", "target": "mallory"})
    make(enforce=True, firewall=FakeFirewall(ok=False), accounts=accounts).handle(item)
    assert accounts.locked == ["mallory"]


@pytest.mark.parametrize("step", ["block_ip", 7, None, {"action": "format_disk", "target": "/"}])
def test_malformed_steps_are_refused(step):
    item = threat("block_ip", "203.0.113.7")
    item["plan"] = [step]
    assert handle(make(), item)["status"] == "refused"


def test_no_plan_is_not_recorded(paths):
    item = threat("block_ip", "203.0.113.7")
    item["plan"] = []
    assert make().handle(item) == []
    assert read_actions(paths) == []


# ------------------------------------------------------------------ staleness
def hours_ago(hours):
    return to_iso(utc_now() - dt.timedelta(hours=hours))


def test_stale_threat_is_not_acted_on(victim):
    # After downtime the saved read position replays old threats. They must not fire.
    item = victim_threat(victim)
    item["ts"] = "2020-01-01T00:00:00Z"
    entry = handle(make(enforce=True, kill_protected_users=True), item)
    assert entry["status"] == "skipped"
    assert victim.poll() is None


def test_old_event_with_a_fresh_score_is_stale():
    # Regression: the guard read the time of scoring, so a 6-hour-old event replayed
    # through the scorer after downtime looked brand new and was acted on.
    firewall = FakeFirewall()
    item = threat("block_ip", "203.0.113.7")
    item["alert"]["event"]["ts"] = hours_ago(6)
    item["alert"]["ts"] = now_iso()
    assert handle(make(enforce=True, firewall=firewall), item)["status"] == "skipped"
    assert firewall.blocked == []


def test_old_alert_with_a_fresh_score_is_stale():
    item = threat("block_ip", "203.0.113.7")
    item["alert"]["event"].pop("ts")
    item["alert"]["ts"] = hours_ago(6)
    assert handle(make(enforce=True), item)["status"] == "skipped"


def test_undated_threat_is_stale():
    item = {"plan": [{"action": "block_ip", "target": "203.0.113.7"}], "alert": {"event": {}}}
    assert handle(make(enforce=True), item)["status"] == "skipped"


def test_threat_time_is_the_oldest_stamp():
    item = {"ts": hours_ago(0), "alert": {"ts": hours_ago(1), "event": {"ts": hours_ago(2)}}}
    assert abs(time.time() - threat_time(item) - 7200) < 5


# --------------------------------------------------------------- flood guard
def test_a_flood_of_threats_cannot_become_a_flood_of_actions():
    firewall = FakeFirewall()
    instance = make(enforce=True, firewall=firewall, max_actions_per_minute=3)
    entries = [handle(instance, threat("block_ip", f"203.0.113.{i + 1}")) for i in range(5)]
    assert [entry["status"] for entry in entries] == ["applied"] * 3 + ["skipped"] * 2
    assert len(firewall.blocked) == 3


def test_the_limit_is_per_action():
    accounts = FakeAccounts()
    instance = make(enforce=True, accounts=accounts, max_actions_per_minute=1)
    handle(instance, threat("block_ip", "203.0.113.1"))
    assert handle(instance, threat("lock_user", "mallory"))["status"] == "applied"


# ------------------------------------------------------------------ block_ip
def test_enforce_blocks_and_records_expiry(paths):
    firewall = FakeFirewall()
    entry = handle(make(enforce=True, firewall=firewall), threat("block_ip", "203.0.113.7"))
    assert entry["status"] == "applied"
    assert firewall.blocked == ["203.0.113.7"]
    saved = read_json(paths.blocked, {})["blocked"]["203.0.113.7"]
    assert saved["expires"] > time.time() + 3000


def test_firewall_failure_is_reported_not_hidden(paths):
    # Regression: failures were swallowed with `|| true` and logged as "blocked".
    entry = handle(make(enforce=True, firewall=FakeFirewall(ok=False)), threat("block_ip", "203.0.113.7"))
    assert entry["status"] == "failed"
    assert read_json(paths.blocked, {}) == {}


def test_repeat_block_is_reported_as_already_blocked():
    instance = make(enforce=True)
    handle(instance, threat("block_ip", "203.0.113.7"))
    assert handle(instance, threat("block_ip", "203.0.113.7"))["status"] == "skipped"


def test_returning_attacker_is_put_back_after_the_firewall_was_emptied():
    # Regression: after a reboot the saved state said "already blocked" and nothing was
    # ever sent to the firewall again.
    handle(make(enforce=True), threat("block_ip", "203.0.113.7"))
    after_reboot = FakeFirewall()
    entry = handle(make(enforce=True, firewall=after_reboot), threat("block_ip", "203.0.113.7"))
    assert after_reboot.blocked == ["203.0.113.7"]
    assert entry["status"] == "skipped"


def test_repeat_block_that_cannot_be_reapplied_is_a_failure():
    handle(make(enforce=True), threat("block_ip", "203.0.113.7"))
    entry = handle(make(enforce=True, firewall=FakeFirewall(ok=False)), threat("block_ip", "203.0.113.7"))
    assert entry["status"] == "failed"


def test_dry_run_entry_does_not_hide_a_real_block():
    handle(make(), threat("block_ip", "203.0.113.7"))
    firewall = FakeFirewall()
    entry = handle(make(enforce=True, firewall=firewall), threat("block_ip", "203.0.113.7"))
    assert entry["status"] == "applied"
    assert firewall.blocked == ["203.0.113.7"]


def test_bans_double_for_repeat_offenders(paths):
    instance = make(enforce=True, block_timeout_sec=100)
    lengths = []
    for _ in range(3):
        handle(instance, threat("block_ip", "203.0.113.7"))
        saved = read_json(paths.blocked, {})["blocked"]["203.0.113.7"]
        lengths.append(round(saved["expires"] - time.time(), -1))
        instance.unblock("203.0.113.7")
    assert lengths == [100, 200, 400]


def test_ban_length_has_a_ceiling(paths):
    instance = make(enforce=True, block_timeout_sec=100, max_block_sec=150)
    for _ in range(3):
        handle(instance, threat("block_ip", "203.0.113.7"))
        instance.unblock("203.0.113.7")
    handle(instance, threat("block_ip", "203.0.113.7"))
    saved = read_json(paths.blocked, {})["blocked"]["203.0.113.7"]
    assert saved["expires"] - time.time() <= 151


@pytest.mark.parametrize(
    "payload",
    [
        "1.2.3.4; rm -rf /",
        "$(reboot)",
        "1.2.3.4'] = 1; import os; os.system('id'); x = ['",
        "not-an-ip",
        "",
        "-j ACCEPT",
    ],
)
def test_injection_payloads_never_reach_firewall(payload):
    # Regression: targets were pasted into Python source and an nft command line.
    firewall = FakeFirewall()
    entry = handle(make(enforce=True, firewall=firewall), threat("block_ip", payload))
    assert entry["status"] == "refused"
    assert firewall.blocked == []


@pytest.mark.parametrize("address", ["127.0.0.1", "::1", "0.0.0.0", "224.0.0.1", "::ffff:127.0.0.1"])
def test_non_routable_addresses_are_never_blocked(address):
    firewall = FakeFirewall()
    entry = handle(make(enforce=True, firewall=firewall), threat("block_ip", address))
    assert entry["status"] == "skipped"
    assert firewall.blocked == []


def write_allow_list(paths, text):
    (paths.config_dir / "allowlist_ips.txt").write_text(text, encoding="utf-8")


@pytest.fixture
def restored_lists(paths):
    yield
    write_allow_list(paths, "127.0.0.1\n::1\n")
    (paths.config_dir / "allowlist_users.txt").write_text("root\n", encoding="utf-8")


def test_allow_list_supports_cidr(paths, restored_lists):
    write_allow_list(paths, "# office\n198.51.100.0/24  # vpn\n")
    instance = make(enforce=True)
    assert handle(instance, threat("block_ip", "198.51.100.9"))["detail"] == "allow-listed"
    assert handle(instance, threat("block_ip", "203.0.113.9"))["status"] == "applied"


def test_allow_list_edit_applies_without_a_restart(paths, restored_lists):
    # Regression: an operator adding their address mid-incident had to restart everything.
    instance = make(enforce=True)
    write_allow_list(paths, "198.51.100.200\n")
    os.utime(paths.config_dir / "allowlist_ips.txt", (1, 1))
    instance.maintain()
    assert handle(instance, threat("block_ip", "198.51.100.200"))["detail"] == "allow-listed"


def test_an_address_allow_listed_later_is_released(paths, restored_lists):
    firewall = FakeFirewall()
    instance = make(enforce=True, firewall=firewall)
    handle(instance, threat("block_ip", "198.51.100.200"))
    write_allow_list(paths, "198.51.100.200\n")
    os.utime(paths.config_dir / "allowlist_ips.txt", (1, 1))
    instance.maintain()
    assert firewall.unblocked == ["198.51.100.200"]
    assert read_json(paths.blocked, {})["blocked"] == {}


def test_own_address_is_never_blocked(monkeypatch):
    monkeypatch.setattr(mod, "local_addresses", lambda: {parse_ip("203.0.113.50")})
    assert handle(make(enforce=True), threat("block_ip", "203.0.113.50"))["status"] == "skipped"


def test_gateway_is_never_blocked():
    instance = make(enforce=True)
    instance.gateways = {parse_ip("203.0.113.1")}
    entry = handle(instance, threat("block_ip", "203.0.113.1"))
    assert entry["status"] == "skipped" and "gateway" in entry["detail"]


def test_mapped_ipv6_is_normalised():
    assert str(parse_ip("::ffff:203.0.113.7")) == "203.0.113.7"


def test_expired_block_is_removed(paths):
    # Regression: block_timeout_sec was recorded but nothing ever unblocked.
    firewall = FakeFirewall()
    instance = make(enforce=True, firewall=firewall, block_timeout_sec=-1)
    handle(instance, threat("block_ip", "203.0.113.7"))
    assert instance.sweep_expired() == ["203.0.113.7"]
    assert firewall.unblocked == ["203.0.113.7"]
    assert read_json(paths.blocked, {})["blocked"] == {}


def test_failed_expiry_stays_listed_for_retry(paths):
    firewall = FakeFirewall()
    instance = make(enforce=True, firewall=firewall, block_timeout_sec=-1)
    handle(instance, threat("block_ip", "203.0.113.7"))
    firewall.ok = False
    assert instance.sweep_expired() == []
    assert "203.0.113.7" in read_json(paths.blocked, {})["blocked"]


def test_manual_unblock_is_audited(paths):
    firewall = FakeFirewall()
    instance = make(enforce=True, firewall=firewall)
    handle(instance, threat("block_ip", "203.0.113.7"))
    assert instance.unblock("203.0.113.7") == (True, "unblocked")
    assert firewall.unblocked == ["203.0.113.7"]
    assert instance.unblock("203.0.113.7")[0] is False
    assert read_actions(paths)[-1]["action"] == "unblock_ip"


def test_reconcile_restores_what_the_kernel_lost():
    # Regression: a reboot or firewall reload silently dropped every active block.
    handle(make(enforce=True), threat("block_ip", "203.0.113.7"))
    handle(make(enforce=True), threat("block_ip", "203.0.113.8"))
    firewall = FakeFirewall(present={"203.0.113.8"})
    assert make(enforce=True, firewall=firewall).reconcile() == ["203.0.113.7"]
    assert firewall.blocked == ["203.0.113.7"]


def test_reconcile_reapplies_everything_when_the_firewall_cannot_list(paths):
    handle(make(enforce=True), threat("block_ip", "203.0.113.7"))
    firewall = FakeFirewall(present=None)
    assert make(enforce=True, firewall=firewall).reconcile() == ["203.0.113.7"]


def test_reconcile_leaves_dry_run_and_expired_entries_alone(paths):
    atomic_write_json(paths.blocked, {"blocked": {
        "203.0.113.7": {"expires": time.time() + 500, "dry_run": True},
        "203.0.113.8": {"expires": time.time() - 500, "dry_run": False},
    }})
    firewall = FakeFirewall(present=set())
    assert make(enforce=True, firewall=firewall).reconcile() == []


def test_dry_run_never_reconciles():
    handle(make(enforce=True), threat("block_ip", "203.0.113.7"))
    firewall = FakeFirewall(present=set())
    assert make(firewall=firewall).reconcile() == []
    assert firewall.blocked == []


# ------------------------------------------------------------------- firewall
def test_no_backend_reports_failure():
    firewall = Firewall("auto")
    firewall.backend = None
    assert firewall.block(parse_ip("203.0.113.7"), 60)[0] is False


def recording(calls, result=(True, "")):
    def record(argv, stdin=None):
        calls.append(argv)
        return result

    return record


def test_nft_commands_are_argument_lists(monkeypatch):
    calls = []
    monkeypatch.setattr(system, "run_command", recording(calls))
    firewall = Firewall("auto")
    firewall.backend = "nft"
    firewall.block(parse_ip("2001:db8::1"), 60)
    assert calls[-1] == [
        "nft", "add", "element", "inet", "sentinelai", "blocked6", "{ 2001:db8::1 timeout 60s }",
    ]


def test_nft_table_created_once_when_missing(monkeypatch):
    calls = []

    def record(argv, stdin=None):
        calls.append(argv)
        return (argv[1] != "list"), ""

    monkeypatch.setattr(system, "run_command", record)
    firewall = Firewall("auto")
    firewall.backend = "nft"
    firewall.block(parse_ip("203.0.113.1"), 60)
    firewall.block(parse_ip("203.0.113.2"), 60)
    assert sum(1 for argv in calls if argv[:2] == ["nft", "-f"]) == 1


def test_nft_rebuilds_a_table_that_vanished(monkeypatch):
    # Regression: after `nft flush ruleset` every block failed until a restart.
    table_exists = {"value": True}
    calls = []

    def record(argv, stdin=None):
        calls.append(argv)
        if argv[:2] == ["nft", "-f"]:
            table_exists["value"] = True
            return True, ""
        if argv[1] == "list":
            return table_exists["value"], ""
        return (True, "") if table_exists["value"] else (False, "Error: No such file or directory")

    monkeypatch.setattr(system, "run_command", record)
    firewall = Firewall("auto")
    firewall.backend = "nft"
    assert firewall.block(parse_ip("203.0.113.1"), 60)[0] is True

    table_exists["value"] = False
    assert firewall.block(parse_ip("203.0.113.2"), 60)[0] is True
    assert ["nft", "-f", "-"] in calls


def test_blocks_also_cover_forwarded_traffic():
    # Otherwise a blocked address could still reach anything published from a container.
    assert "hook forward" in firewall_mod.NFT_RULESET


def test_nft_present_reads_the_sets(monkeypatch):
    output = "elements = { 203.0.113.5 timeout 1h expires 59m58s, 203.0.113.6 expires 1m }"
    monkeypatch.setattr(system, "run_command", lambda argv, stdin=None: (True, output))
    firewall = Firewall("auto")
    firewall.backend = "nft"
    assert firewall.present() == {"203.0.113.5", "203.0.113.6"}


def test_iptables_present_reads_the_rules(monkeypatch):
    output = "-P INPUT ACCEPT\n-A INPUT -s 203.0.113.9/32 -j DROP\n-A INPUT -p tcp -j ACCEPT\n"
    monkeypatch.setattr(system, "run_command", lambda argv, stdin=None: (True, output))
    monkeypatch.setattr(firewall_mod.shutil, "which", lambda name: name == "iptables")
    firewall = Firewall("auto")
    firewall.backend = "iptables"
    assert firewall.present() == {"203.0.113.9"}


def test_windows_block_adds_a_named_inbound_rule(monkeypatch):
    calls = []

    def record(argv, stdin=None):
        calls.append(argv)
        return (argv[3] != "show"), ""

    monkeypatch.setattr(system, "run_command", record)
    firewall = Firewall("auto")
    firewall.backend = "netsh"
    assert firewall.block(parse_ip("203.0.113.7"), 60)[0] is True
    assert calls[-1] == [
        "netsh", "advfirewall", "firewall", "add", "rule", "name=SentinelAI block 203.0.113.7",
        "dir=in", "action=block", "remoteip=203.0.113.7",
    ]


def test_windows_block_does_not_duplicate_a_rule(monkeypatch):
    calls = []
    monkeypatch.setattr(system, "run_command", recording(calls))
    firewall = Firewall("auto")
    firewall.backend = "netsh"
    assert firewall.block(parse_ip("203.0.113.7"), 60) == (True, "rule already present")
    assert all(argv[3] == "show" for argv in calls)


def test_windows_reports_needing_elevation(monkeypatch):
    denied = "The requested operation requires elevation (Run as administrator)."

    def record(argv, stdin=None):
        return (False, "") if argv[3] == "show" else (False, denied)

    monkeypatch.setattr(system, "run_command", record)
    firewall = Firewall("auto")
    firewall.backend = "netsh"
    assert firewall.block(parse_ip("203.0.113.7"), 60) == (False, denied)


def test_windows_unblocking_something_already_gone_is_fine(monkeypatch):
    monkeypatch.setattr(system, "run_command", lambda argv, stdin=None: (False, "No rules match"))
    firewall = Firewall("auto")
    firewall.backend = "netsh"
    assert firewall.unblock(parse_ip("203.0.113.7"))[0] is True


# -------------------------------------------------------------- kill_process
def test_enforce_kills_matching_process(victim):
    entry = handle(make(enforce=True, kill_protected_users=True), victim_threat(victim))
    assert entry["status"] == "applied"
    victim.wait(timeout=5)


def test_kill_takes_child_processes_with_it():
    # A shell left behind by a killed parent keeps the attacker's foothold.
    code = (
        "import subprocess, sys, time;"
        "c = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)']);"
        "print(c.pid, flush=True); time.sleep(60)"
    )
    parent = subprocess.Popen([sys.executable, "-c", code], stdout=subprocess.PIPE, text=True)
    try:
        child = int(parent.stdout.readline())
        entry = handle(make(enforce=True, kill_protected_users=True), victim_threat(parent))
        assert entry["status"] == "applied"
        parent.wait(timeout=5)
        deadline = time.time() + 5
        while psutil.pid_exists(child) and time.time() < deadline:
            time.sleep(0.05)
        assert not psutil.pid_exists(child)
    finally:
        parent.kill()
        parent.wait()


def test_evidence_is_saved_before_the_process_is_gone(victim, paths):
    entry = handle(make(enforce=True, kill_protected_users=True), victim_threat(victim))
    assert "evidence" in entry["detail"]
    saved = json.loads(next(paths.evidence_dir.glob("*.json")).read_text(encoding="utf-8"))
    assert saved["pid"] == victim.pid
    assert saved["exe"] and saved["cmdline"] and saved["sha256"]


@pytest.mark.parametrize("target", ["1", "0", "abc", "-1", "1 2", "１２３"])
def test_invalid_or_system_pids_are_refused(target):
    entry = handle(make(enforce=True), threat("kill_process", target, meta={"proc": "x"}))
    assert entry["status"] == "refused"


def test_own_process_is_refused():
    entry = handle(make(enforce=True), threat("kill_process", str(os.getpid()), meta={"proc": "python"}))
    assert entry["detail"] == "SentinelAI process"


def test_supervised_component_is_refused(paths, victim):
    atomic_write_json(paths.supervisor, {"components": {"x": {"pid": victim.pid}}})
    entry = handle(make(enforce=True, kill_protected_users=True), victim_threat(victim))
    assert entry["detail"] == "SentinelAI process"
    assert victim.poll() is None


def test_reused_pid_is_refused(victim):
    # Regression: a bare PID was trusted, so a reused PID meant killing an innocent process.
    item = threat("kill_process", str(victim.pid), meta={"proc": "definitely-not-this"})
    entry = handle(make(enforce=True, kill_protected_users=True), item)
    assert entry["detail"] == "PID now belongs to a different process"
    assert victim.poll() is None


def test_process_started_after_alert_is_refused(victim):
    item = victim_threat(victim)
    earlier = to_iso(utc_now() - dt.timedelta(seconds=60))
    item["alert"]["event"]["ts"] = earlier
    entry = handle(make(enforce=True, kill_protected_users=True), item)
    assert "PID reused" in entry["detail"]
    assert victim.poll() is None


def test_unidentified_process_is_refused(victim):
    entry = handle(make(enforce=True, kill_protected_users=True), threat("kill_process", str(victim.pid)))
    assert entry["detail"] == "alert does not identify the process"
    assert victim.poll() is None


def test_protected_process_is_refused(victim):
    name = psutil.Process(victim.pid).name()
    instance = make(enforce=True, kill_protected_users=True, protected_processes=[name])
    assert handle(instance, victim_threat(victim))["detail"] == "protected process"
    assert victim.poll() is None


@pytest.mark.parametrize("name", ["lsass.exe", "LSASS", "csrss.exe", "svchost", "systemd"])
def test_critical_system_processes_are_always_protected(name):
    assert system.process_key(name) in make().protected_processes


def test_protected_owner_is_refused(paths, victim, restored_lists):
    (paths.config_dir / "allowlist_users.txt").write_text(own_user() + "\n", encoding="utf-8")
    entry = handle(make(enforce=True), victim_threat(victim))
    assert "protected user" in entry["detail"]
    assert victim.poll() is None


def test_vanished_process_is_skipped():
    assert handle(make(enforce=True), threat("kill_process", "4194000", meta={"proc": "x"}))["status"] == "skipped"


# ----------------------------------------------------------------- lock_user
def test_lock_records_what_is_needed_to_undo_it(paths):
    accounts = FakeAccounts()
    entry = handle(make(enforce=True, accounts=accounts), threat("lock_user", "mallory"))
    assert entry["status"] == "applied"
    assert read_json(paths.locked_users, {})["mallory"]["prior"]["password_locked"] is False


def test_lock_ends_live_sessions(monkeypatch):
    # Regression: the account was locked while the attacker's session carried on.
    instance = make(enforce=True)
    ended = []
    monkeypatch.setattr(instance, "end_sessions", lambda name: ended.append(name) or 2)
    assert "ended 2" in handle(instance, threat("lock_user", "mallory"))["detail"]
    assert ended == ["mallory"]


def test_end_sessions_only_touches_that_account(victim):
    instance = make(enforce=True)
    assert instance.end_sessions("no-such-account-here") == 0
    assert victim.poll() is None


def test_end_sessions_kills_what_the_account_owns(victim, monkeypatch):
    instance = make(enforce=True)
    # Only the victim counts as this account here, or the test would kill itself.
    monkeypatch.setattr(instance, "sentinel_pids", lambda: {
        item.pid for item in psutil.process_iter() if item.pid != victim.pid
    })
    assert instance.end_sessions(own_user()) == 1
    victim.wait(timeout=5)


def test_locking_twice_ends_sessions_again_without_relocking(monkeypatch):
    accounts = FakeAccounts()
    instance = make(enforce=True, accounts=accounts)
    monkeypatch.setattr(instance, "end_sessions", lambda name: 0)
    handle(instance, threat("lock_user", "mallory"))
    assert handle(instance, threat("lock_user", "mallory"))["status"] == "skipped"
    assert accounts.locked == ["mallory"]


def test_unlock_restores_the_account(paths, monkeypatch):
    accounts = FakeAccounts()
    instance = make(enforce=True, accounts=accounts)
    monkeypatch.setattr(instance, "end_sessions", lambda name: 0)
    handle(instance, threat("lock_user", "mallory"))
    assert instance.unlock_user("mallory") == (True, "unlocked")
    assert accounts.unlocked[0][0] == "mallory"
    assert read_json(paths.locked_users, {}) == {}
    assert read_actions(paths)[-1]["action"] == "unlock_user"


def test_unlock_only_touches_accounts_it_locked():
    accounts = FakeAccounts()
    assert make(enforce=True, accounts=accounts).unlock_user("someone")[0] is False
    assert accounts.unlocked == []


@pytest.mark.parametrize("name", ["-e", "a b", "x;id", "../etc", "", "$(id)"])
def test_bad_usernames_are_refused(name):
    assert handle(make(enforce=True), threat("lock_user", name))["status"] == "refused"


@pytest.mark.parametrize("protected", [True, False])
@pytest.mark.parametrize("name", ["root", "Administrator", "SYSTEM"])
def test_system_accounts_can_never_be_locked(protected, name):
    instance = make(enforce=True, kill_protected_users=protected)
    assert handle(instance, threat("lock_user", name))["status"] == "refused"


def test_the_account_running_this_cannot_be_locked_out(monkeypatch):
    # On a laptop this would mean losing the machine and every process on it.
    monkeypatch.setattr(mod.getpass, "getuser", lambda: "operator1")
    instance = make(enforce=True, kill_protected_users=True)
    entry = handle(instance, threat("lock_user", "operator1"))
    assert entry["detail"] == "the account running SentinelAI"


def test_whoever_used_sudo_cannot_be_locked_out(monkeypatch):
    monkeypatch.setenv("SUDO_USER", "Admin1")
    assert handle(make(enforce=True), threat("lock_user", "admin1"))["status"] == "refused"


@pytest.mark.skipif(hasattr(os, "geteuid") and os.geteuid() == 0, reason="root's processes are protected")
def test_their_processes_can_still_be_killed(victim):
    # Malware on a laptop usually runs as the signed-in user, so this must stay possible.
    assert handle(make(enforce=True), victim_threat(victim))["status"] == "applied"
    victim.wait(timeout=5)


def test_lock_failure_is_reported(monkeypatch):
    instance = make(enforce=True, accounts=FakeAccounts(ok=False))
    entry = handle(instance, threat("lock_user", "mallory"))
    assert (entry["status"], entry["detail"]) == ("failed", "no such user")


def test_linux_lock_also_expires_the_account(monkeypatch):
    # Regression: `usermod -L` alone leaves SSH key logins working.
    calls = []

    def record(argv, stdin=None):
        calls.append(argv)
        return True, "mallory:$6$x:19000:0:99999:7:::" if argv[0] == "getent" else ""

    monkeypatch.setattr(system, "run_command", record)
    monkeypatch.setattr(accounts_mod.shutil, "which", lambda name: "/usr/sbin/usermod")
    ok, _, prior = accounts_mod.Accounts()._lock_linux("mallory")
    assert ok and prior == {"password_locked": False, "expire": ""}
    assert calls[-1] == ["usermod", "-L", "-e", "1", "mallory"]


def test_linux_lock_of_a_missing_account_fails_cleanly(monkeypatch):
    monkeypatch.setattr(system, "run_command", lambda argv, stdin=None: (False, ""))
    monkeypatch.setattr(accounts_mod.shutil, "which", lambda name: "/usr/sbin/usermod")
    assert accounts_mod.Accounts()._lock_linux("mallory")[:2] == (False, "no such account")


def test_linux_unlock_puts_the_old_expiry_back(monkeypatch):
    calls = []
    monkeypatch.setattr(system, "run_command", recording(calls))
    monkeypatch.setattr(accounts_mod.shutil, "which", lambda name: "/usr/sbin/usermod")
    accounts_mod.Accounts()._unlock_linux("mallory", {"password_locked": False, "expire": "20000"})
    assert calls[-1] == ["usermod", "-e", "20000", "-U", "mallory"]


def test_linux_unlock_leaves_an_already_locked_password_locked(monkeypatch):
    calls = []
    monkeypatch.setattr(system, "run_command", recording(calls))
    monkeypatch.setattr(accounts_mod.shutil, "which", lambda name: "/usr/sbin/usermod")
    accounts_mod.Accounts()._unlock_linux("mallory", {"password_locked": True, "expire": ""})
    assert calls[-1] == ["usermod", "-e", "", "mallory"]


def test_windows_lock_and_unlock(monkeypatch):
    calls = []
    monkeypatch.setattr(system, "run_command", recording(calls))
    accounts = accounts_mod.Accounts()
    accounts._lock_windows("mallory")
    accounts._unlock_windows("mallory")
    assert calls == [["net", "user", "mallory", "/active:no"], ["net", "user", "mallory", "/active:yes"]]


# ---------------------------------------------------------------- trust check
@pytest.mark.skipif(os.name != "posix", reason="POSIX file ownership")
def test_refuses_to_enforce_from_a_directory_others_can_write(paths):
    # Anyone able to write threats.jsonl could make a root responder act for them.
    os.chmod(paths.data_dir, 0o777)
    try:
        assert make(enforce=True).dry_run is True
    finally:
        os.chmod(paths.data_dir, 0o755)


# ------------------------------------------------------------------ dispatch
def test_unknown_action_is_refused():
    assert handle(make(), threat("format_disk", "/"))["status"] == "refused"
