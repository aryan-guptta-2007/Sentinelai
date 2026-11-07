import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from common.runtime import now_iso
from reporter import notifier
from reporter.analytics import threat_view
from reporter.notifier import Notifier, body, build_channels, clean, escape_slack, headline, syslog_line


def threat(score=90, reason="Failed login burst from 203.0.113.5", ip="203.0.113.5", **extra):
    return {
        "ts": now_iso(),
        "threat_score": score,
        "plan": [{"action": "block_ip", "target": ip}],
        "alert": {"type": "auth_burst", "rule_id": "auth_failed_burst", "reason": reason,
                  "mitre": ["T1110.001"], "advice": "Check this address.",
                  "event": {"ip": ip, "user": "root"}},
        **extra,
    }


class Recorder:
    def __init__(self, failures=0):
        self.failures = failures
        self.sent = []
        self.calls = 0

    def __call__(self, text, view):
        self.calls += 1
        if self.calls <= self.failures:
            raise OSError("destination is down")
        self.sent.append(text)


def build(section=None, recorder=None):
    recorder = recorder or Recorder()
    return Notifier(section or {}, channels=[("test", recorder)], sleep=lambda seconds: None), recorder


def test_a_serious_threat_is_sent():
    instance, recorder = build()
    assert instance.handle(threat()) is True
    assert "203.0.113.5" in recorder.sent[0]


def test_a_low_score_is_not_sent():
    instance, recorder = build({"min_score": 80})
    assert instance.handle(threat(score=79)) is False
    assert recorder.sent == []


def test_a_repeat_within_the_cooldown_is_held_back():
    # One attack must not become a hundred messages, or people stop reading them.
    instance, recorder = build()
    instance.handle(threat())
    assert instance.handle(threat()) is False
    assert len(recorder.sent) == 1


def test_a_different_attacker_is_not_held_back():
    instance, recorder = build()
    instance.handle(threat())
    instance.handle(threat(ip="203.0.113.6"))
    assert len(recorder.sent) == 2


def test_escalation_within_an_incident_gets_through():
    instance, recorder = build()
    instance.handle(threat(score=70, incident="INC-1"))
    instance.handle(threat(score=95, incident="INC-1"))
    assert len(recorder.sent) == 2


def test_rate_limit_caps_a_flood_and_says_so():
    instance, recorder = build({"max_per_minute": 2})
    for index in range(5):
        instance.handle(threat(ip=f"203.0.113.{index + 1}"))
    assert len(recorder.sent) == 2
    assert instance.suppressed == 3
    instance.recent.clear()
    instance.handle(threat(ip="203.0.113.50"))
    assert "3 more held back" in recorder.sent[-1]


def test_delivery_is_retried():
    instance, recorder = build(recorder=Recorder(failures=2))
    assert instance.handle(threat()) is True
    assert len(recorder.sent) == 1


def test_a_dead_destination_does_not_crash_anything():
    instance, recorder = build(recorder=Recorder(failures=99))
    instance.handle(threat())
    assert recorder.calls == 3


def test_one_dead_channel_does_not_stop_the_others():
    good = Recorder()
    instance = Notifier({}, channels=[("bad", Recorder(failures=99)), ("good", good)], sleep=lambda s: None)
    instance.handle(threat())
    assert len(good.sent) == 1


def test_hostile_text_stays_on_one_line():
    # Line breaks would let an attacker write their own fake lines into the message.
    view = threat_view(threat(reason="x\nCRITICAL all clear\r\nignore this"))
    assert "\n" not in headline(view)


def test_control_characters_are_removed():
    assert clean("a\x00b\x1bc\x07") == "a b c"


def test_long_text_is_capped():
    assert len(clean("x" * 9999)) == notifier.MAX_TEXT


def test_slack_markup_is_neutralised():
    # Regression guard: a username of <!channel> would otherwise ping everyone.
    assert escape_slack("<!channel> & <http://evil|click>") == "&lt;!channel&gt; &amp; &lt;http://evil|click&gt;"


def test_slack_sends_escaped_text(monkeypatch):
    sent = {}
    monkeypatch.setattr(notifier, "post_json", lambda url, payload: sent.update(payload))
    notifier.send_slack("http://x")("<!channel>", {})
    assert sent["text"] == "&lt;!channel&gt;"


def test_discord_cannot_ping_everyone(monkeypatch):
    sent = {}
    monkeypatch.setattr(notifier, "post_json", lambda url, payload: sent.update(payload))
    notifier.send_discord("http://x")("@everyone", {})
    assert sent["allowed_mentions"] == {"parse": []}


def test_the_message_says_what_to_do():
    text = body(threat_view(threat()))
    assert "block_ip 203.0.113.5" in text
    assert "T1110.001" in text
    assert "Check this address" in text


def test_no_channels_means_nothing_to_run(config):
    assert build_channels({}) == []


def test_channels_come_from_settings():
    names = [name for name, _ in build_channels({
        "webhook_url": "http://x", "slack_webhook": "http://y", "discord_webhook": "http://z",
        "email_to": "a@example.com", "syslog_host": "127.0.0.1",
    })]
    assert names == ["webhook", "slack", "discord", "email", "syslog"]


def test_secrets_can_stay_out_of_the_config_file(monkeypatch):
    monkeypatch.setenv("SENTINELAI_WEBHOOK_URL", "http://secret")
    assert [name for name, _ in build_channels({})] == ["webhook"]


def test_cef_line_shape():
    line = syslog_line(threat_view(threat())).decode()
    assert line.startswith("<116>1 ")
    assert "CEF:0|SentinelAI|SentinelAI|" in line
    assert "src=203.0.113.5" in line


def test_cef_fields_cannot_be_forged():
    # A CEF consumer splits on | and =, so hostile text must not add fields of its own.
    line = syslog_line(threat_view(threat(reason="x|y=z act=allow"))).decode()
    assert "x\\|y=z" in line
    assert "msg=x|y\\=z act\\=allow" in line


class Capture(BaseHTTPRequestHandler):
    received = []

    def do_POST(self):
        Capture.received.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
        self.send_response(200)
        self.end_headers()

    def log_message(self, *args):
        pass


@pytest.fixture
def web_server():
    Capture.received = []
    server = HTTPServer(("127.0.0.1", 0), Capture)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}/hook"
    server.shutdown()
    server.server_close()


def test_a_real_webhook_is_delivered(web_server):
    instance = Notifier({"webhook_url": web_server}, sleep=lambda s: None)
    assert instance.handle(threat()) is True
    assert Capture.received[0]["threat"]["source_ip"] == "203.0.113.5"


def test_a_real_refused_connection_is_survived():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    instance = Notifier({"webhook_url": f"http://127.0.0.1:{port}/hook"}, sleep=lambda s: None)
    assert instance.handle(threat()) is True


def test_a_real_syslog_datagram_is_delivered():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as receiver:
        receiver.bind(("127.0.0.1", 0))
        receiver.settimeout(5)
        host, port = receiver.getsockname()
        instance = Notifier({"syslog_host": host, "syslog_port": port}, sleep=lambda s: None)
        instance.handle(threat())
        assert b"CEF:0|SentinelAI" in receiver.recv(4096)


def test_the_test_command_reports_each_channel(web_server, config):
    settings = {**config, "notify": {"webhook_url": web_server}}
    assert notifier.send_test(settings) == [("webhook", True)]
