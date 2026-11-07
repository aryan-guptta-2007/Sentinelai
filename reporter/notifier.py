#!/usr/bin/env python3
"""Tell someone. A detection nobody sees has not protected anything.

Sends high-scoring threats to a webhook, Slack, Discord, email or syslog. Everything in a
message started as attacker-controlled text, so it is flattened to one line and stripped
of whatever each destination treats as markup. Delivery is retried, and a destination
that stays down costs a log line, never a crash.
"""

from __future__ import annotations

import collections
import json
import os
import smtplib
import socket
import sys
import time
import urllib.error
import urllib.request
from email.message import EmailMessage
from pathlib import Path
from typing import Any, Callable, Deque, Dict, List, Optional, Tuple

if __package__ in (None, ""):  # allow `python reporter/notifier.py`
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from common.runtime import (
    Follower,
    VERSION,
    deliver,
    exit_with_supervisor,
    get_paths,
    harden_process,
    load_config,
    make_logger,
    now_iso,
)
from reporter.analytics import threat_view

log_message = make_logger("notifier", "notifier.log")

EXIT_UNAVAILABLE = 3  # no destination is configured, so this process has nothing to do
SEND_TIMEOUT_SEC = 5
RETRY_DELAYS_SEC = (1, 3)
MAX_TEXT = 500
HOST = socket.gethostname()
USER_AGENT = f"SentinelAI/{VERSION}"
Sender = Callable[[str, Dict[str, Any]], None]


def clean(value: Any, limit: int = MAX_TEXT) -> str:
    """One line, no control characters, bounded length."""
    return " ".join("".join(ch if ch.isprintable() else " " for ch in str(value)).split())[:limit]


def headline(view: Dict[str, Any]) -> str:
    return f"[SentinelAI] {view['severity'].upper()} {view['score']} on {HOST}: {clean(view['reason'], 200)}"


def body(view: Dict[str, Any]) -> str:
    lines = [headline(view)]
    if view["action"] != "none":
        lines.append(f"Response: {clean(view['action'], 100)} {clean(view['target'], 100)}")
    if view["mitre"]:
        lines.append("ATT&CK: " + clean(", ".join(view["mitre"]), 100))
    if view["advice"]:
        lines.append("Next step: " + clean(view["advice"], 300))
    return "\n".join(lines)


def escape_slack(text: str) -> str:
    # Without this, a username of "<!channel>" would ping everyone in the room.
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def post_json(url: str, payload: Dict[str, Any]) -> None:
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "User-Agent": USER_AGENT},
    )
    with urllib.request.urlopen(request, timeout=SEND_TIMEOUT_SEC) as response:
        response.read()


def send_webhook(url: str) -> Sender:
    def send(text: str, view: Dict[str, Any]) -> None:
        post_json(url, {"text": text, "host": HOST, "threat": view})

    return send


def send_slack(url: str) -> Sender:
    def send(text: str, view: Dict[str, Any]) -> None:
        post_json(url, {"text": escape_slack(text)})

    return send


def send_discord(url: str) -> Sender:
    def send(text: str, view: Dict[str, Any]) -> None:
        # allowed_mentions stops "@everyone" in a username from notifying the server.
        post_json(url, {"content": text[:1900], "allowed_mentions": {"parse": []}})

    return send


def send_email(section: Dict[str, Any]) -> Sender:
    def send(text: str, view: Dict[str, Any]) -> None:
        message = EmailMessage()
        message["Subject"] = clean(headline(view), 200)
        message["From"] = str(section.get("email_from") or f"sentinelai@{HOST}")
        message["To"] = str(section["email_to"])
        message.set_content(text)
        host = str(section.get("smtp_host") or "localhost")
        port = int(section.get("smtp_port", 587))
        with smtplib.SMTP(host, port, timeout=SEND_TIMEOUT_SEC) as server:
            if section.get("smtp_tls", True):
                server.starttls()
            user = str(section.get("smtp_user") or "")
            password = os.environ.get("SENTINELAI_SMTP_PASSWORD", "")
            if user:
                server.login(user, password)
            server.send_message(message)

    return send


def syslog_line(view: Dict[str, Any]) -> bytes:
    """CEF over syslog, the format most SIEMs read without any configuration."""

    def field(value: Any) -> str:
        return clean(value, 300).replace("\\", "\\\\").replace("=", "\\=")

    def header(value: Any) -> str:
        return clean(value, 200).replace("\\", "\\\\").replace("|", "\\|")

    severity = max(0, min(10, int(view["score"]) // 10))
    extension = (
        f"src={field(view['source_ip'])} suser={field(view['user'])} act={field(view['action'])} "
        f"cs1Label=target cs1={field(view['target'])} cs2Label=mitre cs2={field(','.join(view['mitre']))} "
        f"msg={field(view['reason'])}"
    )
    cef = (
        f"CEF:0|SentinelAI|SentinelAI|{VERSION}|{header(view['type'])}|{header(view['reason'])}"
        f"|{severity}|{extension}"
    )
    return f"<116>1 {now_iso()} {clean(HOST, 60)} sentinelai - - - {cef}".encode("utf-8")[:4000]


def send_syslog(host: str, port: int) -> Sender:
    def send(text: str, view: Dict[str, Any]) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.sendto(syslog_line(view), (host, port))

    return send


def build_channels(section: Dict[str, Any]) -> List[Tuple[str, Sender]]:
    channels: List[Tuple[str, Sender]] = []
    webhook = os.environ.get("SENTINELAI_WEBHOOK_URL") or section.get("webhook_url")
    if webhook:
        channels.append(("webhook", send_webhook(str(webhook))))
    slack = os.environ.get("SENTINELAI_SLACK_URL") or section.get("slack_webhook")
    if slack:
        channels.append(("slack", send_slack(str(slack))))
    discord = os.environ.get("SENTINELAI_DISCORD_URL") or section.get("discord_webhook")
    if discord:
        channels.append(("discord", send_discord(str(discord))))
    if section.get("email_to"):
        channels.append(("email", send_email(section)))
    if section.get("syslog_host"):
        channels.append(("syslog", send_syslog(str(section["syslog_host"]), int(section.get("syslog_port", 514)))))
    return channels


class Notifier:
    def __init__(
        self,
        section: Dict[str, Any],
        channels: Optional[List[Tuple[str, Sender]]] = None,
        sleep: Callable[[float], None] = time.sleep,
    ):
        self.min_score = int(section.get("min_score", 70))
        self.cooldown = int(section.get("cooldown_sec", 300))
        self.per_minute = int(section.get("max_per_minute", 20))
        self.channels = build_channels(section) if channels is None else channels
        self.sleep = sleep
        self.last_sent: Dict[str, float] = {}
        self.recent: Deque[float] = collections.deque()
        self.suppressed = 0

    @staticmethod
    def _key(threat: Dict[str, Any], view: Dict[str, Any]) -> str:
        alert = threat.get("alert") or {}
        return f"{threat.get('incident') or alert.get('rule_id')}|{view['source_ip']}|{view['severity']}"

    def _allowed(self, key: str, now: float) -> bool:
        if now - self.last_sent.get(key, -1e12) < self.cooldown:
            return False
        while self.recent and now - self.recent[0] > 60:
            self.recent.popleft()
        if len(self.recent) >= self.per_minute:
            self.suppressed += 1
            return False
        return True

    def handle(self, threat: Dict[str, Any]) -> bool:
        view = threat_view(threat)
        if view["score"] < self.min_score:
            return False
        now = time.time()
        key = self._key(threat, view)
        if not self._allowed(key, now):
            return False
        self.last_sent[key] = now
        self.recent.append(now)
        self._prune(now)

        text = body(view)
        if self.suppressed:
            text += f"\n({self.suppressed} more held back by the rate limit)"
            self.suppressed = 0
        for name, send in self.channels:
            self._deliver(name, send, text, view)
        return True

    def _prune(self, now: float) -> None:
        if len(self.last_sent) > 10000:
            self.last_sent = {k: t for k, t in self.last_sent.items() if now - t < self.cooldown}

    def _deliver(self, name: str, send: Sender, text: str, view: Dict[str, Any]) -> bool:
        for attempt, delay in enumerate((*RETRY_DELAYS_SEC, None)):
            try:
                send(text, view)
                return True
            except (OSError, urllib.error.URLError, smtplib.SMTPException, ValueError) as exc:
                log_message(f"{name} delivery failed (attempt {attempt + 1}): {clean(exc, 200)}")
                if delay is None:
                    return False
                self.sleep(delay)
        return False


def send_test(config: Dict[str, Any]) -> List[Tuple[str, bool]]:
    """Send a sample through every configured channel, so a typo shows up today."""
    notifier = Notifier(config.get("notify", {}))
    view = threat_view(
        {
            "threat_score": 90,
            "plan": [{"action": "block_ip", "target": "203.0.113.5"}],
            "alert": {"type": "test", "reason": "This is a test from SentinelAI", "mitre": ["T1110.001"],
                      "advice": "Nothing to do. If you can read this, alerts reach you."},
        }
    )
    return [(name, notifier._deliver(name, send, body(view), view)) for name, send in notifier.channels]


def main() -> int:
    harden_process()
    exit_with_supervisor()
    config = load_config()
    paths = get_paths(config).ensure()
    notifier = Notifier(config.get("notify", {}))
    if not notifier.channels:
        return EXIT_UNAVAILABLE

    follow = bool(config["modes"].get("follow_files", True))
    names = ", ".join(name for name, _ in notifier.channels)
    log_message(f"started, sending to {names}")
    # Alerts from before this started are history, and a flood of them helps nobody.
    follower = Follower(paths.threats, "notifier", paths.state_dir, start_at_end=True)
    while True:
        for raw in follower.read_available():
            deliver(raw, notifier.handle, log_message, paths.dead_letters)
        if not follow:
            return 0
        time.sleep(follower.poll_sec)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        pass
