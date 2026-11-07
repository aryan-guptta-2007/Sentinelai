#!/usr/bin/env python3
"""SentinelAI dashboard. Read-only: it can display state but never change it.

Every page needs the access token, even on 127.0.0.1. The data files are private to the
account running SentinelAI, and a dashboard open to every local account would hand out
the same records anyway. `sentinel.py token` prints the link.
"""

from __future__ import annotations

import collections
import hashlib
import hmac
import os
import re
import sys
import time
from pathlib import Path
from typing import Any, Deque, Dict, Optional, Set

if __package__ in (None, ""):  # allow `python reporter/web_dashboard.py`
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from flask import Flask, Response, abort, jsonify, redirect, render_template, request

from common.audit import read_actions
from common.runtime import (
    dashboard_token,
    exit_with_supervisor,
    get_paths,
    harden_process,
    load_config,
    read_json,
    read_recent_jsonl,
    run_mode,
    utc_now,
)
from reporter.analytics import MinuteCounts, active_blocks, build_incidents, summarise, threat_view

APP_ROOT = Path(__file__).parent
WINDOWS = {"1h": 1, "6h": 6, "24h": 24, "7d": 168}
READ_LIMIT = 20000
TABLE_LIMIT = 100
LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1"}
HOST_HEADER = re.compile(r"^(?:\[(?P<ipv6>[^\]]+)\]|(?P<name>[^:]+))(?::\d+)?$")
SESSION_COOKIE = "sentinelai_session"
SESSION_MAX_AGE_SEC = 12 * 3600
OPEN_PATHS = {"/api/health", "/login"}
MAX_LOGIN_FAILURES = 10  # per minute, which is plenty for a person and useless for guessing

_counters: Dict[Path, MinuteCounts] = {}
_allowed_hosts: Optional[Set[str]] = None
_login_failures: Deque[float] = collections.deque()

app = Flask(
    __name__,
    static_folder=str(APP_ROOT / "static"),
    template_folder=str(APP_ROOT / "templates"),
)


def allowed_hosts() -> Set[str]:
    global _allowed_hosts
    if _allowed_hosts is None:
        section = load_config().get("dashboard", {})
        _allowed_hosts = LOCAL_HOSTS | {str(section.get("host", ""))}
        _allowed_hosts |= {str(name).lower() for name in section.get("allowed_hosts", [])}
    return _allowed_hosts


def current_token() -> Optional[str]:
    try:
        return dashboard_token(get_paths())
    except OSError:
        return None  # a read-only mount with no token yet: fail closed


def session_value(token: str) -> str:
    """The cookie proves the token was shown, without being the token."""
    return hmac.new(token.encode(), b"sentinelai-session", hashlib.sha256).hexdigest()


def token_is_valid(offered: str, token: str) -> bool:
    return hmac.compare_digest(offered.encode("utf-8", "replace"), token.encode("utf-8"))


def is_authenticated(token: str) -> bool:
    header = request.headers.get("Authorization", "")
    if header.startswith("Bearer ") and token_is_valid(header[7:], token):
        return True
    cookie = request.cookies.get(SESSION_COOKIE, "")
    return hmac.compare_digest(cookie, session_value(token))


def too_many_failures() -> bool:
    now = time.monotonic()
    while _login_failures and now - _login_failures[0] > 60:
        _login_failures.popleft()
    return len(_login_failures) >= MAX_LOGIN_FAILURES


def signed_in_response(target: str, token: str) -> Response:
    response = redirect(target, code=303)
    response.set_cookie(
        SESSION_COOKIE, session_value(token), max_age=SESSION_MAX_AGE_SEC,
        httponly=True, samesite="Strict", path="/",
    )
    return response


@app.before_request
def guard() -> Optional[Any]:
    # DNS rebinding: a web page can point its own domain at 127.0.0.1 and read this API from
    # any browser on the machine. The Host header still carries that domain.
    match = HOST_HEADER.match(request.host.lower())
    name = (match["ipv6"] or match["name"]) if match else ""
    if name not in allowed_hosts():
        abort(403)

    if request.path in OPEN_PATHS or request.path.startswith("/static/"):
        return None
    token = current_token()
    if token is None:
        return jsonify({"error": "no access token yet: run sentinel.py token"}), 503

    offered = request.args.get("token")
    if offered is not None:
        if too_many_failures():
            abort(429)
        if token_is_valid(offered, token):
            return signed_in_response(request.path, token)  # takes the token out of the address bar
        _login_failures.append(time.monotonic())

    if is_authenticated(token):
        return None
    if request.path.startswith("/api/"):
        return jsonify({"error": "sign in required"}), 401
    return redirect("/login", code=303)


@app.after_request
def security_headers(response: Response) -> Response:
    # Everything is served locally, so nothing else ever needs to load or run.
    response.headers["Content-Security-Policy"] = (
        "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; "
        "connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    return response


def counts_for(path: Path) -> MinuteCounts:
    if path not in _counters:
        _counters[path] = MinuteCounts(path)
    counts = _counters[path]
    counts.refresh()
    return counts


@app.route("/login", methods=["GET", "POST"])
def login():
    failed = False
    if request.method == "POST":
        if too_many_failures():
            abort(429)
        token = current_token()
        if token and token_is_valid(request.form.get("token", ""), token):
            return signed_in_response("/", token)
        _login_failures.append(time.monotonic())
        failed = True
    return render_template("login.html", failed=failed), 401 if failed else 200


@app.route("/")
def index() -> str:
    return render_template("index.html")


@app.route("/api/summary")
def summary():
    window = request.args.get("window", "24h")
    hours = WINDOWS.get(window, WINDOWS["24h"])
    paths = get_paths()
    threats_read = read_recent_jsonl(paths.threats, READ_LIMIT)
    payload = summarise(
        [],
        [],
        threats_read,
        hours,
        event_counts=counts_for(paths.events),
        alert_counts=counts_for(paths.alerts),
    )
    payload["window"] = window if window in WINDOWS else "24h"
    payload["threats_capped"] = len(threats_read) >= READ_LIMIT
    return jsonify(payload)


@app.route("/api/threats")
def threats():
    records = read_recent_jsonl(get_paths().threats, TABLE_LIMIT)
    return jsonify([threat_view(item) for item in reversed(records)])


@app.route("/api/incidents")
def incidents():
    paths = get_paths()
    return jsonify(
        build_incidents(read_recent_jsonl(paths.threats, READ_LIMIT), read_actions(paths, READ_LIMIT))[:TABLE_LIMIT]
    )


@app.route("/api/actions")
def actions():
    return jsonify(list(reversed(read_actions(get_paths(), TABLE_LIMIT))))


@app.route("/api/blocked")
def blocked():
    return jsonify(active_blocks(read_json(get_paths().blocked, {}), time.time()))


@app.route("/api/status")
def status():
    config = load_config()
    state = read_json(get_paths().supervisor, {})
    state = state if isinstance(state, dict) else {}
    components: Dict[str, Any] = state.get("components") or {}
    return jsonify(
        {
            "mode": run_mode(config),
            "components": components,
            "updated": state.get("updated"),
            "server_time": utc_now().strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
    )


@app.route("/api/health")
def health():
    return jsonify({"status": "ok"})


def main() -> None:
    harden_process()
    exit_with_supervisor()
    section = load_config().get("dashboard", {})
    host = os.environ.get("SENTINELAI_DASHBOARD_HOST") or section.get("host", "127.0.0.1")
    port = int(section.get("port", 8080))
    current_token()  # created now, so the link works straight away
    try:
        from waitress import serve  # type: ignore
    except ImportError:
        app.run(host, port, debug=False, threaded=True)
    else:
        serve(app, host=host, port=port, threads=4, ident="SentinelAI")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
