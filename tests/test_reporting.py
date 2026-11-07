import datetime as dt
import os
import time

import pytest

from common.audit import AuditLog
from common.runtime import TOKEN_ENV, append_jsonl, dashboard_token, read_json, utc_now
from reporter import analytics, report_generator, web_dashboard

XSS = "<script>alert(1)</script>"


def iso(moment):
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def threat(ts=None, score=90, reason="test", ip="203.0.113.1"):
    return {
        "ts": ts or iso(utc_now()),
        "threat_score": score,
        "plan": [{"action": "block_ip", "target": ip}],
        "alert": {"type": "auth_burst", "reason": reason, "mitre": ["T1110.001"],
                  "event": {"ip": ip, "user": "root"}},
    }


@pytest.fixture
def anonymous():
    return web_dashboard.app.test_client()


@pytest.fixture
def client(anonymous, paths):
    token = dashboard_token(paths)
    anonymous.get(f"/?token={token}")
    return anonymous


@pytest.fixture(autouse=True)
def reset_login_limit():
    web_dashboard._login_failures.clear()


def test_buckets_follow_real_time():
    # Regression: 100 events in one second drew a flat line across all 12 buckets.
    now = utc_now()
    start = now - dt.timedelta(hours=12)
    items = [{"ts": iso(now - dt.timedelta(minutes=5))} for _ in range(100)]
    counts = analytics.time_buckets(items, start, now, 12)
    assert counts == [0] * 11 + [100]


def test_buckets_ignore_records_outside_range():
    now = utc_now()
    items = [{"ts": iso(now - dt.timedelta(days=9))}, {"ts": "garbage"}, {}]
    assert sum(analytics.time_buckets(items, now - dt.timedelta(hours=1), now, 4)) == 0


def test_bucket_labels_match_bucket_count():
    now = utc_now()
    assert len(analytics.bucket_labels(now - dt.timedelta(hours=1), now, 24)) == 24


@pytest.mark.parametrize(
    "score, label", [(95, "critical"), (80, "critical"), (79, "high"), (40, "medium"), (5, "low")]
)
def test_severity_labels(score, label):
    assert analytics.severity_label(score) == label


def test_summary_aggregates():
    stats = analytics.summarise([], [], [threat(), threat(ip="203.0.113.2", score=30)], 24)
    assert stats["totals"]["threats"] == 2
    assert stats["severity"]["critical"] == 1 and stats["severity"]["low"] == 1
    assert stats["mitre"][0] == {"id": "T1110.001", "name": "Password Guessing", "count": 2}


def test_responses_exclude_threats_with_no_action():
    quiet = threat()
    quiet["plan"] = []
    stats = analytics.summarise([], [], [threat(), quiet], 24)
    assert stats["totals"] == {"events": 0, "alerts": 0, "threats": 2, "responses": 1}
    assert sum(stats["response_counts"]) == 1


def test_a_plan_is_shown_as_text():
    item = threat()
    item["plan"].append({"action": "lock_user", "target": "alice"})
    view = analytics.threat_view(item)
    assert view["action"] == "block_ip, lock_user"
    assert view["target"] == "203.0.113.1, alice"


def test_no_plan_is_shown_as_none():
    item = threat()
    item["plan"] = []
    assert analytics.threat_view(item)["action"] == "none"


def write_events(paths, count, moment=None):
    stamp = iso(moment or utc_now())
    with paths.events.open("a", encoding="utf-8") as handle:
        for _ in range(count):
            handle.write(f'{{"ts":"{stamp}","type":"auth_fail"}}\n')


def test_totals_are_exact_past_any_read_limit(client, paths):
    # Regression: 25,000 events showed as 20,000 with nothing to say it had been cut off.
    write_events(paths, 25000)
    assert client.get("/api/summary").get_json()["totals"]["events"] == 25000


def test_a_capped_threat_count_says_so(client, paths, monkeypatch):
    # Regression: the flag was calculated and then shown nowhere, which is the same
    # silent cap that had hidden 5,000 events.
    monkeypatch.setattr(web_dashboard, "READ_LIMIT", 2)
    assert client.get("/api/summary").get_json()["threats_capped"] is False
    for _ in range(3):
        append_jsonl(paths.threats, threat())
    assert client.get("/api/summary").get_json()["threats_capped"] is True


def test_the_page_can_show_the_cap_warning(client):
    assert b'id="capped"' in client.get("/").data
    script = (web_dashboard.APP_ROOT / "static" / "dashboard.js").read_text(encoding="utf-8")
    assert "threats_capped" in script


def test_counts_pick_up_new_lines_only(paths):
    counts = analytics.MinuteCounts(paths.events)
    write_events(paths, 3)
    counts.refresh()
    write_events(paths, 2)
    counts.refresh()
    assert sum(counts.minutes.values()) == 5


def test_a_half_written_line_is_counted_when_it_is_finished(paths):
    counts = analytics.MinuteCounts(paths.events)
    stamp = iso(utc_now())
    with paths.events.open("ab") as handle:
        handle.write(f'{{"ts":"{stamp}","ty'.encode())
    counts.refresh()
    assert sum(counts.minutes.values()) == 0
    with paths.events.open("ab") as handle:
        handle.write(b'pe":"x"}\n')
    counts.refresh()
    assert sum(counts.minutes.values()) == 1


def test_counts_survive_a_rotation(paths):
    import os

    counts = analytics.MinuteCounts(paths.events)
    write_events(paths, 3)
    counts.refresh()
    os.replace(paths.events, paths.events.with_name("events.jsonl.1"))
    write_events(paths, 2)
    counts.refresh()
    assert sum(counts.minutes.values()) == 5


def test_a_fresh_counter_includes_the_rotated_file(paths):
    import os

    write_events(paths, 3)
    os.replace(paths.events, paths.events.with_name("events.jsonl.1"))
    write_events(paths, 2)
    counts = analytics.MinuteCounts(paths.events)
    counts.refresh()
    assert sum(counts.minutes.values()) == 5


def test_counts_reset_if_the_file_is_emptied(paths):
    counts = analytics.MinuteCounts(paths.events)
    write_events(paths, 3)
    counts.refresh()
    paths.events.write_text("", encoding="utf-8")
    counts.refresh()
    assert sum(counts.minutes.values()) == 0


def test_counts_land_in_the_right_bucket(paths):
    now = utc_now()
    counts = analytics.MinuteCounts(paths.events)
    write_events(paths, 4, now - dt.timedelta(minutes=2))
    write_events(paths, 9, now - dt.timedelta(hours=3))
    counts.refresh()
    assert counts.buckets(now - dt.timedelta(hours=1), now, 12) == [0] * 11 + [4]


def test_a_missing_file_counts_as_nothing(paths):
    counts = analytics.MinuteCounts(paths.events)
    counts.refresh()
    assert counts.buckets(utc_now() - dt.timedelta(hours=1), utc_now(), 4) == [0, 0, 0, 0]


def test_active_blocks_hide_expired():
    now = time.time()
    data = {"blocked": {"203.0.113.1": {"expires": now + 60}, "203.0.113.2": {"expires": now - 1}}}
    assert [row["ip"] for row in analytics.active_blocks(data, now)] == ["203.0.113.1"]


def test_active_blocks_tolerate_empty_state():
    assert analytics.active_blocks({}, time.time()) == []
    assert analytics.active_blocks([], time.time()) == []


def test_report_handles_utc_timestamps(paths):
    # Regression: comparing naive and aware datetimes crashed on the first "Z" stamp.
    append_jsonl(paths.events, {"ts": iso(utc_now()), "type": "auth_fail", "msg": "hello"})
    assert "hello" in report_generator.generate().read_text(encoding="utf-8")


def test_report_filters_old_records(paths):
    old = iso(utc_now() - dt.timedelta(days=3))
    append_jsonl(paths.threats, threat(ts=old, reason="ancient"))
    assert "ancient" not in report_generator.generate(hours=24).read_text(encoding="utf-8")


def test_report_escapes_attacker_input(paths):
    # Regression: an SSH username reached the HTML report unescaped.
    append_jsonl(paths.events, {"ts": iso(utc_now()), "type": "auth_fail", "msg": XSS})
    append_jsonl(paths.threats, threat(reason=XSS))
    AuditLog(paths).append({"ts": iso(utc_now()), "detail": XSS})
    document = report_generator.generate().read_text(encoding="utf-8")
    assert "<script>" not in document
    assert "&lt;script&gt;" in document


def test_report_with_no_data(paths):
    assert report_generator.generate().exists()


def test_dashboard_page_and_assets(client):
    page = client.get("/")
    assert page.status_code == 200
    assert b"dashboard.js" in page.data
    assert client.get("/static/dashboard.js").status_code == 200
    assert client.get("/static/dashboard.css").status_code == 200


def test_dashboard_loads_nothing_external(client):
    assert b"https://" not in client.get("/").data


def test_dashboard_script_never_uses_innerhtml():
    source = web_dashboard.APP_ROOT / "static" / "dashboard.js"
    code = "\n".join(
        line for line in source.read_text(encoding="utf-8").splitlines()
        if not line.lstrip().startswith("//")
    )
    assert "innerHTML" not in code


def test_security_headers(client):
    headers = client.get("/").headers
    assert "default-src 'none'" in headers["Content-Security-Policy"]
    assert headers["X-Content-Type-Options"] == "nosniff"


def test_api_works_with_no_data(client, paths):
    for url in ("/api/summary", "/api/threats", "/api/actions", "/api/blocked", "/api/status"):
        assert client.get(url).status_code == 200


def test_api_summary_window(client, paths):
    append_jsonl(paths.threats, threat())
    body = client.get("/api/summary?window=1h").get_json()
    assert body["window"] == "1h" and body["totals"]["threats"] == 1
    assert client.get("/api/summary?window=bogus").get_json()["window"] == "24h"


def test_api_threats_newest_first(client, paths):
    append_jsonl(paths.threats, threat(reason="older"))
    append_jsonl(paths.threats, threat(reason="newer"))
    assert client.get("/api/threats").get_json()[0]["reason"] == "newer"


@pytest.mark.parametrize("host", ["evil.example.com", "evil.example.com:8080", "127.0.0.1.evil.com"])
def test_foreign_host_header_is_refused(client, host):
    # Regression: a web page could point its own domain at 127.0.0.1 and read the API
    # from any browser on the machine (DNS rebinding).
    assert client.get("/api/threats", headers={"Host": host}).status_code == 403


@pytest.mark.parametrize("host", ["localhost", "localhost:8080", "127.0.0.1:8080", "[::1]:8080"])
def test_local_host_headers_are_allowed(client, host):
    assert client.get("/api/health", headers={"Host": host}).status_code == 200


def test_extra_hosts_can_be_allowed(client, monkeypatch):
    monkeypatch.setattr(web_dashboard, "_allowed_hosts", {"sentinel.internal"})
    assert client.get("/api/health", headers={"Host": "sentinel.internal"}).status_code == 200


API = ["/api/summary", "/api/threats", "/api/incidents", "/api/actions", "/api/blocked", "/api/status"]


@pytest.mark.parametrize("url", API)
def test_the_api_needs_the_token_even_on_localhost(anonymous, paths, url):
    # The data files are private, and an open dashboard would hand out the same records
    # to every other account on the machine.
    assert anonymous.get(url).status_code == 401


def test_the_page_sends_strangers_to_sign_in(anonymous, paths):
    response = anonymous.get("/")
    assert response.status_code == 303 and response.headers["Location"].endswith("/login")


def test_health_is_open_for_monitoring(anonymous):
    assert anonymous.get("/api/health").status_code == 200


def test_the_sign_in_page_needs_no_token(anonymous):
    assert anonymous.get("/login").status_code == 200
    assert anonymous.get("/static/dashboard.css").status_code == 200


def test_the_link_signs_in_and_clears_the_address_bar(anonymous, paths):
    response = anonymous.get(f"/?token={dashboard_token(paths)}")
    assert response.status_code == 303
    assert "token" not in response.headers["Location"]
    assert anonymous.get("/api/threats").status_code == 200


def test_the_cookie_cannot_be_read_by_scripts_or_sent_cross_site(anonymous, paths):
    cookie = anonymous.get(f"/?token={dashboard_token(paths)}").headers["Set-Cookie"]
    assert "HttpOnly" in cookie and "SameSite=Strict" in cookie


def test_the_cookie_is_not_the_token(anonymous, paths):
    token = dashboard_token(paths)
    assert token not in anonymous.get(f"/?token={token}").headers["Set-Cookie"]


def test_signing_in_with_the_form(anonymous, paths):
    response = anonymous.post("/login", data={"token": dashboard_token(paths)})
    assert response.status_code == 303
    assert anonymous.get("/api/threats").status_code == 200


def test_a_wrong_token_is_refused(anonymous, paths):
    dashboard_token(paths)
    assert anonymous.post("/login", data={"token": "wrong"}).status_code == 401
    assert anonymous.get("/api/threats").status_code == 401
    assert anonymous.get("/api/threats?token=wrong").status_code == 401


def test_a_bearer_token_works_for_scripts(anonymous, paths):
    headers = {"Authorization": f"Bearer {dashboard_token(paths)}"}
    assert anonymous.get("/api/threats", headers=headers).status_code == 200


def test_a_wrong_bearer_token_is_refused(anonymous, paths):
    dashboard_token(paths)
    assert anonymous.get("/api/threats", headers={"Authorization": "Bearer nope"}).status_code == 401


def test_a_forged_cookie_is_refused(anonymous, paths):
    dashboard_token(paths)
    anonymous.set_cookie(web_dashboard.SESSION_COOKIE, "0" * 64)
    assert anonymous.get("/api/threats").status_code == 401


def test_guessing_is_slowed_down(anonymous, paths):
    dashboard_token(paths)
    for _ in range(web_dashboard.MAX_LOGIN_FAILURES):
        anonymous.post("/login", data={"token": "wrong"})
    assert anonymous.post("/login", data={"token": dashboard_token(paths)}).status_code == 429


def test_token_is_stable_and_long(paths):
    token = dashboard_token(paths)
    assert token == dashboard_token(paths)
    assert len(token) >= 40


def test_a_new_install_gets_a_different_token(paths):
    first = dashboard_token(paths)
    paths.dashboard_token.unlink()
    assert dashboard_token(paths) != first


@pytest.mark.skipif(os.name != "posix", reason="POSIX file modes")
def test_the_token_file_is_private(paths):
    os.umask(0o077)
    dashboard_token(paths)
    assert paths.dashboard_token.stat().st_mode & 0o077 == 0


def test_a_token_can_come_from_the_environment(monkeypatch, paths):
    monkeypatch.setenv(TOKEN_ENV, "from-the-environment")
    assert dashboard_token(paths) == "from-the-environment"
    assert read_json(paths.dashboard_token, {}) == {}


def test_an_existing_token_can_be_read_from_read_only_storage(paths, monkeypatch):
    # The Docker dashboard mounts the data folder read-only, so it cannot take a lock.
    token = dashboard_token(paths)

    def refuse(*args, **kwargs):
        raise OSError("read-only file system")

    monkeypatch.setattr("common.runtime.file_lock", refuse)
    assert dashboard_token(paths) == token


def test_no_token_on_read_only_storage_fails_closed(anonymous, paths, monkeypatch):
    def refuse(*args, **kwargs):
        raise OSError("read-only file system")

    monkeypatch.setattr("common.runtime.file_lock", refuse)
    assert anonymous.get("/api/threats").status_code == 503


def test_no_token_available_fails_closed(anonymous, monkeypatch):
    monkeypatch.setattr(web_dashboard, "current_token", lambda: None)
    assert anonymous.get("/api/threats").status_code == 503


def test_api_is_read_only(client):
    assert client.post("/api/blocked").status_code == 405


def test_default_bind_is_local(home):
    from common.runtime import load_config

    assert load_config()["dashboard"]["host"] == "127.0.0.1"
