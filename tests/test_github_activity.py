"""GitHub activity pattern, replayed from tests/fixtures/github_activity. No network.

mara_lind.json has the shape of the public event feed recorded on 2026-11-26 (two pages, and
GitHub's 404 and 422 bodies). The account, the repositories and every timestamp are invented.
"""

import asyncio
import json
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from main import app
from middleware import rate_limit
from middleware.rate_limit import match_limit
from modules import github_activity as ga

FIXTURES = Path(__file__).parent / "fixtures" / "github_activity"
REAL_CLIENT = httpx.AsyncClient
DATA = json.loads((FIXTURES / "mara_lind.json").read_text(encoding="utf-8"))
LOGIN = DATA["login"]
RATE_BODY = {"message": "API rate limit exceeded for 203.0.113.9.", "documentation_url": "https://docs.github.com/"}


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    ga.clear_cache_for_tests()
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    yield
    ga.clear_cache_for_tests()


def replay(monkeypatch, pages: list | None = None, calls: list | None = None, override=None):
    """Serve the pages in order. `override(page, request)` may return a Response or raise."""
    pages = DATA["pages"] if pages is None else pages

    def handler(request: httpx.Request):
        assert request.url.host == "api.github.com"
        page = int(request.url.params["page"])
        if calls is not None:
            calls.append(request)
        if override:
            resp = override(page, request)
            if resp is not None:
                return resp
        if page > 3:
            return httpx.Response(422, json=DATA["past_last_page"])
        return httpx.Response(200, json=pages[page - 1] if page <= len(pages) else [])

    monkeypatch.setattr(ga.httpx, "AsyncClient", lambda *a, **k: REAL_CLIENT(transport=httpx.MockTransport(handler)))


def run(login: str = LOGIN) -> dict:
    return asyncio.run(ga.run_github_activity(login))


def events_at(hours: dict[int, int], days: int = 20, start=datetime(2026, 9, 1, tzinfo=timezone.utc)) -> list[dict]:
    """`hours` maps a UTC hour to a number of events, spread over `days` different days."""
    out, i = [], 0
    for hour, n in hours.items():
        for _ in range(n):
            d = start + timedelta(days=i % days, hours=hour, minutes=i % 60)
            out.append({"id": str(1000 + i), "type": "PushEvent", "repo": {"name": "mara-lind/tidepool"},
                        "created_at": d.strftime("%Y-%m-%dT%H:%M:%SZ")})
            i += 1
    return out


def hist(hours: dict[int, int]) -> list[int]:
    return [hours.get(h, 0) for h in range(24)]


# ---- the full answer ---------------------------------------------------------------

def test_full_result(monkeypatch):
    calls = []
    replay(monkeypatch, calls=calls)
    out = run()
    assert set(out) == {"username", "found", "state", "cached", "complete", "pages", "events", "window", "hours_utc",
                        "weekdays_utc", "weekday_labels", "types", "repos", "estimate", "estimate_reason"}
    assert out["username"] == LOGIN and out["found"] is True and out["state"] == "ok" and out["cached"] is False
    assert out["events"] == 137 and out["pages"] == 2 and out["complete"] is True
    # page 1 was full, page 2 was not: no third request
    assert [r.url.params["page"] for r in calls] == ["1", "2"]
    assert all(r.url.path == "/users/mara-lind/events/public" and r.url.params["per_page"] == "100" for r in calls)

    assert out["window"] == {"first": "2026-09-01T08:16:52Z", "last": "2026-10-14T16:14:09Z", "days": 44, "active_days": 42}
    assert len(out["hours_utc"]) == 24 and sum(out["hours_utc"]) == 137
    assert len(out["weekdays_utc"]) == 7 and sum(out["weekdays_utc"]) == 137
    assert out["weekday_labels"][0] == "Monday" and out["weekday_labels"][6] == "Sunday"
    assert out["hours_utc"][22:] == [0, 0] and out["hours_utc"][:6] == [0] * 6

    assert out["types"][0] == {"type": "PushEvent", "count": 75} and sum(t["count"] for t in out["types"]) == 137
    assert out["repos"][0] == {"name": "mara-lind/tidepool", "url": "https://github.com/mara-lind/tidepool", "count": 71}
    assert [r["count"] for r in out["repos"]] == sorted((r["count"] for r in out["repos"]), reverse=True)

    est = out["estimate"]
    assert out["estimate_reason"] is None
    assert set(est) == {"utc_offset_from", "utc_offset_to", "utc_offsets", "label", "quiet_start_hour", "quiet_end_hour",
                        "quiet_hours", "quiet_events", "basis", "assumption", "caveat"}
    assert (est["quiet_start_hour"], est["quiet_end_hour"], est["quiet_hours"], est["quiet_events"]) == (22, 6, 8, 0)
    assert est["utc_offsets"] == [-1, 0, 1, 2, 3, 4] and est["label"] == "UTC-1 to UTC+4"
    assert est["basis"] == ("Based on 137 public events over 44 days (42 with activity). "
                            "The longest quiet stretch is 22:00 to 06:00 UTC.")
    assert "hint, not a fact" in est["caveat"] and "not a place" in est["caveat"]


def test_weekday_index_zero_is_monday():
    monday = [{"id": "1", "type": "PushEvent", "created_at": "2026-09-07T10:00:00Z"}]      # 7 September 2026 is a Monday
    sunday = [{"id": "2", "type": "PushEvent", "created_at": "2026-09-06T23:59:59Z"}]
    assert ga.summarize(monday)["weekdays_utc"] == [1, 0, 0, 0, 0, 0, 0]
    assert ga.summarize(sunday)["weekdays_utc"] == [0, 0, 0, 0, 0, 0, 1] and ga.summarize(sunday)["hours_utc"][23] == 1


def test_no_place_is_ever_named(monkeypatch):
    replay(monkeypatch)
    text = json.dumps(run()).lower()
    for word in ("europe", "america", "asia", "africa", "city", "country", "berlin", "stockholm", "cet", "pst",
                 "timezone", "time zone", "lives", "located", "location"):
        assert word not in text, word


def test_repos_are_capped_at_ten_and_types_counted():
    evs = [{"id": str(i), "type": "WatchEvent" if i % 3 else "ForkEvent", "repo": {"name": f"mara-lind/repo-{i % 14}"},
            "created_at": "2026-09-07T10:00:00Z"} for i in range(140)]
    s = ga.summarize(evs)
    assert len(s["repos"]) == 10 and all(r["count"] == 10 for r in s["repos"])
    assert s["types"] == [{"type": "WatchEvent", "count": 93}, {"type": "ForkEvent", "count": 47}]


def test_hostile_rows_are_dropped_or_cleaned():
    evs = [
        {"id": "1", "type": "PushEvent", "repo": {"name": "mara-lind/tidepool"}, "created_at": "2026-09-07T10:00:00Z"},
        {"id": "1", "type": "PushEvent", "repo": {"name": "mara-lind/tidepool"}, "created_at": "2026-09-07T10:00:00Z"},   # same event twice
        {"id": "2", "type": "<script>alert(1)</script>", "repo": {"name": "x/../../etc"}, "created_at": "2026-09-07T11:00:00Z"},
        {"id": "3", "type": "PushEvent", "repo": {"name": "evil.example/x?y=z#frag"}, "created_at": "2026-09-07T12:00:00Z"},
        {"id": "4", "type": "PushEvent", "repo": "nope", "created_at": "not a time"},
        {"id": "5", "type": "PushEvent", "created_at": None}, "junk", None, 7,
    ]
    s = ga.summarize(evs)
    assert s["events"] == 3
    assert s["types"] == [{"type": "PushEvent", "count": 2}]
    assert s["repos"] == [{"name": "mara-lind/tidepool", "url": "https://github.com/mara-lind/tidepool", "count": 1}]
    assert "script" not in json.dumps(s) and "evil.example" not in json.dumps(s)


# ---- the estimate and its thresholds -----------------------------------------------

DAYTIME = {h: 5 for h in range(8, 22)}          # 70 events, quiet 22:00 to 08:00 UTC


def test_enough_data_and_a_clear_quiet_stretch_gives_a_range():
    s = ga.summarize(events_at(DAYTIME))
    est = s["estimate"]
    assert s["estimate_reason"] is None
    assert (est["quiet_start_hour"], est["quiet_end_hour"], est["quiet_hours"]) == (22, 8, 10)
    # 5 - s - L to 2 - s: 5 - 22 - 10 = -27 -> -3, and 2 - 22 = -20 -> +4
    assert est["utc_offsets"] == [-3, -2, -1, 0, 1, 2, 3, 4] and est["label"] == "UTC-3 to UTC+4"
    assert est["utc_offset_from"] == -3 and est["utc_offset_to"] == 4
    assert "70 public events over 20 days (20 with activity)" in est["basis"] and "22:00 to 08:00 UTC" in est["basis"]


@pytest.mark.parametrize("start,length,expected", [
    (22, 8, [-1, 0, 1, 2, 3, 4]),               # asleep around 02:00 UTC
    (6, 8, [-9, -8, -7, -6, -5, -4]),           # asleep around 10:00 UTC
    (14, 6, [9, 10, 11, -12]),                  # the range may cross the date line
    (0, 12, [-7, -6, -5, -4, -3, -2, -1, 0, 1, 2]),
])
def test_offset_range_follows_the_quiet_stretch(start, length, expected):
    quiet = {(start + i) % 24 for i in range(length)}
    hours = [0 if h in quiet else 6 for h in range(24)]
    est, reason = ga.estimate_offset(hours, sum(hours), 30, 40)
    assert reason is None and est["utc_offsets"] == expected and est["quiet_hours"] == length
    assert len(expected) == length - 2
    assert all(-12 <= o <= 14 for o in est["utc_offsets"])


def test_a_few_stray_events_in_the_night_do_not_break_the_stretch():
    hours = hist({**{h: 20 for h in range(8, 22)}, 2: 3, 4: 5})          # 288 events, 2% is 5
    est, reason = ga.estimate_offset(hours, sum(hours), 30, 40)
    assert reason is None and est["quiet_hours"] == 10 and est["quiet_events"] == 8


@pytest.mark.parametrize("events,days,code", [
    (39, 30, "too_few_events"),
    (40, 9, "too_few_days"),
])
def test_too_little_data_gives_no_estimate(events, days, code):
    hours = hist({10: events})
    est, reason = ga.estimate_offset(hours, events, days, 60)
    assert est is None and reason["code"] == code and str(events if code == "too_few_events" else days) in reason["text"]


def test_exactly_at_the_thresholds_is_enough():
    hours = hist({h: 3 for h in range(8, 21)} | {21: 1})   # 40 events, quiet 22:00 to 08:00
    est, reason = ga.estimate_offset(hours, 40, 10, 10)
    assert sum(hours) == 40 and reason is None and est["quiet_hours"] == 10


def test_too_few_days_in_a_real_summary():
    s = ga.summarize(events_at(DAYTIME, days=9))
    assert s["events"] == 70 and s["window"]["active_days"] == 9
    assert s["estimate"] is None and s["estimate_reason"]["code"] == "too_few_days"


def test_round_the_clock_activity_has_no_quiet_window():
    s = ga.summarize(events_at({h: 4 for h in range(24)}))
    assert s["estimate"] is None and s["estimate_reason"]["code"] == "no_quiet_window"
    # a gap shorter than six hours is not a night either
    s = ga.summarize(events_at({h: 4 for h in range(24) if not 2 <= h < 7}))
    assert s["estimate"] is None and s["estimate_reason"]["code"] == "no_quiet_window"


def test_activity_in_a_few_hours_only_is_too_long_a_quiet_window():
    s = ga.summarize(events_at({h: 10 for h in range(9, 17)}))          # quiet for 16 hours
    assert s["estimate"] is None and s["estimate_reason"]["code"] == "quiet_window_too_long"
    assert "16 hours" in s["estimate_reason"]["text"]


def test_two_quiet_stretches_of_the_same_length_are_ambiguous():
    hours = {h: 5 for h in list(range(6, 12)) + list(range(18, 24))}     # quiet 00 to 06 and 12 to 18
    s = ga.summarize(events_at(hours))
    assert s["estimate"] is None and s["estimate_reason"]["code"] == "ambiguous_quiet_window"
    hours = {h: 5 for h in list(range(7, 12)) + list(range(18, 24))}     # 7 hours and 6 hours: still too close
    assert ga.summarize(events_at(hours))["estimate_reason"]["code"] == "ambiguous_quiet_window"
    hours = {h: 5 for h in list(range(8, 14)) + list(range(18, 24))}     # 8 hours and 4 hours: clear
    assert ga.summarize(events_at(hours))["estimate"]["quiet_hours"] == 8


def test_quiet_runs_wrap_around_midnight():
    assert ga.quiet_runs(hist({h: 5 for h in range(3, 20)})) == [(20, 7)]
    assert ga.quiet_runs([0] * 24) == [] and ga.quiet_runs([3] * 24) == []


# ---- states ------------------------------------------------------------------------

def test_no_public_events_is_none_and_the_account_exists(monkeypatch):
    replay(monkeypatch, pages=[[]])
    out = run()
    assert out["state"] == "none" and out["found"] is True and out["events"] == 0
    assert out["hours_utc"] == [0] * 24 and out["estimate"] is None and out["estimate_reason"] is None
    assert out["window"] == {"first": "", "last": "", "days": 0, "active_days": 0}


def test_no_such_account_is_not_found(monkeypatch):
    replay(monkeypatch, override=lambda p, r: httpx.Response(404, json=DATA["not_found"]))
    out = run("nobody-here")
    assert out == {"username": "nobody-here", "found": False, "state": "not_found", "cached": False}


@pytest.mark.parametrize("status,headers", [
    (403, {"x-ratelimit-remaining": "0", "x-ratelimit-reset": "0"}), (403, {}), (429, {"retry-after": "45"}),
])
def test_rate_limit_is_never_no_activity(monkeypatch, status, headers):
    calls = []
    replay(monkeypatch, calls=calls, override=lambda p, r: httpx.Response(status, json=RATE_BODY, headers=headers))
    out = run()
    assert out["state"] == "rate_limited" and out["found"] is None and out["error_code"] == "rate_limited"
    assert out["retry_after"] >= 1 and "events" not in out and "203.0.113.9" not in json.dumps(out)
    run()
    assert len(calls) == 2                       # a rate limited answer is not cached


def test_failures_are_failed(monkeypatch):
    def state(resp_or_exc):
        def override(p, r):
            if isinstance(resp_or_exc, Exception):
                raise resp_or_exc
            return resp_or_exc
        replay(monkeypatch, override=override)
        out = run()
        assert out["state"] == "failed" and out["found"] is None and "events" not in out
        return out

    assert state(httpx.Response(500, text="boom"))["error_code"] == "upstream"
    assert state(httpx.Response(403, json={"message": "Forbidden"}))["error_code"] == "upstream"     # not a rate limit
    assert state(httpx.Response(422, json=DATA["past_last_page"]))["error_code"] == "upstream"       # 422 on page 1 is no end
    assert state(httpx.Response(200, text="<html>"))["error_code"] == "bad_response"
    assert state(httpx.Response(200, json={"message": "odd"}))["error_code"] == "bad_response"
    assert state(httpx.Response(302, headers={"location": "https://elsewhere.example/"}))["error_code"] == "upstream"
    out = state(httpx.ReadTimeout(f"timed out reading /users/{LOGIN}/events"))
    assert out["error_code"] == "timeout" and LOGIN not in json.dumps({k: v for k, v in out.items() if k != "username"})


def test_three_full_pages_stop_at_three_requests(monkeypatch):
    full = [dict(e, id=str(i)) for i, e in enumerate(DATA["pages"][0] * 3)]
    calls = []
    replay(monkeypatch, pages=[full[:100], full[100:200], full[200:300]], calls=calls)
    out = run()
    assert len(calls) == 3 and out["events"] == 300 and out["pages"] == 3 and out["complete"] is True


def test_a_422_after_the_first_page_is_the_end(monkeypatch):
    replay(monkeypatch, pages=[DATA["pages"][0]],
           override=lambda p, r: httpx.Response(422, json=DATA["past_last_page"]) if p == 2 else None)
    out = run()
    assert out["state"] == "ok" and out["events"] == 100 and out["complete"] is True and "later_pages" not in out


@pytest.mark.parametrize("status,later", [(403, "rate_limited"), (500, "failed")])
def test_a_later_page_that_does_not_answer_keeps_the_first_and_says_so(monkeypatch, status, later):
    calls = []
    replay(monkeypatch, calls=calls,
           override=lambda p, r: httpx.Response(status, json=RATE_BODY, headers={"x-ratelimit-remaining": "0"}) if p == 2 else None)
    out = run()
    assert out["state"] == "ok" and out["events"] == 100 and out["complete"] is False and out["later_pages"] == later
    # kept for ten minutes only
    assert run()["cached"] is True and len(calls) == 2
    now = ga.time.time()
    monkeypatch.setattr(ga.time, "time", lambda: now + 601)
    run()
    assert len(calls) == 4


def test_an_event_served_on_two_pages_is_counted_once(monkeypatch):
    page1 = DATA["pages"][0]
    replay(monkeypatch, pages=[page1, [page1[-1]] + DATA["pages"][1]])
    assert run()["events"] == 137


# ---- token and cache ---------------------------------------------------------------

def test_token_is_sent_when_set(monkeypatch):
    calls = []
    replay(monkeypatch, calls=calls)
    run()
    assert all("authorization" not in r.headers for r in calls)
    ga.clear_cache_for_tests()
    monkeypatch.setenv("GITHUB_TOKEN", "test-token-value")
    run()
    assert calls[-1].headers["authorization"] == "Bearer test-token-value"


def test_complete_result_is_cached_for_a_day_whatever_the_case(monkeypatch):
    calls = []
    replay(monkeypatch, calls=calls)
    first = run()
    again = run("Mara-Lind")
    assert len(calls) == 2 and again["cached"] is True and again["username"] == "Mara-Lind"
    assert again["hours_utc"] == first["hours_utc"]
    now = ga.time.time()
    monkeypatch.setattr(ga.time, "time", lambda: now + 86401)
    run()
    assert len(calls) == 4


def test_not_found_is_cached_and_the_cache_is_bounded(monkeypatch):
    calls = []
    replay(monkeypatch, calls=calls, override=lambda p, r: httpx.Response(404, json=DATA["not_found"]))
    run("nobody-here")
    run("nobody-here")
    assert len(calls) == 1
    monkeypatch.setattr(ga, "CACHE_MAX", 3)
    for i in range(6):
        run(f"nobody-{i}")
    assert len(ga._cache) == 3


# ---- endpoint ----------------------------------------------------------------------

@pytest.fixture
def no_limit(monkeypatch):
    monkeypatch.setitem(rate_limit.RATE_LIMITS, "/api/recon/github-activity", (10_000, 60))


def test_endpoint_returns_the_pattern(monkeypatch, no_limit):
    replay(monkeypatch)
    with TestClient(app) as client:
        resp = client.post("/api/recon/github-activity", json={"username": f" @{LOGIN} "})
    assert resp.status_code == 200
    body = resp.json()
    assert body["username"] == LOGIN and body["state"] == "ok" and body["events"] == 137
    assert len(body["hours_utc"]) == 24 and len(body["weekdays_utc"]) == 7 and body["estimate"]["label"] == "UTC-1 to UTC+4"


@pytest.mark.parametrize("body,status", [
    ({"username": ""}, 400), ({"username": "mara lind"}, 400), ({"username": "mara/lind"}, 400),
    ({"username": "-mara"}, 400), ({"username": "mara?page=9"}, 400), ({"username": "x" * 65}, 400),
    ({"username": "x" * 321}, 422), ({}, 422), ({"username": None}, 422), ({"username": [LOGIN]}, 422),
])
def test_endpoint_validation_errors_reach_no_source(monkeypatch, no_limit, body, status):
    calls = []
    replay(monkeypatch, calls=calls)
    with TestClient(app) as client:
        resp = client.post("/api/recon/github-activity", json=body)
    assert resp.status_code == status and calls == []


def test_rate_limit_entry():
    assert match_limit("/api/recon/github-activity") == ("/api/recon/github-activity", 10, 60)
    mw = rate_limit.RateLimitMiddleware(app=None)
    assert [mw.check("203.0.113.9", "/api/recon/github-activity", now=100.0 + i) for i in range(10)] == [None] * 10
    assert mw.check("203.0.113.9", "/api/recon/github-activity", now=111.0) is not None


# ---- logging -----------------------------------------------------------------------

def test_nothing_sensitive_is_logged(monkeypatch, no_limit, caplog):
    secrets = ("mara", "tidepool", "gauge-notes", "harbor-works", "saltmarsh", "203.0.113.9", "utc-1")
    with caplog.at_level(logging.DEBUG):
        with TestClient(app) as client:
            replay(monkeypatch)
            assert client.post("/api/recon/github-activity", json={"username": LOGIN}).status_code == 200
            ga.clear_cache_for_tests()
            replay(monkeypatch, override=lambda p, r: httpx.Response(403, json=RATE_BODY, headers={"x-ratelimit-remaining": "0"}))
            assert client.post("/api/recon/github-activity", json={"username": LOGIN}).json()["state"] == "rate_limited"

            def boom(p, r):
                raise httpx.ConnectError(f"cannot reach {r.url}")
            replay(monkeypatch, override=boom)
            assert client.post("/api/recon/github-activity", json={"username": LOGIN}).json()["state"] == "failed"
            assert client.post("/api/recon/github-activity", json={"username": "mara lind"}).status_code == 400
    ours = [r for r in caplog.records if r.name == "modules.github_activity"]
    assert len(ours) >= 3
    for record in caplog.records:
        fields = json.dumps({k: v for k, v in vars(record).items() if k != "exc_info"}, default=str).lower()
        text = record.getMessage().lower()
        for secret in secrets:
            assert secret not in fields and secret not in text, record
