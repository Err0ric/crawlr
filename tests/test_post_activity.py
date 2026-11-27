"""Post activity (Hacker News, Mastodon, Lobsters), replayed through a mock transport. No network.

The row shapes come from tests/fixtures/post_activity (recorded 2026-11-27, then rewritten:
every account, id and time is invented). Rows are built from those shapes so each test can
place posts in the hours it needs.
"""

import asyncio
import copy
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from core import pinned
from core.netguard import BlockedTarget
from main import app
from middleware import rate_limit
from middleware.rate_limit import match_limit
from modules import activity_pattern as ap
from modules import github_activity as ga
from modules import post_activity as pa
from modules.profiles import mastodon

FIX = Path(__file__).parent / "fixtures" / "post_activity"
HN = json.loads((FIX / "hn_search.json").read_text(encoding="utf-8"))
MASTO = json.loads((FIX / "mastodon.json").read_text(encoding="utf-8"))
LOB = json.loads((FIX / "lobsters.json").read_text(encoding="utf-8"))
USER = "maralind"
START = datetime(2026, 9, 1, tzinfo=timezone.utc)
# Active 08:00 to 21:59 UTC, quiet 22:00 to 07:59: ten hours, so UTC-3 to UTC+4.
DAYTIME = {h: 5 for h in range(8, 22)}


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    pa.clear_cache_for_tests()

    async def public(host, port=443):
        return ["203.0.113.10"]

    monkeypatch.setattr(pinned, "resolve_public", public)
    yield
    pa.clear_cache_for_tests()


def times(hours: dict[int, int] = DAYTIME, days: int = 20, start: datetime = START) -> list[datetime]:
    out, i = [], 0
    for hour, n in hours.items():
        for _ in range(n):
            out.append(start + timedelta(days=i % days, hours=hour, minutes=i % 60))
            i += 1
    return out


def serve(monkeypatch, routes, calls: list | None = None):
    """routes(host, path, params, request) -> httpx.Response, or raises."""
    def handler(request: httpx.Request) -> httpx.Response:
        host = request.headers["host"]
        # The connection goes to the vetted address, with the name kept for TLS and Host.
        assert request.url.host == "203.0.113.10" and request.url.scheme == "https"
        assert request.extensions.get("sni_hostname") == host
        if calls is not None:
            calls.append((host, request.url.path, dict(request.url.params)))
        return routes(host, request.url.path, dict(request.url.params), request)

    monkeypatch.setattr(pa, "_transport", lambda: httpx.MockTransport(handler))


def run(site: str, username: str = USER, instance: str = "") -> dict:
    return asyncio.run(pa.run_post_activity(site, username, instance))


# ---- Hacker News -----------------------------------------------------------------------
def hn_body(when: list[datetime], user: str = USER, total: int | None = None, kinds=("comment", "story")) -> dict:
    body = copy.deepcopy(HN)
    body["hits"] = [{"_tags": [kinds[i % len(kinds)], f"author_{user}", f"story_{9000 + i}"], "created_at_i": int(t.timestamp()),
                     "objectID": str(90000000 + i)} for i, t in enumerate(when)]
    body["nbHits"] = len(when) if total is None else total
    return body


def hn_routes(body, created=1500000000):
    def routes(host, path, params, request):
        if host == "hn.algolia.com":
            return httpx.Response(200, json=body)
        assert host == "hacker-news.firebaseio.com"
        return httpx.Response(200, content=json.dumps(created).encode(), headers={"content-type": "application/json"})
    return routes


def test_hacker_news_is_one_request_and_counts_by_utc_hour(monkeypatch):
    calls = []
    serve(monkeypatch, hn_routes(hn_body(times())), calls)
    out = run("hackernews")
    assert calls == [("hn.algolia.com", "/api/v1/search_by_date", {
        "tags": f"author_{USER}", "hitsPerPage": "1000", "attributesToRetrieve": "created_at_i,_tags", "attributesToHighlight": "[]"})]
    assert out["state"] == "ok" and out["found"] is True and out["complete"] is True and out["cached"] is False
    assert out["site"] == "hackernews" and out["site_name"] == "Hacker News" and out["username"] == USER and "instance" not in out
    assert out["events"] == 70 and sum(out["hours_utc"]) == 70 and sum(out["weekdays_utc"]) == 70
    assert out["hours_utc"][8] == 5 and out["hours_utc"][7] == 0 and len(out["hours_utc"]) == 24 and len(out["weekdays_utc"]) == 7
    assert out["weekday_labels"][0] == "Monday"
    assert out["window"] == {"first": "2026-09-01T08:00:00Z", "last": "2026-09-20T19:59:00Z", "days": 20, "active_days": 20}
    assert out["types"] == [{"type": "comment", "count": 35}, {"type": "story", "count": 35}]
    assert out["read"] == {"posts": 70, "outside_window": 0, "capped": False, "available": 70}
    assert out["unit"] == "public posts" and out["pages"] == 1 and out["bot"] is False
    est = out["estimate"]
    assert out["estimate_reason"] is None
    assert est["utc_offsets"] == [-3, -2, -1, 0, 1, 2, 3, 4] and est["label"] == "UTC-3 to UTC+4"
    assert est["quiet_start_hour"] == 22 and est["quiet_end_hour"] == 8 and est["quiet_hours"] == 10
    assert est["basis"].startswith("Based on 70 public posts over 20 days")
    assert "not a place" in est["caveat"]


def test_the_answer_has_the_keys_the_github_answer_has(monkeypatch):
    serve(monkeypatch, hn_routes(hn_body(times())))
    out = run("hackernews")
    events = [{"id": str(i), "type": "PushEvent", "created_at": t.strftime("%Y-%m-%dT%H:%M:%SZ")} for i, t in enumerate(times())]
    github = ga.summarize(events)
    shared = {"events", "window", "hours_utc", "weekdays_utc", "weekday_labels", "types", "estimate", "estimate_reason"}
    assert shared <= set(out) and shared <= set(github)
    # Same times, same reading: only the word for what was counted differs.
    for key in ("events", "window", "hours_utc", "weekdays_utc"):
        assert out[key] == github[key]
    assert out["estimate"]["utc_offsets"] == github["estimate"]["utc_offsets"]
    assert set(out["estimate"]) == set(github["estimate"])


def test_hacker_news_no_posts_asks_the_official_api_whether_the_id_exists(monkeypatch):
    calls = []
    serve(monkeypatch, hn_routes(hn_body([])), calls)
    out = run("hackernews")
    assert [c[:2] for c in calls] == [("hn.algolia.com", "/api/v1/search_by_date"), ("hacker-news.firebaseio.com", f"/v0/user/{USER}/created.json")]
    assert out["state"] == "none" and out["found"] is True and out["events"] == 0
    assert out["estimate"] is None and out["estimate_reason"] is None and out["window"]["days"] == 0


def test_hacker_news_unknown_id_is_not_found(monkeypatch):
    serve(monkeypatch, hn_routes(hn_body([]), created=None))
    out = run("hackernews")
    assert out == {"site": "hackernews", "site_name": "Hacker News", "username": USER, "found": False, "state": "not_found", "cached": False}


@pytest.mark.parametrize("second", [httpx.Response(503), httpx.Response(200, json={"error": "x"}), httpx.Response(200, text="<html>")])
def test_no_posts_and_an_unanswered_existence_check_is_failed_not_none(monkeypatch, second):
    def routes(host, path, params, request):
        return httpx.Response(200, json=hn_body([])) if host == "hn.algolia.com" else second
    serve(monkeypatch, routes)
    out = run("hackernews")
    assert out["state"] == "failed" and out["found"] is None and out["error_code"] in ("upstream", "bad_response")


def test_ids_are_case_sensitive_and_another_authors_rows_are_dropped(monkeypatch):
    calls = []
    body = hn_body(times())
    body["hits"][0]["_tags"][1] = "author_MaraLind"
    body["hits"][1]["created_at_i"] = True
    body["hits"][2] = "junk"
    serve(monkeypatch, hn_routes(body), calls)
    assert run("hackernews")["events"] == 67
    assert run("hackernews")["cached"] is True and len(calls) == 1
    run("hackernews", "MaraLind")                    # another id: asked on its own
    assert len(calls) == 2 and calls[1][2]["tags"] == "author_MaraLind"


@pytest.mark.parametrize("handle", ["a", "has.dot", "x" * 16, "..", "sp ace"])
def test_a_handle_the_site_cannot_hold_is_answered_without_a_request(monkeypatch, handle):
    calls = []
    serve(monkeypatch, hn_routes(hn_body(times())), calls)
    out = run("hackernews", handle)
    assert out["state"] == "not_found" and out["found"] is False and "nothing was asked" in out["note"] and calls == []


def test_only_the_year_before_the_newest_post_is_counted(monkeypatch):
    recent = times({10: 3}, days=3)
    old = [START - timedelta(days=400 + i) for i in range(5)]
    future = [datetime.now(timezone.utc) + timedelta(days=30)]
    serve(monkeypatch, hn_routes(hn_body(recent + old + future, total=5000)))
    out = run("hackernews")
    assert out["events"] == 3 and out["read"] == {"posts": 8, "outside_window": 5, "capped": True, "available": 5000}
    assert out["window"]["first"].startswith("2026-09-01") and out["window_days_max"] == 365
    assert out["estimate"] is None and out["estimate_reason"]["code"] == "too_few_events"
    assert out["estimate_reason"]["text"] == "Too few public posts to say anything about hours: 3 seen, 40 needed."


def test_a_repeated_row_is_counted_once():
    t = times({10: 2})
    rows = [("1", t[0], "story"), ("1", t[0], "story"), ("2", t[1], "comment"), ("", t[1], "comment")]
    assert pa.summarize(rows)["events"] == 3


def test_rate_limited_is_not_none_and_the_host_is_left_alone(monkeypatch):
    calls = []
    serve(monkeypatch, lambda *a: httpx.Response(429, headers={"retry-after": "120"}), calls)
    out = run("hackernews")
    assert out["state"] == "rate_limited" and out["found"] is None and out["error_code"] == "rate_limited" and out["retry_after"] == 120
    assert "events" not in out
    again = run("hackernews", "someoneelse")
    assert again["state"] == "rate_limited" and 0 < again["retry_after"] <= 121 and len(calls) == 1
    # Another host is still asked.
    serve(monkeypatch, lambda *a: httpx.Response(404), calls)
    assert run("lobsters")["state"] == "not_found" and len(calls) == 2


@pytest.mark.parametrize("answer, code", [
    (httpx.Response(500), "upstream"), (httpx.Response(403), "upstream"), (httpx.Response(200, text="<html>walled</html>"), "bad_response"),
    (httpx.Response(200, json={"hits": "no"}), "bad_response"), (httpx.ReadTimeout("slow"), "timeout"),
    (httpx.ConnectError(f"cannot reach author_{USER}"), "unreachable"),
])
def test_failed_is_failed(monkeypatch, answer, code):
    def routes(host, path, params, request):
        if isinstance(answer, Exception):
            raise answer
        return answer
    serve(monkeypatch, routes)
    out = run("hackernews")
    assert out["state"] == "failed" and out["found"] is None and out["error_code"] == code
    assert USER not in out["error_detail"] and USER not in out["error"]
    assert pa._cache == {}                            # a failure is asked again


def test_a_body_past_the_cap_is_a_failure_and_reading_stops(monkeypatch):
    monkeypatch.setattr(pa, "MAX_JSON", 1000)
    served = []

    class Endless(httpx.AsyncByteStream):
        async def __aiter__(self):
            for _ in range(10_000):
                served.append(1)
                yield b" " * 500

    serve(monkeypatch, lambda *a: httpx.Response(200, stream=Endless()))
    out = run("hackernews")
    assert out["state"] == "failed" and out["error_code"] == "bad_response" and len(served) <= 4


def test_a_host_that_does_not_resolve_to_a_public_address_is_never_contacted(monkeypatch):
    calls = []
    serve(monkeypatch, hn_routes(hn_body(times())), calls)

    async def private(host, port=443):
        raise BlockedTarget(f"{host} resolves to a non-public address")

    monkeypatch.setattr(pinned, "resolve_public", private)
    out = run("hackernews")
    assert out["state"] == "failed" and out["error_code"] == "blocked_target" and calls == []


# ---- Mastodon --------------------------------------------------------------------------
def statuses(when: list[datetime], first_id: int = 117000000000001000) -> list[dict]:
    rows = []
    for i, t in enumerate(sorted(when, reverse=True)):
        row = copy.deepcopy(MASTO["status"])
        row.update(id=str(first_id - i), created_at=t.strftime("%Y-%m-%dT%H:%M:%S.000Z"))
        if i % 5 == 1:
            row["in_reply_to_id"] = "116000000000000001"
        if i % 5 == 2:
            row["reblog"] = {"id": "115000000000000001"}
        rows.append(row)
    return rows


def masto_routes(rows: list[dict], account: dict | None = None, override=None):
    account = MASTO["account"] if account is None else account

    def routes(host, path, params, request):
        if override:
            resp = override(host, path, params)
            if resp is not None:
                return resp
        if path == "/api/v1/accounts/lookup":
            return httpx.Response(200, json=account)
        assert path == f"/api/v1/accounts/{account['id']}/statuses" and params["limit"] == "40"
        older = [r for r in rows if "max_id" not in params or int(r["id"]) < int(params["max_id"])]
        return httpx.Response(200, json=older[:40])
    return routes


def test_mastodon_pages_by_max_id_and_stops_at_a_short_page(monkeypatch):
    calls = []
    rows = statuses(times())                         # 70 statuses: a full page and a short one
    serve(monkeypatch, masto_routes(rows), calls)
    out = run("mastodon", USER, "mastodon.social")
    assert {c[0] for c in calls} == {"mastodon.social"}
    assert calls[0][1:] == ("/api/v1/accounts/lookup", {"acct": USER})
    assert [c[2] for c in calls[1:]] == [{"limit": "40"}, {"limit": "40", "max_id": rows[39]["id"]}]
    assert out["state"] == "ok" and out["instance"] == "mastodon.social" and out["pages"] == 2 and out["events"] == 70
    assert out["read"] == {"posts": 70, "outside_window": 0, "capped": False, "available": 57}
    assert {t["type"]: t["count"] for t in out["types"]} == {"post": 42, "reply": 14, "boost": 14}
    assert out["estimate"]["label"] == "UTC-3 to UTC+4" and out["complete"] is True


def test_mastodon_stops_at_the_page_cap(monkeypatch):
    calls = []
    serve(monkeypatch, masto_routes(statuses(times({h: 20 for h in range(8, 22)}))), calls)       # 280 statuses
    out = run("mastodon")
    assert len(calls) == 1 + pa.MASTODON_PAGES and out["pages"] == pa.MASTODON_PAGES
    assert out["read"]["posts"] == 200 and out["read"]["capped"] is True and out["complete"] is True
    assert out["instance"] == "mastodon.social"       # the default when none is named


def test_mastodon_other_instance_on_the_list_is_asked_there(monkeypatch):
    other = next(h for h in mastodon.INSTANCES if h != "mastodon.social")
    calls = []
    serve(monkeypatch, masto_routes(statuses(times())), calls)
    out = run("mastodon", USER, other)
    assert {c[0] for c in calls} == {other} and out["instance"] == other
    # The same handle on another instance is another account: its own cache entry.
    assert run("mastodon", USER, "mastodon.social")["cached"] is False


def test_mastodon_instance_not_on_the_list_is_never_asked(monkeypatch):
    calls = []
    serve(monkeypatch, masto_routes(statuses(times())), calls)
    out = run("mastodon", USER, "evil.example.org")
    assert out["state"] == "failed" and calls == []
    assert pa.mastodon_instances() == tuple(mastodon.INSTANCES)


def test_mastodon_states(monkeypatch):
    serve(monkeypatch, masto_routes([], override=lambda h, p, q: httpx.Response(404, json=MASTO["not_found"])))
    assert run("mastodon")["state"] == "not_found"
    pa.clear_cache_for_tests()
    serve(monkeypatch, masto_routes([]))
    out = run("mastodon")
    assert out["state"] == "none" and out["found"] is True and out["pages"] == 1
    pa.clear_cache_for_tests()
    # An account that is not the one asked for (a remote one, or another name) is not read.
    serve(monkeypatch, masto_routes([], account={**MASTO["account"], "acct": "maralind@elsewhere.example"}))
    assert run("mastodon")["state"] == "failed"
    serve(monkeypatch, masto_routes([], account={**MASTO["account"], "id": "../1"}))
    assert run("mastodon")["state"] == "failed"
    # The statuses are closed to visitors on some instances: a failure, not "no posts".
    serve(monkeypatch, masto_routes([], override=lambda h, p, q: httpx.Response(401, json={"error": "x"}) if p.endswith("/statuses") else None))
    out = run("mastodon")
    assert out["state"] == "failed" and out["error_code"] == "upstream" and out["error_detail"] == "HTTP 401 from mastodon.social"


@pytest.mark.parametrize("status, later", [(429, "rate_limited"), (502, "failed")])
def test_a_later_page_that_does_not_answer_leaves_a_partial_reading(monkeypatch, status, later):
    rows = statuses(times())
    serve(monkeypatch, masto_routes(rows, override=lambda h, p, q: httpx.Response(status) if "max_id" in q else None))
    out = run("mastodon")
    assert out["state"] == "ok" and out["complete"] is False and out["later_pages"] == later and out["events"] == 40 and out["pages"] == 1
    key = ("mastodon", "mastodon.social", USER)
    assert pa._cache[key][0] - pa.time.time() <= pa.CACHE_TTL_PARTIAL + 1


def test_a_bot_account_is_counted_and_gets_no_estimate(monkeypatch):
    serve(monkeypatch, masto_routes(statuses(times()), account={**MASTO["account"], "bot": True}))
    out = run("mastodon")
    assert out["state"] == "ok" and out["bot"] is True and out["events"] == 70
    assert out["estimate"] is None and out["estimate_reason"]["code"] == "bot_account"


# ---- Lobsters --------------------------------------------------------------------------
def stories(when: list[datetime]) -> list[dict]:
    rows = []
    central = timezone(timedelta(hours=-6))
    for i, t in enumerate(sorted(when, reverse=True)):
        row = copy.deepcopy(LOB["story"])
        row.update(short_id=f"s{i:05d}", created_at=t.astimezone(central).isoformat(timespec="milliseconds"))
        rows.append(row)
    return rows


def lob_routes(rows: list[dict], override=None):
    def routes(host, path, params, request):
        assert host == "lobste.rs" and params == {}
        if override:
            resp = override(path)
            if resp is not None:
                return resp
        if path.lower() == f"/~{USER}.json":
            return httpx.Response(200, json=LOB["user"])
        if path == f"/~{USER}/stories.json":
            return httpx.Response(200, json=rows[:25])
        prefix = f"/~{USER}/stories/page/"
        assert path.startswith(prefix) and path.endswith(".json")
        page = int(path[len(prefix):-5])
        return httpx.Response(200, json=rows[(page - 1) * 25:page * 25])
    return routes


def test_lobsters_reads_the_account_then_story_pages_in_utc(monkeypatch):
    calls = []
    serve(monkeypatch, lob_routes(stories(times())), calls)
    out = run("lobsters", "MaraLind")                 # the path uses the site's own spelling of the handle
    assert [c[1] for c in calls] == ["/~MaraLind.json", f"/~{USER}/stories.json", f"/~{USER}/stories/page/2.json", f"/~{USER}/stories/page/3.json"]
    assert out["state"] == "ok" and out["events"] == 70 and out["pages"] == 3 and out["username"] == "MaraLind"
    # Times arrive with the site's own offset and are counted in UTC.
    assert out["hours_utc"][8] == 5 and out["hours_utc"][2] == 0 and out["estimate"]["label"] == "UTC-3 to UTC+4"
    assert out["unit"] == "submitted stories" and "Submitted stories only" in out["counts"]
    assert out["types"] == [{"type": "story", "count": 70}] and out["read"]["available"] is None
    assert out["estimate"]["basis"].startswith("Based on 70 submitted stories")


def test_lobsters_page_cap_and_states(monkeypatch):
    calls = []
    serve(monkeypatch, lob_routes(stories(times({h: 10 for h in range(8, 22)}))), calls)
    out = run("lobsters")
    assert len(calls) == 1 + pa.LOBSTERS_PAGES and out["read"] == {"posts": 100, "outside_window": 0, "capped": True, "available": None}
    pa.clear_cache_for_tests()
    serve(monkeypatch, lob_routes([], override=lambda p: httpx.Response(404, text="<html>User not found</html>")))
    assert run("lobsters")["state"] == "not_found"
    pa.clear_cache_for_tests()
    serve(monkeypatch, lob_routes([]))
    assert run("lobsters")["state"] == "none"
    pa.clear_cache_for_tests()
    # The story list answers 500 for some handles: unknown, never "no stories".
    serve(monkeypatch, lob_routes([], override=lambda p: httpx.Response(500, text="oops") if "stories" in p else None))
    out = run("lobsters")
    assert out["state"] == "failed" and out["found"] is None and out["error_code"] == "upstream"
    serve(monkeypatch, lob_routes([], override=lambda p: httpx.Response(200, json={**LOB["user"], "username": "other"}) if p.endswith(f"{USER}.json") else None))
    assert run("lobsters")["state"] == "failed"


# ---- Comparing ranges ------------------------------------------------------------------
def est(*offsets):
    return {"state": "ok", "estimate": {"utc_offsets": list(offsets)}}


def test_compare_offsets():
    none = {"state": "ok", "estimate": None, "estimate_reason": {"code": "too_few_events"}}
    assert ap.compare_offsets([est(-5, -4, -3), est(-3, -2)]) == {"verdict": "agree", "compared": 2, "shared": [-3], "label": "UTC-3"}
    assert ap.compare_offsets([est(-5, -4, -3), est(1, 2), est(-4)])["verdict"] == "disagree"
    assert ap.compare_offsets([est(-5, -4), none, {"state": "failed"}, None, "x"]) == {"verdict": "not_enough_data", "compared": 1, "shared": [], "label": ""}
    assert ap.compare_offsets([]) ["verdict"] == "not_enough_data" and ap.compare_offsets(None)["verdict"] == "not_enough_data"
    # A range over the date line is two runs, and the shared part is worded that way.
    got = ap.compare_offsets([est(11, 12, -11, -10), est(12, -11, -10, -9), none])
    assert got == {"verdict": "agree", "compared": 2, "shared": [12, -11, -10], "label": "UTC+12 or UTC-11 to UTC-10"}
    assert ap.compare_offsets([est(1, 2), est(1, 99)])["verdict"] == "not_enough_data"       # not offsets: takes no part


def test_compare_reads_real_answers(monkeypatch):
    serve(monkeypatch, hn_routes(hn_body(times())))
    hn = run("hackernews")
    events = [{"id": str(i), "created_at": t.strftime("%Y-%m-%dT%H:%M:%SZ")} for i, t in enumerate(times({h: 5 for h in range(11, 24)}))]
    got = ap.compare_offsets([hn, ga.summarize(events)])
    assert got["verdict"] == "agree" and got["shared"] and set(got["shared"]) < set(hn["estimate"]["utc_offsets"])


# ---- Never raises, never logs the handle -------------------------------------------------
def test_never_raises():
    assert run("nosuchsite")["state"] == "failed"
    assert asyncio.run(pa.run_post_activity("hackernews", None))["state"] == "failed"


def test_nothing_about_the_account_is_logged(monkeypatch, caplog):
    with caplog.at_level("DEBUG"):
        serve(monkeypatch, hn_routes(hn_body(times())))
        run("hackernews")
        serve(monkeypatch, masto_routes(statuses(times())))
        run("mastodon")
        pa.clear_cache_for_tests()
        serve(monkeypatch, lambda *a: httpx.Response(500))
        run("hackernews")
        run("lobsters")
    text = caplog.text + " ".join(str(vars(r)) for r in caplog.records)
    assert caplog.records and USER not in text and "mastodon.social" not in text


def test_no_em_dash_in_the_modules():
    for mod in (pa, ap, pinned):
        assert chr(0x2014) not in Path(mod.__file__).read_text(encoding="utf-8")


# ---- Endpoint --------------------------------------------------------------------------
@pytest.fixture(scope="module")
def c():
    with TestClient(app) as client:
        yield client


def test_endpoint(c, monkeypatch):
    monkeypatch.setitem(rate_limit.RATE_LIMITS, "/api/recon/post-activity", (10_000, 60))
    calls = []
    serve(monkeypatch, hn_routes(hn_body(times())), calls)
    r = c.post("/api/recon/post-activity", json={"site": "hackernews", "username": "@" + USER})
    assert r.status_code == 200 and r.json()["state"] == "ok" and r.json()["username"] == USER
    assert c.post("/api/recon/post-activity", json={"site": "HackerNews ", "username": USER}).json()["cached"] is True
    n = len(calls)
    assert c.post("/api/recon/post-activity", json={"site": "twitter", "username": USER}).status_code == 400
    assert c.post("/api/recon/post-activity", json={"site": "hackernews", "username": "no/slash"}).status_code == 400
    assert c.post("/api/recon/post-activity", json={"site": "hackernews"}).status_code == 422
    for bad in ("evil.example.org", "127.0.0.1", "mastodon.social.evil.example.org", "not a host"):
        r = c.post("/api/recon/post-activity", json={"site": "mastodon", "username": USER, "instance": bad})
        assert r.status_code == 400
    assert len(calls) == n
    serve(monkeypatch, masto_routes(statuses(times())), calls)
    r = c.post("/api/recon/post-activity", json={"site": "mastodon", "username": USER, "instance": "https://Mastodon.Social/"})
    assert r.status_code == 200 and r.json()["instance"] == "mastodon.social" and r.json()["state"] == "ok"
    r = c.post("/api/recon/post-activity", json={"site": "mastodon", "username": USER})
    assert r.json()["instance"] == "mastodon.social" and r.json()["cached"] is True


def test_rate_limit_entry():
    group, limit, window = match_limit("/api/recon/post-activity")
    assert group == "/api/recon/post-activity" and (limit, window) == (10, 60)
