"""Profile archive. The index answers come from tests/fixtures/profile_archive through a mock
transport: no network. cdx_ok.json is a sample of the rows the Wayback CDX API sent for an
organisation's page on 2026-11-26 (timestamps and digests only, nothing names an account);
cdx_none.json is its whole answer for a page it holds no capture of. The profile URLs below
use an invented handle."""

import asyncio
import json
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from fastapi.testclient import TestClient

from main import app
import middleware.rate_limit as rl
from middleware.rate_limit import match_limit
from modules import profile_archive as pa

FIXTURES = Path(__file__).parent / "fixtures" / "profile_archive"
HANDLE = "mara-quillfeather"
URL = f"https://github.com/{HANDLE}"
OK_BODY = (FIXTURES / "cdx_ok.json").read_text(encoding="utf-8")
NONE_BODY = (FIXTURES / "cdx_none.json").read_text(encoding="utf-8")


@pytest.fixture(autouse=True)
def _clean():
    pa.clear_cache_for_tests()
    yield
    pa.clear_cache_for_tests()


@pytest.fixture(scope="module")
def c():
    with TestClient(app) as client:
        yield client


def serve(monkeypatch, answer, calls: list | None = None):
    """answer: (status, body) | Exception to raise | callable(request)."""
    def handler(request: httpx.Request) -> httpx.Response:
        if calls is not None:
            calls.append(request)
        if isinstance(answer, Exception):
            raise answer
        if callable(answer):
            return answer(request)
        status, body = answer
        return httpx.Response(status, text=body, headers={"content-type": "application/json"})

    monkeypatch.setattr(pa, "_transport", lambda: httpx.MockTransport(handler))


def run(url: str) -> dict:
    return asyncio.run(pa.run_profile_archive(url))


def cdx(rows: list[str]) -> str:
    return json.dumps([["timestamp", "digest"]] + [[ts, f"D{n}"] for n, ts in enumerate(rows)])


# --------------------------------------------------------------------------------------
# The request
# --------------------------------------------------------------------------------------
def test_one_request_to_the_cdx_index_and_nowhere_else(monkeypatch):
    calls = []
    serve(monkeypatch, (200, OK_BODY), calls)
    run(URL)
    assert len(calls) == 1
    req = calls[0]
    assert req.method == "GET" and req.url.host == "web.archive.org" and req.url.path == "/cdx/search/cdx"
    assert req.url.scheme == "https"
    assert parse_qs(urlsplit(str(req.url)).query) == {
        "url": [URL], "matchType": ["exact"], "output": ["json"], "fl": ["timestamp,digest"],
        "filter": ["statuscode:200"], "collapse": ["timestamp:8"], "limit": ["10000"],
    }


def test_timeout_is_eight_seconds():
    assert pa.TIMEOUT == 8


# --------------------------------------------------------------------------------------
# States
# --------------------------------------------------------------------------------------
def test_ok_from_the_recorded_answer(monkeypatch):
    serve(monkeypatch, (200, OK_BODY))
    got = run(URL)
    rows = json.loads(OK_BODY)[1:]
    assert got["state"] == "ok" and got["url"] == URL and got["cached"] is False
    assert got["count"] == len(rows) == 65
    assert got["first"] == "2008-04-14T00:28:56Z"
    assert got["last"] == "2026-11-26T01:12:16Z"
    assert got["distinct_versions"] == len({r[1] for r in rows})
    assert got["truncated"] is False
    assert "error" not in got and "reason" not in got
    snaps = got["snapshots"]
    assert len(snaps) == 6
    assert snaps[0] == {"timestamp": got["first"], "url": f"https://web.archive.org/web/20080414002856/{URL}"}
    assert snaps[-1] == {"timestamp": got["last"], "url": f"https://web.archive.org/web/20261126011216/{URL}"}
    assert [s["timestamp"] for s in snaps] == sorted(s["timestamp"] for s in snaps)
    years = [s["timestamp"][:4] for s in snaps]
    assert len(set(years)) == len(years)


def test_none_is_the_archive_saying_it_holds_nothing(monkeypatch):
    serve(monkeypatch, (200, NONE_BODY))
    got = run(URL)
    assert got == {"url": URL, "state": "none", "count": 0, "first": None, "last": None, "snapshots": [],
                   "distinct_versions": 0, "truncated": False, "cached": False, "note": pa.NONE_NOTE}
    # only captures of the page itself are asked for, and the note says so
    assert "no capture of the page itself" in got["note"] and "redirect" in got["note"]


def test_a_header_with_no_rows_is_none(monkeypatch):
    serve(monkeypatch, (200, '[["timestamp","digest"]]'))
    assert run(URL)["state"] == "none"


def test_rate_limited(monkeypatch):
    serve(monkeypatch, (429, "Too Many Requests"))
    got = run(URL)
    assert got["state"] == "rate_limited" and got["error_code"] == "rate_limited"
    assert got["count"] == 0 and got["snapshots"] == [] and got["first"] is None


@pytest.mark.parametrize("answer, code", [
    ((400, ""), "upstream"),                                  # what the API sends for a request it does not accept
    ((500, "oops"), "upstream"),
    ((503, "<html>busy</html>"), "upstream"),
    ((200, "<html>not json</html>"), "bad_response"),
    ((200, '{"error": "x"}'), "bad_response"),                # JSON, but not a list
    ((200, '[{"a": 1}]'), "bad_response"),                    # a list with no header row
    ((200, ""), "bad_response"),
    (httpx.ReadTimeout("slow"), "timeout"),
    (httpx.ConnectError("refused"), "unreachable"),
])
def test_a_failure_is_failed_and_never_none(monkeypatch, answer, code):
    serve(monkeypatch, answer)
    got = run(URL)
    assert got["state"] == "failed" and got["error_code"] == code
    assert got["error"] and got["count"] == 0 and got["snapshots"] == []


def test_error_detail_never_holds_the_url_or_exception_text(monkeypatch):
    serve(monkeypatch, httpx.ConnectError(f"cannot reach {URL}"))
    got = run(URL)
    assert got["error_detail"] == "ConnectError"
    assert HANDLE not in json.dumps({k: v for k, v in got.items() if k != "url"})


def test_an_oversized_answer_is_failed(monkeypatch):
    monkeypatch.setattr(pa, "MAX_BODY", 100)
    serve(monkeypatch, (200, OK_BODY))
    assert run(URL)["state"] == "failed"


def test_malformed_rows_are_skipped(monkeypatch):
    body = json.dumps([["timestamp", "digest"], ["20200101000000", "A"], ["2020", "B"], "junk", [None, "C"],
                       ["20210101000000"], ["2022010100000x", "D"]])
    serve(monkeypatch, (200, body))
    got = run(URL)
    assert got["state"] == "ok" and got["count"] == 2 and got["distinct_versions"] == 1


def test_truncated_when_the_row_limit_is_reached(monkeypatch):
    monkeypatch.setattr(pa, "ROW_LIMIT", 3)
    serve(monkeypatch, (200, cdx(["20200101000000", "20210101000000", "20220101000000"])))
    assert run(URL)["truncated"] is True


# --------------------------------------------------------------------------------------
# Snapshot selection and URL building
# --------------------------------------------------------------------------------------
def ts(year: int, month: int = 6) -> str:
    return f"{year}{month:02d}15120000"


def test_pick_nothing_and_one():
    assert pa.pick_snapshots([]) == []
    assert pa.pick_snapshots([ts(2020)]) == [ts(2020)]


def test_pick_first_and_last_only_when_no_year_lies_between():
    same_year = [ts(2020, 1), ts(2020, 5), ts(2020, 9)]
    assert pa.pick_snapshots(same_year) == [ts(2020, 1), ts(2020, 9)]
    adjacent = [ts(2020, 1), ts(2020, 9), ts(2021, 2), ts(2021, 8)]
    assert pa.pick_snapshots(adjacent) == [ts(2020, 1), ts(2021, 8)]


def test_pick_one_per_year_between():
    stamps = [ts(2018), ts(2019, 2), ts(2019, 9), ts(2020, 3), ts(2020, 4), ts(2021)]
    assert pa.pick_snapshots(stamps) == [ts(2018), ts(2019, 2), ts(2020, 3), ts(2021)]


def test_pick_is_capped_and_spread():
    stamps = [ts(y) for y in range(2005, 2026)]              # 19 years between the ends
    got = pa.pick_snapshots(stamps)
    assert len(got) == 6 and got[0] == ts(2005) and got[-1] == ts(2025)
    years = [int(g[:4]) for g in got]
    assert years == sorted(set(years))
    gaps = [b - a for a, b in zip(years, years[1:])]
    assert max(gaps) - min(gaps) <= 1                         # evenly spread


@pytest.mark.parametrize("n", range(1, 30))
def test_pick_never_repeats_and_never_exceeds_six(n):
    stamps = [ts(2000 + y) for y in range(n)]
    got = pa.pick_snapshots(stamps)
    assert len(got) == len(set(got)) <= 6
    assert got == sorted(got) and got[0] == stamps[0] and got[-1] == stamps[-1]
    assert len(got) == min(n, 6)


def test_snapshot_url_and_iso():
    assert pa.snapshot_url("20190704153000", URL) == f"https://web.archive.org/web/20190704153000/{URL}"
    assert pa.iso("20190704153000") == "2019-07-04T15:30:00Z"


def test_rows_out_of_order_are_sorted(monkeypatch):
    serve(monkeypatch, (200, cdx(["20220101000000", "20190101000000", "20200101000000"])))
    got = run(URL)
    assert got["first"] == "2019-01-01T00:00:00Z" and got["last"] == "2022-01-01T00:00:00Z"
    assert [s["timestamp"][:4] for s in got["snapshots"]] == ["2019", "2020", "2022"]


# --------------------------------------------------------------------------------------
# Refusals: no request is made
# --------------------------------------------------------------------------------------
@pytest.mark.parametrize("url", [
    f"https://onlyfans.com/{HANDLE}",
    f"https://www.pornhub.com/users/{HANDLE}",
    f"https://{HANDLE}.fansly.com/",
    f"http://tinder.com/@{HANDLE}",
    f"HTTPS://OKCUPID.COM/profile/{HANDLE}",
])
def test_adult_and_dating_hosts_are_refused_with_no_request(monkeypatch, url):
    calls = []
    serve(monkeypatch, (200, OK_BODY), calls)
    got = run(url)
    assert calls == []
    assert got["state"] == "refused" and got["reason"] == "adult_site" and got["note"] == pa.REFUSALS["adult_site"]
    assert got["count"] == 0 and got["snapshots"] == [] and got["cached"] is False
    assert HANDLE not in json.dumps(got)


@pytest.mark.parametrize("url, reason", [
    ("ftp://github.com/x", "bad_url"),
    ("javascript:alert(1)", "bad_url"),
    ("github.com/x", "bad_url"),
    ("https://", "bad_url"),
    ("https://user:pw@github.com/x", "bad_url"),
    ("https://github.com:8443/x", "bad_url"),
    ("https://github.com:notaport/x", "bad_url"),
    ("https://github.com/a b", "bad_url"),
    ("https://github.com/a\nb", "bad_url"),
    ("https://github.com/<script>", "bad_url"),
    ("https://github.com/" + "a" * 600, "bad_url"),
    ("", "bad_url"),
    ("https://127.0.0.1/x", "not_public_host"),
    ("https://[::1]/x", "not_public_host"),
    ("https://localhost/x", "not_public_host"),
    ("https://intranet/x", "not_public_host"),
    ("https://bad_host-.com/x", "not_public_host"),
])
def test_urls_that_are_not_looked_up(monkeypatch, url, reason):
    calls = []
    serve(monkeypatch, (200, OK_BODY), calls)
    got = run(url)
    assert calls == [] and got["state"] == "refused" and got["reason"] == reason
    assert got["note"] in pa.REFUSALS.values() and got["url"] == ""


def test_check_url_cleans_without_touching_path_or_query():
    assert pa.check_url("  HTTPS://GitHub.com/Mara-Quillfeather?tab=Repos#top ") == ("https://github.com/Mara-Quillfeather?tab=Repos", "")
    assert pa.check_url("https://mara.substack.com") == ("https://mara.substack.com/", "")
    assert pa.check_url("https://github.com./x") == ("https://github.com/x", "")


# --------------------------------------------------------------------------------------
# Cache
# --------------------------------------------------------------------------------------
def test_answer_is_cached_for_a_day(monkeypatch):
    calls = []
    serve(monkeypatch, (200, OK_BODY), calls)
    first = run(URL)
    second = run(URL + "#bio")                                # the fragment is not part of the key
    assert len(calls) == 1 and second["cached"] is True
    assert {**second, "cached": False} == first
    second["snapshots"][0]["url"] = "changed"                 # a caller cannot change the cached copy
    assert run(URL)["snapshots"][0]["url"].startswith("https://web.archive.org/web/")
    assert pa.CACHE_TTL == 24 * 3600


def test_cache_keeps_path_case_apart(monkeypatch):
    calls = []
    serve(monkeypatch, (200, NONE_BODY), calls)
    run(URL)
    run(URL.upper().replace("HTTPS://GITHUB.COM", "https://github.com"))
    assert len(calls) == 2


def test_none_is_cached_and_expires(monkeypatch):
    calls = []
    serve(monkeypatch, (200, NONE_BODY), calls)
    now = [1000.0]
    monkeypatch.setattr(pa.time, "time", lambda: now[0])
    run(URL)
    now[0] += pa.CACHE_TTL - 1
    assert run(URL)["cached"] is True
    now[0] += 2
    assert run(URL)["cached"] is False and len(calls) == 2


@pytest.mark.parametrize("answer", [(429, ""), (500, ""), httpx.ReadTimeout("slow")])
def test_a_failure_is_cached_only_briefly(monkeypatch, answer):
    calls = []
    serve(monkeypatch, answer, calls)
    now = [1000.0]
    monkeypatch.setattr(pa.time, "time", lambda: now[0])
    run(URL)
    assert run(URL)["cached"] is True and len(calls) == 1
    now[0] += pa.CACHE_TTL_SOFT + 1
    assert run(URL)["cached"] is False and len(calls) == 2


def test_cache_is_bounded_and_refusals_are_not_cached(monkeypatch):
    monkeypatch.setattr(pa, "CACHE_MAX", 3)
    serve(monkeypatch, (200, NONE_BODY))
    for n in range(6):
        run(f"https://github.com/{HANDLE}-{n}")
    run(f"https://onlyfans.com/{HANDLE}")
    assert len(pa._cache) == 3
    assert all("onlyfans" not in key for key in pa._cache)


# --------------------------------------------------------------------------------------
# Logs
# --------------------------------------------------------------------------------------
def test_nothing_from_the_url_is_logged(monkeypatch, caplog):
    with caplog.at_level("DEBUG"):
        serve(monkeypatch, (200, OK_BODY))
        run(URL)
        run(URL)
        pa.clear_cache_for_tests()
        serve(monkeypatch, httpx.ConnectError(f"cannot reach {URL}"))
        run(URL)
        run(f"https://onlyfans.com/{HANDLE}")
        run(f"ftp://{HANDLE}.example.org/")
    text = caplog.text + " ".join(str(vars(r)) for r in caplog.records)
    assert caplog.records
    assert HANDLE not in text and "github.com" not in text and "onlyfans" not in text


# --------------------------------------------------------------------------------------
# Endpoint
# --------------------------------------------------------------------------------------
def test_endpoint_shape(c, monkeypatch):
    monkeypatch.setitem(rl.RATE_LIMITS, "/api/recon/profile-archive", (1000, 60))
    calls = []
    serve(monkeypatch, (200, OK_BODY), calls)
    r = c.post("/api/recon/profile-archive", json={"url": URL})
    assert r.status_code == 200
    got = r.json()
    assert set(got) == {"url", "state", "count", "first", "last", "snapshots", "distinct_versions", "truncated", "cached"}
    assert got["state"] == "ok" and got["url"] == URL and len(calls) == 1
    assert all(set(s) == {"timestamp", "url"} for s in got["snapshots"])


def test_endpoint_refuses_an_adult_host_with_a_state_not_an_error(c, monkeypatch):
    monkeypatch.setitem(rl.RATE_LIMITS, "/api/recon/profile-archive", (1000, 60))
    calls = []
    serve(monkeypatch, (200, OK_BODY), calls)
    r = c.post("/api/recon/profile-archive", json={"url": f"https://chaturbate.com/{HANDLE}/"})
    assert r.status_code == 200 and r.json()["state"] == "refused" and r.json()["reason"] == "adult_site"
    assert calls == []


def test_endpoint_validation(c, monkeypatch):
    monkeypatch.setitem(rl.RATE_LIMITS, "/api/recon/profile-archive", (1000, 60))
    calls = []
    serve(monkeypatch, (200, OK_BODY), calls)
    assert c.post("/api/recon/profile-archive", json={}).status_code == 422
    assert c.post("/api/recon/profile-archive", json={"url": ""}).status_code == 422
    assert c.post("/api/recon/profile-archive", json={"url": "https://github.com/" + "a" * 600}).status_code == 422
    assert c.post("/api/recon/profile-archive", json={"url": ["x"]}).status_code == 422
    r = c.post("/api/recon/profile-archive", json={"url": "file:///etc/passwd"})
    assert r.status_code == 200 and r.json()["state"] == "refused" and r.json()["reason"] == "bad_url"
    assert calls == []


def test_rate_limit_entry():
    group, limit, window = match_limit("/api/recon/profile-archive")
    assert group == "/api/recon/profile-archive" and (limit, window) == (10, 60)


def test_no_em_dash_in_the_module_or_its_copy():
    text = Path(pa.__file__).read_text(encoding="utf-8")
    assert chr(0x2014) not in text


# --------------------------------------------------------------------------------------
# A body larger than the cap, a prefix query
# --------------------------------------------------------------------------------------
def test_a_body_past_the_cap_is_dropped_while_it_streams(monkeypatch):
    monkeypatch.setattr(pa, "MAX_BODY", 1000)
    served = []

    class Endless(httpx.AsyncByteStream):
        async def __aiter__(self):
            for _ in range(10_000):
                served.append(1)
                yield b"x" * 500

    serve(monkeypatch, lambda request: httpx.Response(200, stream=Endless()))
    got = run(URL)
    assert got["state"] == "failed" and got["error_code"] == "bad_response"
    assert len(served) <= 4                    # reading stopped at the cap: the rest was never taken


@pytest.mark.parametrize("url", ["https://github.com/sam*", "https://github.com/*", "https://github.com/sam/*", "https://*.github.com/sam", "https://github.com/sam?tab=*"])
def test_a_url_with_a_star_is_refused_before_any_request(monkeypatch, url):
    calls = []
    serve(monkeypatch, (200, OK_BODY), calls)
    got = run(url)
    assert got["state"] == "refused" and got["reason"] in ("bad_url", "not_public_host") and calls == []
    assert pa.check_url("https://github.com/sam*") == ("", "bad_url")
