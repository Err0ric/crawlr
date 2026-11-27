"""Archive diff. The two captures come from tests/fixtures/archive_diff through a mock
transport: no network. The page, the person and every address in it are invented."""

import asyncio
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from core import pinned, profile_record
from core.netguard import BlockedTarget
from main import app
import middleware.rate_limit as rl
from middleware.rate_limit import match_limit
from modules import archive_diff as ad
from modules import profile_archive

FIX = Path(__file__).parent / "fixtures" / "archive_diff"
OLDER = (FIX / "older.html").read_bytes()
NEWER = (FIX / "newer.html").read_bytes()
HANDLE = "mara-quillfeather"
URL = f"https://codeplace.example/{HANDLE}"
T1, T2 = "20190304050607", "20240102030405"
ISO1, ISO2 = "2019-03-04T05:06:07Z", "2024-01-02T03:04:05Z"
HTML = {"content-type": "text/html; charset=utf-8"}


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    ad.clear_cache_for_tests()
    profile_record.clear()

    async def public(host, port=443):
        assert host == "web.archive.org"            # no other name is ever resolved
        return ["203.0.113.20"]

    monkeypatch.setattr(pinned, "resolve_public", public)
    yield
    ad.clear_cache_for_tests()
    profile_record.clear()


def serve(monkeypatch, pages: dict, calls: list | None = None):
    """pages: {timestamp: (status, body, headers) | Exception | callable(request)}."""
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["host"] == "web.archive.org" and request.extensions.get("sni_hostname") == "web.archive.org"
        assert request.url.host == "203.0.113.20" and request.url.scheme == "https" and request.method == "GET"
        path = request.url.raw_path.decode()
        assert path.startswith("/web/") and path[19:23] == "id_/"
        ts = path[5:19]
        if calls is not None:
            calls.append((ts, path[23:]))
        answer = pages.get(ts, (404, b"", {}))
        if isinstance(answer, Exception):
            raise answer
        if callable(answer):
            return answer(request)
        status, body, headers = answer
        return httpx.Response(status, content=body, headers=headers)

    monkeypatch.setattr(ad, "_transport", lambda: httpx.MockTransport(handler))


def both(monkeypatch, calls=None, older=OLDER, newer=NEWER):
    serve(monkeypatch, {T1: (200, older, HTML), T2: (200, newer, HTML)}, calls)


def run(url=URL, a=ISO1, b=ISO2) -> dict:
    return asyncio.run(ad.run_archive_diff(url, a, b))


# --------------------------------------------------------------------------------------
# ok
# --------------------------------------------------------------------------------------
def test_two_requests_to_the_archive_and_what_was_removed_and_added(monkeypatch):
    calls = []
    both(monkeypatch, calls)
    out = run()
    assert sorted(calls) == [(T1, URL), (T2, URL)]
    assert out["state"] == "ok" and out["url"] == URL and out["cached"] is False and out["swapped"] is False and out["complete"] is True
    assert out["removed"]["text"] == [
        "Mara Quillfeather", "Maps and bread. Night shift cartographer at Example Maps.", "Formerly at Tideline Surveys, Lisbon.",
        "Lisbon", "@maraq", "mail", "run", "elsewhere", "picture", "portrait", "Hidden override and a bell here",
        "oldmaps Scans of harbour charts"]
    assert out["removed"]["text_total"] == 12
    assert out["removed"]["links"] == [{"url": "https://social.example.net/@maraq", "external": True},
                                       {"url": f"{URL}/oldmaps", "external": False}]
    assert out["added"] == {"text": ["Mara Q", "Maps and bread.", "photos"], "text_total": 3,
                            "links": [{"url": "https://photos.example.com/maraq", "external": True}], "links_total": 1}
    assert out["from"] == {
        "state": "ok", "timestamp": ISO1, "asked": ISO1, "exact": True, "url": f"https://web.archive.org/web/{T1}/{URL}",
        "bytes": len(OLDER), "truncated": False, "title": "mara-quillfeather (Mara Quillfeather) · Codeplace", "text_lines": 18, "links": 6}
    assert out["to"]["timestamp"] == ISO2 and out["to"]["text_lines"] == 9 and out["to"]["links"] == 5


def test_what_comes_back_is_plain_text_and_safe_links_only(monkeypatch):
    both(monkeypatch)
    out = run()
    flat = repr(out)
    assert "<" not in flat and "script text" not in flat and "color: red" not in flat and "Turn on scripts" not in flat
    assert "‮" not in flat and "\x07" not in flat
    urls = [r["url"] for side in ("removed", "added") for r in out[side]["links"]]
    assert all(u.startswith(("https://", "http://")) for u in urls)
    assert not any(bad in flat for bad in ("onlyfans", "javascript:", "mailto:", "avatars.", ".png"))
    for side in ("removed", "added"):
        assert all(isinstance(line, str) for line in out[side]["text"])


def test_the_times_may_come_in_either_order_and_in_either_form(monkeypatch):
    both(monkeypatch)
    out = run(a=T2, b=T1)
    assert out["swapped"] is True and out["from"]["timestamp"] == ISO1 and out["to"]["timestamp"] == ISO2
    assert "Lisbon" in out["removed"]["text"] and out["cached"] is False
    again = run()
    assert again["cached"] is True and again["swapped"] is False and again["removed"] == out["removed"]


def test_same(monkeypatch):
    both(monkeypatch, newer=OLDER.replace(b"<p>12 followers</p>", b"<p>12   followers</p><script>var n = 2;</script>"))
    out = run()
    assert out["state"] == "same" and out["complete"] is True
    assert out["removed"] == out["added"] == {"text": [], "text_total": 0, "links": [], "links_total": 0}
    assert out["from"]["text_lines"] == out["to"]["text_lines"] == 18


def test_a_line_that_moved_is_not_a_change():
    a = ad.extract(b"<p>one</p><p>two</p><a href='/x'>x</a>", "text/html", URL)
    b = ad.extract(b"<p>two</p><a href='/x#top'>x</a><p>one</p>", "text/html", URL)
    got = ad.diff(a, b, URL)
    assert got["removed"]["text_total"] == 0 and got["added"]["text_total"] == 0 and got["removed"]["links_total"] == 0


# --------------------------------------------------------------------------------------
# none, rate limited, failed
# --------------------------------------------------------------------------------------
def test_a_missing_capture_is_none_and_says_which(monkeypatch):
    serve(monkeypatch, {T1: (200, OLDER, HTML)})
    out = run()
    assert out["state"] == "none" and out["missing"] == ["to"]
    assert out["to"]["state"] == "none" and out["to"]["reason"] == "missing" and out["to"]["note"] == ad.SIDE_NOTES["missing"]
    assert out["from"]["state"] == "ok" and out["removed"]["text"] == [] and "error" not in out
    ad.clear_cache_for_tests()
    serve(monkeypatch, {})
    assert run()["missing"] == ["from", "to"]


def test_a_capture_that_is_not_a_page_is_not_read(monkeypatch):
    serve(monkeypatch, {T1: (200, OLDER, HTML), T2: (200, b"\x89PNG....", {"content-type": "image/png"})})
    out = run()
    assert out["state"] == "none" and out["missing"] == ["to"] and out["to"]["reason"] == "not_a_page" and out["to"]["bytes"] == 0


def test_rate_limited(monkeypatch):
    serve(monkeypatch, {T1: (200, OLDER, HTML), T2: (429, b"", {"retry-after": "90"})})
    out = run()
    assert out["state"] == "rate_limited" and out["error_code"] == "rate_limited" and out["retry_after"] == 90
    assert out["to"]["state"] == "rate_limited" and out["from"]["state"] == "ok" and out["removed"]["text"] == []


@pytest.mark.parametrize("answer, code", [
    ((500, b"", {}), "upstream"), ((403, b"", {}), "upstream"), (httpx.ReadTimeout("slow"), "timeout"),
    (httpx.ConnectError(f"cannot reach {URL}"), "unreachable"),
])
def test_failed_is_not_none(monkeypatch, answer, code):
    serve(monkeypatch, {T1: answer, T2: (200, NEWER, HTML)})
    out = run()
    assert out["state"] == "failed" and out["error_code"] == code and "missing" not in out
    assert HANDLE not in out["error_detail"] and "codeplace" not in out["error_detail"]
    assert out["from"]["state"] == "failed" and out["complete"] is False
    # A failure is kept only briefly.
    assert ad._cache_get((URL, T1, T2)) is not None
    monkeypatch.setattr(ad.time, "time", lambda t=ad.time.time(): t + ad.CACHE_TTL_SOFT + 5)
    assert ad._cache_get((URL, T1, T2)) is None


def test_an_answer_is_cached_for_a_day(monkeypatch):
    calls = []
    both(monkeypatch, calls)
    run()
    assert run()["cached"] is True and len(calls) == 2
    monkeypatch.setattr(ad.time, "time", lambda t=ad.time.time(): t + ad.CACHE_TTL + 5)
    assert run()["cached"] is False and len(calls) == 4


def test_a_blocked_resolution_reaches_no_host(monkeypatch):
    calls = []
    both(monkeypatch, calls)

    async def private(host, port=443):
        raise BlockedTarget("not public")

    monkeypatch.setattr(pinned, "resolve_public", private)
    out = run()
    assert out["state"] == "failed" and out["error_code"] == "blocked_target" and calls == []


# --------------------------------------------------------------------------------------
# Redirects
# --------------------------------------------------------------------------------------
def test_the_nearest_capture_is_followed_and_named(monkeypatch):
    near = "20190301000000"
    calls = []
    serve(monkeypatch, {
        T1: (302, b"", {"location": f"https://web.archive.org/web/{near}id_/http://www.codeplace.example/{HANDLE}"}),
        near: (200, OLDER, HTML), T2: (200, NEWER, HTML)}, calls)
    out = run()
    assert out["state"] == "ok" and out["from"]["exact"] is False
    assert out["from"]["timestamp"] == "2019-03-01T00:00:00Z" and out["from"]["asked"] == ISO1
    assert out["from"]["url"] == f"https://web.archive.org/web/{near}/{URL}"
    # The hop was asked for with this module's own URL, not with the Location header's.
    assert sorted(calls) == [(near, URL), (T1, URL), (T2, URL)]


@pytest.mark.parametrize("location", [
    f"https://web.archive.org/web/20190301000000id_/https://codeplace.example/login?return_to=/{HANDLE}",
    f"https://web.archive.org/web/20190301000000id_/https://other.example.org/{HANDLE}",
    f"https://evil.example.org/web/20190301000000id_/{URL}",
    f"https://web.archive.org/web/20190301000000/{URL}",
    "http://169.254.169.254/latest/meta-data/",
    "",
])
def test_a_redirect_to_anything_else_is_not_followed(monkeypatch, location):
    calls = []
    serve(monkeypatch, {T1: (302, b"", {"location": location}), T2: (200, NEWER, HTML), "20190301000000": (200, OLDER, HTML)}, calls)
    out = run()
    assert out["state"] == "none" and out["missing"] == ["from"] and out["from"]["reason"] == "redirect"
    assert sorted(calls) == [(T1, URL), (T2, URL)]


def test_redirects_are_bounded(monkeypatch):
    def hop(request):
        ts = int(request.url.raw_path.decode()[5:19])
        return httpx.Response(302, headers={"location": f"/web/{ts + 1}id_/{URL}"})

    calls = []
    serve(monkeypatch, {T2: (200, NEWER, HTML), **{str(int(T1) + i): hop for i in range(10)}}, calls)
    out = run()
    assert out["state"] == "failed" and out["error_code"] == "bad_response" and len(calls) == 1 + ad.MAX_HOPS + 1


def test_both_times_leading_to_one_capture_is_same(monkeypatch):
    serve(monkeypatch, {T1: (302, b"", {"location": f"/web/{T2}id_/{URL}"}), T2: (200, NEWER, HTML)})
    out = run()
    assert out["state"] == "same" and out["from"]["timestamp"] == out["to"]["timestamp"] == ISO2 and "same capture" in out["note"]


# --------------------------------------------------------------------------------------
# Size
# --------------------------------------------------------------------------------------
def test_a_capture_past_the_cap_is_cut_while_it_streams(monkeypatch):
    monkeypatch.setattr(ad, "MAX_BODY", 2000)
    served = []

    class Endless(httpx.AsyncByteStream):
        async def __aiter__(self):
            yield b"<html><body><p>first line</p>"
            for n in range(10_000):
                served.append(1)
                yield b"<p>filler %d</p>" % n + b" " * 500

    serve(monkeypatch, {T1: lambda r: httpx.Response(200, stream=Endless(), headers=HTML), T2: (200, NEWER, HTML)})
    out = run()
    assert out["state"] == "ok" and out["from"]["truncated"] is True and out["from"]["bytes"] == 2000 and out["complete"] is False
    assert "first line" in out["removed"]["text"] and len(served) <= 6


def test_lists_are_capped_and_lines_clipped(monkeypatch):
    many = b"<html><body>" + b"".join(b"<p>line %d</p><a href='/p/%d'>l</a>" % (n, n) for n in range(300)) + b"<p>" + b"x" * 1000 + b"</p></body></html>"
    both(monkeypatch, older=many, newer=b"<html><body><p>nothing</p></body></html>")
    out = run()
    assert len(out["removed"]["text"]) == ad.MAX_LINES_OUT and out["removed"]["text_total"] == 302
    assert len(out["removed"]["links"]) == ad.MAX_LINKS_OUT and out["removed"]["links_total"] == 300
    assert out["complete"] is False and out["from"]["text_lines"] == 302
    assert max(len(line) for line in ad.extract(many, "text/html", URL)["lines"]) == ad.LINE_MAX
    chunks = ad.guard_texts(out)        # neither page has a title here: the lines alone
    assert chunks and all(len(c) <= 2000 for c in chunks) and "\n".join(chunks).split("\n") == out["removed"]["text"] + out["added"]["text"]


# --------------------------------------------------------------------------------------
# Reading a page
# --------------------------------------------------------------------------------------
def test_extract_charsets_plain_text_and_broken_pages():
    latin = "<html><head><title>Café</title></head><body><p>José Müller</p></body></html>".encode("latin-1")
    assert ad.extract(latin, "text/html; charset=ISO-8859-1", URL) == {"title": "Café", "lines": ["José Müller"], "links": []}
    meta = b"<html><head><meta charset='windows-1252'></head><body>Jos\xe9</body></html>"
    assert ad.extract(meta, "text/html", URL)["lines"] == ["José"]
    # A charset that is not one, or a codec that is not text, falls back to UTF-8.
    for bogus in ("nonsense", "zlib", "base64"):
        assert ad.extract("<p>hé</p>".encode(), f"text/html; charset={bogus}", URL)["lines"] == ["hé"]
    plain = ad.extract(b"one\n<b>two</b>\n\none\n", "text/plain", URL)
    assert plain == {"title": "", "lines": ["one", "<b>two</b>"], "links": []}       # text, not markup: nothing is parsed
    broken = ad.extract(b"<html><body><p>kept<div><a href='https://ok.example.org/a'>a</a><script>lost", "text/html", URL)
    assert broken["lines"] == ["kept", "a"] and broken["links"] == ["https://ok.example.org/a"]
    assert ad.extract(b"", "text/html", URL) == {"title": "", "lines": [], "links": []}
    # A head that never closes does not hide the body.
    assert ad.extract(b"<head><title>t</title><body><p>seen</p>", "text/html", URL)["lines"] == ["seen"]


def test_links_are_made_absolute_and_archive_wrappers_removed():
    page = (b"<a href='repo'>r</a><a href='//cdn.example.org/x.js'>c</a><a href='/web/20190101000000/https://kept.example.org/a?b=1#frag'>w</a>"
            b"<a href='https://web.archive.org/web/2019/http://also.example.org/'>w2</a><a href='HTTPS://Up.example.org/'>u</a>"
            b"<a href='ftp://files.example.org/x'>f</a><a href='https://user:pw@creds.example.org/'>c</a><a href='https://10.0.0.1/'>ip</a>"
            b"<a href=''>empty</a><a>none</a><a href='https://tinder.com/@x'>d</a>")
    links = ad.extract(page, "text/html", URL + "/")["links"]
    assert links == [f"{URL}/repo", "https://kept.example.org/a?b=1", "http://also.example.org/", "https://Up.example.org/"]


# --------------------------------------------------------------------------------------
# Refusals
# --------------------------------------------------------------------------------------
@pytest.mark.parametrize("url, a, b, reason", [
    (f"https://onlyfans.com/{HANDLE}", ISO1, ISO2, "adult_site"),
    (f"https://www.tinder.com/@{HANDLE}", ISO1, ISO2, "adult_site"),
    ("file:///etc/passwd", ISO1, ISO2, "bad_url"),
    (f"https://user:pw@codeplace.example/{HANDLE}", ISO1, ISO2, "bad_url"),
    (f"https://codeplace.example:8443/{HANDLE}", ISO1, ISO2, "bad_url"),
    (f"https://codeplace.example/{HANDLE}*", ISO1, ISO2, "bad_url"),
    ("https://127.0.0.1/x", ISO1, ISO2, "not_public_host"),
    ("https://localhost/x", ISO1, ISO2, "not_public_host"),
    (URL, "yesterday", ISO2, "bad_timestamp"),
    (URL, ISO1, "2024-13-40T00:00:00Z", "bad_timestamp"),
    (URL, "20190304050607id_/https://evil.example.org", ISO2, "bad_timestamp"),
    (URL, "18990101000000", ISO2, "bad_timestamp"),
    (URL, "29990101000000", ISO2, "bad_timestamp"),
    (URL, "", ISO2, "bad_timestamp"),
    (URL, ISO1, T1, "same_timestamp"),
])
def test_refused_before_any_request(monkeypatch, url, a, b, reason):
    calls = []
    both(monkeypatch, calls)
    out = run(url, a, b)
    assert out["state"] == "refused" and out["reason"] == reason and out["note"] == ad.REFUSALS[reason] and out["url"] == ""
    assert calls == [] and out["from"] is None and out["removed"]["text"] == []


def test_the_url_check_is_the_capture_lists_own():
    for url in (URL, URL + "#frag", "HTTP://Codeplace.Example/x?tab=repos", "https://onlyfans.com/x", "ftp://x.example.org/", "https://x.example.org/a b"):
        clean, reason = profile_archive.check_url(url)
        out = asyncio.run(ad.run_archive_diff(url, T1, T1))          # refused either way: no request is made
        assert out["reason"] == (reason or "same_timestamp")


def test_never_raises():
    assert asyncio.run(ad.run_archive_diff(None, None, None))["state"] == "refused"
    assert asyncio.run(ad.run_archive_diff(URL, 5, [])) ["state"] == "refused"


# --------------------------------------------------------------------------------------
# Logging, endpoint, guard record
# --------------------------------------------------------------------------------------
def test_nothing_from_the_url_or_the_pages_is_logged(monkeypatch, caplog):
    with caplog.at_level("DEBUG"):
        both(monkeypatch)
        run()
        run()
        ad.clear_cache_for_tests()
        serve(monkeypatch, {T1: httpx.ConnectError(f"cannot reach {URL}"), T2: (200, NEWER, HTML)})
        run()
        run(f"https://onlyfans.com/{HANDLE}")
    text = caplog.text + " ".join(str(vars(r)) for r in caplog.records)
    assert caplog.records
    assert HANDLE not in text and "codeplace" not in text and "onlyfans" not in text and "Quillfeather" not in text and "Lisbon" not in text


@pytest.fixture()
def c():
    with TestClient(app) as client:
        yield client


def test_endpoint_and_the_guard_record(c, monkeypatch):
    monkeypatch.setitem(rl.RATE_LIMITS, "/api/recon/archive-diff", (1000, 60))
    calls = []
    both(monkeypatch, calls)
    r = c.post("/api/recon/archive-diff", json={"url": URL, "from": ISO1, "to": ISO2, "username": HANDLE})
    assert r.status_code == 200
    out = r.json()
    assert out["state"] == "ok" and set(out) == {"url", "state", "from", "to", "removed", "added", "complete", "swapped", "cached"}
    # The text that came back is on this visitor's record for the minor guard, as text to scan.
    profile_record.bind(c.cookies.get("crawlr_run"))
    texts = profile_record.texts(HANDLE)
    assert len(texts) == 1 and texts[0]["source"] == "Internet Archive" and texts[0]["url"] == out["from"]["url"]
    assert texts[0]["bio"].split("\n") == [out["from"]["title"], out["to"]["title"]] + out["removed"]["text"] + out["added"]["text"]
    assert not profile_record.ran(HANDLE)             # it never counts as having read the profiles
    profile_record.bind("")
    assert profile_record.texts(HANDLE) == []         # another visitor has no such record

    # Without a handle there is no diff, and a cached answer is recorded like a fresh one.
    profile_record.clear()
    assert c.post("/api/recon/archive-diff", json={"url": URL, "from": ISO1, "to": ISO2}).status_code == 422
    r = c.post("/api/recon/archive-diff", json={"url": URL, "from": T2, "to": T1, "username": "@" + HANDLE})
    assert r.json()["cached"] is True and r.json()["swapped"] is True and len(calls) == 2
    profile_record.bind(c.cookies.get("crawlr_run"))
    assert len(profile_record.texts(HANDLE)) == 1


def test_endpoint_refusals_and_bad_bodies(c, monkeypatch):
    monkeypatch.setitem(rl.RATE_LIMITS, "/api/recon/archive-diff", (1000, 60))
    calls = []
    both(monkeypatch, calls)
    post = lambda body: c.post("/api/recon/archive-diff", json=body)      # noqa: E731
    assert post({}).status_code == 422
    assert post({"url": URL, "from": ISO1}).status_code == 422
    assert post({"url": URL, "from_": ISO1, "to": ISO2}).status_code == 422
    assert post({"url": "https://codeplace.example/" + "a" * 600, "from": ISO1, "to": ISO2}).status_code == 422
    assert post({"url": URL, "from": "1" * 41, "to": ISO2}).status_code == 422
    assert post({"url": URL, "from": ISO1, "to": ISO2, "username": "no/slash"}).status_code == 400
    r = post({"url": f"https://onlyfans.com/{HANDLE}", "from": ISO1, "to": ISO2, "username": HANDLE})
    assert r.status_code == 200 and r.json()["state"] == "refused" and r.json()["reason"] == "adult_site"
    r = post({"url": URL, "from": "now", "to": ISO2, "username": HANDLE})
    assert r.status_code == 200 and r.json()["reason"] == "bad_timestamp"
    assert calls == []
    profile_record.bind(c.cookies.get("crawlr_run"))
    assert profile_record.texts(HANDLE) == []


def test_rate_limit_entry():
    group, limit, window = match_limit("/api/recon/archive-diff")
    assert group == "/api/recon/archive-diff" and (limit, window) == (4, 60)


def test_no_em_dash_in_the_module():
    assert chr(0x2014) not in Path(ad.__file__).read_text(encoding="utf-8")
