"""Tracker and ad IDs. Pages come from tests/fixtures/tracker_ids through a mock transport: no
network and no DNS. Every ID, site name and host in the fixtures is invented."""

import asyncio
import gzip
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from core import netguard as ng
from core.netguard import BlockedTarget
from main import app
from middleware.rate_limit import match_limit
from modules import tracker_ids as ti

FIXTURES = Path(__file__).parent / "fixtures" / "tracker_ids"
FULL = (FIXTURES / "home_full.html").read_text(encoding="utf-8")
DECOYS = (FIXTURES / "home_decoys.html").read_text(encoding="utf-8")
DOMAIN = "larkspur-tide.example"
PUBLIC_IP = "93.184.216.34"


@pytest.fixture(autouse=True)
def _clean():
    ti.clear_cache_for_tests()
    yield
    ti.clear_cache_for_tests()


@pytest.fixture(scope="module")
def c():
    with TestClient(app) as client:
        yield client


def html(body: str, status: int = 200, **headers) -> httpx.Response:
    return httpx.Response(status, content=body.encode("utf-8"), headers={"content-type": "text/html; charset=utf-8", **headers})


def coded(body: bytes, coding: str) -> httpx.Response:
    """A body in a content coding, left as the wire would carry it."""
    return httpx.Response(200, stream=httpx.ByteStream(body), headers={"content-type": "text/html", "content-encoding": coding})


def serve(monkeypatch, answer, calls: list | None = None, private: tuple = ()):
    """answer: httpx.Response | Exception | callable(request). Every host resolves to a public
    address, except the ones in `private`, which the guard refuses."""
    async def resolve(host, port=443):
        if host in private:
            raise BlockedTarget("not public")
        return [PUBLIC_IP]

    def handler(request: httpx.Request) -> httpx.Response:
        if calls is not None:
            calls.append(request)
        if isinstance(answer, Exception):
            raise answer
        return answer(request) if callable(answer) else answer

    monkeypatch.setattr(ng, "resolve_public", resolve)
    monkeypatch.setattr(ti, "_inner_transport", lambda: httpx.MockTransport(handler))


def run(domain: str = DOMAIN) -> dict:
    return asyncio.run(ti.run_tracker_ids(domain))


def by_kind(ids: list[dict]) -> dict:
    return {i["kind"]: i for i in ids}


# --------------------------------------------------------------------------------------
# Extraction
# --------------------------------------------------------------------------------------
def test_every_kind_is_read_from_the_vendor_snippets():
    ids = by_kind(ti.extract_ids(FULL))
    assert {k: (v["value"], v["normalized"]) for k, v in ids.items()} == {
        "google_analytics_4": ("G-QX7L2M9KD4", "G-QX7L2M9KD4"),
        "google_analytics_ua": ("UA-48213907-3", "UA-48213907"),
        "google_ads": ("AW-918273645", "AW-918273645"),
        "google_tag_manager": ("GTM-K7RW2PX", "GTM-K7RW2PX"),
        "adsense": ("ca-pub-4821730956127843", "pub-4821730956127843"),
        "meta_pixel": ("734920156483921", "734920156483921"),
        "hotjar": ("3948271", "3948271"),
        "yandex_metrica": ("58203417", "58203417"),
        "matomo": ("stats.quillmoor-hosting.example/matomo", "stats.quillmoor-hosting.example/matomo"),
        "microsoft_clarity": ("k4m9x2pq7z", "k4m9x2pq7z"),
        "linkedin_insight": ("4827193", "4827193"),
        "google_site_verification": ("Zk3vQ9d_LmT4xYp7Rw2NcB8sHf6JgAe1UoI5tDqXyV0", "Zk3vQ9d_LmT4xYp7Rw2NcB8sHf6JgAe1UoI5tDqXyV0"),
        "bing_site_verification": ("0a1b2c3d4e5f60718293a4b5c6d7e8f9", "0A1B2C3D4E5F60718293A4B5C6D7E8F9"),
        "cloudflare_insights": ("9f8e7d6c5b4a39281706f5e4d3c2b1a0", "9f8e7d6c5b4a39281706f5e4d3c2b1a0"),
    }
    assert set(ids) == set(ti.KINDS)                      # the fixture covers every kind there is
    assert ids["matomo"]["site_id"] == "7"


def test_where_each_id_was_seen():
    ids = by_kind(ti.extract_ids(FULL))
    assert ids["google_analytics_4"]["seen_in"] == ["script_src", "inline_script"]
    assert ids["adsense"]["seen_in"] == ["script_src", "meta_tag", "attribute"]
    assert ids["google_tag_manager"]["seen_in"] == ["inline_script", "noscript_tag"]
    assert ids["meta_pixel"]["seen_in"] == ["inline_script", "noscript_tag"]
    assert ids["google_site_verification"]["seen_in"] == ["meta_tag"]
    assert ids["cloudflare_insights"]["seen_in"] == ["attribute"]
    for row in ids.values():
        assert set(row["seen_in"]) <= set(ti.WHERE)


def test_row_shape_key_scope_and_search_string():
    ids = by_kind(ti.extract_ids(FULL))
    ua = ids["google_analytics_ua"]
    assert set(ua) == {"kind", "label", "value", "normalized", "key", "scope", "seen_in", "search", "meaning"}
    assert ua["key"] == "google_analytics_ua:UA-48213907" and ua["scope"] == "account"
    assert ua["search"] == '"UA-48213907-"'              # the account, with the dash so UA-482139070 is not a hit
    assert ids["adsense"]["search"] == '"pub-4821730956127843"'
    assert ids["google_tag_manager"]["scope"] == "site"
    for row in ids.values():
        assert row["scope"] in ("account", "site") and row["search"].startswith('"') and row["search"].endswith('"')
        assert "http" not in row["search"]               # a string to copy, never a third-party URL


def test_two_properties_of_one_analytics_account_share_a_normalized_form():
    page = "<script>gtag('config', 'UA-48213907-1');</script><script>ga('create', \"UA-48213907-2\", 'auto');</script>"
    ids = ti.extract_ids(page)
    assert [i["value"] for i in ids] == ["UA-48213907-1", "UA-48213907-2"]
    assert {i["normalized"] for i in ids} == {"UA-48213907"} and len({i["key"] for i in ids}) == 1


def test_look_alikes_outside_a_vendor_snippet_are_not_ids():
    assert ti.extract_ids(DECOYS) == []


@pytest.mark.parametrize("page", [
    "", "<html>", "<script>", "<script>gtag('config', 'G-", "<meta name=google-site-verification>",
    "<script src='https://www.googletagmanager.com/gtag/js?id='></script>",
    "<script src='http://[::1/gtag/js?id=G-QX7L2M9KD4'></script>",
    "<script data-cf-beacon='[1,2]' src='x.js'></script>", "<script data-cf-beacon='{\"token\": 5}' src='x.js'></script>",
    "\x00\x01<<<>>>" * 50,
])
def test_broken_markup_gives_nothing_and_does_not_raise(page):
    assert ti.extract_ids(page) == []


def test_a_page_cut_inside_a_script_still_gives_what_was_there():
    page = FULL[: FULL.index("gtag('config', 'UA-48213907-3');") + 34]
    kinds = {i["kind"] for i in ti.extract_ids(page)}
    assert {"google_analytics_4", "google_analytics_ua"} <= kinds and "meta_pixel" not in kinds


def test_the_list_is_bounded():
    page = "<script>" + "".join(f"ga('create', 'UA-{100000 + n}-1');" for n in range(500)) + "</script>"
    assert len(ti.extract_ids(page)) == ti.MAX_IDS


def test_findings_are_info_only():
    rows = ti.findings_for(ti.extract_ids(FULL))
    assert len(rows) == len(ti.KINDS) and {r["level"] for r in rows} == {"info"}
    assert rows[0]["title"] == "Google Analytics 4: G-QX7L2M9KD4"
    assert rows[0]["detail"].startswith("Seen in a script address and an inline script.")


def test_no_em_dashes_in_any_copy():
    text = " ".join([ti.NONE_NOTE, ti.OFF_SITE_NOTE, ti.CAPPED_NOTE, *WHERE_AND_KINDS()])
    assert "—" not in text and "–" not in text


def WHERE_AND_KINDS():
    return [*ti.WHERE.values(), *(part for row in ti.KINDS.values() for part in row)]


# --------------------------------------------------------------------------------------
# States
# --------------------------------------------------------------------------------------
def test_ok_one_request_to_the_home_page(monkeypatch):
    calls = []
    serve(monkeypatch, html(FULL), calls)
    out = run()
    assert out["state"] == "ok" and out["count"] == 14 and len(out["ids"]) == 14 and out["cached"] is False
    assert out["requests_target"] is True and out["off_site"] is False and out["truncated"] is False
    assert out["url"] == f"https://{DOMAIN}/" and out["final_host"] == DOMAIN and out["note"] == ""
    assert len(out["findings"]) == 14 and "error" not in out
    assert len(calls) == 1
    req = calls[0]
    assert req.method == "GET" and req.url.host == PUBLIC_IP and req.url.path == "/" and req.headers["host"] == DOMAIN
    assert not req.url.query


def test_none_is_a_read_page_with_no_id(monkeypatch):
    serve(monkeypatch, html(DECOYS))
    out = run()
    assert out["state"] == "none" and out["ids"] == [] and out["findings"] == [] and "error" not in out
    assert "not proof" in out["note"]


@pytest.mark.parametrize("status", [401, 403, 429, 451])
def test_blocked_is_not_none(monkeypatch, status):
    serve(monkeypatch, html("<h1>Access denied</h1>", status))
    out = run()
    assert out["state"] == "blocked" and out["ids"] == []
    assert out["error_code"] == ("rate_limited" if status == 429 else "blocked") and out["error"]


def test_a_challenge_page_is_blocked(monkeypatch):
    serve(monkeypatch, html("<title>Just a moment...</title>", 503, server="cloudflare"))
    assert run()["state"] == "blocked"
    ti.clear_cache_for_tests()
    serve(monkeypatch, html(FULL, 200, **{"cf-mitigated": "challenge"}))
    assert run()["state"] == "blocked"


@pytest.mark.parametrize("answer, code", [
    (html("gone", 404), "not_found"),
    (html("oops", 500), "upstream"),
    (httpx.ConnectTimeout("t"), "timeout"),
    (httpx.ConnectError("refused"), "unreachable"),
    (httpx.Response(200, content=b'{"a": 1}', headers={"content-type": "application/json"}), "bad_response"),
    (coded(b"\x1f\x8bnot gzip at all", "gzip"), "bad_response"),
    (coded(b"xx", "br"), "bad_response"),
])
def test_failed_is_not_none(monkeypatch, answer, code):
    serve(monkeypatch, answer)
    out = run()
    assert out["state"] == "failed" and out["error_code"] == code and out["ids"] == []
    assert DOMAIN not in out["error_detail"] and DOMAIN not in out["error"]


def test_a_private_host_is_never_fetched(monkeypatch):
    calls = []
    serve(monkeypatch, html(FULL), calls, private=(DOMAIN,))
    out = run()
    assert out["state"] == "failed" and out["error_code"] == "blocked_target" and calls == []


def test_a_redirect_to_a_private_host_is_refused(monkeypatch):
    calls = []
    serve(monkeypatch, lambda r: httpx.Response(302, headers={"location": "https://intranet.larkspur-tide.example/"}), calls,
          private=("intranet.larkspur-tide.example",))
    out = run()
    assert out["state"] == "failed" and out["error_code"] == "blocked_target" and len(calls) == 1


def test_a_redirect_to_another_site_is_said(monkeypatch):
    def answer(request):
        if request.headers["host"] == DOMAIN:
            return httpx.Response(301, headers={"location": "https://quillmoor-parking.example/landing"})
        return html(FULL)
    serve(monkeypatch, answer)
    out = run()
    assert out["state"] == "ok" and out["off_site"] is True and out["final_host"] == "quillmoor-parking.example"
    assert out["url"] == "https://quillmoor-parking.example/landing" and "another site" in out["note"]


def test_www_is_the_same_site(monkeypatch):
    serve(monkeypatch, lambda r: html(FULL) if r.headers["host"].startswith("www.") else httpx.Response(301, headers={"location": f"https://www.{DOMAIN}/"}))
    out = run()
    assert out["state"] == "ok" and out["off_site"] is False and out["final_host"] == f"www.{DOMAIN}"


def test_a_huge_page_is_cut_at_the_cap_and_says_so(monkeypatch):
    page = FULL + "<!-- " + "x" * (ti.MAX_BYTES + 5000) + " --><script>fbq('init', '111111111111111');</script>"
    serve(monkeypatch, html(page))
    out = run()
    assert out["state"] == "ok" and out["truncated"] is True and "1.5 MB" in out["note"]
    assert "111111111111111" not in [i["value"] for i in out["ids"]] and out["count"] == 14


def test_gzip_is_read_and_a_gzip_bomb_is_cut_at_the_cap(monkeypatch):
    serve(monkeypatch, lambda r: coded(gzip.compress(FULL.encode()), "gzip"))
    assert run()["count"] == 14
    ti.clear_cache_for_tests()
    bomb = gzip.compress(b"<p>" + b" " * 60_000_000)
    assert len(bomb) < 100_000
    serve(monkeypatch, lambda r: coded(bomb, "gzip"))
    out = run()
    assert out["state"] == "none" and out["truncated"] is True


def test_answers_are_cached_and_a_cached_answer_is_a_copy(monkeypatch):
    calls = []
    serve(monkeypatch, html(FULL), calls)
    first = run()
    first["ids"].clear()
    second = run()
    assert len(calls) == 1 and second["cached"] is True and second["count"] == 14 and len(second["ids"]) == 14


def test_nothing_about_the_target_is_logged(monkeypatch, caplog):
    serve(monkeypatch, html(FULL))
    with caplog.at_level("DEBUG"):
        run()
    text = " ".join(f"{r.getMessage()} {r.__dict__}" for r in caplog.records if r.name == "modules.tracker_ids")
    assert "tracker ids" in text and DOMAIN not in text and "UA-48213907" not in text


# --------------------------------------------------------------------------------------
# Endpoint
# --------------------------------------------------------------------------------------
def test_endpoint_and_rate_limit(monkeypatch, c):
    serve(monkeypatch, html(FULL))
    r = c.post("/api/recon/tracker-ids", json={"domain": f"https://{DOMAIN}/some/path"})
    assert r.status_code == 200 and r.json()["state"] == "ok" and r.json()["domain"] == DOMAIN
    assert match_limit("/api/recon/tracker-ids")[0] == "/api/recon/tracker-ids"


@pytest.mark.parametrize("bad", ["", "not a domain", "8.8.8.8", "a" * 400, "exa mple.com", "-x.example"])
def test_endpoint_refuses_what_is_not_a_domain(monkeypatch, c, bad):
    calls = []
    serve(monkeypatch, html(FULL), calls)
    r = c.post("/api/recon/tracker-ids", json={"domain": bad})
    assert r.status_code in (400, 422) and calls == []
