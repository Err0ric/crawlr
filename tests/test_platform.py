import gzip
import re
import time

import pytest
from fastapi.testclient import TestClient

from main import app, asset_fingerprint
from middleware.observability import CSP


@pytest.fixture(scope="module")
def c():
    with TestClient(app) as client:
        yield client


@pytest.mark.parametrize("path", ["/", "/api/health", "/robots.txt", "/sitemap.xml"])
def test_head_is_allowed(c, path):
    r = c.head(path)
    assert r.status_code == 200 and r.text == ""


def test_index_references_fingerprinted_assets(c):
    html = c.get("/").text
    fp = asset_fingerprint()
    assert re.fullmatch(r"[0-9a-f]{12}", fp)
    assert f"/assets/{fp}/js/app.js" in html and f"/assets/{fp}/css/app.css" in html
    assert "/static/v2/" not in html and "{{SITE_URL}}" not in html


def test_fingerprinted_assets_are_cached_for_a_year_and_html_is_not(c):
    fp = asset_fingerprint()
    r = c.get(f"/assets/{fp}/js/app.js")
    assert r.status_code == 200 and "javascript" in r.headers["content-type"]
    assert r.headers["cache-control"] == "public, max-age=31536000, immutable"
    assert c.get("/").headers["cache-control"] == "no-cache"
    # a stale fingerprint (page loaded before a deploy) still resolves
    assert c.get("/assets/000000000000/js/core.js").status_code == 200
    # misses are not cached, and the mount cannot escape static/v2
    miss = c.get(f"/assets/{fp}/js/nope.js")
    assert miss.status_code == 404 and "immutable" not in miss.headers.get("cache-control", "")
    assert c.get(f"/assets/{fp}/../../main.py").status_code == 404
    assert c.get(f"/assets/{fp}/%2e%2e/%2e%2e/main.py").status_code == 404


def test_fingerprint_changes_when_a_file_changes(tmp_path, monkeypatch):
    import main
    (tmp_path / "index.html").write_text("<script src='/static/v2/js/a.js'></script>")
    (tmp_path / "js").mkdir()
    (tmp_path / "js" / "a.js").write_text("one")
    monkeypatch.setattr(main, "UI_DIR", tmp_path)
    monkeypatch.setattr(main, "_fingerprint_cache", None)
    before = main.asset_fingerprint()
    assert main.asset_fingerprint() == before
    (tmp_path / "js" / "a.js").write_text("two, and longer")
    assert main.asset_fingerprint() != before


def test_responses_are_gzipped(c):
    fp = asset_fingerprint()
    for path in ("/", f"/assets/{fp}/css/app.css", f"/assets/{fp}/js/investigate.js"):
        r = c.get(path, headers={"accept-encoding": "gzip"})
        assert r.headers.get("content-encoding") == "gzip", path
    raw = c.get(f"/assets/{fp}/css/app.css", headers={"accept-encoding": "identity"})
    assert "content-encoding" not in raw.headers


def test_robots_and_sitemap(c):
    robots = c.get("/robots.txt")
    assert robots.headers["content-type"].startswith("text/plain")
    assert "Disallow: /api/" in robots.text and "Sitemap: https://crawlr.lol/sitemap.xml" in robots.text
    sm = c.get("/sitemap.xml")
    assert "xml" in sm.headers["content-type"] and "<loc>https://crawlr.lol/</loc>" in sm.text


def test_social_and_seo_tags(c):
    html = c.get("/").text
    for needle in ('<link rel="canonical" href="https://crawlr.lol/">', 'property="og:title"', 'property="og:description"',
                   'property="og:image" content="https://crawlr.lol/static/og.png"', 'name="twitter:card" content="summary_large_image"',
                   'name="description"'):
        assert needle in html, needle
    og = c.get("/static/og.png")
    assert og.status_code == 200 and og.headers["content-type"] == "image/png"


def test_csp_has_no_inline_scripts_or_third_party_hosts(c):
    csp = c.get("/").headers["content-security-policy"]
    assert csp == CSP
    script = next(d for d in csp.split("; ") if d.startswith("script-src"))
    assert script == "script-src 'self'"
    for gone in ("unsafe-inline' https://cdnjs", "cdnjs.cloudflare.com", "fonts.googleapis.com", "fonts.gstatic.com"):
        assert gone not in csp


def test_page_loads_nothing_from_third_party_origins(c):
    html = c.get("/").text
    assert "fonts.googleapis.com" not in html and "fonts.gstatic.com" not in html and "cdnjs" not in html
    assert not re.search(r"<script(?![^>]*\bsrc=)[^>]*>\s*\S", html), "inline script found"
    assert not re.search(r"\son[a-z]+\s*=", html), "inline event handler found"
    fp = asset_fingerprint()
    assert c.get(f"/assets/{fp}/vendor/d3.min.js").status_code == 200
    css = c.get(f"/assets/{fp}/css/app.css").text
    assert "font-display: swap" in css.replace("font-display:swap", "font-display: swap")
    for url in re.findall(r"url\(([^)]+)\)", css):
        assert not url.strip("'\"").startswith("http"), url
    assert "cdnjs" not in c.get(f"/assets/{fp}/js/recon.js").text


def test_ci_compiles_core():
    ci = open(".github/workflows/ci.yml").read()
    assert "compileall -q main.py routers modules middleware core" in ci
    for t in ("detect", "contrast", "brief"):
        assert f"node tests/js/{t}.test.mjs" in ci


def test_api_docs_are_off_by_default(c):
    assert c.get("/docs").status_code == 404
    assert c.get("/openapi.json").status_code == 404
    assert c.get("/redoc").status_code == 404
    assert "/docs" not in c.get("/robots.txt").text      # nothing to hide, so nothing to list


def test_api_docs_can_be_switched_on(monkeypatch):
    import importlib
    import main
    monkeypatch.setenv("ENABLE_API_DOCS", "true")
    try:
        fresh = importlib.reload(main)
        with TestClient(fresh.app) as client:
            assert client.get("/docs").status_code == 200
            assert "paths" in client.get("/openapi.json").json()
    finally:
        monkeypatch.delenv("ENABLE_API_DOCS")
        importlib.reload(main)


def test_plate_lookup_is_gone(c):
    assert c.post("/api/vehicles/plate", json={"plate": "ABC123", "state": "WA"}).status_code == 404
    html = c.get("/").text
    assert "plateIn" not in html and "License plate" not in html
    assert "vinIn" in html                                  # the VIN decoder (official NHTSA API) stays
    fp = asset_fingerprint()
    assert "kbb" not in c.get(f"/assets/{fp}/js/tools.js").text.lower()


# --- platform check (modules/platform_check.py) ---------------------------------------------
# Every body below is a trimmed recording of what the site sent to an anonymous server-side
# GET on 2026-11-14 (tests/fixtures/platform). No network.

import asyncio  # noqa: E402
from pathlib import Path  # noqa: E402

import httpx  # noqa: E402

from modules import platform_check as pc  # noqa: E402

FIX = Path(__file__).parent / "fixtures" / "platform"
RULE = {r["name"]: r for r in pc.RULES}
MISSING = "zq7xkv3mwp9tjh2rnb5ycd8fgl4sae"


def fx(name: str) -> str:
    return (FIX / name).read_text(encoding="utf-8")


@pytest.fixture(autouse=True)
def _clean_platform_cache():
    pc.clear_cache_for_tests()
    yield
    pc.clear_cache_for_tests()


def verdict(platform, username, body, status=200, final_url=None):
    rule = RULE[platform]
    return pc.classify_page(rule, username, status, final_url or rule["url"].format(username=username), body)


@pytest.mark.parametrize("platform,username,fixture,name", [
    ("Instagram", "torvalds", "instagram_found.html", "Sam Example"),
    ("Instagram", "Err0ric", "instagram_found_mixed_case.html", "Eric Henderson"),
    ("Instagram", "err0ric", "instagram_found_mixed_case.html", "Eric Henderson"),
    ("X", "torvalds", "x_found.html", "torvalds"),
    ("X", "TORVALDS", "x_found.html", "torvalds"),
    ("Threads", "torvalds", "threads_found.html", "Sam Example"),
    ("Threads", "Err0ric", "threads_found_bio.html", "Eric Henderson"),
    ("TikTok", "torvalds", "tiktok_found.html", "Torvalds"),
    ("Facebook", "torvalds", "facebook_found.html", "Patrick Torvalds"),
])
def test_found_needs_a_marker_that_names_the_handle(platform, username, fixture, name):
    v = verdict(platform, username, fx(fixture))
    assert v["state"] == "found" and v["display_name"] == name
    assert username in v["evidence"] or "links to itself" in v["evidence"]
    # the same page fetched for a different handle proves nothing about that handle
    other = verdict(platform, "someoneelse", fx(fixture))
    assert other["state"] != "found"


@pytest.mark.parametrize("platform,fixture,status", [
    ("Instagram", "instagram_error_page.html", 200),
    ("X", "x_not_found.html", 404),
    ("TikTok", "tiktok_not_found.html", 200),
])
def test_not_found_pages_are_recognised(platform, fixture, status):
    v = verdict(platform, MISSING[:15], fx(fixture), status=status)
    assert v["state"] == "not_found" and v["evidence"]


@pytest.mark.parametrize("platform,fixture,status,final_url,state,evidence", [
    ("Threads", "threads_login_wall.html", 200, "https://www.threads.com/login/?next=https%3A%2F%2Fwww.threads.com%2F%40x%2F", "blocked", "login wall"),
    ("Threads", "threads_login_wall.html", 200, None, "blocked", "login wall"),                  # by the page title alone
    ("Instagram", "", 200, "https://www.instagram.com/accounts/login/?next=%2Fx%2F", "blocked", "login wall"),
    ("Facebook", "facebook_refused.html", 400, None, "blocked", "refused"),
    ("Facebook", "facebook_unavailable.html", 200, None, "unknown", "missing profile and a login-only one"),
    ("LinkedIn", "linkedin_999.html", 999, None, "blocked", "HTTP 999"),
    ("LinkedIn", "", 200, "https://www.linkedin.com/authwall?trk=x", "blocked", "login wall"),
    ("X", "", 403, None, "blocked", "HTTP 403"),
    ("TikTok", "", 429, None, "blocked", "HTTP 429"),
    ("Instagram", "", 401, None, "blocked", "HTTP 401"),
    ("TikTok", "", 503, None, "unknown", "HTTP 503"),
])
def test_walls_and_refusals_are_blocked_never_a_negative(platform, fixture, status, final_url, state, evidence):
    v = verdict(platform, "torvalds", fx(fixture) if fixture else "", status=status, final_url=final_url)
    assert v["state"] == state and evidence in v["evidence"]
    assert v["state"] not in ("found", "not_found")


@pytest.mark.parametrize("platform", sorted(RULE))
def test_a_bare_200_is_unknown_on_every_platform(platform):
    for body in ("", "   ", "<html><head><title>Loading</title></head><body><div id='app'></div></body></html>"):
        v = verdict(platform, "torvalds", body)
        assert v["state"] == "unknown", (platform, body)
        row = pc._row(RULE[platform], "torvalds", v)
        assert row["found"] is None


def test_the_tiktok_not_found_phrase_is_not_a_marker():
    # It sits in the translation table of every TikTok page, including a real profile's.
    assert "find this account" in fx("tiktok_found.html")
    assert verdict("TikTok", "torvalds", fx("tiktok_found.html"))["state"] == "found"
    shell = '<script>{"Couldn\'t find this account":"Couldn\'t find this account"}</script>'
    assert verdict("TikTok", "torvalds", shell)["state"] == "unknown"


def test_a_found_marker_on_an_error_status_is_not_found_true():
    v = verdict("X", "torvalds", fx("x_found.html"), status=403)
    assert v["state"] == "blocked"


def test_linkedin_has_no_found_or_not_found_rule():
    assert not RULE["LinkedIn"].get("found") and not RULE["LinkedIn"].get("not_found")
    page = '<html><head><title>Linus Torvalds | LinkedIn</title><link rel="canonical" href="https://www.linkedin.com/in/torvalds"></head></html>'
    assert verdict("LinkedIn", "torvalds", page)["state"] == "unknown"


# --- the whole run, with the HTTP layer faked ------------------------------------------------

REAL_ASYNC_CLIENT = httpx.AsyncClient


def fake_sites(monkeypatch, responder, calls=None):
    def handler(request: httpx.Request):
        if calls is not None:
            calls.append(str(request.url))
        return responder(request)

    monkeypatch.setattr(pc.httpx, "AsyncClient", lambda *a, **k: REAL_ASYNC_CLIENT(transport=httpx.MockTransport(handler), follow_redirects=True))


def site_responder(pages: dict, default=None):
    """pages: {"host/path-fragment": (status, body) | httpx.Response | Exception}."""
    def respond(request: httpx.Request):
        url = str(request.url)
        for needle, answer in pages.items():
            if needle in url:
                if isinstance(answer, Exception):
                    raise answer
                if isinstance(answer, httpx.Response):
                    return answer
                return httpx.Response(answer[0], text=answer[1])
        return default or httpx.Response(200, text="")
    return respond


def by_platform(out):
    return {r["platform"]: r for r in out["results"]}


def test_run_reports_every_state_in_the_contract_shape(monkeypatch):
    calls = []
    fake_sites(monkeypatch, site_responder({
        "instagram.com/torvalds": (200, fx("instagram_found.html")),
        "x.com/torvalds": (200, fx("x_found.html")),
        "threads.com/@torvalds": httpx.Response(302, headers={"location": "https://www.threads.com/login/?next=x"}),
        "threads.com/login": (200, fx("threads_login_wall.html")),
        "tiktok.com/@torvalds": (200, fx("tiktok_not_found.html")),
        "tiktok.com/@tiktok": (200, fx("tiktok_found.html").replace("torvalds", "tiktok")),
        "facebook.com/torvalds": (200, fx("facebook_unavailable.html")),
        "linkedin.com": (999, fx("linkedin_999.html")),
    }), calls)
    out = asyncio.run(pc.run_platform_check("torvalds"))
    rows = by_platform(out)
    # Reddit and Discord are always part of a run, after the page rules.
    assert list(rows) == ["Facebook", "Instagram", "X", "Threads", "TikTok", "LinkedIn", "Reddit", "Discord"]
    assert {p: r["state"] for p, r in rows.items()} == {
        "Facebook": "unknown", "Instagram": "found", "X": "found", "Threads": "blocked",
        "TikTok": "not_found", "LinkedIn": "blocked", "Reddit": "unknown", "Discord": "unknown"}
    assert out["username"] == "torvalds" and out["total"] == 2 and out["checked"] == 8
    for r in out["results"]:
        assert {"platform", "url", "state", "found", "evidence", "display_name", "public_url"} <= set(r)
        assert r["found"] is (True if r["state"] == "found" else False if r["state"] == "not_found" else None)
        assert r["evidence"] and r["public_url"] is (r["platform"] != "Discord")
    assert rows["Instagram"]["url"] == "https://www.instagram.com/torvalds/" and rows["Instagram"]["display_name"] == "Sam Example"
    assert rows["Threads"]["evidence"] == "login wall"
    # no adult site in an ordinary run: not as a row, not as a link, not as a request
    assert "onlyfans" not in str(out).lower() and not any("onlyfans" in c for c in calls)
    assert not any(r.get("manual") or r["state"] == "manual" for r in out["results"])


def test_every_request_is_a_get_with_navigation_headers(monkeypatch):
    seen = []

    def respond(request):
        seen.append((request.method, request.headers.get("sec-fetch-mode"), request.headers.get("user-agent", "")))
        return httpx.Response(200, text="")

    fake_sites(monkeypatch, respond)
    asyncio.run(pc.run_platform_check("torvalds"))
    pages = [x for x in seen if x[0] == "GET"]
    # Six profile pages and Reddit's about.json, each a browser navigation; Discord's sign-up check is the one POST.
    assert len(pages) == 7 and all(mode == "navigate" and "Mozilla" in ua for _m, mode, ua in pages)
    assert [m for m, _mode, _ua in seen if m != "GET"] == ["POST"] and len(seen) == 8


def test_a_not_found_page_is_only_believed_when_the_canary_is_readable(monkeypatch):
    # Instagram serves the same error page for a missing handle and for a real profile when
    # it degrades the request. With the canary unreadable too, the answer is "blocked".
    fake_sites(monkeypatch, site_responder({"instagram.com": (200, fx("instagram_error_page.html"))}))
    row = by_platform(asyncio.run(pc.run_platform_check("torvalds")))["Instagram"]
    assert row["state"] == "blocked" and row["found"] is None and "every profile" in row["evidence"]

    pc.clear_cache_for_tests()
    calls = []
    fake_sites(monkeypatch, site_responder({
        "instagram.com/instagram/": (200, fx("instagram_found.html").replace("torvalds", "instagram")),
        "instagram.com": (200, fx("instagram_error_page.html")),
    }), calls)
    row = by_platform(asyncio.run(pc.run_platform_check(MISSING)))["Instagram"]
    assert row["state"] == "not_found" and row["found"] is False
    # the canary answer is reused for the next handle
    asyncio.run(pc.run_platform_check("anotherhandle"))
    assert sum("instagram.com/instagram/" in c for c in calls) == 1


def test_the_canary_handle_itself_cannot_be_reported_missing(monkeypatch):
    fake_sites(monkeypatch, site_responder({"instagram.com": (200, fx("instagram_error_page.html"))}))
    row = by_platform(asyncio.run(pc.run_platform_check("instagram")))["Instagram"]
    assert row["state"] == "blocked"


def test_network_failures_are_unknown_with_a_code_never_false(monkeypatch):
    fake_sites(monkeypatch, site_responder({
        "instagram.com": httpx.ConnectTimeout("timed out"),
        "x.com": httpx.ConnectError("connection refused"),
        "tiktok.com": (500, "oops"),
    }))
    rows = by_platform(asyncio.run(pc.run_platform_check("torvalds")))
    assert rows["Instagram"]["state"] == "unknown" and rows["Instagram"]["found"] is None and rows["Instagram"]["error_code"] == "timeout"
    assert rows["X"]["state"] == "unknown" and rows["X"]["error_code"] == "unreachable"
    assert rows["TikTok"]["state"] == "unknown" and rows["TikTok"]["error_code"] == "upstream"
    for r in rows.values():
        assert r["found"] is not False
        assert "torvalds" not in r["evidence"] and "://" not in r["evidence"]


def test_a_slow_site_times_out_without_holding_up_the_rest(monkeypatch):
    async def slow_fetch(client, url):
        if "instagram" in url:
            await asyncio.sleep(5)
        return 200, url, fx("x_found.html") if "x.com" in url else ""

    monkeypatch.setattr(pc, "_fetch", slow_fetch)
    started = time.monotonic()
    rows = by_platform(asyncio.run(pc.run_platform_check("torvalds", timeout=0.2)))
    assert time.monotonic() - started < 2
    assert rows["Instagram"]["state"] == "unknown" and rows["Instagram"]["error_code"] == "timeout"
    assert rows["X"]["state"] == "found"


def test_sherlock_sites_are_skipped(monkeypatch):
    calls = []
    fake_sites(monkeypatch, site_responder({}), calls)
    out = asyncio.run(pc.run_platform_check("torvalds", ["Facebook", "Twitter", "threads", "GitHub"]))
    assert [r["platform"] for r in out["results"]] == ["Instagram", "TikTok", "LinkedIn", "Reddit", "Discord"]
    assert out["checked"] == 5
    assert not any(h in c for c in calls for h in ("facebook.com", "x.com", "threads.com"))
    # "X" covers the X row as well
    out = asyncio.run(pc.run_platform_check("torvalds", ["X"]))
    assert "X" not in [r["platform"] for r in out["results"]]


def test_found_and_not_found_are_cached_for_a_day_and_nothing_else_is(monkeypatch):
    calls = []
    pages = {
        "instagram.com/torvalds": (200, fx("instagram_found.html")),
        "x.com/x": (200, fx("x_found.html").replace("torvalds", "x")),
        "x.com/torvalds": (404, fx("x_not_found.html")),
        "linkedin.com": (999, ""),
    }
    fake_sites(monkeypatch, site_responder(pages), calls)
    first = by_platform(asyncio.run(pc.run_platform_check("torvalds")))
    assert first["Instagram"]["state"] == "found" and first["X"]["state"] == "not_found" and first["LinkedIn"]["state"] == "blocked"
    calls.clear()
    second = by_platform(asyncio.run(pc.run_platform_check("Torvalds")))       # handles are not case sensitive
    assert second["Instagram"]["state"] == "found" and second["X"]["state"] == "not_found"
    assert second["Instagram"]["url"] == "https://www.instagram.com/Torvalds/"
    assert not any("instagram.com" in c or "x.com" in c for c in calls)
    assert any("linkedin.com" in c for c in calls) and any("tiktok.com" in c for c in calls)   # blocked and unknown are retried

    # after the TTL the answer is fetched again
    monkeypatch.setattr(pc, "CACHE_TTL", -1)
    calls.clear()
    asyncio.run(pc.run_platform_check("torvalds"))
    assert any("instagram.com/torvalds" in c for c in calls)


def test_the_cache_is_bounded(monkeypatch):
    monkeypatch.setattr(pc, "CACHE_MAX", 3)
    for i in range(6):
        pc._cache_put(("Instagram", f"user{i}"), {"state": "found"})
    assert len(pc._cache) == 3 and ("Instagram", "user5") in pc._cache and ("Instagram", "user0") not in pc._cache


def test_platform_check_endpoint(c, monkeypatch):
    fake_sites(monkeypatch, site_responder({"instagram.com/Err0ric": (200, fx("instagram_found_mixed_case.html"))}))
    r = c.post("/api/recon/platform-check", json={"username": "Err0ric", "sherlock_sites": ["Facebook"]})
    assert r.status_code == 200
    body = r.json()
    rows = by_platform(body)
    assert rows["Instagram"]["state"] == "found" and rows["Instagram"]["found"] is True
    assert rows["Instagram"]["display_name"] == "Eric Henderson" and body["total"] == 1
    assert "Facebook" not in rows and "OnlyFans" not in rows


def test_no_adult_platforms_were_added():
    # OnlyFans used to be a manual link here. Adult and dating sites live only in
    # modules/adult_check.py, behind the opt-in.
    from modules import adult_check
    assert pc.MANUAL_PLATFORMS == []
    hosts = {adult_check._site(r["url"]) for r in pc.RULES}
    assert not (hosts & adult_check.HOSTS) and "onlyfans.com" in adult_check.HOSTS
    assert [r["name"] for r in pc.RULES] == ["Facebook", "Instagram", "X", "Threads", "TikTok", "LinkedIn"]
