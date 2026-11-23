"""Adult and dating site check. Every body is a trimmed recording of what the site sent to an
anonymous server-side GET on 2026-11-14 (tests/fixtures/adult): title, text meta tags and the
marker region only. No network: the HTTP layer is a mock transport."""

import asyncio
import json
import re
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from core import adult_guard
from core import profile_record
from main import app
import middleware.rate_limit as rl
from middleware.rate_limit import match_limit
from modules import adult_check as ac

FIX = Path(__file__).parent / "fixtures" / "adult"
RULE = {r["name"]: r for r in ac.RULES}
NOBODY = "qzx7vk2mwp9rtb4ynh6jds3lfg8cae"     # the random 30-character handle the fixtures were recorded with
PHRASES = set(ac.EVIDENCE.values())
ROW_KEYS = {"platform", "category", "url", "state", "found", "evidence", "display_name", "joined", "followers", "bio", "hint"}
STATES = {"found", "not_found", "blocked", "unknown", "no_public_url"}


def fx(name: str) -> str:
    return (FIX / name).read_text(encoding="utf-8")


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    ac.clear_cache_for_tests()
    # These tests post to the endpoint more often than one visitor may in a minute.
    monkeypatch.setitem(rl.RATE_LIMITS, "/api/recon/adult-check", (1000, 60))
    yield
    ac.clear_cache_for_tests()


@pytest.fixture(scope="module")
def c():
    with TestClient(app) as client:
        yield client


def verdict(platform, username, body, status=200, final_url=None, redirected=False):
    rule = RULE[platform]
    return ac.classify_response(rule, username, status, final_url or ac._check_url(rule, username), body, redirected)


# ---- the pure classifier, from recorded pages ------------------------------------------

# platform, the account the page was recorded for, fixture, status, evidence key
FOUND = [
    ("Fansly", "fansly", "fansly_found.json", 200, "site_data"),
    ("Pornhub", "pornhub", "pornhub_found.html", 200, "page_names_handle"),
    ("xHamster", "xhamster", "xhamster_found.html", 200, "page_names_handle"),
    ("Chaturbate", "chaturbate", "chaturbate_found.html", 200, "site_data"),
    ("JustFor.Fans", "justforfans", "justforfans_found.html", 200, "page_names_handle"),
    ("Tinder", "tinder", "tinder_found.html", 200, "site_data"),
]
# platform, fixture, status, final url (None: no redirect), evidence key
NOT_FOUND = [
    ("Fansly", "fansly_not_found.json", 200, None, "lookup_empty"),
    ("Pornhub", "pornhub_not_found.html", 404, None, "no_such_user"),
    ("xHamster", "xhamster_not_found.html", 404, None, "no_such_user"),
    ("Chaturbate", "chaturbate_not_found.html", 404, None, "no_such_user"),
    ("JustFor.Fans", "justforfans_not_found.html", 200, "https://justfor.fans/explore.php?error=usernotfound", "no_such_user"),
    ("Tinder", "tinder_not_found.html", 200, None, "no_such_user"),
]


@pytest.mark.parametrize("platform,handle,fixture,status,key", FOUND, ids=[f[0] for f in FOUND])
def test_recorded_profile_pages_are_found(platform, handle, fixture, status, key):
    got = verdict(platform, handle, fx(fixture), status)
    assert (got["state"], got["evidence_key"]) == ("found", key)
    # handles are not case sensitive
    assert verdict(platform, handle.upper(), fx(fixture), status)["state"] == "found"
    # the same page asked about a different handle proves nothing about that handle
    assert verdict(platform, "someoneelse", fx(fixture), status)["state"] == "unknown"
    # a found marker on an error status is not a profile
    if RULE[platform].get("reader") != "fansly":
        assert verdict(platform, handle, fx(fixture), 503)["state"] == "unknown"


@pytest.mark.parametrize("platform,fixture,status,final,key", NOT_FOUND, ids=[n[0] for n in NOT_FOUND])
def test_recorded_no_such_user_pages_are_not_found(platform, fixture, status, final, key):
    got = verdict(platform, NOBODY, fx(fixture), status, final, redirected=bool(final))
    assert (got["state"], got["evidence_key"]) == ("not_found", key)
    assert got["display_name"] == "" and got["bio"] == "" and got["followers"] is None


def test_a_chaturbate_account_with_no_room_data_is_found_by_its_title():
    # Recorded for an account that exists but has no room: the page carries the title marker only.
    body = fx("chaturbate_found_no_room.html")
    assert "broadcaster_username" not in body
    got = verdict("Chaturbate", "sam_example", body, 200)
    assert (got["state"], got["evidence_key"]) == ("found", "page_names_handle")
    assert verdict("Chaturbate", "sam", body, 200)["state"] == "unknown"                 # a prefix of the handle is not the handle
    # the 404 page's own og:title starts with the site name, which is also the canary-like handle
    assert verdict("Chaturbate", "chaturbate", fx("chaturbate_not_found.html"), 404)["state"] == "not_found"


def test_at_least_three_platforms_conclude_each_way():
    assert len(FOUND) >= 3 and len(NOT_FOUND) >= 3
    able = sorted(r["name"] for r in ac.RULES if r.get("found") and r.get("not_found"))
    assert able == sorted(f[0] for f in FOUND) == sorted(n[0] for n in NOT_FOUND)


@pytest.mark.parametrize("platform", [r["name"] for r in ac.RULES if ac.is_fetched(r)])
def test_a_bare_200_is_never_found(platform):
    for body in ("", "<html><head><title>Welcome</title></head><body>hello</body></html>", "{}", '{"success":true}'):
        got = verdict(platform, "torvalds", body, 200)
        assert got["state"] == "unknown", (platform, body, got)


def test_a_404_without_the_sites_own_page_is_not_a_negative():
    # Pornhub, xHamster and Chaturbate conclude only on their own not-found page AND a 404.
    for platform, fixture in (("Pornhub", "pornhub_not_found.html"), ("xHamster", "xhamster_not_found.html"), ("Chaturbate", "chaturbate_not_found.html")):
        assert verdict(platform, NOBODY, fx(fixture), 200)["state"] == "unknown"                       # the page without the status
        assert verdict(platform, NOBODY, "<html><title>Not here</title></html>", 404)["state"] == "unknown"   # the status without the page
    # JustFor.Fans concludes only on the redirect, never on the explore page by itself.
    assert verdict("JustFor.Fans", NOBODY, fx("justforfans_not_found.html"), 200)["state"] == "unknown"


def test_walls_gates_and_refusals_are_blocked_never_a_negative():
    # FetLife sends every handle to its sign-in page.
    for handle in ("fetlife", NOBODY):
        got = verdict("FetLife", handle, fx("fetlife_login.html"), 200, "https://fetlife.com/login", redirected=True)
        assert (got["state"], got["evidence_key"]) == ("blocked", "login_wall")
    assert verdict("FetLife", NOBODY, fx("fetlife_login.html"), 200)["evidence_key"] == "login_wall"       # by title alone
    assert not RULE["FetLife"].get("found") and not RULE["FetLife"].get("not_found")
    # a redirect to a sign-in path on any platform
    got = verdict("Pornhub", "torvalds", "<html><title>Sign in</title></html>", 200, "https://www.pornhub.com/login?redirect=x", redirected=True)
    assert (got["state"], got["evidence_key"]) == ("blocked", "login_wall")
    # refusals and bot checks, including a not-found page served behind one
    for status in (401, 403, 429):
        assert verdict("xHamster", "torvalds", "denied", status) == ac._verdict("blocked", "refused")
        assert verdict("Fansly", "torvalds", "{}", status) == ac._verdict("blocked", "refused")
    challenge = "<html><head><title>Just a moment...</title></head><body><script>window._cf_chl_opt={}</script></body></html>"
    for platform in ("Chaturbate", "Tinder", "JustFor.Fans"):
        assert verdict(platform, "torvalds", challenge, 403)["state"] == "blocked"
        assert verdict(platform, "torvalds", challenge, 200) == ac._verdict("blocked", "challenge")
    gate = "<html><head><title>Age Verification</title></head><body>Please confirm you are over 18.</body></html>"
    assert verdict("Chaturbate", "torvalds", gate, 200) == ac._verdict("blocked", "challenge")


def test_errors_and_unreadable_answers_are_unknown():
    assert verdict("Pornhub", "torvalds", "oops", 503)["evidence_key"] == "http_error"
    assert verdict("Fansly", "torvalds", "<html>gateway</html>", 200)["evidence_key"] == "unreadable"
    assert verdict("Fansly", "torvalds", '{"success":false,"response":[]}', 200)["state"] == "unknown"
    assert verdict("Fansly", "torvalds", "{}", 500)["state"] == "unknown"
    # an answer that lists a different account is not this handle
    assert verdict("Fansly", "torvalds", fx("fansly_found.json"), 200) == ac._verdict("unknown", "no_marker")


def test_text_metadata_is_read_only_when_the_page_states_it():
    got = verdict("Fansly", "fansly", fx("fansly_found.json"))
    assert (got["display_name"], got["followers"], got["bio"], got["joined"]) == ("Fansly", 9294, "Official Fansly Account.", "")
    got = verdict("Tinder", "tinder", fx("tinder_found.html"))
    assert got["display_name"] == "Tomasz" and got["bio"] == "" and got["followers"] is None        # an invented first name
    for platform, handle, fixture, status, _ in FOUND:
        if platform not in ("Fansly", "Tinder"):
            got = verdict(platform, handle, fx(fixture), status)
            assert (got["display_name"], got["joined"], got["followers"], got["bio"]) == ("", "", None, "")


def fansly_account(**fields) -> str:
    account = {"id": "1", "username": "sam_example", "displayName": "Sam Example", "followCount": 12, "about": "Hi there."}
    account.update(fields)
    return json.dumps({"success": True, "response": [account]})


@pytest.mark.parametrize("about,expected", [
    ("Coffee, cats and long walks.", "Coffee, cats and long walks."),
    ("see more at https://cdn.example/clip.mp4", ""),
    ("my page: example.com/sam", ""),
    ('<a href="x">link</a>', ""),
    ("x" * 500, "x" * 300),
    (None, ""), (17, ""),
])
def test_a_bio_is_returned_only_as_plain_text(about, expected):
    assert verdict("Fansly", "sam_example", fansly_account(about=about))["bio"] == expected


def test_image_fields_in_a_site_answer_never_reach_the_row():
    body = fansly_account(avatar={"id": "9", "locations": [{"location": "https://cdn.example/a/avatar.jpg"}]},
                          banner={"locations": [{"location": "https://cdn.example/a/banner.png"}]},
                          displayName="https://cdn.example/pic.webp", followCount="1,204")
    got = verdict("Fansly", "sam_example", body)
    assert got["state"] == "found" and got["display_name"] == "" and got["followers"] == 1204
    row = ac._row(RULE["Fansly"], "sam_example", got)
    assert set(row) == ROW_KEYS and "cdn.example" not in json.dumps(row)


# ---- only a recorded rule may conclude -------------------------------------------------

def fixture_backed(rule: dict, field: str, pattern: str, handles: tuple) -> bool:
    """Does a recorded page in tests/fixtures/adult show this marker for a handle it was recorded with?"""
    for path in sorted(FIX.iterdir()):
        body = path.read_text(encoding="utf-8")
        for redirected_to in ("", "https://justfor.fans/explore.php?error=usernotfound"):
            fields = ac.page_fields(200, redirected_to, body, bool(redirected_to))
            for handle in handles:
                if re.search(pattern.replace("{u}", re.escape(handle)), fields.get(field, ""), re.I):
                    return True
    return False


def test_only_recorded_rules_can_conclude_found_or_not_found():
    recorded_for = {f[0]: f[1] for f in FOUND}
    able_found, able_not_found = [], []
    for rule in ac.RULES:
        assert rule["src"] in ("recorded", "unrecorded") and rule["category"] in ("adult", "dating"), rule["name"]
        if rule.get("found") or rule.get("not_found"):
            assert rule["src"] == "recorded" and ac.is_fetched(rule), rule["name"]
        for field, pattern, key in rule.get("found", []):
            assert key in ("page_names_handle", "site_data") and "{u}" in pattern, (rule["name"], pattern)
            assert field not in ("final_url", "redirected_to", "status"), rule["name"]       # the request cannot prove itself
            assert fixture_backed(rule, field, pattern, (recorded_for[rule["name"]],)), (rule["name"], pattern)
            able_found.append(rule["name"])
        for field, pattern, key in rule.get("not_found", []):
            assert key in ("no_such_user", "lookup_empty"), rule["name"]
            assert fixture_backed(rule, field, pattern, (NOBODY,)), (rule["name"], pattern)
            able_not_found.append(rule["name"])
        for _, _, key in rule.get("wall", []):
            assert key in ("login_wall", "challenge"), rule["name"]
    assert sorted(set(able_found)) == sorted(set(able_not_found)) == ["Chaturbate", "Fansly", "JustFor.Fans", "Pornhub", "Tinder", "xHamster"]


def test_every_other_rule_is_enumerated_and_cannot_conclude():
    static = {r["name"]: r["static"] for r in ac.RULES if r.get("static")}
    assert static == {
        "OnlyFans": ("unknown", "same_page"), "LoyalFans": ("unknown", "same_page"), "Stripchat": ("unknown", "unrecorded"),
        "ManyVids": ("no_public_url", "no_public_url"), "Clips4Sale": ("no_public_url", "no_public_url"),
        "Bumble": ("no_public_url", "no_public_url"), "Hinge": ("no_public_url", "no_public_url"),
        "OkCupid": ("no_public_url", "no_public_url"), "Plenty of Fish": ("no_public_url", "no_public_url"),
        "Grindr": ("no_public_url", "no_public_url"),
    }
    for rule in ac.RULES:
        if rule.get("static"):
            assert rule["static"][0] in ("unknown", "no_public_url") and rule.get("hint") in ac.HINTS, rule["name"]
            assert not rule.get("found") and not rule.get("not_found") and not rule.get("canary"), rule["name"]
            assert bool(rule["url"]) is (rule["static"][0] == "unknown"), rule["name"]
    # A rule that was never recorded cannot conclude even if someone gives it markers.
    fake = {**RULE["Pornhub"], "src": "unrecorded"}
    assert ac.classify_response(fake, "pornhub", 200, "", fx("pornhub_found.html")) == ac._verdict("unknown", "unrecorded")
    assert ac.classify_response(fake, NOBODY, 404, "", fx("pornhub_not_found.html")) == ac._verdict("unknown", "unrecorded")
    # The app-shell sites send one page for every handle, so nothing in it names anyone.
    for name in ("onlyfans_app_shell.html", "loyalfans_app_shell.html"):
        assert NOBODY not in fx(name) and "<title>" in fx(name)
    assert [r["name"] for r in ac.RULES] == [
        "OnlyFans", "Fansly", "Pornhub", "xHamster", "Chaturbate", "Stripchat", "ManyVids", "Clips4Sale", "FetLife",
        "JustFor.Fans", "LoyalFans", "Tinder", "Bumble", "Hinge", "OkCupid", "Plenty of Fish", "Grindr"]


def test_fixtures_are_small_text_with_no_media_addresses():
    for path in FIX.iterdir():
        text = path.read_text(encoding="utf-8")
        assert len(text) < 4000, path.name
        assert not re.search(r"\.(?:jpe?g|png|webp|gif|svg|mp4|webm|m3u8)\b", text, re.I), path.name
        assert not re.search(r"<img|og:image|twitter:image|\bsrc=", text, re.I), path.name
        assert chr(8212) not in text, path.name


def test_evidence_and_hints_are_closed_sets_without_placeholders():
    for text in list(ac.EVIDENCE.values()) + list(ac.HINTS.values()):
        assert text.endswith(".") and "{" not in text and chr(8212) not in text
    used = {key for r in ac.RULES for kind in ("found", "not_found", "wall") for _, _, key in r.get(kind, [])}
    used |= {r["static"][1] for r in ac.RULES if r.get("static")}
    assert used <= set(ac.EVIDENCE)


# ---- the whole run, with the HTTP layer faked ---------------------------------------------

def fake_sites(monkeypatch, pages: dict, calls: list | None = None, default=None):
    """pages: {"host/path-fragment": (status, body) | httpx.Response | Exception | callable(request)}."""
    def handler(request: httpx.Request):
        url = str(request.url)
        if calls is not None:
            calls.append((request.method, url, dict(request.headers)))
        for needle, answer in pages.items():
            if needle in url:
                if isinstance(answer, Exception):
                    raise answer
                if callable(answer):
                    return answer(request)
                if isinstance(answer, httpx.Response):
                    return answer
                return httpx.Response(answer[0], text=answer[1])
        return default or httpx.Response(200, text="")

    monkeypatch.setattr(ac, "_client", lambda timeout: httpx.AsyncClient(transport=httpx.MockTransport(handler), timeout=timeout, follow_redirects=False))



@pytest.fixture(autouse=True)
def _ordinary_sources_on_record(monkeypatch):
    """This file tests what happens once an adult pass is allowed. The rule that the ordinary
    sources must have run first, and the check of what they found, are tested in
    test_adult_guard.py and test_adult_tools.py; here every handle counts as on record."""
    profile_record.clear()
    monkeypatch.setattr(profile_record, "ran", lambda handle: True)
    yield
    profile_record.clear()

def run(username, **kw):
    return asyncio.run(ac.run_adult_check(username, **kw))


def by_platform(out):
    return {r["platform"]: r for r in out["results"]}


def as_handle(fixture: str, recorded: str, handle: str) -> str:
    return fx(fixture).replace(recorded, handle)


def media_leaks(value, path="") -> list[str]:
    """Every key or value in a response that looks like an image or media reference."""
    bad = []
    if isinstance(value, dict):
        for key, item in value.items():
            if re.search(r"image|avatar|thumb|banner|photo|picture|preview|poster", str(key), re.I):
                bad.append(f"{path}.{key}")
            bad += media_leaks(item, f"{path}.{key}")
    elif isinstance(value, list):
        for n, item in enumerate(value):
            bad += media_leaks(item, f"{path}[{n}]")
    elif isinstance(value, str):
        if re.search(r"\.(?:jpe?g|png|webp|gif|avif|svg|mp4|webm|mov|m3u8)\b", value, re.I) or re.search(r"/(?:avatars?|thumbs?|thumbnails?|banners?)/", value, re.I):
            bad.append(f"{path}={value[:60]}")
    return bad


FULL_RUN = {
    "apiv3.fansly.com/api/v1/account?usernames=torvalds": (200, fansly_account(
        username="Torvalds", displayName="Sam Example", followCount=41, about="Plain words only.",
        avatar={"locations": [{"location": "https://cdn.example/u/avatar.jpg"}]}, banner={"location": "https://cdn.example/u/banner.png"})),
    "pornhub.com/users/torvalds": (200, as_handle("pornhub_found.html", "pornhub", "torvalds")),
    "xhamster.com/users/torvalds": (404, fx("xhamster_not_found.html")),
    "chaturbate.com/torvalds/": (404, fx("chaturbate_not_found.html")),
    "fetlife.com/torvalds": httpx.Response(302, headers={"location": "https://fetlife.com/login"}),
    "fetlife.com/login": (200, fx("fetlife_login.html")),
    "justfor.fans/torvalds": httpx.Response(302, headers={"location": "/explore.php?error=usernotfound"}),
    "justfor.fans/explore.php": (200, fx("justforfans_not_found.html")),
    "tinder.com/@torvalds": (200, "<html><head><title>Tinder</title></head><body>nothing to read</body></html>"),
}


def test_run_reports_every_state_in_the_contract_shape(monkeypatch):
    calls = []
    fake_sites(monkeypatch, FULL_RUN, calls)
    out = run("torvalds")
    rows = by_platform(out)
    assert list(rows) == [r["name"] for r in ac.RULES]
    assert {p: r["state"] for p, r in rows.items()} == {
        "OnlyFans": "unknown", "Fansly": "found", "Pornhub": "found", "xHamster": "not_found", "Chaturbate": "not_found",
        "Stripchat": "unknown", "ManyVids": "no_public_url", "Clips4Sale": "no_public_url", "FetLife": "blocked",
        "JustFor.Fans": "not_found", "LoyalFans": "unknown", "Tinder": "unknown",
        "Bumble": "no_public_url", "Hinge": "no_public_url", "OkCupid": "no_public_url", "Plenty of Fish": "no_public_url", "Grindr": "no_public_url"}
    assert (out["username"], out["checked"], out["total"]) == ("torvalds", 7, 2) and set(out) == {"username", "checked", "total", "results"}
    for r in out["results"]:
        assert set(r) == ROW_KEYS, r["platform"]
        assert r["state"] in STATES and r["category"] in ("adult", "dating")
        assert r["found"] is (True if r["state"] == "found" else False if r["state"] == "not_found" else None)
        assert r["evidence"] in PHRASES and (r["hint"] == "" or r["hint"] in ac.HINTS.values())
        assert (r["url"] == "") is (r["state"] == "no_public_url")
        if r["state"] != "found":
            assert (r["display_name"], r["joined"], r["followers"], r["bio"]) == ("", "", None, "")
    assert {r["platform"] for r in out["results"] if r["category"] == "dating"} == {"Tinder", "Bumble", "Hinge", "OkCupid", "Plenty of Fish", "Grindr"}
    fansly = rows["Fansly"]
    assert (fansly["url"], fansly["display_name"], fansly["followers"], fansly["bio"]) == ("https://fansly.com/torvalds", "Sam Example", 41, "Plain words only.")
    assert rows["FetLife"]["evidence"] == ac.EVIDENCE["login_wall"] and rows["FetLife"]["hint"] == ac.HINTS["sign_in"]
    assert rows["OnlyFans"]["url"] == "https://onlyfans.com/torvalds" and rows["OnlyFans"]["hint"] == ac.HINTS["open_link"]
    assert rows["Grindr"]["evidence"] == ac.EVIDENCE["no_public_url"] and rows["Grindr"]["hint"] == ac.HINTS["app_only"]
    assert rows["Stripchat"]["evidence"] == ac.EVIDENCE["unrecorded"]

    # no image or media reference anywhere in the response
    assert media_leaks(out) == [] and "cdn.example" not in json.dumps(out)

    # one GET per fetched platform plus the redirects that stayed on the site, all as a browser navigation
    urls = [u for _, u, _ in calls]
    assert len(urls) == 9 and all(m == "GET" and h.get("sec-fetch-mode") == "navigate" and "Mozilla" in h.get("user-agent", "") for m, _, h in calls)
    # a platform that cannot be checked is never contacted
    for host in ("onlyfans", "loyalfans", "stripchat", "manyvids", "clips4sale", "bumble", "hinge", "okcupid", "pof.com", "grindr"):
        assert not any(host in u for u in urls), host
    # every request went to one of the fixed hosts
    assert {httpx.URL(u).host for u in urls} == {"apiv3.fansly.com", "www.pornhub.com", "xhamster.com", "chaturbate.com", "fetlife.com", "justfor.fans", "tinder.com"}


def test_a_tinder_not_found_page_is_only_believed_when_the_canary_is_readable(monkeypatch):
    # Tinder answers a handle with no web profile with its homepage and HTTP 200. With the
    # canary unreadable too, that page says nothing.
    fake_sites(monkeypatch, {"tinder.com": (200, fx("tinder_not_found.html"))})
    row = by_platform(run("torvalds"))["Tinder"]
    assert (row["state"], row["found"], row["evidence"]) == ("blocked", None, ac.EVIDENCE["canary_failed"])

    ac.clear_cache_for_tests()
    calls = []
    fake_sites(monkeypatch, {"tinder.com/@tinder": (200, fx("tinder_found.html")), "tinder.com": (200, fx("tinder_not_found.html"))}, calls)
    row = by_platform(run(NOBODY))["Tinder"]
    assert (row["state"], row["found"], row["evidence"]) == ("not_found", False, ac.EVIDENCE["no_such_user"])
    # the canary answer is reused for the next handle
    run("anotherhandle")
    assert sum(1 for _, u, _ in calls if u.endswith("/@tinder")) == 1
    # and the canary handle itself can never be reported missing
    ac.clear_cache_for_tests()
    fake_sites(monkeypatch, {"tinder.com": (200, fx("tinder_not_found.html"))})
    assert by_platform(run("tinder"))["Tinder"]["state"] == "blocked"


def test_network_failures_are_unknown_with_a_code_never_false(monkeypatch):
    fake_sites(monkeypatch, {
        "pornhub.com": httpx.ConnectError("[Errno 8] nodename nor servname provided"),
        "xhamster.com": httpx.ReadTimeout("slow"),
        "chaturbate.com": httpx.ConnectError("connection refused"),
        "fansly.com": (502, "bad gateway"),
    })
    rows = by_platform(run("torvalds"))
    assert (rows["Pornhub"]["state"], rows["Pornhub"]["error_code"], rows["Pornhub"]["evidence"]) == ("unknown", "dns", ac.EVIDENCE["dns"])
    assert (rows["xHamster"]["state"], rows["xHamster"]["error_code"]) == ("unknown", "timeout")
    assert (rows["Chaturbate"]["state"], rows["Chaturbate"]["error_code"]) == ("unknown", "unreachable")
    assert (rows["Fansly"]["state"], rows["Fansly"]["error_code"]) == ("unknown", "upstream")
    assert all(r["found"] is None for r in rows.values())
    # the exception text can hold the URL, and the URL holds the handle: none of it is returned
    assert "nodename" not in json.dumps(rows) and "Errno" not in json.dumps(rows)


def test_a_slow_site_times_out_without_holding_up_the_rest(monkeypatch):
    async def slow(request):
        await asyncio.sleep(5)
        return httpx.Response(200, text="")

    async def handler(request: httpx.Request):
        if "pornhub" in str(request.url):
            return await slow(request)
        return httpx.Response(404, text=fx("xhamster_not_found.html")) if "xhamster" in str(request.url) else httpx.Response(200, text="")

    monkeypatch.setattr(ac, "_client", lambda timeout: httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=False))
    rows = by_platform(run("torvalds", timeout=0.2))
    assert (rows["Pornhub"]["state"], rows["Pornhub"]["error_code"]) == ("unknown", "timeout")
    assert rows["xHamster"]["state"] == "not_found"


def test_a_redirect_is_followed_only_while_it_stays_on_the_site(monkeypatch):
    calls = []
    fake_sites(monkeypatch, {
        "pornhub.com/users/torvalds": httpx.Response(302, headers={"location": "https://elsewhere.example/landing"}),
        "de.xhamster.com/users/torvalds": (200, as_handle("xhamster_found.html", "xhamster", "torvalds").replace("xHamster&#039;s", "torvalds&#039;s")),
        "//xhamster.com/users/torvalds": httpx.Response(301, headers={"location": "https://de.xhamster.com/users/torvalds"}),
        "chaturbate.com/torvalds/": httpx.Response(302, headers={"location": "http://169.254.169.254/latest/meta-data/"}),
        "justfor.fans/torvalds": httpx.Response(302, headers={"location": "javascript:alert(1)"}),
    }, calls)
    rows = by_platform(run("torvalds"))
    assert (rows["Pornhub"]["state"], rows["Pornhub"]["evidence"]) == ("unknown", ac.EVIDENCE["off_site"])
    assert rows["Chaturbate"]["evidence"] == ac.EVIDENCE["off_site"]
    # a Location that is not a web address is refused by the HTTP client itself
    assert (rows["JustFor.Fans"]["state"], rows["JustFor.Fans"]["found"]) == ("unknown", None)
    assert rows["xHamster"]["state"] == "found"                    # a subdomain of the same site is the same site
    urls = [u for _, u, _ in calls]
    assert not any("elsewhere.example" in u or "169.254" in u or "javascript" in u for u in urls)


def test_redirect_loops_end(monkeypatch):
    fake_sites(monkeypatch, {"pornhub.com": httpx.Response(302, headers={"location": "https://www.pornhub.com/users/torvalds"})})
    row = by_platform(run("torvalds"))["Pornhub"]
    assert (row["state"], row["evidence"]) == ("unknown", ac.EVIDENCE["failed"])


def test_only_the_first_300_kb_of_a_page_is_read(monkeypatch):
    marker = as_handle("chaturbate_found.html", "chaturbate", "torvalds")
    pulled = []

    class Body(httpx.AsyncByteStream):
        def __init__(self, parts):
            self.parts = parts

        async def __aiter__(self):
            for part in self.parts:
                pulled.append(len(part))
                yield part

    def big(request):
        return httpx.Response(200, stream=Body([b" " * 100_000] * 10 + [marker.encode()]))

    fake_sites(monkeypatch, {"chaturbate.com": big})
    row = by_platform(run("torvalds"))["Chaturbate"]
    assert row["state"] == "unknown" and row["evidence"] == ac.EVIDENCE["no_marker"]       # the marker sat past the cap
    assert sum(pulled) <= ac.MAX_BODY == 300_000


def test_found_and_not_found_are_cached_for_a_day_and_nothing_else_is(monkeypatch):
    calls = []
    fake_sites(monkeypatch, FULL_RUN, calls)
    first = by_platform(run("torvalds"))
    n = len(calls)
    second = by_platform(run("Torvalds"))                     # handles are not case sensitive
    for name in ("Fansly", "Pornhub", "xHamster", "Chaturbate", "JustFor.Fans"):
        assert second[name]["state"] == first[name]["state"]
    assert second["Fansly"]["display_name"] == "Sam Example" and second["Pornhub"]["url"] == "https://www.pornhub.com/users/Torvalds"
    again = [u for _, u, _ in calls[n:]]
    assert len(again) == 2 and all("fetlife" in u or "tinder" in u for u in again)       # blocked and unknown are asked again
    assert ac.CACHE_TTL == 24 * 3600
    # an entry past its time is dropped
    key = ("Pornhub", "torvalds")
    ac._cache[key] = (ac.time.time() - ac.CACHE_TTL - 1, ac._cache[key][1])
    assert ac._cache_get(key) is None and key not in ac._cache
    # no cached row holds anything but text metadata
    assert media_leaks([row for _, row in ac._cache.values()]) == []


def test_the_cache_is_bounded(monkeypatch):
    monkeypatch.setattr(ac, "CACHE_MAX", 3)
    for i in range(6):
        ac._cache_put(("Pornhub", f"user{i}"), {"state": "found"})
    assert len(ac._cache) == 3 and ("Pornhub", "user5") in ac._cache and ("Pornhub", "user0") not in ac._cache


# ---- the guard and the endpoint ----------------------------------------------------------

def no_network(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("a request was about to leave")
    monkeypatch.setattr(ac, "_client", boom)


def test_the_module_refuses_a_handle_that_suggests_a_minor_before_any_request(monkeypatch):
    no_network(monkeypatch)
    out = run("jake_13yo")
    assert out["results"] == [] and out["checked"] == 0 and out["error_code"] == "minor_guard"
    assert out["error_detail"] == adult_guard.REASONS["age"]
    # and for a clean handle whose profiles suggest a minor
    profile_record.note("river_stone", "github", {"found": True, "profile_url": "https://github.com/river_stone", "bio": "16 | junior in high school"})
    out = run("river_stone")
    assert out["results"] == [] and out["error_code"] == "minor_guard" and out["block_snippet"] == "16 | junior in high school"


def test_the_module_refuses_until_an_ordinary_source_has_run(monkeypatch):
    no_network(monkeypatch)
    monkeypatch.undo()
    no_network(monkeypatch)
    profile_record.clear()
    out = run("torvalds")
    assert out["results"] == [] and out["checked"] == 0 and out["error_code"] == "mainstream_first"


@pytest.mark.parametrize("handle", ["jake_13yo", "age14jay", "15yo_alex", "underage_x", "pr3teen", "13yo"])
def test_endpoint_answers_400_minor_guard_and_contacts_nothing(c, monkeypatch, handle):
    no_network(monkeypatch)
    r = c.post("/api/recon/adult-check", json={"username": handle})
    body = r.json()
    assert r.status_code == 400 and body["error_code"] == body["code"] == "minor_guard"
    assert body["error_detail"] == body["reason"] and body["reason"] in adult_guard.REASONS.values()
    assert body["detail"] == body["error"] == adult_guard.MESSAGE and handle not in json.dumps(body)


def test_endpoint_has_no_way_around_the_guard(c, monkeypatch):
    no_network(monkeypatch)
    for extra in ({"force": True}, {"override": True}, {"nsfw": True}, {"adult": True}, {"confirm_adult": True}):
        r = c.post("/api/recon/adult-check", json={"username": "jake_13yo", **extra}, headers={"X-Override": "1"})
        assert r.status_code == 400 and r.json()["error_code"] == "minor_guard"


def test_endpoint_runs_the_check_and_validates_the_handle(c, monkeypatch):
    fake_sites(monkeypatch, FULL_RUN)
    r = c.post("/api/recon/adult-check", json={"username": "@torvalds"})
    body = r.json()
    assert r.status_code == 200 and body["username"] == "torvalds" and body["total"] == 2 and len(body["results"]) == len(ac.RULES)
    assert media_leaks(body) == []
    no_network(monkeypatch)
    for bad in ("", "a b", "x/../y", "name?x=1", "--proxy", "a" * 65, "user@example.com"):
        assert c.post("/api/recon/adult-check", json={"username": bad}).status_code == 400, bad
    assert c.post("/api/recon/adult-check", json={}).status_code == 422
    assert c.get("/api/recon/adult-check").status_code == 405


def test_endpoint_is_rate_limited_like_platform_check(monkeypatch):
    monkeypatch.undo()
    assert match_limit("/api/recon/adult-check") == ("/api/recon/adult-check", 10, 60)
    assert match_limit("/api/recon/adult-check")[1:] == match_limit("/api/recon/platform-check")[1:]


def test_no_target_value_is_logged(c, monkeypatch, caplog):
    fake_sites(monkeypatch, FULL_RUN)
    with caplog.at_level("DEBUG"):
        run("torvalds")
        asyncio.run(ac.run_adult_check("jake_13yo"))
    assert "torvalds" not in caplog.text and "jake_13yo" not in caplog.text
    src = (Path(__file__).parent.parent / "modules" / "adult_check.py").read_text()
    assert "log." not in src and "print(" not in src
