"""Reddit and Discord rows of the platform check (modules/platform_check.py). No network.

Recorded on 2026-11-14: reddit_blocked.html, discord_taken.json, discord_free.json and
discord_invalid.json. Hand-written from the documented shapes, never recorded:
reddit_about_found.json, reddit_about_suspended.json, reddit_not_found.json, reddit_token.json
(Reddit refuses this path without credentials) and discord_rate_limited.json.
"""

import asyncio
import base64
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from main import app
from middleware.rate_limit import match_limit
from modules import platform_check as pc

FIX = Path(__file__).parent / "fixtures" / "platform"
REAL_ASYNC_CLIENT = httpx.AsyncClient
BLOCKED_TEXT = "Reddit refuses requests from servers, so this could not be checked automatically."
TAKEN_TEXT = "Discord's sign-up check says this handle is taken. Discord has no public profile page, so who holds it is unknown."


def fx(name: str) -> str:
    return (FIX / name).read_text(encoding="utf-8")


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    pc.clear_cache_for_tests()
    for k in ("REDDIT_CLIENT_ID", "REDDIT_CLIENT_SECRET", "REDDIT_USER_AGENT"):
        monkeypatch.delenv(k, raising=False)
    yield
    pc.clear_cache_for_tests()


def fake(monkeypatch, responder, calls=None):
    def handler(request: httpx.Request):
        if calls is not None:
            calls.append(request)
        return responder(request)

    monkeypatch.setattr(pc.httpx, "AsyncClient", lambda *a, **k: REAL_ASYNC_CLIENT(transport=httpx.MockTransport(handler), follow_redirects=True))


def json_resp(status, name):
    return httpx.Response(status, text=fx(name), headers={"content-type": "application/json"})


def run(username, only):
    return {r["platform"]: r for r in asyncio.run(pc.run_platform_check(username, only=only))["results"]}


# ---- Reddit, keyless ------------------------------------------------------------------------

def test_reddit_blocked_page_is_blocked_with_the_reason_and_the_link(monkeypatch):
    calls = []
    fake(monkeypatch, lambda r: httpx.Response(403, text=fx("reddit_blocked.html"), headers={"content-type": "text/html"}), calls)
    row = run("sam_example", ("Reddit",))["Reddit"]
    assert row["state"] == "blocked" and row["found"] is None
    assert row["evidence"] == BLOCKED_TEXT
    assert row["hint"] == "Open the link in a browser. A missing account shows 'nobody on Reddit goes by that name'."
    assert row["url"] == "https://www.reddit.com/user/sam_example" and row["public_url"] is True
    # one GET of about.json, as a browser navigation, and nothing else
    assert len(calls) == 1 and calls[0].method == "GET" and str(calls[0].url) == "https://www.reddit.com/user/sam_example/about.json"
    assert calls[0].headers["sec-fetch-mode"] == "navigate" and "authorization" not in calls[0].headers
    # blocked is not cached: the next run asks again
    run("sam_example", ("Reddit",))
    assert len(calls) == 2


def test_reddit_keyless_found_reads_the_documented_fields(monkeypatch):
    fake(monkeypatch, lambda r: json_resp(200, "reddit_about_found.json"))
    row = run("Sam_Example", ("Reddit",))["Reddit"]       # Reddit names are not case sensitive
    assert row["state"] == "found" and row["found"] is True
    assert row["display_name"] == "Sam Example" and row["bio"] == "Invented person for a test fixture. Maps and bread."
    assert row["created"] == "2015-01-01" and row["karma"] == 1354
    # the picture address is unescaped for the avatar comparison, which fetches it on the server
    assert row["avatar_url"].startswith("https://styles.redditmedia.com/") and "&amp;" not in row["avatar_url"] and "&height=256" in row["avatar_url"]
    assert "note" not in row and "hint" not in row


def test_reddit_json_that_names_another_account_is_unknown(monkeypatch):
    fake(monkeypatch, lambda r: json_resp(200, "reddit_about_found.json"))
    row = run("someone_else", ("Reddit",))["Reddit"]
    assert row["state"] == "unknown" and row["found"] is None


def test_reddit_keyless_404_body_is_not_found_and_cached(monkeypatch):
    calls = []
    fake(monkeypatch, lambda r: json_resp(404, "reddit_not_found.json"), calls)
    row = run("zq7xkv3mwp9tjh2r", ("Reddit",))["Reddit"]
    assert row["state"] == "not_found" and row["found"] is False and "nobody goes by that name" in row["evidence"]
    run("ZQ7xkv3mwp9tjh2r", ("Reddit",))
    assert len(calls) == 1


@pytest.mark.parametrize("status,ctype,body", [
    (429, "application/json", '{"message": "Too Many Requests", "error": 429}'),
    (403, "application/json", '{"message": "Forbidden", "error": 403}'),
    (200, "text/html; charset=utf-8", "<html><body>Please wait while we verify you are human</body></html>"),
    (200, "application/json", "<!doctype html><title>Just a moment</title>"),
    (404, "text/html", "<html>page not found</html>"),
])
def test_reddit_refusals_and_html_are_blocked_never_not_found(status, ctype, body):
    v = pc.classify_reddit("sam_example", status, ctype, body)
    assert v["state"] == "blocked" and v["evidence"] == BLOCKED_TEXT


def test_reddit_errors_are_unknown_with_a_code(monkeypatch):
    v = pc.classify_reddit("sam_example", 503, "application/json", "{}")
    assert v["state"] == "unknown" and v["error_code"] == "upstream"

    def boom(request):
        raise httpx.ConnectTimeout("timed out")
    fake(monkeypatch, boom)
    row = run("sam_example", ("Reddit",))["Reddit"]
    assert row["state"] == "unknown" and row["error_code"] == "timeout" and row["found"] is None
    assert "sam_example" not in row["evidence"]


@pytest.mark.parametrize("handle", ["ab", "first.last", "a" * 21])
def test_a_handle_reddit_cannot_hold_makes_no_request(monkeypatch, handle):
    calls = []
    fake(monkeypatch, lambda r: httpx.Response(500), calls)
    row = run(handle, ("Reddit",))["Reddit"]
    assert row["state"] == "not_found" and row["evidence"].startswith("Not a valid Reddit name") and calls == []


# ---- Reddit, with the optional credentials (written from the documentation, unrecorded) ------

def oauth_site(about, token=None, keyless=None, calls=None):
    def respond(request):
        if calls is not None:
            calls.append(request)
        url = str(request.url)
        if url == "https://www.reddit.com/api/v1/access_token":
            return token or json_resp(200, "reddit_token.json")
        if url.startswith("https://oauth.reddit.com/user/"):
            return about(request) if callable(about) else about
        return keyless or httpx.Response(403, text=fx("reddit_blocked.html"), headers={"content-type": "text/html"})
    return respond


def with_credentials(monkeypatch):
    monkeypatch.setenv("REDDIT_CLIENT_ID", "test-client")
    monkeypatch.setenv("REDDIT_CLIENT_SECRET", "test-secret")


def test_reddit_oauth_found_uses_basic_auth_then_the_bearer_token(monkeypatch):
    with_credentials(monkeypatch)
    calls = []
    fake(monkeypatch, oauth_site(json_resp(200, "reddit_about_found.json")), calls)
    row = run("sam_example", ("Reddit",))["Reddit"]
    assert row["state"] == "found" and row["display_name"] == "Sam Example" and row["karma"] == 1354
    token, about = calls
    assert token.method == "POST" and token.content == b"grant_type=client_credentials"
    assert token.headers["authorization"] == "Basic " + base64.b64encode(b"test-client:test-secret").decode()
    assert about.method == "GET" and str(about.url) == "https://oauth.reddit.com/user/sam_example/about"
    assert about.headers["authorization"] == "Bearer test-token-not-a-real-one"
    # a descriptive client name, not a browser's
    assert "crawlr" in about.headers["user-agent"].lower() and "Mozilla" not in about.headers["user-agent"]


def test_reddit_oauth_token_is_cached_until_it_expires(monkeypatch):
    with_credentials(monkeypatch)
    calls = []
    fake(monkeypatch, oauth_site(json_resp(404, "reddit_not_found.json")), calls)
    first = run("first_handle", ("Reddit",))["Reddit"]
    assert first["state"] == "not_found" and first["found"] is False
    # the API hides shadow-banned accounts behind the same 404, and the row says so
    assert first["hidden_possible"] is True
    assert first["evidence"] == "Reddit's API has no visible account with this name (a hidden or shadow-banned account looks the same)"
    assert run("second_handle", ("Reddit",))["Reddit"]["state"] == "not_found"
    urls = [str(c.url) for c in calls]
    assert urls.count("https://www.reddit.com/api/v1/access_token") == 1 and len(urls) == 3
    # once it has expired a new one is asked for
    pc._reddit_token["expires"] = 0
    run("third_handle", ("Reddit",))
    assert [str(c.url) for c in calls].count("https://www.reddit.com/api/v1/access_token") == 2


def test_reddit_oauth_suspended_account_is_found_with_a_note(monkeypatch):
    with_credentials(monkeypatch)
    fake(monkeypatch, oauth_site(json_resp(200, "reddit_about_suspended.json")))
    row = run("sam_example", ("Reddit",))["Reddit"]
    assert row["state"] == "found" and row["note"] == "suspended" and "suspended" in row["evidence"]
    assert row["display_name"] == "" and "avatar_url" not in row


@pytest.mark.parametrize("status", [401, 403, 429, 500])
def test_reddit_oauth_refusals_fall_back_to_the_keyless_request_and_are_never_not_found(monkeypatch, status):
    with_credentials(monkeypatch)
    calls = []
    fake(monkeypatch, oauth_site(httpx.Response(status, json={"message": "nope", "error": status})), calls)
    row = run("sam_example", ("Reddit",))["Reddit"]
    assert row["state"] == "blocked" and row["found"] is None
    assert str(calls[-1].url) == "https://www.reddit.com/user/sam_example/about.json" and "authorization" not in calls[-1].headers
    if status == 429:
        assert row["error_code"] == "rate_limited" and "rate limiting" in row["evidence"]
    else:
        assert row["evidence"] == BLOCKED_TEXT
    if status == 401:
        assert pc._reddit_token["value"] == ""       # a refused token is not reused


def test_reddit_oauth_falls_back_when_the_token_cannot_be_had(monkeypatch):
    with_credentials(monkeypatch)
    calls = []
    fake(monkeypatch, oauth_site(None, token=httpx.Response(401, json={"message": "Unauthorized", "error": 401}),
                                 keyless=json_resp(200, "reddit_about_found.json")), calls)
    row = run("sam_example", ("Reddit",))["Reddit"]
    assert row["state"] == "found"            # the keyless answer is used when it has one
    assert [str(c.url) for c in calls] == ["https://www.reddit.com/api/v1/access_token", "https://www.reddit.com/user/sam_example/about.json"]


def test_a_refused_token_request_is_not_repeated_on_every_lookup(monkeypatch):
    with_credentials(monkeypatch)
    calls = []
    fake(monkeypatch, oauth_site(None, token=httpx.Response(401, json={"message": "Unauthorized", "error": 401})), calls)
    for handle in ("first_handle", "second_handle", "third_handle"):
        assert run(handle, ("Reddit",))["Reddit"]["state"] == "blocked"
    urls = [str(c.url) for c in calls]
    assert urls.count("https://www.reddit.com/api/v1/access_token") == 1 and len(urls) == 4
    # after a few minutes it is tried again
    pc._reddit_token["retry_at"] = 0
    run("fourth_handle", ("Reddit",))
    assert [str(c.url) for c in calls].count("https://www.reddit.com/api/v1/access_token") == 2


def test_the_keyless_404_makes_no_claim_about_hidden_accounts(monkeypatch):
    fake(monkeypatch, lambda r: json_resp(404, "reddit_not_found.json"))
    row = run("zq7xkv3mwp9tjh2r", ("Reddit",))["Reddit"]
    assert row["state"] == "not_found" and "hidden_possible" not in row


def test_reddit_oauth_network_failure_falls_back(monkeypatch):
    with_credentials(monkeypatch)

    def about(request):
        raise httpx.ConnectError("refused")
    fake(monkeypatch, oauth_site(about))
    assert run("sam_example", ("Reddit",))["Reddit"]["state"] == "blocked"


def test_no_credentials_means_no_token_request(monkeypatch):
    monkeypatch.setenv("REDDIT_CLIENT_ID", "only-half")
    calls = []
    fake(monkeypatch, oauth_site(httpx.Response(500)), calls)
    run("sam_example", ("Reddit",))
    assert [str(c.url) for c in calls] == ["https://www.reddit.com/user/sam_example/about.json"]


# ---- Discord ---------------------------------------------------------------------------------

def test_discord_taken_is_its_own_state_and_never_found(monkeypatch):
    calls = []
    fake(monkeypatch, lambda r: json_resp(200, "discord_taken.json"), calls)
    row = run("Sam_Example", ("Discord",))["Discord"]
    assert row["state"] == "taken" and row["found"] is None and row["evidence"] == TAKEN_TEXT
    assert row["url"] == "" and row["public_url"] is False and row["display_name"] == "" and row["hint"].startswith("Discord has no public profile page")
    # one POST with the handle in lowercase
    assert len(calls) == 1 and calls[0].method == "POST" and calls[0].content == b'{"username":"sam_example"}'
    assert str(calls[0].url) == "https://discord.com/api/v9/unique-username/username-attempt-unauthed"
    # cached for the day, whatever the case
    run("sam_example", ("Discord",))
    assert len(calls) == 1
    out = asyncio.run(pc.run_platform_check("sam_example", only=("Discord",)))
    assert out["total"] == 0        # nothing was read


def test_discord_free_is_not_found(monkeypatch):
    fake(monkeypatch, lambda r: json_resp(200, "discord_free.json"))
    row = run("zq7xkv3mwp9tjh2rnb5ycd8f", ("Discord",))["Discord"]
    assert row["state"] == "not_found" and row["found"] is False and "free" in row["evidence"]


def test_discord_refusing_the_handle_is_not_found_and_says_why(monkeypatch):
    fake(monkeypatch, lambda r: json_resp(400, "discord_invalid.json"))
    row = run("discordfan", ("Discord",))["Discord"]
    assert row["state"] == "not_found" and row["evidence"].startswith("Discord does not allow this handle")
    # the site's own message is not passed on
    assert "cannot contain" not in row["evidence"]


@pytest.mark.parametrize("status", [429, 200])
def test_discord_rate_limit_is_blocked_never_not_found(monkeypatch, status):
    calls = []
    fake(monkeypatch, lambda r: json_resp(status, "discord_rate_limited.json"), calls)
    row = run("sam_example", ("Discord",))["Discord"]
    assert row["state"] == "blocked" and row["found"] is None and row["error_code"] == "rate_limited"
    run("sam_example", ("Discord",))
    assert len(calls) == 2          # not cached


@pytest.mark.parametrize("status,body,state", [
    (403, "<html>Access denied</html>", "blocked"),
    (500, "oops", "unknown"),
    (200, "{}", "unknown"),
    (200, '{"taken": "yes"}', "unknown"),
    (400, '{"code": 50109, "message": "The request body contains invalid JSON."}', "unknown"),
])
def test_discord_anything_else_is_unknown_or_blocked(status, body, state):
    v = pc.classify_discord(status, body)
    assert v["state"] == state


@pytest.mark.parametrize("handle", ["a", "john-smith", "x" * 33])
def test_a_handle_discord_cannot_hold_makes_no_request(monkeypatch, handle):
    calls = []
    fake(monkeypatch, lambda r: httpx.Response(500), calls)
    row = run(handle, ("Discord",))["Discord"]
    assert row["state"] == "not_found" and row["evidence"].startswith("Not a valid Discord handle") and calls == []


def test_discord_network_failure_is_unknown(monkeypatch):
    def boom(request):
        raise httpx.ConnectError("refused")
    fake(monkeypatch, boom)
    row = run("sam_example", ("Discord",))["Discord"]
    assert row["state"] == "unknown" and row["error_code"] == "unreachable"


# ---- both, through the endpoint ---------------------------------------------------------------

def test_both_rows_are_in_every_run_even_when_a_tool_listed_them(monkeypatch):
    def respond(request):
        host = request.url.host
        if host == "discord.com":
            return json_resp(200, "discord_taken.json")
        if host == "www.reddit.com":
            return httpx.Response(403, text=fx("reddit_blocked.html"), headers={"content-type": "text/html"})
        return httpx.Response(200, text="")
    fake(monkeypatch, respond)
    with TestClient(app) as c:
        r = c.post("/api/recon/platform-check", json={"username": "sam_example", "sherlock_sites": ["Reddit", "Discord", "Facebook"]})
    rows = {x["platform"]: x for x in r.json()["results"]}
    assert rows["Reddit"]["state"] == "blocked" and rows["Discord"]["state"] == "taken" and "Facebook" not in rows
    assert match_limit("/api/recon/platform-check")[1:] == (10, 60)


def test_settings_are_documented():
    env = (Path(__file__).parent.parent / ".env.example").read_text(encoding="utf-8")
    assert "REDDIT_CLIENT_ID=" in env and "REDDIT_CLIENT_SECRET=" in env
