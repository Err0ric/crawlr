"""Handle probe (modules/handle_probe.py): one similar handle, on a click. No network.

GitHub, the platform pages, Reddit, Discord and Bluesky are answered by mock transports from
the recorded fixtures; the picture hashing is replaced by a recorder, so the test can see which
picture addresses the server would fetch and that none of them reaches the answer.
"""

import asyncio
import json
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from core.adult_sites import is_adult_site
from main import app
from middleware.rate_limit import match_limit
from modules import avatar_hash as ah
from modules import github as gh
from modules import handle_probe as hp
from modules import platform_check as pc

FIX = Path(__file__).parent / "fixtures"
REAL_ASYNC_CLIENT = httpx.AsyncClient
THUMB = "data:image/webp;base64,UklGRhIAAABXRUJQVlA4TAYAAAAvQWxvAGs="
GH_USER = {"login": "samexample", "name": "Sam Example", "bio": "Maps and bread", "location": "Lisbon", "blog": "https://sam.example.org",
           "twitter_username": "sam_example", "followers": 12, "public_repos": 3, "html_url": "https://github.com/samexample",
           "avatar_url": "https://avatars.githubusercontent.com/u/1?v=4", "created_at": "2015-01-01T00:00:00Z"}


def fx(*parts: str) -> str:
    # The Bluesky fixture's handle has a hyphen, which Discord does not allow; the probe tests
    # use one handle that every source can hold.
    return FIX.joinpath(*parts).read_text(encoding="utf-8").replace("sam-example.bsky.social", "samexample.bsky.social")


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    for m in (hp, pc, gh, ah):
        m.clear_cache_for_tests()
    for k in ("REDDIT_CLIENT_ID", "REDDIT_CLIENT_SECRET", "GITHUB_TOKEN"):
        monkeypatch.delenv(k, raising=False)
    yield
    for m in (hp, pc, gh, ah):
        m.clear_cache_for_tests()


def world(monkeypatch, pages: dict, calls: list, pictures: list):
    """pages: {"host/path-fragment": httpx.Response | Exception}. Anything else answers 200 with an empty body."""
    def handler(request: httpx.Request):
        calls.append(request)
        url = str(request.url)
        for needle, answer in pages.items():
            if needle in url:
                if isinstance(answer, Exception):
                    raise answer
                return answer
        return httpx.Response(200, text="")

    client = lambda *a, **k: REAL_ASYNC_CLIENT(transport=httpx.MockTransport(handler), follow_redirects=True)
    for m in (hp, pc, gh):
        monkeypatch.setattr(m.httpx, "AsyncClient", client)

    async def fake_hash(images):
        pictures.extend(i["url"] for i in images)
        return {"results": [{"id": i["id"], "hash": "0f1e2d3c4b5a6978", "default": "default" in i["url"], **({} if "default" in i["url"] else {"thumb": THUMB})} for i in images]}
    monkeypatch.setattr(hp, "run_avatar_hash", fake_hash)


def j(status, body):
    return httpx.Response(status, text=body if isinstance(body, str) else json.dumps(body), headers={"content-type": "application/json"})


def typical():
    return {
        "api.github.com/users/samexample": j(200, GH_USER),
        "instagram.com/samexample": httpx.Response(200, text=fx("platform", "instagram_found.html").replace("torvalds", "samexample")),
        "instagram.com/instagram/": httpx.Response(200, text=fx("platform", "instagram_found.html").replace("torvalds", "instagram")),
        "x.com/samexample": httpx.Response(404, text=fx("platform", "x_not_found.html")),
        "x.com/x": httpx.Response(200, text=fx("platform", "x_found.html").replace("torvalds", "x")),
        "threads.com": httpx.Response(200, text=fx("platform", "threads_login_wall.html")),
        "tiktok.com": httpx.ConnectTimeout("timed out"),
        "facebook.com": httpx.Response(200, text=fx("platform", "facebook_unavailable.html")),
        "reddit.com": httpx.Response(403, text=fx("platform", "reddit_blocked.html"), headers={"content-type": "text/html"}),
        "discord.com": j(200, fx("platform", "discord_taken.json")),
        "public.api.bsky.app": j(200, fx("probe", "bluesky_profile.json")),
    }


def probe(username="samexample"):
    return asyncio.run(hp.run_handle_probe(username))


def test_every_source_keeps_its_own_state(monkeypatch):
    calls, pictures = [], []
    world(monkeypatch, typical(), calls, pictures)
    out = probe()
    assert out["username"] == "samexample" and out["cached"] is False
    assert out["sources"] == {
        "GitHub": "found", "Facebook": "unknown", "Instagram": "found", "X": "not_found", "Threads": "blocked",
        "TikTok": "unknown", "Reddit": "blocked", "Discord": "taken", "Bluesky": "found"}
    assert list(out["sources"]) == list(hp.SOURCES) and "LinkedIn" not in out["sources"]
    # only a profile that was read is a profile: Discord's taken handle is a source state and nothing more
    assert [p["site"] for p in out["profiles"]] == ["GitHub", "Instagram", "Bluesky"]
    g, i, b = out["profiles"]
    assert g == {"site": "GitHub", "url": "https://github.com/samexample", "state": "found", "name": "Sam Example", "bio": "Maps and bread",
                 "location": "Lisbon", "created": "2015-01-01T00:00:00Z", "followers": 12, "note": "",
                 "links": ["https://sam.example.org", "https://x.com/sam_example"],
                 "avatar_hash": "0f1e2d3c4b5a6978", "avatar_default": False, "thumb": THUMB, "avatar_state": "ok"}
    assert i["name"] == "Sam Example" and i["avatar_hash"] == "" and i["thumb"] == "" and i["followers"] is None
    assert i["avatar_state"] == "none"       # the page gives no picture address: none, which is not "failed"
    assert b["url"] == "https://bsky.app/profile/samexample.bsky.social" and b["name"] == "Sam Example" and b["followers"] == 10
    assert b["bio"] == "Invented person for a test fixture. Maps and bread." and b["created"].startswith("2024-08-30")


def test_pictures_are_hashed_on_the_server_and_no_picture_address_is_returned(monkeypatch):
    calls, pictures = [], []
    world(monkeypatch, typical(), calls, pictures)
    out = probe()
    assert pictures == ["https://avatars.githubusercontent.com/u/1?v=4",
                        "https://cdn.bsky.app/img/avatar/plain/did:plc:aaaaaaaaaaaaaaaaaaaaaaaa/bafkreiaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]
    text = json.dumps(out)
    assert "avatar_url" not in text and "_avatar" not in text and "avatars.githubusercontent.com" not in text and "cdn.bsky.app" not in text
    for p in out["profiles"]:
        assert set(p) == {"site", "url", "state", "name", "bio", "location", "created", "followers", "note", "links", "avatar_hash", "avatar_default", "thumb", "avatar_state"}


def test_a_placeholder_picture_is_flagged_and_gets_no_thumbnail(monkeypatch):
    pages = typical()
    pages["api.github.com/users/samexample"] = j(200, {**GH_USER, "avatar_url": "https://example.org/default-avatar.png"})
    world(monkeypatch, pages, [], [])
    g = probe()["profiles"][0]
    assert g["avatar_default"] is True and g["thumb"] == "" and g["avatar_hash"] and g["avatar_state"] == "default"


def settled_pages():
    blocked = httpx.Response(403, text="")
    return {"api.github.com": j(200, GH_USER), "public.api.bsky.app": j(400, fx("probe", "bluesky_not_found.json")),
            "discord.com": j(200, fx("platform", "discord_free.json")), "reddit.com": blocked, "instagram.com": blocked, "x.com": blocked,
            "threads.com": blocked, "tiktok.com": blocked, "facebook.com": blocked}


@pytest.mark.parametrize("how", ["raises", "image_error"])
def test_a_picture_that_could_not_be_read_is_failed_not_missing_and_is_not_kept_for_a_day(monkeypatch, how):
    world(monkeypatch, settled_pages(), [], [])

    async def broken(images):
        if how == "raises":
            raise RuntimeError("decoder blew up")
        return {"results": [{"id": i["id"], "error": "The image could not be read.", "error_code": "bad_response"} for i in images]}
    monkeypatch.setattr(hp, "run_avatar_hash", broken)
    out = probe()
    g = out["profiles"][0]
    assert g["site"] == "GitHub" and g["avatar_hash"] == "" and g["thumb"] == "" and g["avatar_state"] == "failed"
    # every source settled, but the picture did not: asked again soon, never cached for the day
    assert set(out["sources"].values()) <= {"found", "not_found", "blocked"}
    assert 0 < hp._cache["samexample"][0] - __import__("time").time() <= hp.CACHE_TTL_PARTIAL


def test_only_the_fixed_sources_are_asked_and_never_an_adult_site(monkeypatch):
    calls, pictures = [], []
    world(monkeypatch, typical(), calls, pictures)
    probe()
    hosts = sorted({c.url.host for c in calls})
    assert hosts == ["api.github.com", "discord.com", "public.api.bsky.app", "www.facebook.com", "www.instagram.com",
                     "www.reddit.com", "www.threads.com", "www.tiktok.com", "x.com"]
    assert not any(is_adult_site(url=str(c.url)) for c in calls) and not any(is_adult_site(url=u) for u in pictures)
    assert "linkedin" not in " ".join(hosts)
    # one request per source, plus the canaries of the two sites that showed a not-found page
    per_host = {h: sum(c.url.host == h for c in calls) for h in hosts}
    assert per_host == {"api.github.com": 1, "discord.com": 1, "public.api.bsky.app": 1, "www.facebook.com": 1, "www.instagram.com": 1,
                        "www.reddit.com": 1, "www.threads.com": 1, "www.tiktok.com": 1, "x.com": 2}
    bsky = [c for c in calls if c.url.host == "public.api.bsky.app"][0]
    assert bsky.method == "GET" and bsky.url.params["actor"] == "samexample.bsky.social" and "authorization" not in bsky.headers


def test_sherlock_and_maigret_are_not_part_of_it():
    src = Path(hp.__file__).read_text(encoding="utf-8")
    assert "import" in src and "run_sherlock" not in src and "run_maigret" not in src and "adult_check" not in src


def test_not_found_everywhere_is_not_found_not_failed(monkeypatch):
    pages = {
        "api.github.com": j(404, {"message": "Not Found"}),
        "public.api.bsky.app": j(400, fx("probe", "bluesky_not_found.json")),
        "discord.com": j(200, fx("platform", "discord_free.json")),
        "reddit.com": j(404, fx("platform", "reddit_not_found.json")),
    }
    world(monkeypatch, pages, [], [])
    out = probe("zq7xkv3mwp9tjh2r")
    assert out["profiles"] == []
    assert out["sources"]["GitHub"] == "not_found" and out["sources"]["Bluesky"] == "not_found"
    assert out["sources"]["Discord"] == "not_found" and out["sources"]["Reddit"] == "not_found"
    # a bare 200 from a profile page proves nothing
    assert out["sources"]["Instagram"] == "unknown"


def test_rate_limits_and_failures_are_their_own_states(monkeypatch):
    pages = typical()
    pages["api.github.com/users/samexample"] = httpx.Response(403, json={"message": "API rate limit exceeded"}, headers={"x-ratelimit-remaining": "0"})
    pages["public.api.bsky.app"] = httpx.ConnectError("refused")
    pages["discord.com"] = j(429, fx("platform", "discord_rate_limited.json"))
    world(monkeypatch, pages, [], [])
    out = probe()
    assert out["sources"]["GitHub"] == "rate_limited" and out["sources"]["Bluesky"] == "failed" and out["sources"]["Discord"] == "rate_limited"
    assert [p["site"] for p in out["profiles"]] == ["Instagram"]


@pytest.mark.parametrize("handle", ["sam_example", "sam.example", "ab", "a" * 19, "-sam", "sam-"])
def test_bluesky_is_not_asked_for_a_name_it_cannot_hold(monkeypatch, handle):
    calls = []
    world(monkeypatch, {}, calls, [])
    out = probe(handle)
    assert out["sources"]["Bluesky"] == "not_asked" and not any(c.url.host == "public.api.bsky.app" for c in calls)


def test_bluesky_answer_for_another_handle_is_not_a_profile(monkeypatch):
    world(monkeypatch, {"public.api.bsky.app": j(200, fx("probe", "bluesky_profile.json"))}, [], [])
    out = probe("someone-else")
    assert out["sources"]["Bluesky"] == "unknown" and out["profiles"] == []


def test_the_answer_is_cached_for_a_day_per_handle(monkeypatch):
    pages = {
        "api.github.com": j(200, GH_USER), "public.api.bsky.app": j(400, fx("probe", "bluesky_not_found.json")),
        "discord.com": j(200, fx("platform", "discord_free.json")), "reddit.com": httpx.Response(403, text=fx("platform", "reddit_blocked.html"), headers={"content-type": "text/html"}),
        "instagram.com": httpx.Response(403, text=""), "x.com": httpx.Response(403, text=""),
        "threads.com": httpx.Response(200, text=fx("platform", "threads_login_wall.html")), "tiktok.com": httpx.Response(403, text=""), "facebook.com": httpx.Response(403, text=""),
    }
    calls = []
    world(monkeypatch, pages, calls, [])
    first = probe("SamExample")
    assert first["cached"] is False and set(first["sources"].values()) <= {"found", "not_found", "blocked"}
    n = len(calls)
    second = probe("samexample")
    assert second["cached"] is True and len(calls) == n and second["profiles"] == first["profiles"] and second["username"] == "samexample"
    assert hp._cache["samexample"][0] - __import__("time").time() > 23 * 3600


def test_an_answer_with_a_failed_source_is_kept_only_briefly(monkeypatch):
    world(monkeypatch, typical(), [], [])     # TikTok timed out
    probe()
    assert 0 < hp._cache["samexample"][0] - __import__("time").time() <= hp.CACHE_TTL_PARTIAL


def test_the_cache_is_bounded(monkeypatch):
    monkeypatch.setattr(hp, "CACHE_MAX", 3)
    for i in range(6):
        hp._cache_put(f"h{i}", {"profiles": []}, 60)
    assert list(hp._cache) == ["h3", "h4", "h5"]


def test_endpoint_validates_and_is_rate_limited(monkeypatch):
    calls = []
    world(monkeypatch, typical(), calls, [])
    with TestClient(app) as c:
        for bad in ("", "a b", "x" * 65, "-rf", "../etc", "a/b", "name@example.org"):
            assert c.post("/api/recon/handle-probe", json={"username": bad}).status_code == 400, bad
        assert calls == []
        assert c.post("/api/recon/handle-probe", json={}).status_code == 422
        r = c.post("/api/recon/handle-probe", json={"username": "@samexample"})
    assert r.status_code == 200 and r.json()["username"] == "samexample" and r.json()["sources"]["Discord"] == "taken"
    assert match_limit("/api/recon/handle-probe") == ("/api/recon/handle-probe", 10, 60)


def test_nothing_about_the_handle_is_logged(monkeypatch, caplog):
    pages = typical()
    pages["public.api.bsky.app"] = httpx.ConnectError("refused for samexample")
    world(monkeypatch, pages, [], [])
    with caplog.at_level("DEBUG"):
        probe()
    assert caplog.records and not any("samexample" in (r.getMessage() + json.dumps({k: str(v) for k, v in r.__dict__.items()})) for r in caplog.records)
