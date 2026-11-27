"""Profile sources (modules/profiles): keyless public APIs, asked at once. No network.

Every host is answered by one mock transport from tests/fixtures/profiles (recorded once, then
every person in them replaced by an invented one). The picture hashing is replaced by a
recorder, so a test can see which picture addresses the server would fetch and that none of them
reaches the answer.
"""

import asyncio
import json
import re
import time
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from core import adult_guard, profile_record
from core.adult_sites import is_adult_site
from main import app
from middleware.rate_limit import match_limit
from modules import profiles as pf
from modules.profiles import base, keybase, mastodon

FIX = Path(__file__).parent / "fixtures"
REAL_ASYNC_CLIENT = httpx.AsyncClient
THUMB = "data:image/webp;base64,UklGRhIAAABXRUJQVlA4TAYAAAAvQWxvAGs="
H = "samexample"
ALL = [s.ID for s in pf.SOURCES]
HOSTS = {
    "gitlab": "gitlab.com", "keybase": "keybase.io", "hackernews": "hacker-news.firebaseio.com", "mastodon": "mastodon.social",
    "dockerhub": "hub.docker.com", "npm": "registry.npmjs.org", "devto": "dev.to", "lichess": "lichess.org", "chesscom": "api.chess.com",
    "codeberg": "codeberg.org", "bluesky": "public.api.bsky.app", "wikipedia": "en.wikipedia.org", "gravatar": "api.gravatar.com",
    "codeforces": "codeforces.com", "lobsters": "lobste.rs", "huggingface": "huggingface.co",
    "launchpad": "api.launchpad.net", "gitea": "gitea.com",
    # one source per Mastodon instance: the list is mastodon.INSTANCES and nowhere else
    **{s.ID: s.HOST for s in mastodon.SOURCES},
}
OTHER_INSTANCES = [s for s in mastodon.SOURCES if s.ID != "mastodon"]
N = len(ALL)
PICTURE_HOSTS = ("gitlab.com/uploads", "amazonaws.com", "files.mastodon.social", "gravatar.com/avatar", "media2.dev.to", "chesscomfiles.com",
                 "codeberg.org/avatars", "gitea.com/avatars", *(f"files.{s.HOST}" for s in OTHER_INSTANCES), "cdn.bsky.app", "userpic.codeforces.org", "lobste.rs/avatars", "cdn-avatars.huggingface.co")


def fx(name: str) -> str:
    return (FIX / "profiles" / name).read_text(encoding="utf-8")


def bsky(name: str) -> str:
    return (FIX / "probe" / name).read_text(encoding="utf-8").replace("sam-example.bsky.social", f"{H}.bsky.social")


def masto(host: str) -> str:
    """The recorded mastodon.social account as another instance would answer it."""
    return fx("mastodon_found.json").replace("mastodon.social", host)


def j(status, body, **headers):
    return httpx.Response(status, text=body if isinstance(body, str) else json.dumps(body), headers={"content-type": "application/json", **headers})


def found():
    """Every source has the account. Keys are "host/path fragment"; the longest match answers."""
    return {
        "gitlab.com/api/v4/users": j(200, fx("gitlab_found.json")),
        "keybase.io/_/api/1.0/user/lookup.json": j(200, fx("keybase_found.json")),
        "hacker-news.firebaseio.com/v0/user/samexample/created.json": j(200, "1187454947"),
        "hacker-news.firebaseio.com/v0/user/samexample/karma.json": j(200, "4423"),
        "hacker-news.firebaseio.com/v0/user/samexample/about.json": j(200, fx("hackernews_about.json")),
        "mastodon.social/api/v1/accounts/lookup": j(200, fx("mastodon_found.json")),
        "hub.docker.com/v2/users/samexample/": j(200, fx("dockerhub_user.json")),
        "registry.npmjs.org/-/v1/search": j(200, fx("npm_found.json")),
        "dev.to/api/users/by_username": j(200, fx("devto_found.json")),
        "lichess.org/api/user/samexample": j(200, fx("lichess_found.json")),
        "api.chess.com/pub/player/samexample": j(200, fx("chesscom_found.json")),
        "codeberg.org/api/v1/users/samexample": j(200, fx("codeberg_found.json")),
        "public.api.bsky.app/xrpc/app.bsky.actor.getProfile": j(200, bsky("bluesky_profile.json")),
        "en.wikipedia.org/w/api.php": j(200, fx("wikipedia_found.json")),
        "api.gravatar.com/v3/profiles/samexample": j(200, fx("gravatar_found.json")),
        "codeforces.com/api/user.info": j(200, fx("codeforces_found.json")),
        "lobste.rs/~samexample.json": j(200, fx("lobsters_found.json")),
        "huggingface.co/api/users/samexample/overview": j(200, fx("huggingface_found.json")),
        "api.launchpad.net/1.0/~samexample": j(200, fx("launchpad_found.json")),
        "gitea.com/api/v1/users/samexample": j(200, fx("gitea_found.json")),
        **{f"{s.HOST}/api/v1/accounts/lookup": j(200, masto(s.HOST)) for s in OTHER_INSTANCES},
    }


def absent():
    """Each API's own answer that there is no such account."""
    return {
        "gitlab": j(200, fx("gitlab_not_found.json")), "keybase": j(200, fx("keybase_not_found.json")), "hackernews": j(200, "null"),
        "mastodon": j(404, fx("mastodon_not_found.json")), "dockerhub": j(404, fx("dockerhub_not_found.json")),
        "devto": j(404, fx("devto_not_found.json")), "lichess": j(404, fx("lichess_not_found.json")),
        "chesscom": j(404, fx("chesscom_not_found.json")), "codeberg": j(404, fx("codeberg_not_found.json")),
        "bluesky": j(400, bsky("bluesky_not_found.json")), "wikipedia": j(200, fx("wikipedia_missing.json")),
        "gravatar": j(404, fx("gravatar_not_found.json")), "codeforces": j(400, fx("codeforces_not_found.json")),
        "lobsters": httpx.Response(404, text=fx("lobsters_not_found.html"), headers={"content-type": "text/html; charset=utf-8"}),
        "huggingface": j(404, fx("huggingface_not_found.json")),
        "launchpad": httpx.Response(404, text=fx("launchpad_not_found.txt"), headers={"content-type": "text/plain;charset=utf-8"}),
        "gitea": j(404, fx("gitea_not_found.json")),
        **{s.ID: j(404, fx("mastodon_not_found.json")) for s in OTHER_INSTANCES},
    }


def with_source(source: str, answer) -> dict:
    """Everything found, except that one source's host answers `answer` on every path."""
    pages = {k: v for k, v in found().items() if not k.startswith(HOSTS[source] + "/")}
    pages[HOSTS[source] + "/"] = answer
    return pages


def world(monkeypatch, pages: dict, calls: list | None = None, pictures: list | None = None):
    calls = [] if calls is None else calls
    pictures = [] if pictures is None else pictures

    def handler(request: httpx.Request):
        calls.append(request)
        url = f"{request.url.host}{request.url.path}"
        best = max((n for n in pages if url.startswith(n)), key=len, default=None)
        if best is None:
            return httpx.Response(599, text="no fixture for this address")
        answer = pages[best]
        if isinstance(answer, Exception):
            raise answer
        return answer

    monkeypatch.setattr(pf.httpx, "AsyncClient", lambda *a, **k: REAL_ASYNC_CLIENT(transport=httpx.MockTransport(handler), follow_redirects=True))

    async def fake_hash(images):
        pictures.extend(i["url"] for i in images)
        return {"results": [{"id": i["id"], "hash": "0f1e2d3c4b5a6978", "default": False, "thumb": THUMB} for i in images]}
    monkeypatch.setattr(pf, "run_avatar_hash", fake_hash)
    return calls, pictures


@pytest.fixture(autouse=True)
def _clean():
    pf.clear_cache_for_tests()
    profile_record.clear()
    yield
    pf.clear_cache_for_tests()
    profile_record.clear()


def run(username=H):
    return asyncio.run(pf.run_profiles(username))


def ttl(source: str, handle: str = H) -> float:
    """Seconds one source's answer for one handle is still kept."""
    return pf._cache[(source, handle)][0] - time.time()


def by_source(out) -> dict:
    return {p["source"]: p for p in out["profiles"]}


# ---- the registry ------------------------------------------------------------------------

def test_the_registry_is_one_module_per_source_with_a_fixed_host_and_no_adult_site():
    assert len(ALL) == len(set(ALL)) == 25 and set(ALL) == set(HOSTS)
    assert len({s.SITE for s in pf.SOURCES}) == 25 and len(set(HOSTS.values())) == 25
    package = Path(pf.__file__).parent
    for src in pf.SOURCES:
        # one file per source, except that every Mastodon instance is read by mastodon.py
        name = "mastodon" if src in mastodon.SOURCES else src.ID
        assert (package / f"{name}.py").is_file() and src.SITE and src.HANDLE_RE.pattern.startswith("^")
        text = (package / f"{name}.py").read_text(encoding="utf-8")
        code = text.split('"""', 2)[2]                                                    # the code, not the docstring
        hosts = set(re.findall(r"https://([a-z0-9.-]+\.[a-z]+)", code)) | {HOSTS[src.ID]}
        assert f'"{HOSTS[src.ID]}' in code or f"//{HOSTS[src.ID]}" in code, src.ID
        assert not is_adult_site(src.SITE) and not any(is_adult_site(url=f"https://{h}/") for h in hosts)
        assert asyncio.iscoroutinefunction(src.read)
    assert "scratch" not in " ".join(ALL)


def test_no_em_dash_and_no_exception_text_in_the_package():
    for path in [*Path(pf.__file__).parent.glob("*.py"), Path(__file__)]:
        text = path.read_text(encoding="utf-8")
        assert "\u2014" not in text and "\u2013" not in text, path.name
        if path != Path(__file__):
            assert "str(e)" not in text and "str(exc" not in text and "run_sherlock" not in text and "run_maigret" not in text


# ---- found -------------------------------------------------------------------------------

def test_every_source_reads_its_profile(monkeypatch):
    calls, pictures = world(monkeypatch, found())
    out = run()
    assert out["username"] == H and out["cached"] is False
    assert list(out["sources"]) == ALL and all(e["state"] == "found" for e in out["sources"].values())
    assert {e["site"] for e in out["sources"].values()} == {s.SITE for s in pf.SOURCES}
    assert [p["source"] for p in out["profiles"]] == ALL
    p = by_source(out)
    keys = {"site", "source", "handle", "url", "state", "display_name", "name", "bio", "location", "company", "website", "links", "emails",
            "created", "last_active", "accounts", "stats", "followers", "items", "note", "avatar_hash", "avatar_default", "thumb", "avatar_state"}
    for row in out["profiles"]:
        assert set(row) - {"guard"} == keys and row["state"] == "found" and row["name"] == row["display_name"], row["source"]
        assert all(isinstance(v, int) and not isinstance(v, bool) for v in row["stats"].values())
        assert row["followers"] == row["stats"].get("followers")

    # the handle as the site spells it, and an address built from it
    assert {s: (r["handle"], r["url"]) for s, r in p.items()} == {
        "gitlab": ("SamExample", "https://gitlab.com/SamExample"),
        "keybase": (H, "https://keybase.io/samexample"),
        "hackernews": (H, "https://news.ycombinator.com/user?id=samexample"),
        "mastodon": ("SamExample", "https://mastodon.social/@SamExample"),
        "dockerhub": (H, "https://hub.docker.com/u/samexample"),
        "npm": (H, "https://www.npmjs.com/~samexample"),
        "devto": (H, "https://dev.to/samexample"),
        "lichess": ("SamExample", "https://lichess.org/@/SamExample"),
        "chesscom": (H, "https://www.chess.com/member/samexample"),
        "codeberg": (H, "https://codeberg.org/samexample"),
        "bluesky": ("samexample.bsky.social", "https://bsky.app/profile/samexample.bsky.social"),
        "wikipedia": ("Samexample", "https://en.wikipedia.org/wiki/Special:Contributions/Samexample"),
        "gravatar": (H, "https://gravatar.com/samexample"),
        "codeforces": ("SamExample", "https://codeforces.com/profile/SamExample"),
        "lobsters": (H, "https://lobste.rs/~samexample"),
        "huggingface": ("SamExample", "https://huggingface.co/SamExample"),
        "launchpad": (H, "https://launchpad.net/~samexample"),
        "gitea": (H, "https://gitea.com/samexample"),
        **{s.ID: ("SamExample", f"https://{s.HOST}/@SamExample") for s in OTHER_INSTANCES},
    }
    g = p["gitlab"]
    assert g["display_name"] == "Sam Example" and g["emails"] == ["sam@example.org"] and g["note"] == ""
    d = p["dockerhub"]
    assert (d["display_name"], d["location"], d["company"], d["website"], d["created"]) == ("Sam Example", "Lisbon", "Example Maps", "http://sam.example.org/", "2014-05-02T16:11:11Z")
    assert d["links"] == ["http://sam.example.org/"] and d["note"] == ""
    n = p["npm"]
    assert n["emails"] == ["sam@example.org", "sam.work@example.com"] and n["stats"] == {"packages": 3} and n["last_active"] == "2026-11-19T07:47:40Z"
    assert n["items"] == [{"name": "map-tiles", "url": "https://www.npmjs.com/package/map-tiles", "kind": "package"},
                          {"name": "@samexample/bread", "url": "https://www.npmjs.com/package/@samexample/bread", "kind": "package"}]
    t = p["devto"]
    assert t["created"] == "2015-12-27" and t["bio"].startswith("Maps and bread") and t["website"] == "http://sam.example.org"
    assert t["accounts"] == [{"site": "GitHub", "handle": H, "url": "https://github.com/samexample", "proof": "listed"},
                             {"site": "X", "handle": "sam_example", "url": "https://x.com/sam_example", "proof": "listed"}]
    li = p["lichess"]
    assert (li["display_name"], li["location"], li["created"], li["last_active"]) == ("Sam Example", "Lisbon", "2010-11-22T08:48:00Z", "2026-11-26T21:38:34Z")
    assert li["stats"] == {"games": 23960, "rating_bullet": 1807, "rating_blitz": 1772, "rating_rapid": 1855}      # a provisional rating is left out
    assert li["links"] == ["https://github.com/samexample", "https://mastodon.social/@sam_example", "https://sam.example.org/chess"]
    assert li["accounts"] == [{"site": "GitHub", "handle": H, "url": "https://github.com/samexample", "proof": "listed"},
                              {"site": "mastodon.social", "handle": "sam_example", "url": "https://mastodon.social/@sam_example", "proof": "listed"}]
    assert li["avatar_state"] == "none"
    c = p["chesscom"]
    assert (c["display_name"], c["location"], c["followers"], c["created"], c["last_active"]) == ("Sam Example", "PT", 94, "2007-05-07T16:50:00Z", "2026-11-27T00:11:34Z")
    cb = p["codeberg"]
    assert cb["emails"] == [] and cb["website"] == "https://sam.example.org" and cb["created"] == "2022-11-06T06:18:11Z"      # the noreply placeholder is dropped
    assert cb["stats"] == {"followers": 65, "following": 3, "starred": 12} and cb["bio"] == "Maps and bread."
    b = p["bluesky"]
    assert b["display_name"] == "Sam Example" and b["stats"] == {"followers": 10, "following": 2, "posts": 0} and b["created"] == "2024-08-30T21:52:31Z"
    w = p["wikipedia"]
    assert w["stats"] == {"edits": 1515} and w["created"] == "2009-03-27T20:47:31Z" and w["avatar_state"] == "none"
    gr = p["gravatar"]
    assert gr["company"] == "Cartographer, Example Maps" and gr["location"] == "Lisbon"
    assert gr["accounts"] == [{"site": "WordPress", "handle": H, "url": "https://samexample.wordpress.com", "proof": "listed"},
                              {"site": "X", "handle": "sam_example", "url": "https://x.com/sam_example", "proof": "listed"},
                              {"site": "LinkedIn", "handle": "sam-example", "url": "https://www.linkedin.com/in/sam-example", "proof": "listed"},
                              {"site": "Tumblr", "handle": "", "url": "https://samexample.tumblr.example", "proof": "listed"}]      # the hidden one is left out
    cf = p["codeforces"]
    assert (cf["display_name"], cf["location"], cf["company"]) == ("Sam Example", "Lisbon, Portugal", "Example University")
    assert cf["stats"] == {"rating": 1761, "max_rating": 1815, "friend_of": 91} and cf["avatar_state"] == "none"       # its picture host refuses servers
    lo = p["lobsters"]
    assert lo["bio"] == "Hi, I'm Sam Example, an invented person for a test fixture. Maps Bread, see the blog"
    assert lo["links"] == ["https://sam.example.org", "https://blog.example.net/bread"] and lo["stats"] == {"karma": 412} and lo["created"] == "2012-08-15T01:25:08Z"
    assert lo["accounts"] == [{"site": "GitHub", "handle": H, "url": "https://github.com/samexample", "proof": "listed"}]
    hf = p["huggingface"]
    assert hf["bio"] == "<3 maps and bread for everyone" and hf["followers"] == 53 and hf["stats"]["models"] == 5
    assert hf["items"] == [{"name": "Example Maps", "url": "https://huggingface.co/example-maps", "kind": "organization"}]

    # one request per source, three to Hacker News, never anything else
    per_host = {h: sum(c.url.host == h for c in calls) for h in sorted({c.url.host for c in calls})}
    assert per_host == {**{h: 1 for h in HOSTS.values()}, "hacker-news.firebaseio.com": 3}
    assert all(c.method == "GET" and "authorization" not in c.headers and "CrawlR" in c.headers["user-agent"] for c in calls)
    asked = {c.url.host: c for c in calls}
    assert asked["gitlab.com"].url.params["username"] == H and asked["dev.to"].url.params["url"] == H
    assert asked["keybase.io"].url.params["usernames"] == H and asked["keybase.io"].url.params["fields"] == "basics,profile,proofs_summary,pictures"
    assert asked["registry.npmjs.org"].url.params["text"] == "maintainer:samexample" and asked["codeforces.com"].url.params["handles"] == H
    assert asked["public.api.bsky.app"].url.params["actor"] == "samexample.bsky.social" and asked["mastodon.social"].url.params["acct"] == H
    assert dict(asked["en.wikipedia.org"].url.params) == {"action": "query", "list": "users", "ususers": H, "usprop": "editcount|registration", "format": "json"}
    assert not any(is_adult_site(url=str(c.url)) for c in calls) and not any(is_adult_site(url=u) for u in pictures)


def test_pictures_are_hashed_on_the_server_and_no_picture_address_is_returned(monkeypatch):
    _calls, pictures = world(monkeypatch, found())
    out = run()
    assert len(pictures) == 12 + len(OTHER_INSTANCES) and all(u.startswith("https://") for u in pictures)
    assert pictures[0] == "https://gitlab.com/uploads/-/system/user/avatar/1000001/avatar.png?v=1"
    assert "https://lobste.rs/avatars/samexample-100.png" in pictures                    # built here from the checked handle
    assert not any("codeforces" in u for u in pictures)
    text = json.dumps(out)
    for needle in ("avatar_url", "_avatar", "avatarUrl", "gravatar_url", "profile_image", "titlePhoto", *PICTURE_HOSTS):
        assert needle not in text, needle
    assert not re.search(r"\.(?:png|jpe?g|gif|webp|svg)\b", text.replace(THUMB, ""))
    p = by_source(out)
    without = {"hackernews", "npm", "lichess", "wikipedia", "codeforces", "launchpad"}
    for source, row in p.items():
        if source in without:
            assert row["avatar_state"] == "none" and row["avatar_hash"] == "" and row["thumb"] == "", source
        else:
            assert row["avatar_state"] == "ok" and row["avatar_default"] is False, source
    assert p["gitlab"]["avatar_state"] == "ok" and p["gitlab"]["avatar_hash"] == "0f1e2d3c4b5a6978" and p["gitlab"]["thumb"] == THUMB


def test_a_known_placeholder_is_default_without_a_fetch_and_a_failed_picture_is_failed(monkeypatch):
    missing = json.loads(fx("mastodon_found.json"))
    missing["avatar"] = missing["avatar_static"] = "https://mastodon.social/avatars/original/missing.png"
    pages = found()
    pages["mastodon.social/api/v1/accounts/lookup"] = j(200, missing)
    world(monkeypatch, pages)

    async def broken(images):
        assert not any("missing.png" in i["url"] for i in images)
        return {"results": [{"id": i["id"], "error": "The image could not be read.", "error_code": "bad_response"} if i["id"] == "gitlab"
                            else {"id": i["id"], "hash": "0f1e2d3c4b5a6978", "default": i["id"] == "codeberg", "thumb": THUMB} for i in images]}
    monkeypatch.setattr(pf, "run_avatar_hash", broken)
    out = run()
    p = by_source(out)
    assert (p["mastodon"]["avatar_state"], p["mastodon"]["avatar_default"], p["mastodon"]["avatar_hash"], p["mastodon"]["thumb"]) == ("default", True, "", "")
    assert (p["gitlab"]["avatar_state"], p["gitlab"]["avatar_hash"], p["gitlab"]["thumb"]) == ("failed", "", "")
    assert (p["codeberg"]["avatar_state"], p["codeberg"]["avatar_default"], p["codeberg"]["thumb"]) == ("default", True, "")
    # the profile whose picture was not read is asked again soon; the others are kept for the day
    assert 0 < ttl("gitlab") <= pf.CACHE_TTL_PARTIAL
    assert all(ttl(s) > 23 * 3600 for s in ALL if s != "gitlab")


def test_a_picture_step_that_raises_leaves_the_profiles_in_place(monkeypatch):
    world(monkeypatch, found())

    async def boom(images):
        raise RuntimeError("decoder blew up for samexample")
    monkeypatch.setattr(pf, "run_avatar_hash", boom)
    out = run()
    assert len(out["profiles"]) == N and by_source(out)["gitlab"]["avatar_state"] == "failed" and by_source(out)["wikipedia"]["avatar_state"] == "none"


# ---- not found, blocked, rate limited, failed: one source at a time ------------------------

@pytest.mark.parametrize("source", [s for s in ALL if s != "npm"])
def test_the_apis_own_no_such_account_is_not_found(monkeypatch, source):
    world(monkeypatch, with_source(source, absent()[source]))
    out = run()
    assert out["sources"][source] == {"site": out["sources"][source]["site"], "state": "not_found"}
    # one source's answer changes nothing for the others
    assert [p["source"] for p in out["profiles"]] == [s for s in ALL if s != source]
    assert all(e["state"] == "found" for s, e in out["sources"].items() if s != source)
    assert ttl(source) > 23 * 3600


def test_not_found_everywhere(monkeypatch):
    pages = {HOSTS[s] + "/": a for s, a in absent().items()}
    pages["registry.npmjs.org/"] = j(200, fx("npm_none.json"))
    world(monkeypatch, pages)
    out = run("samexample")
    assert out["profiles"] == []
    assert {s: e["state"] for s, e in out["sources"].items()} == {**{s: "not_found" for s in ALL}, "npm": "unknown"}


def test_npm_without_packages_is_unknown_not_absent_and_still_settled(monkeypatch):
    world(monkeypatch, with_source("npm", j(200, fx("npm_none.json"))))
    out = run()
    assert out["sources"]["npm"] == {"site": "npm", "state": "unknown", "note": pf.npm.NO_PACKAGES}
    assert "npm" not in by_source(out) and ttl("npm") > 23 * 3600


@pytest.mark.parametrize("source", ALL)
@pytest.mark.parametrize("status,state", [(403, "blocked"), (401, "blocked"), (429, "rate_limited")])
def test_a_refusal_is_blocked_or_rate_limited_and_never_not_found(monkeypatch, source, status, state):
    world(monkeypatch, with_source(source, httpx.Response(status, text="<html><title>Just a moment...</title></html>", headers={"content-type": "text/html"})))
    out = run()
    entry = out["sources"][source]
    assert entry["state"] == state and source not in by_source(out)
    assert ("error_code" in entry) == (state == "rate_limited")
    if state == "rate_limited":
        assert entry["error_code"] == "rate_limited" and entry["error"] and H not in json.dumps(entry)
    assert sum(e["state"] == "found" for e in out["sources"].values()) == N - 1
    # a refusal is usually a passing condition, so that one source is asked again soon; the
    # others keep their answers for the day
    assert 0 < ttl(source) <= pf.CACHE_TTL_PARTIAL
    assert all(ttl(s) > 23 * 3600 for s in ALL if s != source)
    if state == "rate_limited":
        assert entry["retry_after"] == pf.BACKOFF_DEFAULT


@pytest.mark.parametrize("source", ALL)
def test_a_web_page_where_json_was_expected_is_a_wall(monkeypatch, source):
    world(monkeypatch, with_source(source, httpx.Response(200, text="<!doctype html><html><body>Checking your browser</body></html>", headers={"content-type": "text/html"})))
    assert run()["sources"][source]["state"] == "blocked"


@pytest.mark.parametrize("source", ALL)
@pytest.mark.parametrize("how,code", [("500", "upstream"), ("timeout", "timeout"), ("refused", "unreachable"), ("garbage", "bad_response")])
def test_a_source_that_fails_is_failed_with_error_fields_and_sinks_nothing_else(monkeypatch, source, how, code):
    answer = {"500": httpx.Response(503, text="upstream connect error"), "timeout": httpx.ConnectTimeout(f"timed out asking for {H}"),
              "refused": httpx.ConnectError(f"refused https://example.invalid/{H}"), "garbage": httpx.Response(200, text="{\"truncated\": ")}[how]
    world(monkeypatch, with_source(source, answer))
    out = run()
    entry = out["sources"][source]
    assert entry["state"] == "failed" and entry["error_code"] == code and entry["error"] and set(entry) == {"site", "state", "error", "error_code", "error_detail"}
    assert H not in json.dumps(entry) and "example.invalid" not in json.dumps(entry)      # never str(exception)
    assert sum(e["state"] == "found" for e in out["sources"].values()) == N - 1 and len(out["profiles"]) == N - 1
    assert 0 < ttl(source) <= pf.CACHE_TTL_PARTIAL and all(ttl(s) > 23 * 3600 for s in ALL if s != source)


@pytest.mark.parametrize("source", ALL)
def test_an_answer_about_somebody_else_or_an_odd_status_is_unknown(monkeypatch, source):
    world(monkeypatch, with_source(source, j(418, {"teapot": True})))
    assert run()["sources"][source]["state"] == "unknown"
    pf.clear_cache_for_tests()
    world(monkeypatch, found())
    out = run("samexampla")          # every fixture names samexample, so nothing may be read for this handle
    states = {s: e["state"] for s, e in out["sources"].items()}
    # GitLab's list has no row for the name; npm lists no package for it; Hacker News never echoes the ID
    assert states["gitlab"] == "unknown" and states["npm"] == "unknown"
    assert all(v in ("unknown", "failed") for s, v in states.items() if s != "hackernews"), states
    assert [p["source"] for p in out["profiles"]] in ([], ["hackernews"])


def test_a_slow_source_times_out_alone(monkeypatch):
    world(monkeypatch, found())
    monkeypatch.setattr(pf, "SOURCE_TIMEOUT", 0.05)

    async def hang(client, username):
        await asyncio.sleep(5)
    monkeypatch.setattr(pf.lichess, "read", hang)
    out = run()
    assert out["sources"]["lichess"]["state"] == "failed" and out["sources"]["lichess"]["error_code"] == "timeout"
    assert sum(e["state"] == "found" for e in out["sources"].values()) == N - 1


def test_the_total_cap_ends_the_run_and_marks_what_was_still_out(monkeypatch):
    world(monkeypatch, found())
    monkeypatch.setattr(pf, "TOTAL_TIMEOUT", 0.05)

    async def hang(client, username):
        await asyncio.sleep(5)
    monkeypatch.setattr(pf.keybase, "read", hang)
    started = time.time()
    out = run()
    assert time.time() - started < 2
    assert out["sources"]["keybase"]["state"] == "failed" and out["sources"]["keybase"]["error_code"] == "timeout" and len(out["profiles"]) == N - 1


def test_a_source_that_raises_anything_is_failed(monkeypatch):
    world(monkeypatch, found())

    async def boom(client, username):
        raise RuntimeError(f"unexpected for {username}")
    monkeypatch.setattr(pf.devto, "read", boom)
    out = run()
    assert out["sources"]["devto"]["state"] == "failed" and out["sources"]["devto"]["error_detail"] == "RuntimeError" and len(out["profiles"]) == N - 1


def test_a_response_that_is_too_large_is_a_failure(monkeypatch):
    world(monkeypatch, with_source("lichess", httpx.Response(200, text="[" + "1," * base.MAX_BODY + "1]")))
    out = run()
    assert out["sources"]["lichess"]["state"] == "failed" and out["sources"]["lichess"]["error_code"] == "bad_response"


def test_a_redirect_to_another_host_is_never_followed(monkeypatch):
    pages = with_source("devto", httpx.Response(302, headers={"location": "https://evil.example.net/steal"}))
    pages["evil.example.net/"] = j(200, fx("devto_found.json"))
    calls, _ = world(monkeypatch, pages)
    out = run()
    assert out["sources"]["devto"]["state"] == "unknown" and not any(c.url.host == "evil.example.net" for c in calls)


# ---- handles a site cannot hold ----------------------------------------------------------

def test_a_handle_a_site_cannot_hold_is_not_asked_there(monkeypatch):
    calls, _ = world(monkeypatch, {HOSTS[s] + "/": a for s, a in absent().items()} | {"registry.npmjs.org/": j(200, fx("npm_none.json"))})
    out = run("sam.example")
    states = {s: e["state"] for s, e in out["sources"].items()}
    not_asked = {s for s, v in states.items() if v == "not_asked"}
    assert not_asked == {"keybase", "hackernews", "dockerhub", "devto", "lichess", "chesscom", "bluesky", "gravatar", "lobsters", *(s.ID for s in mastodon.SOURCES)}
    assert {c.url.host for c in calls} == {HOSTS[s] for s in ALL if s not in not_asked}
    assert all(set(out["sources"][s]) == {"site", "state"} for s in not_asked)
    assert states["gitlab"] == "not_found" and ttl("gitlab", "sam.example") > 23 * 3600
    assert not any(k[0] in not_asked for k in pf._cache)          # nothing was asked, so nothing is kept


@pytest.mark.parametrize("source,handle,ok", [
    ("keybase", "a" * 17, False), ("keybase", "sam_example", True), ("keybase", "sam-example", False),
    ("hackernews", "a", False), ("hackernews", "a" * 16, False), ("hackernews", "sam-ex_1", True),
    ("mastodon", "sam-example", False), ("mastodon", "Sam_Example", True),
    ("dockerhub", "s", False), ("devto", "sam.example", False), ("lichess", "_sam", False), ("lichess", "a" * 31, False),
    ("chesscom", "ab", False), ("chesscom", "sam_example-1", True), ("codeberg", "sam.", False), ("codeberg", "s", True),
    ("bluesky", "sam_example", False), ("bluesky", "ab", False), ("bluesky", "a" * 19, False), ("bluesky", "Sam-Example", True),
    ("wikipedia", "192.168.0.1", False), ("wikipedia", "Sam_Example", True),
    ("gravatar", "a" * 32, False), ("gravatar", "0123456789abcdef" * 4, False), ("gravatar", "sam-example", False), ("gravatar", "samexample", True),
    ("codeforces", "ab", False), ("codeforces", "sam.example", True), ("lobsters", "a" * 26, False),
    ("huggingface", "sam--example", False), ("huggingface", "sam-example", True), ("gitlab", "s", False), ("gitlab", "sam.", False),
    ("npm", "Sam.Example", True),
    ("launchpad", "s", False), ("launchpad", "-sam", False), ("launchpad", "sam.example-1", True), ("launchpad", "sam_example", False),
    ("gitea", "sam.", False), ("gitea", "sam_example", True), ("gitea", "a" * 41, False),
])
def test_handle_rules(source, handle, ok):
    assert bool(getattr(pf, source).HANDLE_RE.fullmatch(handle)) is ok


# ---- source by source --------------------------------------------------------------------

def test_keybase_proofs_become_linked_accounts_with_the_proof_address(monkeypatch):
    world(monkeypatch, found())
    k = by_source(run())["keybase"]
    assert (k["display_name"], k["location"], k["created"]) == ("Sam Example", "Lisbon", "2014-02-06T02:18:28Z")
    assert k["accounts"] == [
        {"site": "X", "handle": "sam_example", "url": "https://x.com/sam_example", "proof": "keybase", "proof_url": "https://twitter.com/sam_example/status/100000000000000001"},
        {"site": "GitHub", "handle": "samexample", "url": "https://github.com/samexample", "proof": "keybase", "proof_url": "https://gist.github.com/00000000000000000001"},
        {"site": "Reddit", "handle": "sam_example", "url": "https://www.reddit.com/user/sam_example", "proof": "keybase",
         "proof_url": "https://www.reddit.com/r/KeybaseProofs/comments/aaaaaa/my_keybase_proof/"},
        {"site": "Hacker News", "handle": "samexample", "url": "https://news.ycombinator.com/user?id=samexample", "proof": "keybase",
         "proof_url": "https://news.ycombinator.com/user?id=samexample"},
        {"site": "Website", "handle": "sam.example.org", "url": "https://sam.example.org", "proof": "keybase", "proof_url": "https://sam.example.org/keybase.txt"},
        {"site": "mastodon.social", "handle": "sam_example", "url": "https://mastodon.social/@sam_example", "proof": "keybase",
         "proof_url": "https://mastodon.social/@sam_example/100000000000000001"},
    ]
    # the DNS proof names the same address as the website proof, so it is one account; a proof
    # that does not pass, a name that is no handle and an adult site are left out
    assert k["stats"] == {"proofs": 7} and "revoked-sam" not in json.dumps(k) and "pornhub" not in json.dumps(k)


def test_keybase_proofs_mapping_alone():
    def proof(**kw):
        return {"state": 1, "proof_url": "https://proof.example.org/p", **kw}
    assert keybase.proofs(None) == [] and keybase.proofs({"all": "x"}) == [] and keybase.proofs({"all": [None, {"state": 1}]}) == []
    got = keybase.proofs({"all": [
        proof(proof_type="dns", nametag="Sam.Example.org", service_url="http://sam.example.org"),
        proof(proof_type="generic_web_site", nametag="localhost", service_url="http://localhost"),
        proof(proof_type="github", nametag="sam example", service_url="https://github.com/x"),
        proof(proof_type="generic_social", nametag="sam", presentation_group="social.example.net", service_url="javascript:alert(1)"),
        proof(proof_type="facebook", nametag="sam.example", service_url="https://facebook.com/sam.example", proof_url="ftp://nope"),
        proof(proof_type="github", nametag="waiting", state=0),
    ]})
    assert got == [{"site": "DNS", "handle": "sam.example.org", "url": "https://sam.example.org", "proof": "keybase", "proof_url": "https://proof.example.org/p"},
                   {"site": "Facebook", "handle": "sam.example", "url": "https://www.facebook.com/sam.example", "proof": "keybase"}]


def test_keybase_other_answers(monkeypatch):
    for body, state in (({"status": {"code": 205, "name": "NOT_FOUND"}}, "not_found"), ({"status": {"code": 100, "name": "INPUT_ERROR"}}, "unknown"),
                        ({"status": {"code": 0, "name": "OK"}, "them": []}, "unknown")):
        pf.clear_cache_for_tests()
        world(monkeypatch, with_source("keybase", j(200, body)))
        assert run()["sources"]["keybase"]["state"] == state, body


def test_hacker_news_about_is_plain_text_with_its_links_and_ids_keep_their_case(monkeypatch):
    world(monkeypatch, found())
    h = by_source(run())["hackernews"]
    assert h["bio"] == "Maps & bread. I'm at https://sam.example.org/ Write to sam@example.org. Invented person for a test fixture."
    assert h["guard"] == {"bio": "Maps & bread. I'm at https://sam.example.org/\nWrite to sam@example.org.\nInvented person for a test fixture."}
    assert h["links"] == ["https://sam.example.org/"] and h["emails"] == ["sam@example.org"]
    assert h["stats"] == {"karma": 4423} and h["created"] == "2007-08-18T16:35:47Z" and h["display_name"] == ""
    assert "<" not in h["bio"] and "alert" not in h["bio"] and "\u202e" not in json.dumps(h, ensure_ascii=False)

    # "SamExample" is another ID: the three paths carry it as typed, and null means no such user
    pf.clear_cache_for_tests()
    calls, _ = world(monkeypatch, found() | {"hacker-news.firebaseio.com/v0/user/SamExample/": j(200, "null")})
    out = run("SamExample")
    assert out["sources"]["hackernews"]["state"] == "not_found"
    assert sorted(c.url.path for c in calls if c.url.host == "hacker-news.firebaseio.com") == [
        "/v0/user/SamExample/about.json", "/v0/user/SamExample/created.json", "/v0/user/SamExample/karma.json"]


def test_hacker_news_without_a_bio_is_a_whole_answer(monkeypatch):
    pages = found()
    pages["hacker-news.firebaseio.com/v0/user/samexample/about.json"] = j(200, "null")      # the API's own "no bio"
    world(monkeypatch, pages)
    out = run()
    h = by_source(out)["hackernews"]
    assert h["bio"] == "" and h["note"] == "" and h["stats"] == {"karma": 4423}
    assert out["sources"]["hackernews"] == {"site": "Hacker News", "state": "found"} and ttl("hackernews") > 23 * 3600


@pytest.mark.parametrize("part,answer,row_note,said", [
    ("about", httpx.Response(500, text=""), "bio not read", "the bio"),
    ("about", httpx.Response(429, text="slow down"), "bio not read", "the bio"),
    ("about", httpx.ReadTimeout("timed out"), "bio not read", "the bio"),
    ("about", httpx.Response(200, text="<html>Checking your browser</html>"), "bio not read", "the bio"),
    ("karma", httpx.Response(503, text=""), "karma not read", "the karma"),
    ("both", httpx.Response(502, text=""), "bio and karma not read", "the bio and the karma"),
])
def test_a_part_hacker_news_did_not_answer_for_is_unread_and_never_empty(monkeypatch, part, answer, row_note, said):
    pages = found()
    for name in ("about", "karma"):
        if part in (name, "both"):
            pages[f"hacker-news.firebaseio.com/v0/user/samexample/{name}.json"] = answer
    world(monkeypatch, pages)
    out = run()
    h, entry = by_source(out)["hackernews"], out["sources"]["hackernews"]
    assert h["created"] == "2007-08-18T16:35:47Z" and h["note"] == row_note
    assert entry == {"site": "Hacker News", "state": "found", "note": f"Hacker News did not answer for {said}. Unknown, not empty."}
    if part != "karma":
        assert h["bio"] == ""
    else:
        assert h["bio"].startswith("Maps & bread") and h["stats"] == {}
    # unsettled: asked again soon, and the other sources keep their day
    assert 0 < ttl("hackernews") <= pf.CACHE_TTL_PARTIAL and all(ttl(s) > 23 * 3600 for s in ALL if s != "hackernews")
    assert bool(pf._backing_off("hackernews")) == (getattr(answer, "status_code", 0) == 429)


def test_hacker_news_whose_first_field_fails_is_failed_whole(monkeypatch):
    pages = found()
    pages["hacker-news.firebaseio.com/v0/user/samexample/created.json"] = httpx.ReadTimeout("timed out")
    world(monkeypatch, pages)
    out = run()
    assert out["sources"]["hackernews"]["state"] == "failed" and out["sources"]["hackernews"]["error_code"] == "timeout" and "hackernews" not in by_source(out)


@pytest.mark.parametrize("source", ["keybase", "hackernews", "gitlab", "npm", "bluesky", "wikipedia", "codeforces"])
def test_a_404_is_not_absence_where_the_api_says_absence_another_way(monkeypatch, source):
    world(monkeypatch, with_source(source, j(404, {"message": "Not Found"})))
    out = run()
    assert out["sources"][source]["state"] == "unknown" and source not in by_source(out)
    assert 0 < ttl(source) <= pf.CACHE_TTL_PARTIAL


def test_a_follow_up_that_contradicts_the_first_answer_is_unknown(monkeypatch):
    # Docker Hub said "an organization, over there", and over there says 404.
    pages = with_source("dockerhub", j(404, fx("dockerhub_not_found.json")))
    pages["hub.docker.com/v2/users/samexample/"] = httpx.Response(308, headers={"location": "/v2/orgs/samexample"})
    world(monkeypatch, pages)
    assert run()["sources"]["dockerhub"]["state"] == "unknown"
    # Hugging Face gave its own spelling, and that spelling answers 404.
    pf.clear_cache_for_tests()
    pages = with_source("huggingface", j(404, fx("huggingface_not_found.json")))
    pages["huggingface.co/api/users/samexample/overview"] = httpx.Response(307, headers={"location": "/api/users/SamExample/overview"})
    world(monkeypatch, pages)
    assert run()["sources"]["huggingface"]["state"] == "unknown"
    # and a follow-up that fails is a failure, never an absent account
    pf.clear_cache_for_tests()
    pages["huggingface.co/api/users/SamExample/overview"] = httpx.Response(503, text="")
    world(monkeypatch, pages)
    assert run()["sources"]["huggingface"]["state"] == "failed"


def test_html_to_text():
    text, links = base.html_text("<p>One &amp; two<br>three</p><ul><li>four <a href='https://a.example.org/x'>five</a></li></ul><style>p{}</style><script>bad()</script>six&#x27;s")
    assert text == "One & two\nthree\nfour five\nsix's" and links == ["https://a.example.org/x"]
    assert base.html_text(None) == ("", []) and base.html_text("") == ("", []) and base.html_text("<p><b>unclosed") == ("unclosed", [])
    assert base.html_text("a\x00b\x07c\u202ed")[0] == "abcd"
    assert len(base.html_text("x" * 5000)[0]) == base.GUARD_BIO_MAX


def test_mastodon_fields_carry_verified_links(monkeypatch):
    world(monkeypatch, found())
    m = by_source(run())["mastodon"]
    assert m["display_name"] == "Sam Example" and m["bio"] == "Maps & bread, with @Mastodon. Invented person for a test fixture."
    assert (m["created"], m["last_active"]) == ("2016-03-16T00:00:00Z", "2026-11-20")
    assert m["stats"] == {"followers": 120, "following": 80, "posts": 450} and m["followers"] == 120
    assert m["accounts"] == [
        {"site": "GitHub", "handle": H, "url": "https://github.com/samexample", "proof": "verified_link"},
        {"site": "sam.example.org", "handle": "", "url": "https://sam.example.org", "proof": "verified_link"}]      # a listed link to an unknown site is a link, not an account
    assert m["links"] == ["https://github.com/samexample", "https://sam.example.org", "https://blog.example.net/sam", "https://mastodon.social/@Mastodon"]
    assert "javascript" not in json.dumps(m)
    assert mastodon.field_links(None) == ([], []) and mastodon.field_links([None, {"value": 5}, {"value": "plain words"}]) == ([], [])


def test_mastodon_reads_only_a_local_account(monkeypatch):
    remote = {**json.loads(fx("mastodon_found.json")), "acct": "SamExample@elsewhere.example.org"}
    world(monkeypatch, with_source("mastodon", j(200, remote)))
    assert run()["sources"]["mastodon"]["state"] == "unknown"


def test_docker_hub_organization_is_read_from_the_address_built_here(monkeypatch):
    pages = found()
    pages["hub.docker.com/v2/users/samexample/"] = httpx.Response(308, headers={"location": "/v2/orgs/samexample"})
    pages["hub.docker.com/v2/orgs/samexample"] = j(200, fx("dockerhub_org.json"))
    calls, _ = world(monkeypatch, pages)
    d = by_source(run())["dockerhub"]
    assert (d["display_name"], d["note"], d["website"], d["url"]) == ("Example Maps Images", "organization", "https://maps.example.org", "https://hub.docker.com/u/samexample")
    assert [c.url.path for c in calls if c.url.host == "hub.docker.com"] == ["/v2/users/samexample/", "/v2/orgs/samexample"]

    # a redirect anywhere else is not followed
    pf.clear_cache_for_tests()
    pages["hub.docker.com/v2/users/samexample/"] = httpx.Response(308, headers={"location": "/v2/orgs/somebodyelse"})
    calls, _ = world(monkeypatch, pages)
    assert run()["sources"]["dockerhub"]["state"] == "unknown" and sum(c.url.host == "hub.docker.com" for c in calls) == 1


def test_hugging_face_follows_its_own_spelling_once(monkeypatch):
    pages = {k: v for k, v in found().items() if not k.startswith("huggingface.co/")}
    pages["huggingface.co/api/users/samexample/overview"] = httpx.Response(307, headers={"location": "/api/users/SamExample/overview"})
    pages["huggingface.co/api/users/SamExample/overview"] = j(200, fx("huggingface_found.json"))
    calls, _ = world(monkeypatch, pages)
    assert by_source(run())["huggingface"]["handle"] == "SamExample"
    assert [c.url.path for c in calls if c.url.host == "huggingface.co"] == ["/api/users/samexample/overview", "/api/users/SamExample/overview"]
    pf.clear_cache_for_tests()
    pages["huggingface.co/api/users/samexample/overview"] = httpx.Response(307, headers={"location": "/api/users/other/overview"})
    calls, _ = world(monkeypatch, pages)
    assert run()["sources"]["huggingface"]["state"] == "unknown" and sum(c.url.host == "huggingface.co" for c in calls) == 1


def test_the_apis_own_rate_messages(monkeypatch):
    world(monkeypatch, with_source("codeforces", j(503, {"status": "FAILED", "comment": "Call limit exceeded"})))
    assert run()["sources"]["codeforces"]["state"] == "rate_limited"
    pf.clear_cache_for_tests()
    world(monkeypatch, with_source("wikipedia", j(200, {"error": {"code": "ratelimited", "info": "You've exceeded your rate limit."}})))
    assert run()["sources"]["wikipedia"]["state"] == "rate_limited"
    pf.clear_cache_for_tests()
    world(monkeypatch, with_source("wikipedia", j(200, {"error": {"code": "maxlag", "info": "Waiting for a database server"}})))
    entry = run()["sources"]["wikipedia"]
    assert entry["state"] == "failed" and entry["error_code"] == "upstream"
    pf.clear_cache_for_tests()
    world(monkeypatch, with_source("wikipedia", j(200, {"query": {"users": [{"name": "Samexample", "invalid": ""}]}})))
    assert run()["sources"]["wikipedia"]["state"] == "not_found"


def test_closed_and_unusual_accounts_are_noted(monkeypatch):
    pages = found()
    pages["lichess.org/api/user/samexample"] = j(200, {"id": "samexample", "username": "samexample", "disabled": True})
    pages["api.chess.com/pub/player/samexample"] = j(200, {**json.loads(fx("chesscom_found.json")), "status": "closed:fair_play_violations"})
    pages["gitlab.com/api/v4/users"] = j(200, [{**json.loads(fx("gitlab_found.json"))[0], "state": "blocked"}])
    world(monkeypatch, pages)
    p = by_source(run())
    assert p["lichess"]["note"] == "closed" and p["lichess"]["stats"] == {} and p["chesscom"]["note"] == "closed" and p["gitlab"]["note"] == "blocked"


# ---- outside data ------------------------------------------------------------------------

def test_links_are_http_or_https_to_a_named_host_and_nothing_else():
    ok = {"https://sam.example.org/a?b=c": "https://sam.example.org/a?b=c", "http://sam.example.org": "http://sam.example.org",
          "sam.example.org/maps": "https://sam.example.org/maps", "  https://sam.example.org  ": "https://sam.example.org"}
    for given, want in ok.items():
        assert base.safe_link(given) == want
    for bad in ("javascript:alert(1)", "data:text/html,x", "ftp://sam.example.org", "//sam.example.org", "/relative", "mailto:sam@example.org",
                "https://user:pw@sam.example.org", "https://sam.example.org:8443/", "https://127.0.0.1/", "https://localhost/x", "http://[::1]/",
                "https://sam.example.org/a b", "https://sam.example.org/\x00", "https://" + "a" * 300 + ".example.org", "not a link", "", None, 5,
                "https://sam.example.org/me.png", "https://sam.example.org/pic.JPG", "https://www.pornhub.com/users/samexample", "@sam", "#tag"):
        assert base.safe_link(bad) == "", bad


def test_emails_are_checked_and_placeholders_are_dropped():
    assert base.safe_email(" sam@example.org ") == "sam@example.org"
    for bad in ("sam@noreply.codeberg.org", "1+sam@users.noreply.github.com", "no-reply@example.org", "sam@@example.org", "sam", "", None,
                "sam@example", "a..b@example.org", "x" * 250 + "@example.org"):
        assert base.safe_email(bad) == "", bad


def test_the_row_clips_cleans_and_filters_everything():
    row = base.profile(
        "x", "X", "h\x00andle", "https://x.example.org/handle", display_name="N" * 300 + "\x07", bio="line one\r\n\tline  two \u202e" + "b" * 3000,
        location="L\nisbon", company=5, website="javascript:alert(1)",
        links=["https://a.example.org", "https://a.example.org", "nope://x", "https://www.pornhub.com/x", *[f"https://l{i}.example.org" for i in range(20)]],
        emails=["sam@example.org", "SAM@example.org", "bad", None, *[f"e{i}@example.org" for i in range(10)]],
        created="not a date", last_active=1795729114701,
        accounts=[None, base.known_account("github", "sam", "listed"), base.known_account("github", "sam", "listed"), base.known_account("github", "no good", "listed")],
        stats={"followers": 5, "bad": "7", "neg": -1, "flag": True, "none": None, **{f"k{i}": i for i in range(20)}},
        items=[None, base.item("pkg", "https://p.example.org/pkg", "package"), base.item("", "https://p.example.org", "package"), base.item("x", "javascript:x", "package")],
        note="n" * 100, avatar="http://insecure.example.org/a.png")
    assert row["handle"] == "handle" and len(row["display_name"]) == base.NAME_MAX and row["location"] == "L isbon" and row["company"] == ""
    assert len(row["bio"]) == base.BIO_MAX and row["bio"].startswith("line one line two bbb") and len(row["guard"]["bio"]) == base.GUARD_BIO_MAX
    assert row["guard"]["bio"].startswith("line one\nline two bbb")
    assert row["website"] == "" and len(row["links"]) == base.MAX_LINKS and row["links"][:2] == ["https://a.example.org", "https://l0.example.org"]
    assert row["emails"][:2] == ["sam@example.org", "e0@example.org"] and len(row["emails"]) == base.MAX_EMAILS
    assert row["created"] == "" and row["last_active"] == "2026-11-26T21:38:34Z"
    assert row["accounts"] == [{"site": "GitHub", "handle": "sam", "url": "https://github.com/sam", "proof": "listed"}]
    assert row["stats"]["followers"] == 5 and len(row["stats"]) == base.MAX_STATS and not {"bad", "neg", "flag", "none"} & set(row["stats"])
    assert row["items"] == [{"name": "pkg", "url": "https://p.example.org/pkg", "kind": "package"}] and len(row["note"]) == base.NOTE_MAX
    assert row["_avatar"] == ""                                   # only an https picture is ever fetched
    short = base.profile("x", "X", "h", "https://x.example.org/h", bio="short bio")
    assert "guard" not in short and short["bio"] == "short bio" and short["followers"] is None


def test_dates():
    assert base.iso(1187454947) == "2007-08-18T16:35:47Z" and base.iso(1290415680000) == "2010-11-22T08:48:00Z"
    assert base.iso("2022-11-06T07:18:11+01:00") == "2022-11-06T06:18:11Z" and base.iso("2019-11-23T17:38:57.000Z") == "2019-11-23T17:38:57Z"
    assert base.iso("2026-11-20") == "2026-11-20" and base.iso("Dec 27, 2015") == "2015-12-27"
    for bad in (None, "", "soon", True, -5, 0, "0001-01-01T00:00:00Z", "9999-01-01", 10 ** 30, [], "2015-13-45"):
        assert base.iso(bad) == "", bad


def test_accounts_from_addresses():
    f = base.account_from_url
    assert f("https://github.com/samexample", "listed") == {"site": "GitHub", "handle": "samexample", "url": "https://github.com/samexample", "proof": "listed"}
    assert f("https://twitter.com/sam_example", "listed")["url"] == "https://x.com/sam_example"
    assert f("https://old.reddit.com/u/sam_example", "listed")["url"] == "https://www.reddit.com/user/sam_example"
    assert f("https://www.youtube.com/@samexample", "listed")["handle"] == "samexample"
    assert f("https://bsky.app/profile/sam.example.org", "listed")["site"] == "Bluesky"
    assert f("https://lichess.org/@/SamExample", "listed")["url"] == "https://lichess.org/@/SamExample"
    assert f("https://news.ycombinator.com/user?id=samexample", "listed")["site"] == "Hacker News"
    assert f("https://fosstodon.example.org/@sam", "verified_link") == {"site": "fosstodon.example.org", "handle": "sam", "url": "https://fosstodon.example.org/@sam", "proof": "verified_link"}
    for other in ("https://github.com/samexample/repo", "https://github.com/", "https://sam.example.org/about", "https://reddit.com/r/maps", "javascript:x", None,
                  "https://www.pornhub.com/users/sam"):
        assert f(other, "listed") is None, other


@pytest.mark.parametrize("url", [
    "https://www.youtube.com/watch?v=abc123", "https://www.youtube.com/watch", "https://youtube.com/playlist?list=PL123", "https://www.youtube.com/results?search_query=sam",
    "https://www.youtube.com/channel/UCabc123", "https://www.youtube.com/c/samexample", "https://www.youtube.com/user/samexample", "https://www.youtube.com/samexample",
    "https://www.youtube.com/@watch", "https://www.youtube.com/@samexample?si=abc", "https://www.youtube.com/@samexample/videos",
    "https://www.facebook.com/profile.php?id=42", "https://www.facebook.com/profile.php", "https://www.facebook.com/sharer.php", "https://facebook.com/groups",
    "https://www.facebook.com/marketplace", "https://www.facebook.com/sam.example?ref=share",
    "https://github.com/sponsors", "https://github.com/orgs", "https://github.com/organizations", "https://github.com/about", "https://github.com/login",
    "https://github.com/signup", "https://github.com/settings", "https://github.com/features", "https://github.com/pricing", "https://github.com/topics",
    "https://github.com/marketplace", "https://github.com/notifications", "https://github.com/explore", "https://github.com/Search", "https://github.com/samexample?tab=repositories",
    "https://x.com/search?q=alice", "https://x.com/search", "https://x.com/home", "https://x.com/explore", "https://x.com/intent", "https://twitter.com/share",
    "https://twitter.com/hashtag", "https://x.com/i", "https://x.com/intent/tweet?text=hi", "https://twitter.com/sam_example?lang=en",
    "https://gitlab.com/explore", "https://gitlab.com/users", "https://gitlab.com/help", "https://gitlab.com/robots.txt",
    "https://www.instagram.com/explore", "https://www.instagram.com/p", "https://www.instagram.com/accounts", "https://www.twitch.tv/directory",
    "https://dev.to/t", "https://dev.to/search?q=sam", "https://dev.to/settings", "https://codeberg.org/explore", "https://codeberg.org/user",
    "https://keybase.io/docs", "https://www.reddit.com/user/sam_example?sort=top", "https://bsky.app/profile/sam.example.org?x=1",
    "https://news.ycombinator.com/user?id=samexample&next=1", "https://news.ycombinator.com/user?name=samexample", "https://news.ycombinator.com/item?id=12345",
    "https://news.ycombinator.com/user?id=samexample&id=other", "https://sam.wordpress.com/?p=5", "https://fosstodon.example.org/@sam?page=2",
])
def test_an_address_that_is_a_page_of_the_site_is_not_an_account(url):
    assert base.account_from_url(url, "listed") is None
    assert base.safe_link(url) == url                 # it stays an ordinary link


def test_profile_addresses_are_still_read_as_accounts():
    f = base.account_from_url
    want = {
        "https://www.youtube.com/@handle": ("YouTube", "handle", "https://www.youtube.com/@handle"),
        "https://m.youtube.com/@handle/": ("YouTube", "handle", "https://www.youtube.com/@handle"),
        "https://github.com/handle": ("GitHub", "handle", "https://github.com/handle"),
        "https://github.com/handle/": ("GitHub", "handle", "https://github.com/handle"),
        "https://github.com/handle#readme": ("GitHub", "handle", "https://github.com/handle"),
        "https://x.com/handle": ("X", "handle", "https://x.com/handle"),
        "https://twitter.com/handle": ("X", "handle", "https://x.com/handle"),
        "https://mobile.twitter.com/handle": ("X", "handle", "https://x.com/handle"),
        "https://www.facebook.com/sam.example": ("Facebook", "sam.example", "https://www.facebook.com/sam.example"),
        "https://www.instagram.com/sam.example/": ("Instagram", "sam.example", "https://www.instagram.com/sam.example/"),
        "https://gitlab.com/samexample": ("GitLab", "samexample", "https://gitlab.com/samexample"),
        "https://www.twitch.tv/samexample": ("Twitch", "samexample", "https://www.twitch.tv/samexample"),
        "https://dev.to/samexample": ("dev.to", "samexample", "https://dev.to/samexample"),
        "https://codeberg.org/samexample": ("Codeberg", "samexample", "https://codeberg.org/samexample"),
        "https://keybase.io/samexample": ("Keybase", "samexample", "https://keybase.io/samexample"),
        "https://www.linkedin.com/in/sam-example": ("LinkedIn", "sam-example", "https://www.linkedin.com/in/sam-example"),
        "https://news.ycombinator.com/user?id=samexample": ("Hacker News", "samexample", "https://news.ycombinator.com/user?id=samexample"),
        "https://samexample.wordpress.com": ("WordPress", "samexample", "https://samexample.wordpress.com"),
    }
    for url, (site, handle, address) in want.items():
        assert f(url, "listed") == {"site": site, "handle": handle, "url": address, "proof": "listed"}, url


def test_a_reserved_word_is_not_an_account_however_it_arrives():
    # a Keybase proof or a profile field can name one of these as a handle
    for key, word in (("github", "sponsors"), ("github", "Settings"), ("twitter", "search"), ("twitter", "i"), ("facebook", "profile.php"),
                      ("facebook", "index.html"), ("youtube", "watch"), ("gitlab", "explore"), ("devto", "top")):
        assert base.known_account(key, word, "listed") is None, (key, word)
        assert base.reserved(key, word)
    assert not base.reserved("github", "samexample") and base.known_account("twitter", "@sam_example", "listed")["handle"] == "sam_example"


def test_a_link_with_a_hidden_character_is_refused_whole():
    for bad in ("https://sam.example.org/\u202egnp.exe", "https://sam.example.org/a\u200bb", "https://sam.example.org/\u2066x\u2069", "https://sam.example.org/\ufeffx",
                "https://sam.example.org/a\u00adb", "https://sam.\u200dexample.org/", "https://sam.example.org/\ue000", "\u202ehttps://sam.example.org/"):
        assert base.safe_link(bad) == "", ascii(bad)
        assert base.account("Site", "sam", bad, "listed") is None and base.item("x", bad, "package") is None
    assert base.safe_link("https://sam.example.org/caf\u00e9") == "https://sam.example.org/caf\u00e9"       # a letter is not a format character
    row = base.profile("x", "X", "h", "https://x.example.org/h", website="https://sam.example.org/\u202egnp.exe", links=["https://ok.example.org/a\u200b", "https://fine.example.org"])
    assert row["website"] == "" and row["links"] == ["https://fine.example.org"]


def test_a_mastodon_field_is_a_link_only_when_it_is_written_as_one():
    fields = [{"name": "Pronouns", "value": "she.her"}, {"name": "Site", "value": "sam.example.org/maps"}, {"name": "Rel", "value": "<a href=\"she.her\">she.her</a>"},
              {"name": "Blog", "value": "https://blog.example.net/sam"}, {"name": "Old", "value": "HTTP://old.example.net"},
              {"name": "Code", "value": "<a href=\"https://github.com/samexample\" rel=\"me\">github.com/samexample</a>", "verified_at": "2026-01-01T00:00:00Z"},
              {"name": "Ftp", "value": "ftp://files.example.net"}]
    links, accounts = mastodon.field_links(fields)
    assert links == ["https://blog.example.net/sam", "HTTP://old.example.net", "https://github.com/samexample"]
    assert [a and a["site"] for a in accounts] == [None, None, "GitHub"]
    assert base.account("Pornhub", "sam", "https://sam.example.org", "listed") is None and base.account("", "sam", "https://sam.example.org", "listed") is None
    assert base.known_account("nowhere", "sam", "listed") is None and base.known_account("github", None, "listed") is None


# ---- Mastodon beyond mastodon.social, Launchpad, Gitea.com --------------------------------

def test_the_mastodon_instances_are_one_fixed_list_and_each_is_a_source_of_its_own():
    assert mastodon.INSTANCES[0] == "mastodon.social" and 6 <= len(mastodon.INSTANCES) <= 9 and len(set(mastodon.INSTANCES)) == len(mastodon.INSTANCES)
    assert [s.HOST for s in mastodon.SOURCES] == list(mastodon.INSTANCES)
    assert [(s.ID, s.SITE) for s in mastodon.SOURCES][:3] == [("mastodon", "Mastodon"), ("mastodon_mastodon_online", "Mastodon (mastodon.online)"),
                                                              ("mastodon_mstdn_social", "Mastodon (mstdn.social)")]
    assert all(re.fullmatch(r"mastodon(_[a-z0-9_]+)?", s.ID) and s.HANDLE_RE is mastodon.HANDLE_RE for s in mastodon.SOURCES)
    assert all(base.HOSTNAME_RE.fullmatch(h) and not is_adult_site(url=f"https://{h}/") for h in mastodon.INSTANCES)
    # the registry holds exactly these and no other spelling of the list exists in the package
    assert [s for s in pf.SOURCES if s.ID.startswith("mastodon")] == list(mastodon.SOURCES)
    others = [h for h in mastodon.INSTANCES if h != "mastodon.social"]
    for path in Path(pf.__file__).parent.glob("*.py"):
        if path.name != "mastodon.py":
            assert not any(h in path.read_text(encoding="utf-8") for h in others), path.name


def test_each_mastodon_instance_keeps_its_own_row_and_its_own_state(monkeypatch):
    pages = {k: v for k, v in found().items() if "/api/v1/accounts/lookup" not in k}
    wall = httpx.Response(403, text="<html><title>Just a moment...</title></html>", headers={"content-type": "text/html"})
    answers = {"mastodon.social": j(404, fx("mastodon_not_found.json")), "mastodon.online": j(404, fx("mastodon_not_found.json")),
               "mstdn.social": httpx.Response(429, text="{}", headers={"retry-after": "60"}), "fosstodon.org": j(200, masto("fosstodon.org")),
               "hachyderm.io": wall, "infosec.exchange": httpx.Response(503, text=""), "mas.to": httpx.ConnectTimeout(f"timed out for {H}"),
               "mastodon.world": j(200, masto("mastodon.world"))}
    assert set(answers) == set(mastodon.INSTANCES)
    calls, pictures = world(monkeypatch, pages | {f"{h}/api/v1/accounts/lookup": a for h, a in answers.items()})
    out = run()
    states = {s.HOST: out["sources"][s.ID]["state"] for s in mastodon.SOURCES}
    assert states == {"mastodon.social": "not_found", "mastodon.online": "not_found", "mstdn.social": "rate_limited", "fosstodon.org": "found",
                      "hachyderm.io": "blocked", "infosec.exchange": "failed", "mas.to": "failed", "mastodon.world": "found"}
    assert out["sources"]["mastodon_mstdn_social"]["retry_after"] == 60 and out["sources"]["mastodon_mas_to"]["error_code"] == "timeout"
    assert out["sources"]["mastodon_hachyderm_io"] == {"site": "Mastodon (hachyderm.io)", "state": "blocked"}
    p = by_source(out)
    assert "mastodon" not in p and set(k for k in p if k.startswith("mastodon")) == {"mastodon_fosstodon_org", "mastodon_mastodon_world"}
    f = p["mastodon_fosstodon_org"]
    assert (f["site"], f["handle"], f["url"], f["display_name"]) == ("Mastodon (fosstodon.org)", "SamExample", "https://fosstodon.org/@SamExample", "Sam Example")
    # rel=me links the instance verified keep their proof on every instance
    assert f["accounts"] == [{"site": "GitHub", "handle": H, "url": "https://github.com/samexample", "proof": "verified_link"},
                             {"site": "sam.example.org", "handle": "", "url": "https://sam.example.org", "proof": "verified_link"}]
    assert f["avatar_state"] == "ok" and "https://files.fosstodon.org/accounts/avatars/000/000/001/original/0000000000000000.png" in pictures
    # one request per instance, each with the handle and nothing else
    asked = [c for c in calls if c.url.host in mastodon.INSTANCES]
    assert sorted(c.url.host for c in asked) == sorted(mastodon.INSTANCES) and all(dict(c.url.params) == {"acct": H} for c in asked)
    # the settled answers are kept for the day, the others are asked again soon, each alone
    assert ttl("mastodon") > 23 * 3600 and ttl("mastodon_fosstodon_org") > 23 * 3600
    assert all(0 < ttl(i) <= pf.CACHE_TTL_PARTIAL for i in ("mastodon_mstdn_social", "mastodon_hachyderm_io", "mastodon_infosec_exchange", "mastodon_mas_to"))
    assert pf._backing_off("mastodon_mstdn_social") and not pf._backing_off("mastodon") and not pf._backing_off("mastodon_fosstodon_org")


def test_a_mastodon_instance_reads_only_its_own_accounts_and_notes_a_move(monkeypatch):
    remote = {**json.loads(masto("hachyderm.io")), "acct": "SamExample@mastodon.social"}
    moved = {**json.loads(masto("mas.to")), "moved": {"id": "1", "username": "SamExample", "acct": "SamExample@fosstodon.org"}}
    pages = found() | {"hachyderm.io/api/v1/accounts/lookup": j(200, remote), "mas.to/api/v1/accounts/lookup": j(200, moved)}
    world(monkeypatch, pages)
    out = run()
    assert out["sources"]["mastodon_hachyderm_io"]["state"] == "unknown" and "mastodon_hachyderm_io" not in by_source(out)
    assert by_source(out)["mastodon_mas_to"]["note"] == "moved" and by_source(out)["mastodon"]["note"] == ""


def test_launchpad_reads_the_person_and_says_what_kind_of_record_it_is(monkeypatch):
    calls, pictures = world(monkeypatch, found())
    lp = by_source(run("SamExample"))["launchpad"]          # Launchpad names are lower case, whatever was typed
    assert next(c for c in calls if c.url.host == "api.launchpad.net").url.path == "/1.0/~samexample"
    assert (lp["site"], lp["handle"], lp["url"], lp["display_name"]) == ("Launchpad", H, "https://launchpad.net/~samexample", "Sam Example")
    assert lp["bio"] == "Maps and bread. Invented person for a test fixture." and lp["created"] == "2011-05-26T10:29:24Z"
    assert lp["stats"] == {"karma": 1204} and lp["note"] == "" and lp["emails"] == [] and lp["avatar_state"] == "none"
    assert not any("launchpad" in u for u in pictures)       # its picture address is a redirect, so it is not read
    record = json.loads(fx("launchpad_found.json"))
    for change, note in (({"is_valid": False, "karma": 0}, pf.launchpad.NOT_ACTIVE), ({"is_team": True}, "team"), ({"is_team": True, "is_valid": False}, "team")):
        pf.clear_cache_for_tests()
        world(monkeypatch, with_source("launchpad", j(200, {**record, **change})))
        assert by_source(run())["launchpad"]["note"] == note
    assert len(pf.launchpad.NOT_ACTIVE) <= base.NOTE_MAX
    pf.clear_cache_for_tests()
    world(monkeypatch, with_source("launchpad", j(200, {**record, "name": "somebody-else"})))
    assert run()["sources"]["launchpad"]["state"] == "unknown"


def test_gitea_reads_the_user_and_drops_the_placeholder_address(monkeypatch):
    world(monkeypatch, found())
    g = by_source(run())["gitea"]
    assert (g["site"], g["handle"], g["url"], g["display_name"], g["location"]) == ("Gitea.com", H, "https://gitea.com/samexample", "Sam Example", "Lisbon")
    assert g["emails"] == [] and g["website"] == "https://sam.example.org" and g["created"] == "2018-11-27T17:33:38Z" and g["note"] == ""
    assert g["stats"] == {"followers": 7, "following": 2, "starred": 31} and g["avatar_state"] == "ok"
    shown = {**json.loads(fx("gitea_found.json")), "email": "sam@example.org", "type": "Organization"}
    pf.clear_cache_for_tests()
    world(monkeypatch, with_source("gitea", j(200, shown)))
    g = by_source(run())["gitea"]
    assert g["emails"] == ["sam@example.org"] and g["note"] == "organization"


# ---- the cache ---------------------------------------------------------------------------

def test_the_answer_is_cached_for_a_day_per_handle_as_typed(monkeypatch):
    calls, pictures = world(monkeypatch, found())
    first = run()
    n, k = len(calls), len(pictures)
    second = run()
    assert second["cached"] is True and first["cached"] is False and len(calls) == n and len(pictures) == k
    assert second["profiles"] == first["profiles"] and second["sources"] == first["sources"]
    assert first["asked"] == ALL and second["asked"] == [] and all(ttl(s) > 23 * 3600 for s in ALL)
    run("SamExample")                # Hacker News IDs are case sensitive, so another spelling is another question
    assert len(calls) > n and {k[1] for k in pf._cache} == {H, "SamExample"}


def test_one_unsettled_source_is_asked_again_alone(monkeypatch):
    calls, pictures = world(monkeypatch, with_source("lichess", httpx.Response(503, text="")))
    first = run()
    assert first["sources"]["lichess"]["state"] == "failed" and first["cached"] is False and first["asked"] == ALL
    del calls[:], pictures[:]
    second = run()                      # inside the ten minutes: everything is still kept
    assert second["cached"] is True and calls == [] and second["sources"] == first["sources"]
    pf._cache[("lichess", H)] = (time.time() - 1, *pf._cache[("lichess", H)][1:])       # the short keep has run out
    world(monkeypatch, found(), calls, pictures)
    third = run()
    assert {c.url.host for c in calls} == {"lichess.org"} and len(calls) == 1 and pictures == []
    assert third["asked"] == ["lichess"] and third["cached"] is False
    assert third["sources"]["lichess"]["state"] == "found" and [p["source"] for p in third["profiles"]] == ALL
    assert {k: v for k, v in by_source(third).items() if k != "lichess"} == by_source(first)
    assert ttl("lichess") > 23 * 3600


def test_a_failed_picture_is_fetched_again_with_its_profile_only(monkeypatch):
    calls, _ = world(monkeypatch, found())

    async def broken(images):
        return {"results": [{"id": i["id"], "error": "The image could not be read.", "error_code": "bad_response"} if i["id"] == "codeberg"
                            else {"id": i["id"], "hash": "0f1e2d3c4b5a6978", "default": False, "thumb": THUMB} for i in images]}
    monkeypatch.setattr(pf, "run_avatar_hash", broken)
    assert by_source(run())["codeberg"]["avatar_state"] == "failed"
    pf._cache[("codeberg", H)] = (time.time() - 1, *pf._cache[("codeberg", H)][1:])
    del calls[:]
    _, pictures = world(monkeypatch, found(), calls)
    out = run()
    assert {c.url.host for c in calls} == {"codeberg.org"} and len(pictures) == 1 and out["asked"] == ["codeberg"]
    assert by_source(out)["codeberg"]["avatar_state"] == "ok"


def test_a_source_that_said_429_is_left_alone_for_everyone_for_a_while(monkeypatch):
    limited = httpx.Response(429, text="{}", headers={"content-type": "application/json", "retry-after": "120"})
    calls, _ = world(monkeypatch, with_source("gravatar", limited))
    first = run()
    assert first["sources"]["gravatar"]["state"] == "rate_limited" and first["sources"]["gravatar"]["retry_after"] == 120
    del calls[:]
    other = run("otherhandle")          # another handle, moments later: Gravatar is not asked
    assert not any(c.url.host == "api.gravatar.com" for c in calls) and len(calls) > 10
    entry = other["sources"]["gravatar"]
    assert entry["state"] == "rate_limited" and entry["error_code"] == "rate_limited" and 0 < entry["retry_after"] <= 120
    assert "gravatar" not in other["asked"] and ("gravatar", "otherhandle") not in pf._cache
    # when the wait is over it is asked again
    pf._backoff["gravatar"] = time.time() - 1
    del calls[:]
    world(monkeypatch, found(), calls)
    third = run("thirdhandle")
    assert any(c.url.host == "api.gravatar.com" for c in calls) and "gravatar" in third["asked"] and "gravatar" not in pf._backoff


def test_the_wait_after_a_429_has_a_default_and_a_ceiling(monkeypatch):
    for header, want in (({}, pf.BACKOFF_DEFAULT), ({"retry-after": "999999"}, pf.BACKOFF_MAX), ({"retry-after": "Wed, 21 Oct 2026 07:28:00 GMT"}, pf.BACKOFF_DEFAULT),
                         ({"retry-after": "0"}, pf.BACKOFF_DEFAULT), ({"retry-after": "-5"}, pf.BACKOFF_DEFAULT)):
        pf.clear_cache_for_tests()
        world(monkeypatch, with_source("lobsters", httpx.Response(429, text="", headers=header)))
        assert run()["sources"]["lobsters"]["retry_after"] == want, header
        assert 0 < pf._backoff["lobsters"] - time.time() <= want
    # the API's own rate message in a 200 or a 400 counts too
    pf.clear_cache_for_tests()
    world(monkeypatch, with_source("codeforces", j(400, {"status": "FAILED", "comment": "Call limit exceeded"})))
    assert run()["sources"]["codeforces"]["state"] == "rate_limited" and pf._backing_off("codeforces")


def test_the_cache_is_bounded_and_expires(monkeypatch):
    monkeypatch.setattr(pf, "CACHE_MAX", 3)
    for i in range(6):
        pf._cache_put(("gitlab", f"h{i}"), {"site": "GitLab", "state": "not_found"}, None, 60)
    assert list(pf._cache) == [("gitlab", "h3"), ("gitlab", "h4"), ("gitlab", "h5")]
    pf._cache_put(("gitlab", "old"), {"site": "GitLab", "state": "not_found"}, None, -1)
    assert pf._cache_get(("gitlab", "old")) is None and ("gitlab", "old") not in pf._cache


# ---- the endpoint ------------------------------------------------------------------------

def test_endpoint_validates_and_answers_in_the_documented_shape(monkeypatch):
    calls, _ = world(monkeypatch, found())
    with TestClient(app) as c:
        # Seven requests here and one in the next test: the route allows ten a minute.
        for bad in ("", "a b", "x" * 65, "-rf", "a/b"):
            assert c.post("/api/recon/profiles", json={"username": bad}).status_code == 400, bad
        assert calls == []
        assert c.post("/api/recon/profiles", json={}).status_code == 422
        assert c.get("/api/recon/profiles").status_code == 405
        r = c.post("/api/recon/profiles", json={"username": "@samexample"})
    body = r.json()
    assert r.status_code == 200 and set(body) == {"username", "profiles", "sources", "cached", "asked"} and body["username"] == H
    assert list(body["sources"]) == ALL and len(body["profiles"]) == N
    assert all(set(e) >= {"site", "state"} and e["state"] in pf.STATES for e in body["sources"].values())
    assert match_limit("/api/recon/profiles") == ("/api/recon/profiles", 10, 60)


def test_names_and_bios_go_on_the_visitors_record_for_the_minor_guard(monkeypatch):
    young = {**json.loads(fx("devto_found.json")), "summary": "Maps. " * 120 + "16 | junior in high school"}       # the signal is past what a row shows
    pages = found()
    pages["dev.to/api/users/by_username"] = j(200, young)
    world(monkeypatch, pages)
    with TestClient(app) as c:
        r = c.post("/api/recon/profiles", json={"username": H})
        assert r.status_code == 200
        profile_record.bind(c.cookies.get("crawlr_run"))
        texts = profile_record.texts(H)
        assert profile_record.outcomes(H) == {"profiles": "ok"}
        # text to scan and nothing more: this source never counts as having read the profiles
        assert not profile_record.ran(H) and "profiles" not in profile_record.profile_readers() and adult_guard.gate(H)[0] == 409
        by_site = {t["source"]: t for t in texts}
        assert set(by_site) == {s.SITE for s in pf.SOURCES} - {"npm", "Wikipedia"}       # those two rows carry no name and no text
        assert by_site["Keybase"] == {"source": "Keybase", "url": "https://keybase.io/samexample", "name": "Sam Example",
                                      "bio": "Maps and bread. Invented person for a test fixture.", "text": "Lisbon"}
        assert by_site["Docker Hub"]["text"] == "Example Maps\nLisbon" and by_site["Hacker News"]["bio"].count("\n") == 2
        row = next(p for p in r.json()["profiles"] if p["source"] == "devto")
        assert "junior" not in row["bio"] and len(row["bio"]) == base.BIO_MAX and by_site["dev.to"]["bio"].endswith("16 | junior in high school")
        # once a profile reader has answered, the adult pass is refused on this text
        profile_record.note(H, "maigret", {"results": []})
        refused = adult_guard.gate(H)
        assert refused and refused[0] == 400
        # another visitor has no such record
        profile_record.bind("")
        assert profile_record.texts(H) == []


def test_the_record_reads_only_profiles_that_were_found():
    answer = {"profiles": [{"site": "GitLab", "url": "https://gitlab.com/x", "state": "found", "display_name": "River", "bio": "short", "company": "Co", "location": "Leeds",
                            "guard": {"bio": "the whole bio"}},
                           {"site": "Odd", "url": "https://odd.example.org/x", "state": "blocked", "display_name": "No", "bio": "no"},
                           {"site": "Pornhub", "url": "https://www.pornhub.com/users/x", "state": "found", "bio": "i'm 15"},
                           "junk", {"site": "Empty", "url": "https://e.example.org/x", "state": "found"}]}
    assert profile_record.entries_of("profiles", answer) == [
        {"source": "GitLab", "url": "https://gitlab.com/x", "name": "River", "bio": "the whole bio", "text": "Co\nLeeds"}]
    assert profile_record.entries_of("profiles", {}) == [] and "profiles" in profile_record.SOURCES


def test_nothing_about_the_handle_or_a_profile_is_logged(monkeypatch, caplog):
    pages = {k: v for k, v in with_source("keybase", httpx.ConnectError(f"refused for {H}")).items() if not k.startswith("lichess.org/")}
    pages["lichess.org/"] = httpx.Response(429, text=f"slow down {H}")
    world(monkeypatch, pages)

    async def boom(images):
        raise RuntimeError(f"decoder blew up for {H}")
    monkeypatch.setattr(pf, "run_avatar_hash", boom)
    with caplog.at_level("DEBUG"):
        run()
    ours = [r for r in caplog.records if r.name.startswith("modules.profiles")]
    assert {r.getMessage() for r in ours} == {"profile source did not answer", "profile pictures failed", "profile sources answered"}
    summary = next(r for r in ours if r.getMessage() == "profile sources answered")
    assert (summary.asked, summary.found, summary.failed, summary.rate_limited) == (N, N - 2, 1, 1)
    for r in caplog.records:
        line = (r.getMessage() + json.dumps({k: str(v) for k, v in r.__dict__.items()})).lower()
        assert H not in line and "sam example" not in line and "example.org" not in line and "lisbon" not in line, r.getMessage()


def test_handle_probe_still_reads_bluesky_through_this_package(monkeypatch):
    from modules import handle_probe as hp
    assert hp.bluesky is pf.bluesky
    world(monkeypatch, {"public.api.bsky.app/": j(200, bsky("bluesky_profile.json"))})
    states, rows = asyncio.run(hp._bluesky(H))
    assert states == {"Bluesky": "found"} and rows[0]["url"] == "https://bsky.app/profile/samexample.bsky.social" and rows[0]["followers"] == 10
    assert rows[0]["_avatar"].startswith("https://cdn.bsky.app/")
    assert asyncio.run(hp._bluesky("sam_example")) == ({"Bluesky": "not_asked"}, [])
