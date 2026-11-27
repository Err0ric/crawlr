"""Commit emails on GitLab, Codeberg and Gitea.com (modules/commit_emails.py), replayed from
tests/fixtures/commit_emails. Every person in the fixtures is invented. No network."""

import asyncio
import json
import time
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from core.adult_sites import is_adult_site
from main import app
from middleware.rate_limit import match_limit
from modules import commit_emails as ce

FIX = Path(__file__).parent / "fixtures"
REAL_ASYNC_CLIENT = httpx.AsyncClient
H = "samexample"
ROW_KEYS = {"email", "name", "how", "how_note", "self_declared", "commits", "first_commit", "last_commit", "repos"}
TOP_KEYS = {"site", "site_name", "username", "state", "cached", "emails", "emails_state", "complete", "sections", "repos", "counts", "requests", "note"}


def fx(name: str) -> str:
    folder = "profiles" if name.startswith("profiles/") else "commit_emails"
    return (FIX / folder / name.removeprefix("profiles/")).read_text(encoding="utf-8")


def j(status, body, **headers):
    return httpx.Response(status, text=body if isinstance(body, str) else json.dumps(body), headers={"content-type": "application/json", **headers})


def gitlab_pages() -> dict:
    return {
        "gitlab.com/api/v4/users": j(200, fx("gitlab_user.json")),
        "gitlab.com/api/v4/users/1000001/projects": j(200, fx("gitlab_projects.json")),
        "gitlab.com/api/v4/projects/3000001/repository/commits": j(200, fx("gitlab_commits_maps.json")),
        "gitlab.com/api/v4/projects/3000004/repository/commits": j(200, fx("gitlab_commits_notes.json")),
        "gitlab.com/api/v4/projects/3000005/repository/commits": j(404, fx("gitlab_commits_none.json")),
    }


def forgejo_pages(host: str = "codeberg.org") -> dict:
    swap = lambda text: text.replace("codeberg.org", host)      # noqa: E731
    return {
        f"{host}/api/v1/users/samexample": j(200, swap(fx("profiles/codeberg_found.json"))),
        f"{host}/api/v1/users/samexample/repos": j(200, swap(fx("codeberg_repos.json"))),
        f"{host}/api/v1/repos/samexample/maps/commits": j(200, swap(fx("codeberg_commits_maps.json"))),
        f"{host}/api/v1/repos/samexample/bread/commits": j(200, swap(fx("codeberg_commits_bread.json"))),
        f"{host}/api/v1/repos/samexample/tiles-fork/commits": j(200, swap(fx("codeberg_commits_fork.json"))),
    }


def world(monkeypatch, pages: dict, calls: list | None = None):
    calls = [] if calls is None else calls

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

    monkeypatch.setattr(ce.httpx, "AsyncClient", lambda *a, **k: REAL_ASYNC_CLIENT(transport=httpx.MockTransport(handler), follow_redirects=True))
    return calls


@pytest.fixture(autouse=True)
def _clean():
    ce.clear_cache_for_tests()
    yield
    ce.clear_cache_for_tests()


def run(site="gitlab", username=H):
    return asyncio.run(ce.run_commit_emails(site, username))


def ttl(site: str, handle: str = H) -> float:
    return ce._cache[(site, handle)][0] - time.time()


# ---- the list of sites ---------------------------------------------------------------------

def test_three_fixed_hosts_none_of_them_adult_and_the_caps_are_small():
    assert {k: f.host for k, f in ce.SITES.items()} == {"gitlab": "gitlab.com", "codeberg": "codeberg.org", "gitea": "gitea.com"}
    assert not any(is_adult_site(f.name, f"https://{f.host}/") for f in ce.SITES.values())
    assert ce.MAX_REQUESTS == 5 and ce.MAX_REPOS == 3 and 1 + 1 + ce.MAX_REPOS <= ce.MAX_REQUESTS
    text = Path(ce.__file__).read_text(encoding="utf-8")
    assert "\u2014" not in text and "\u2013" not in text and "str(e)" not in text and "str(exc" not in text
    here = Path(__file__).read_text(encoding="utf-8")
    assert "\u2014" not in here and "\u2013" not in here


# ---- GitLab: only the author line can tie a commit to the account ------------------------------

def test_gitlab_reads_own_commits_in_the_accounts_own_projects(monkeypatch):
    calls = world(monkeypatch, gitlab_pages())
    out = run()
    assert set(out) == TOP_KEYS | {"handle", "profile_url", "display_name"}
    assert (out["site"], out["site_name"], out["username"], out["state"], out["cached"]) == ("gitlab", "GitLab", H, "found", False)
    assert (out["handle"], out["profile_url"], out["display_name"]) == ("SamExample", "https://gitlab.com/SamExample", "Sam Example")
    assert out["note"] == ce.NOTE and "self-declared" in out["note"] and "forged" in out["note"]

    # the account's own namespace only, a project with a branch only, the three most recent
    assert out["repos"] == [
        {"name": "SamExample/maps", "url": "https://gitlab.com/SamExample/maps", "fork": None, "state": "ok", "commits_seen": 9},
        {"name": "SamExample/bread_notes", "url": "https://gitlab.com/SamExample/bread_notes", "fork": None, "state": "ok", "commits_seen": 2},
        {"name": "SamExample/dot.files", "url": "https://gitlab.com/SamExample/dot.files", "fork": None, "state": "empty", "commits_seen": 0},
    ]
    assert out["sections"] == {"account": "found", "repos": "ok"} and out["complete"] is True and out["emails_state"] == "found"
    assert out["counts"] == {"repos_listed": 4, "repos_read": 2, "commits_seen": 11, "own": 8, "noreply": 1, "other_authors": 3}

    assert all(set(r) == ROW_KEYS and r["self_declared"] is True and r["how"] == "author_line_match" for r in out["emails"])
    assert all(r["how_note"] == ce.HOW_NOTES["author_line_match"] and "weakly" in r["how_note"] for r in out["emails"])
    assert [(r["email"], r["name"], r["commits"]) for r in out["emails"]] == [
        ("sam@example.org", "Sam Example", 4),                  # one row whatever the capitals of the address
        ("sam.work@example.com", "samexample", 1),              # the author name is the login
        ("samexample@example.net", "an old nickname", 1),       # the local part is the login
        ("sam.home@example.org", "Sam Example", 1),
    ]
    first = out["emails"][0]
    assert (first["first_commit"], first["last_commit"]) == ("2019-07-07T07:07:07Z", "2026-10-27T10:47:39Z")
    assert first["repos"] == ["SamExample/maps", "SamExample/bread_notes"]
    # another author's address is never returned, and neither is a placeholder
    text = json.dumps(out)
    assert "river" not in text.lower() and "bot@example.com" not in text and "noreply.gitlab.com" not in text

    assert len(calls) == out["requests"] == 5 and {c.url.host for c in calls} == {"gitlab.com"}
    assert all(c.method == "GET" and "authorization" not in c.headers and "private-token" not in c.headers and "CrawlR" in c.headers["user-agent"] for c in calls)
    assert calls[0].url.params["username"] == H and dict(calls[1].url.params) == {"order_by": "last_activity_at", "per_page": "20"}
    assert sorted(c.url.path for c in calls[2:]) == [f"/api/v4/projects/{n}/repository/commits" for n in (3000001, 3000004, 3000005)]
    assert all(c.url.params["per_page"] == "30" for c in calls[2:])


def test_gitlabs_empty_list_is_not_found_and_a_404_there_is_not(monkeypatch):
    calls = world(monkeypatch, {"gitlab.com/": j(200, "[]")})
    out = run()
    assert (out["state"], out["emails_state"], out["complete"], out["emails"], out["requests"]) == ("not_found", "none", True, [], 1)
    assert out["sections"] == {"account": "not_found", "repos": "not_asked"} and len(calls) == 1 and ttl("gitlab") > 23 * 3600
    ce.clear_cache_for_tests()
    world(monkeypatch, {"gitlab.com/": j(404, {"message": "404 Not Found"})})
    assert run()["state"] == "unknown"


def test_an_account_with_nothing_to_read_is_none_and_complete(monkeypatch):
    pages = gitlab_pages()
    pages["gitlab.com/api/v4/users/1000001/projects"] = j(200, "[]")
    calls = world(monkeypatch, pages)
    out = run()
    assert (out["state"], out["sections"]["repos"], out["emails_state"], out["complete"], out["repos"]) == ("found", "none", "none", True, [])
    assert len(calls) == 2 and ttl("gitlab") > 23 * 3600


def test_only_other_peoples_commits_gives_none_with_the_count(monkeypatch):
    pages = gitlab_pages()
    other = [c for c in json.loads(fx("gitlab_commits_maps.json")) if c["author_name"] in ("River Other", "Dependency Bot")]
    for pid in (3000001, 3000004, 3000005):
        pages[f"gitlab.com/api/v4/projects/{pid}/repository/commits"] = j(200, other)
    world(monkeypatch, pages)
    out = run()
    assert out["emails"] == [] and out["emails_state"] == "none" and out["complete"] is True
    assert out["counts"]["other_authors"] == 9 and out["counts"]["own"] == 0


# ---- Codeberg and Gitea.com: the forge links a commit to an account ---------------------------

@pytest.mark.parametrize("site,host", [("codeberg", "codeberg.org"), ("gitea", "gitea.com")])
def test_forgejo_prefers_what_the_forge_attributes_and_originals_before_forks(monkeypatch, site, host):
    calls = world(monkeypatch, forgejo_pages(host))
    out = run(site)
    assert (out["state"], out["handle"], out["profile_url"], out["display_name"]) == ("found", H, f"https://{host}/samexample", "Sam Example")
    # no mirror, no empty repository, nobody else's repository; the fork comes last
    assert [(r["name"], r["fork"], r["state"], r["commits_seen"]) for r in out["repos"]] == [
        ("samexample/maps", False, "ok", 6), ("samexample/bread", False, "ok", 1), ("samexample/tiles-fork", True, "ok", 2)]
    assert all(r["url"] == f"https://{host}/{r['name']}" for r in out["repos"])
    assert out["emails"] == [
        {"email": "sam@example.org", "name": "Sam Example", "how": "forge_attributed", "commits": 3, "first_commit": "2026-01-15T09:00:00Z",
         "last_commit": "2026-10-30T09:00:00Z", "repos": ["samexample/maps", "samexample/tiles-fork"],
         "how_note": ce.HOW_NOTES["forge_attributed"], "self_declared": True},
        # first seen on an unlinked commit under the profile's name, then linked by the forge in another repository: the stronger tie stands
        {"email": "sam.old@example.com", "name": "Sam Example", "how": "forge_attributed", "commits": 2, "first_commit": "2024-12-03T04:31:23Z",
         "last_commit": "2025-10-10T08:00:00Z", "repos": ["samexample/maps", "samexample/bread"],
         "how_note": ce.HOW_NOTES["forge_attributed"], "self_declared": True},
    ]
    assert out["counts"] == {"repos_listed": 3, "repos_read": 3, "commits_seen": 9, "own": 6, "noreply": 1, "other_authors": 3}
    text = json.dumps(out).lower()
    assert "river" not in text and "upstream" not in text and "weblate" not in text and "@noreply" not in text
    assert len(calls) == out["requests"] == 5 and {c.url.host for c in calls} == {host}
    assert dict(calls[1].url.params) == {"limit": "10"}
    assert all(dict(c.url.params) == {"limit": "30", "stat": "false", "verification": "false", "files": "false"} for c in calls[2:])


def test_an_unlinked_commit_under_the_accounts_name_is_the_weaker_tie(monkeypatch):
    pages = forgejo_pages()
    del pages["codeberg.org/api/v1/repos/samexample/bread/commits"]
    pages["codeberg.org/api/v1/repos/samexample/bread/commits"] = j(409, {"message": "Git Repository is empty."})
    world(monkeypatch, pages)
    out = run("codeberg")
    rows = {r["email"]: r for r in out["emails"]}
    assert rows["sam.old@example.com"]["how"] == "author_line_match" and rows["sam@example.org"]["how"] == "forge_attributed"
    assert [r["email"] for r in out["emails"]] == ["sam@example.org", "sam.old@example.com"]       # the stronger tie first
    assert out["repos"][1]["state"] == "empty" and out["complete"] is True


def test_the_rules_alone():
    assert ce.is_own("Sam Example", "x@example.org", "samexample", "Sam Example") and ce.is_own(" SAMEXAMPLE ", "", "samexample", "")
    assert ce.is_own("whoever", "SamExample@example.org", "samexample", "") and not ce.is_own("", "", "samexample", "")
    assert not ce.is_own("Sam", "sam@example.org", "samexample", "Sam Example") and not ce.is_own("", "x@example.org", "samexample", "")
    repo = {"name": "samexample/maps"}
    many = [{"name": "samexample", "email": f"sam{i}@example.org", "date": "2026-01-01T00:00:00Z", "linked": False} for i in range(15)]
    odd = [{"name": "samexample", "email": "not an address", "date": None, "linked": True},
           {"name": "samexample\u202e\x00 x", "email": "sam@example.org", "date": "never", "linked": True}]
    rows, counts = ce.collect([(repo, many + odd)], "samexample", "")
    assert len(rows) == ce.MAX_EMAILS and rows[0] == {"email": "sam@example.org", "name": "samexample x", "how": "forge_attributed", "commits": 1,
                                                       "first_commit": "", "last_commit": "", "repos": ["samexample/maps"],
                                                       "how_note": ce.HOW_NOTES["forge_attributed"], "self_declared": True}
    assert counts == {"commits_seen": 17, "own": 17, "noreply": 0, "other_authors": 0}
    picked = ce.pick_repos([{"name": n, "fork": f, "_at": at} for n, f, at in (("a", True, "2026"), ("b", False, "2021"), ("c", None, "2024"), ("d", False, "2022"), ("e", True, "2025"))])
    assert [r["name"] for r in picked] == ["c", "d", "b"]


# ---- a refusal or a failure is never "not found", and never "no addresses" ---------------------

@pytest.mark.parametrize("site,host", [("gitlab", "gitlab.com"), ("codeberg", "codeberg.org"), ("gitea", "gitea.com")])
@pytest.mark.parametrize("answer,state,code", [
    (httpx.Response(403, text="<html>Just a moment...</html>"), "blocked", None),
    (httpx.Response(401, text="{}"), "blocked", None),
    (httpx.Response(200, text="<!doctype html><html>Checking your browser</html>"), "blocked", None),
    (httpx.Response(429, text="{}", headers={"retry-after": "90"}), "rate_limited", "rate_limited"),
    (httpx.Response(503, text="upstream connect error"), "failed", "upstream"),
    (httpx.Response(200, text="{\"truncated\": "), "failed", "bad_response"),
    (httpx.ConnectTimeout(f"timed out asking for {H}"), "failed", "timeout"),
    (httpx.ConnectError(f"refused https://example.invalid/{H}"), "failed", "unreachable"),
    (httpx.Response(302, headers={"location": "https://evil.example.net/steal"}), "unknown", None),
    (httpx.Response(418, text="{}"), "unknown", None),
])
def test_an_account_lookup_that_did_not_answer(monkeypatch, site, host, answer, state, code):
    calls = world(monkeypatch, {f"{host}/": answer, "evil.example.net/": j(200, "[]")})
    out = run(site)
    assert out["state"] == state and out["state"] != "not_found" and out["emails"] == []
    assert out["emails_state"] == "unknown" and out["complete"] is False and out["sections"] == {"account": state, "repos": "not_asked"}
    assert ("error_code" in out) == (code is not None)
    if code:
        assert out["error_code"] == code and out["error"] and H not in json.dumps(out).replace(f'"username": "{H}"', "") and "example.invalid" not in json.dumps(out)
    assert out.get("retry_after") == (90 if state == "rate_limited" else None)
    assert len(calls) == 1 and all(c.url.host == host for c in calls) and 0 < ttl(site) <= ce.CACHE_TTL_PARTIAL


@pytest.mark.parametrize("status,state", [(403, "blocked"), (429, "rate_limited"), (500, "failed"), (404, "not_found")])
def test_a_repository_list_that_did_not_answer_leaves_the_emails_unknown(monkeypatch, status, state):
    pages = gitlab_pages()
    pages["gitlab.com/api/v4/users/1000001/projects"] = httpx.Response(status, text="{}")
    calls = world(monkeypatch, pages)
    out = run()
    assert out["state"] == "found" and out["sections"] == {"account": "found", "repos": state}
    assert out["emails"] == [] and out["emails_state"] == "unknown" and out["complete"] is False and len(calls) == 2
    assert 0 < ttl("gitlab") <= ce.CACHE_TTL_PARTIAL
    assert ("retry_after" in out) == (state == "rate_limited")


def test_one_repository_that_did_not_answer_keeps_the_others_and_is_incomplete(monkeypatch):
    pages = gitlab_pages()
    pages["gitlab.com/api/v4/projects/3000001/repository/commits"] = httpx.Response(403, text="{}")
    world(monkeypatch, pages)
    out = run()
    assert [r["state"] for r in out["repos"]] == ["blocked", "ok", "empty"] and out["complete"] is False
    assert [r["email"] for r in out["emails"]] == ["sam@example.org", "sam.home@example.org"] and out["emails_state"] == "found"
    assert 0 < ttl("gitlab") <= ce.CACHE_TTL_PARTIAL
    # nothing read at all and a part missing: unknown, never none
    ce.clear_cache_for_tests()
    for pid in (3000001, 3000004, 3000005):
        pages[f"gitlab.com/api/v4/projects/{pid}/repository/commits"] = httpx.Response(503, text="")
    world(monkeypatch, pages)
    out = run()
    assert out["emails_state"] == "unknown" and [r["state"] for r in out["repos"]] == ["failed"] * 3


def test_an_answer_about_somebody_else_is_unknown(monkeypatch):
    world(monkeypatch, gitlab_pages() | forgejo_pages() | {"codeberg.org/api/v1/users/samexampla": j(200, fx("profiles/codeberg_found.json"))})
    assert run("gitlab", "samexampla")["state"] == "unknown" and run("codeberg", "samexampla")["state"] == "unknown"


def test_a_handle_the_site_cannot_hold_is_not_asked(monkeypatch):
    calls = world(monkeypatch, gitlab_pages() | forgejo_pages())
    for site, handle in (("gitlab", "s"), ("codeberg", "sam."), ("gitea", "a" * 41)):
        out = run(site, handle)
        assert (out["state"], out["requests"], out["emails_state"]) == ("not_asked", 0, "unknown") and set(out) == TOP_KEYS
    assert calls == [] and not ce._cache


def test_the_request_cap_holds_whatever_the_list_says(monkeypatch):
    monkeypatch.setattr(ce, "MAX_REPOS", 10)
    calls = world(monkeypatch, gitlab_pages() | {"gitlab.com/api/v4/projects/3000006/repository/commits": j(200, fx("gitlab_commits_notes.json"))})
    out = run()
    assert len(calls) == ce.MAX_REQUESTS == out["requests"]
    assert [r["state"] for r in out["repos"]] == ["ok", "ok", "empty", "unknown"] and out["complete"] is False


def test_a_slow_site_ends_as_failed(monkeypatch):
    world(monkeypatch, gitlab_pages())
    monkeypatch.setattr(ce, "TOTAL_TIMEOUT", 0.05)

    async def hang(*a, **k):
        await asyncio.sleep(5)
    monkeypatch.setattr(ce, "_read", hang)
    out = run()
    assert out["state"] == "failed" and out["error_code"] == "timeout" and out["error_detail"] == "TimeoutError"


# ---- the cache and the wait after a 429 --------------------------------------------------------

def test_a_whole_answer_is_kept_for_a_day_whatever_the_capitals(monkeypatch):
    calls = world(monkeypatch, gitlab_pages())
    first = run()
    n = len(calls)
    second = run("gitlab", "SamExample")
    assert len(calls) == n and second["cached"] is True and first["cached"] is False and second["username"] == "SamExample"
    assert {k: v for k, v in second.items() if k not in ("cached", "username")} == {k: v for k, v in first.items() if k not in ("cached", "username")}
    assert ttl("gitlab") > 23 * 3600
    run("codeberg")          # another site is another question
    assert len(calls) > n


def test_a_429_leaves_the_site_alone_for_everyone_for_a_while(monkeypatch):
    calls = world(monkeypatch, {"codeberg.org/": httpx.Response(429, text="{}")} | gitlab_pages())
    assert run("codeberg")["retry_after"] == ce.BACKOFF_DEFAULT
    del calls[:]
    other = run("codeberg", "otherhandle")
    assert calls == [] and other["state"] == "rate_limited" and other["error_code"] == "rate_limited" and 0 < other["retry_after"] <= ce.BACKOFF_DEFAULT
    assert ("codeberg", "otherhandle") not in ce._cache
    assert run("gitlab")["state"] == "found"          # the wait belongs to the one site
    ce._backoff["codeberg"] = time.time() - 1
    ce._cache.clear()                                 # the refusal itself is kept for ten minutes
    world(monkeypatch, forgejo_pages())
    assert run("codeberg")["state"] == "found" and "codeberg" not in ce._backoff


def test_the_cache_is_bounded_and_expires(monkeypatch):
    monkeypatch.setattr(ce, "CACHE_MAX", 2)
    for i in range(4):
        ce._cache_put(("gitlab", f"h{i}"), {"state": "not_found"}, 60)
    assert list(ce._cache) == [("gitlab", "h2"), ("gitlab", "h3")]
    ce._cache_put(("gitlab", "old"), {"state": "not_found"}, -1)
    assert ce._cache_get(("gitlab", "old")) is None


# ---- the endpoint, and the log -----------------------------------------------------------------

def test_endpoint_validates_site_and_handle(monkeypatch):
    calls = world(monkeypatch, gitlab_pages())
    with TestClient(app) as c:
        for body in ({"site": "github", "username": H}, {"site": "evil.example.net", "username": H}, {"site": "", "username": H},
                     {"site": "gitlab", "username": "a b"}, {"site": "gitlab", "username": "a/b"}, {"site": "gitlab", "username": "-rf"}):
            assert c.post("/api/recon/commit-emails", json=body).status_code == 400, body
        assert c.post("/api/recon/commit-emails", json={"username": H}).status_code == 422
        assert c.get("/api/recon/commit-emails").status_code == 405
        assert calls == []
        r = c.post("/api/recon/commit-emails", json={"site": " GitLab ", "username": "@samexample"})
    body = r.json()
    assert r.status_code == 200 and body["state"] == "found" and body["username"] == H and len(body["emails"]) == 4
    assert match_limit("/api/recon/commit-emails") == ("/api/recon/commit-emails", 10, 60)


def test_nothing_about_the_account_is_logged(monkeypatch, caplog):
    world(monkeypatch, gitlab_pages())
    with caplog.at_level("DEBUG"):
        run()
        ce.clear_cache_for_tests()
        world(monkeypatch, {"gitlab.com/": httpx.ConnectError(f"refused for {H}")})
        run()
    ours = [r for r in caplog.records if r.name == "modules.commit_emails"]
    assert [r.getMessage() for r in ours] == ["commit emails finished"] * 2
    assert (ours[0].site, ours[0].state, ours[0].emails, ours[0].requests, ours[1].state) == ("gitlab", "found", 4, 5, "failed")
    for r in caplog.records:
        line = (r.getMessage() + json.dumps({k: str(v) for k, v in r.__dict__.items()})).lower()
        assert H not in line and "sam example" not in line and "example.org" not in line and "example.com" not in line, r.getMessage()
