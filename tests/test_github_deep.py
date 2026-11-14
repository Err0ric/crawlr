"""Deep GitHub pull, replayed from recorded API responses in tests/fixtures/github. No network."""

import asyncio
import base64
import hashlib
import json
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from main import app
from middleware.rate_limit import match_limit
from modules import github as gh

FIXTURES = Path(__file__).parent / "fixtures" / "github"
REAL_CLIENT = httpx.AsyncClient


def fixture(name: str) -> dict:
    return json.loads((FIXTURES / f"{name}.json").read_text(encoding="utf-8"))


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    gh.clear_cache_for_tests()
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    yield
    gh.clear_cache_for_tests()


def replay(monkeypatch, data: dict, calls: list | None = None, override=None):
    """Serve one user's recorded responses. `override(section, request)` may return a Response."""

    def section_of(request: httpx.Request) -> str:
        path = request.url.path
        if request.url.host == "raw.githubusercontent.com":
            return "readme"
        if path.startswith("/repos/"):
            return "commits"
        return {"social_accounts": "social_accounts", "orgs": "orgs", "repos": "repos", "keys": "keys",
                "gpg_keys": "gpg_keys", "public": "events"}[path.rsplit("/", 1)[-1]]

    def handler(request: httpx.Request):
        section = section_of(request)
        if calls is not None:
            calls.append((section, request))
        if override:
            resp = override(section, request)
            if resp is not None:
                return resp
        if section == "readme":
            return httpx.Response(200, text=data["readme"]) if data.get("readme") else httpx.Response(404, text="404: Not Found")
        return httpx.Response(200, json=data[section])

    monkeypatch.setattr(gh.httpx, "AsyncClient", lambda *a, **k: REAL_CLIENT(transport=httpx.MockTransport(handler)))


def deep(name: str) -> dict:
    return asyncio.run(gh.run_github_deep(name))


# ---- full results ------------------------------------------------------------------

def test_full_deep_result_for_torvalds(monkeypatch):
    calls = []
    replay(monkeypatch, fixture("torvalds"), calls)
    out = deep("torvalds")

    assert out["found"] is True and out["state"] == "ok" and out["cached"] is False
    assert set(out["sections"]) == set(gh.DEEP_SECTIONS) and set(out["sections"].values()) == {"ok"}
    assert out["social_accounts"] == [] and out["orgs"] == [] and out["readme_links"] == []
    assert out["keys"]["gpg"] == []

    # top repositories: by stars, forks left out, at most five
    names = [r["name"] for r in out["top_repos"]]
    assert names == ["linux", "AudioNoise", "GuitarPedal", "uemacs", "test-tlb"]
    assert out["top_repos"][0]["url"] == "https://github.com/torvalds/linux" and out["top_repos"][0]["language"] == "C"
    assert all(r["fork"] is False for r in out["top_repos"])
    assert out["languages"][0] == "C" and "C++" not in out["languages"]     # C++ only appears in a fork

    # the SSH key is reported as type and fingerprint, never as key material
    assert out["keys"]["ssh"] == [{"type": "ssh-rsa", "fingerprint": "SHA256:SlSdsTYgtT3jhz1QFhVbDqazjuoZLbtqMs8nIVqaL9A"}]
    assert "AAAAB3NzaC1yc2E" not in json.dumps(out)

    # public push events no longer carry commits, so the email comes from the one fallback call
    assert out["commit_emails"] == [{"email": "torvalds@linux-foundation.org", "name": "Linus Torvalds", "repo": "torvalds/linux"}]
    commits = [r for s, r in calls if s == "commits"]
    assert len(commits) == 1 and commits[0].url.path == "/repos/torvalds/linux/commits"
    assert commits[0].url.params["author"] == "torvalds"
    assert len(calls) == 8 <= gh.DEEP_MAX_REQUESTS


def test_full_deep_result_for_err0ric(monkeypatch):
    calls = []
    replay(monkeypatch, fixture("err0ric"), calls)
    out = deep("Err0ric")

    assert out["found"] is True and out["state"] == "ok"
    assert out["social_accounts"] == [
        {"provider": "linkedin", "url": "https://www.linkedin.com/in/eric-henderson-/"},
        {"provider": "mastodon", "url": "https://infosec.exchange/@Err0ric"},
    ]
    # README links: the project links stay, the raw.githubusercontent.com images go
    assert out["readme_links"] == ["https://github.com/Err0ric/lure", "https://darkwire.tech", "https://crawlr.lol"]
    assert out["top_repos"][0]["name"] == "crawlr" and all(not r["fork"] for r in out["top_repos"])
    assert out["keys"] == {"ssh": [], "gpg": []}
    # 3 of the 4 recorded commits use the GitHub noreply address; only the real one is reported
    assert [c["email"] for c in out["commit_emails"]] == ["err0ric@example.org"]
    assert out["commit_emails"][0]["repo"] == "Err0ric/crawlr"
    assert len(calls) <= gh.DEEP_MAX_REQUESTS


# ---- states ------------------------------------------------------------------------

@pytest.mark.parametrize("status", [403, 429])
def test_rate_limited_section_gives_partial_not_an_empty_answer(monkeypatch, status):
    limited = lambda section, request: httpx.Response(status, json={"message": "API rate limit exceeded"}) if section == "keys" else None
    replay(monkeypatch, fixture("torvalds"), override=limited)
    out = deep("torvalds")
    assert out["found"] is True and out["state"] == "partial"
    assert out["sections"]["ssh_keys"] == "rate_limited"
    assert {v for k, v in out["sections"].items() if k != "ssh_keys"} == {"ok"}
    assert out["top_repos"] and out["commit_emails"]          # the other sections still arrive


def test_failed_section_is_marked_failed(monkeypatch):
    def broken(section, request):
        if section == "orgs":
            return httpx.Response(502, text="bad gateway")
        if section == "social_accounts":
            raise httpx.ConnectTimeout("timed out")
        return None
    replay(monkeypatch, fixture("err0ric"), override=broken)
    out = deep("Err0ric")
    assert out["state"] == "partial"
    assert out["sections"]["orgs"] == "failed" and out["sections"]["social_accounts"] == "failed"


def test_everything_rate_limited_is_unknown_never_not_found(monkeypatch):
    replay(monkeypatch, fixture("torvalds"), override=lambda s, r: httpx.Response(403, json={}))
    out = deep("torvalds")
    assert out["found"] is None and out["error_code"] == "rate_limited"
    assert "torvalds" not in out["error"] and "http" not in out["error"]
    # and it is not cached: the next call asks again
    replay(monkeypatch, fixture("torvalds"))
    assert deep("torvalds")["found"] is True


def test_user_not_found(monkeypatch):
    calls = []
    replay(monkeypatch, {}, calls, override=lambda s, r: httpx.Response(404, json={"message": "Not Found"}))
    out = deep("nobody-here-zz9q")
    assert out == {"username": "nobody-here-zz9q", "found": False}
    assert not [s for s, _ in calls if s == "commits"]


def test_missing_profile_readme_is_not_a_failure(monkeypatch):
    replay(monkeypatch, fixture("torvalds"))      # the fixture has no README: raw host answers 404
    out = deep("torvalds")
    assert out["sections"]["readme_links"] == "ok" and out["readme_links"] == [] and out["state"] == "ok"


# ---- cache -------------------------------------------------------------------------

def test_cache_hit_spends_no_requests(monkeypatch):
    calls = []
    replay(monkeypatch, fixture("torvalds"), calls)
    first = deep("torvalds")
    spent = len(calls)
    second = deep("Torvalds")
    assert first["cached"] is False and second["cached"] is True and len(calls) == spent
    assert second["top_repos"] == first["top_repos"]


def test_partial_results_are_cached_briefly_and_complete_ones_for_a_day(monkeypatch):
    replay(monkeypatch, fixture("torvalds"), override=lambda s, r: httpx.Response(429, json={}) if s == "orgs" else None)
    assert deep("torvalds")["state"] == "partial"
    expires, _ = gh._deep_cache["torvalds"]
    assert 0 < expires - gh.time.time() <= gh.DEEP_TTL_PARTIAL

    gh.clear_cache_for_tests()
    replay(monkeypatch, fixture("torvalds"))
    assert deep("torvalds")["state"] == "ok"
    expires, _ = gh._deep_cache["torvalds"]
    assert expires - gh.time.time() > 23 * 3600

    # an expired entry is dropped
    gh._deep_cache["torvalds"] = (gh.time.time() - 1, {"found": True})
    assert gh._deep_cache_get("torvalds") is None


def test_token_goes_to_the_api_but_not_to_the_raw_file_host(monkeypatch):
    calls = []
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_test_token")
    replay(monkeypatch, fixture("err0ric"), calls)
    deep("Err0ric")
    for section, request in calls:
        if section == "readme":
            assert "authorization" not in request.headers
        else:
            assert request.headers["authorization"] == "Bearer ghp_test_token"


# ---- commit emails -----------------------------------------------------------------

def push_event(actor: str, commits: list[tuple[str, str]], repo: str = "torvalds/linux") -> dict:
    return {"type": "PushEvent", "actor": {"login": actor}, "repo": {"name": repo}, "payload": {"commits": [
        {"sha": "0" * 40, "author": {"email": email, "name": name}, "message": "x"} for email, name in commits]}}


def test_push_event_commits_keep_only_the_accounts_own_authorship(monkeypatch):
    data = fixture("torvalds")
    data["events"] = [
        push_event("torvalds", [
            ("1024025+torvalds@users.noreply.github.com", "Linus Torvalds"),   # own, but noreply
            ("noreply@github.com", "torvalds"),                                # own name, noreply
            ("dev.one@example.org", "Dev One"),                                # someone else's commit in a merge
            ("torvalds@linux-foundation.org", "Linus Torvalds"),               # email local part is the login
            ("TORVALDS@linux-foundation.org", "Linus Torvalds"),               # duplicate, different case
            ("penguin@example.org", "Torvalds"),                               # author name is the login
            ("", "torvalds"),
            ("torvalds.fan@example.org", "Not Linus"),                         # only resembles the login
        ] + [(f"dev{i}@example.org", f"Dev {i}") for i in range(15)]),
        # a push by another account to the same repo, even with a matching author line, is not counted
        push_event("someone-else", [("impostor@example.org", "torvalds")]),
        {"type": "WatchEvent", "actor": {"login": "torvalds"}, "repo": {"name": "a/b"}, "payload": {}},
    ]
    calls = []
    replay(monkeypatch, data, calls)
    out = deep("torvalds")
    assert out["commit_emails"] == [
        {"email": "torvalds@linux-foundation.org", "name": "Linus Torvalds", "repo": "torvalds/linux"},
        {"email": "penguin@example.org", "name": "Torvalds", "repo": "torvalds/linux"},
    ]
    # nobody else's address can come back as the target's
    blob = json.dumps(out)
    assert "dev.one@example.org" not in blob and "dev3@example.org" not in blob
    assert "impostor@example.org" not in blob and "torvalds.fan@example.org" not in blob and "noreply" not in blob
    # the events carried commits, so the fallback call is not made
    assert not [s for s, _ in calls if s == "commits"] and len(calls) == 7


def test_profile_name_matches_only_when_the_profile_lookup_cached_it(monkeypatch):
    data = fixture("torvalds")
    data["events"] = [push_event("torvalds", [("lt@example.org", "Linus Torvalds"), ("dev.one@example.org", "Dev One")])]
    replay(monkeypatch, data)
    assert deep("torvalds")["commit_emails"] == []            # name unknown: dropped rather than guessed

    gh.clear_cache_for_tests()
    gh._cache_put("torvalds", {"username": "torvalds", "found": True, "name": "Linus Torvalds"})
    replay(monkeypatch, data)
    assert [c["email"] for c in deep("torvalds")["commit_emails"]] == ["lt@example.org"]


def test_push_event_commit_emails_are_capped_at_ten(monkeypatch):
    data = fixture("torvalds")
    data["events"] = [push_event("torvalds", [(f"alias{i}@example.org", "torvalds") for i in range(15)])]
    replay(monkeypatch, data)
    emails = [c["email"] for c in deep("torvalds")["commit_emails"]]
    assert len(emails) == gh.MAX_COMMIT_EMAILS == 10 and emails[0] == "alias0@example.org"


def test_fallback_commits_need_the_linked_github_login(monkeypatch):
    data = fixture("torvalds")
    row = lambda email, name, login: {"sha": "0" * 40, "commit": {"author": {"email": email, "name": name}},
                                      "author": {"login": login} if login else None}
    data["commits"] = [
        row("dev.one@example.org", "Dev One", "dev-one"),             # another account's commit
        row("torvalds@example.org", "Linus Torvalds", None),           # matching name, not linked to any account
        row("torvalds@linux-foundation.org", "Linus Torvalds", "Torvalds"),
        row("1024025+torvalds@users.noreply.github.com", "Linus Torvalds", "torvalds"),
    ]
    replay(monkeypatch, data)
    out = deep("torvalds")
    assert out["commit_emails"] == [{"email": "torvalds@linux-foundation.org", "name": "Linus Torvalds", "repo": "torvalds/linux"}]
    assert out["sections"]["commit_emails"] == "ok"


def test_profile_readme_download_stops_at_the_cap(monkeypatch):
    data = fixture("err0ric")
    sent = {"chunks": 0}

    class Endless(httpx.AsyncByteStream):
        async def __aiter__(self):
            yield b"see https://first.example.org/page \n"
            while sent["chunks"] < 10_000:                  # 640 MB if nothing stops it
                sent["chunks"] += 1
                yield b"x" * 65536

    class Transport(httpx.AsyncBaseTransport):              # unlike MockTransport, this does not pre-read
        async def handle_async_request(self, request):
            if request.url.host == "raw.githubusercontent.com":
                return httpx.Response(200, stream=Endless())
            section = "commits" if request.url.path.startswith("/repos/") else {"public": "events"}.get(
                request.url.path.rsplit("/", 1)[-1], request.url.path.rsplit("/", 1)[-1])
            return httpx.Response(200, json=data[section])

    monkeypatch.setattr(gh.httpx, "AsyncClient", lambda *a, **k: REAL_CLIENT(transport=Transport()))
    out = deep("Err0ric")
    assert out["sections"]["readme_links"] == "ok" and out["readme_links"] == ["https://first.example.org/page"]
    assert sent["chunks"] <= gh.README_MAX_BYTES // 65536 + 2


def test_compressed_profile_readme_is_refused(monkeypatch):
    gz = lambda s, r: httpx.Response(200, content=b"\x1f\x8b", headers={"content-encoding": "gzip"}) if s == "readme" else None
    replay(monkeypatch, fixture("err0ric"), override=gz)
    out = deep("Err0ric")
    assert out["sections"]["readme_links"] == "failed" and out["state"] == "partial"


@pytest.mark.parametrize("email,expected", [
    ("143530211+Err0ric@users.noreply.github.com", True), ("noreply@github.com", True),
    ("build-noreply@example.org", True), ("", True), ("torvalds@linux-foundation.org", False),
])
def test_is_noreply(email, expected):
    assert gh.is_noreply(email) is expected


# ---- fingerprints and links --------------------------------------------------------

def test_ssh_fingerprint_matches_ssh_keygen():
    # Reference value from `ssh-keygen -lf` on the recorded public key.
    key = fixture("torvalds")["keys"][0]["key"]
    assert gh.ssh_fingerprint(key) == {"type": "ssh-rsa", "fingerprint": "SHA256:SlSdsTYgtT3jhz1QFhVbDqazjuoZLbtqMs8nIVqaL9A"}
    # and the definition itself: unpadded base64 of the SHA-256 of the decoded blob
    blob = b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20" + bytes(range(32))
    fp = gh.ssh_fingerprint("ssh-ed25519 " + base64.b64encode(blob).decode() + " someone@host")
    assert fp["type"] == "ssh-ed25519"
    assert fp["fingerprint"] == "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")
    assert "=" not in fp["fingerprint"] and len(fp["fingerprint"]) == 7 + 43


@pytest.mark.parametrize("bad", ["", "ssh-rsa", "ssh-rsa not*base64", "ssh-rsa ="])
def test_ssh_fingerprint_rejects_garbage(bad):
    assert gh.ssh_fingerprint(bad) is None


def test_readme_links_dedupe_and_drop_badges():
    text = """
    [![build](https://img.shields.io/badge/build-passing-green)](https://ci.example.org/run/1)
    <img src="https://raw.githubusercontent.com/x/x/main/banner.png">
    <a href="https://example.org/about/">about</a> and again https://www.example.org/about.
    Blog: http://blog.example.org/post?id=1 , logo https://example.org/logo.svg
    ![stats](https://github-readme-stats.vercel.app/api?username=x)
    """
    assert gh.readme_links(text) == ["https://ci.example.org/run/1", "https://example.org/about/", "http://blog.example.org/post?id=1"]
    many = " ".join(f"https://example.org/p{i}" for i in range(50))
    assert len(gh.readme_links(many)) == gh.MAX_README_LINKS == 20


def test_gpg_keys_report_key_id_and_emails(monkeypatch):
    data = fixture("torvalds")
    data["gpg_keys"] = [{"id": 3, "key_id": "3262EFF25BA0D270", "raw_key": "-----BEGIN PGP PUBLIC KEY BLOCK-----",
                         "emails": [{"email": "dev.one@example.org", "verified": True},
                                    {"email": "1+dev@users.noreply.github.com", "verified": True}]}]
    replay(monkeypatch, data)
    out = deep("torvalds")
    assert out["keys"]["gpg"] == [{"key_id": "3262EFF25BA0D270", "emails": ["dev.one@example.org"]}]
    assert "BEGIN PGP" not in json.dumps(out)


# ---- profile lookup additions ------------------------------------------------------

def test_profile_lookup_adds_twitter_username_and_hireable(monkeypatch):
    user = {"name": "Dev One", "html_url": "https://github.com/dev-one", "twitter_username": "dev_one", "hireable": True}
    monkeypatch.setattr(gh.httpx, "AsyncClient", lambda *a, **k: REAL_CLIENT(transport=httpx.MockTransport(lambda r: httpx.Response(200, json=user))))
    out = asyncio.run(gh.run_github("dev-one"))
    assert out["twitter_username"] == "dev_one" and out["hireable"] is True

    gh.clear_cache_for_tests()
    bare = {"name": "Dev Two", "twitter_username": None, "hireable": None}
    monkeypatch.setattr(gh.httpx, "AsyncClient", lambda *a, **k: REAL_CLIENT(transport=httpx.MockTransport(lambda r: httpx.Response(200, json=bare))))
    out = asyncio.run(gh.run_github("dev-two"))
    assert "twitter_username" not in out and "hireable" not in out


# ---- route -------------------------------------------------------------------------

def test_route_returns_the_deep_result_and_validates_the_username(monkeypatch):
    replay(monkeypatch, fixture("torvalds"))
    with TestClient(app) as c:
        r = c.post("/api/recon/github-deep", json={"username": "torvalds"})
        assert r.status_code == 200 and r.json()["found"] is True and r.json()["state"] == "ok"
        for bad in ("", "--proxy=http://x", "a b", "a/b", "x" * 65, "../etc"):
            assert c.post("/api/recon/github-deep", json={"username": bad}).status_code in (400, 422), bad


def test_new_endpoints_have_their_own_rate_limits():
    assert match_limit("/api/recon/github-deep")[0] == "/api/recon/github-deep"
    assert match_limit("/api/recon/avatar-hash")[0] == "/api/recon/avatar-hash"
    assert match_limit("/api/recon/github")[0] == "/api/recon"
