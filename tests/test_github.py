import asyncio
import time

import httpx
import pytest
from fastapi.testclient import TestClient

from main import app
from modules import github as gh


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    gh.clear_cache_for_tests()
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    yield
    gh.clear_cache_for_tests()


REAL_CLIENT = httpx.AsyncClient


def fake_github(monkeypatch, responder, calls=None):
    real = REAL_CLIENT

    def handler(request: httpx.Request):
        if calls is not None:
            calls.append(request)
        return responder(request)

    monkeypatch.setattr(gh.httpx, "AsyncClient", lambda *a, **k: real(transport=httpx.MockTransport(handler)))


USER = {"name": "Linus Torvalds", "location": "Portland, OR", "company": "Linux Foundation", "public_repos": 12,
        "followers": 5, "html_url": "https://github.com/torvalds", "avatar_url": "https://avatars.example/u/1", "created_at": "2011-09-03T15:26:22Z"}


@pytest.mark.parametrize("status,headers", [
    (403, {"x-ratelimit-remaining": "0", "x-ratelimit-reset": str(int(time.time()) + 1800)}),
    (429, {"retry-after": "120"}),
    (403, {}),
])
def test_rate_limit_is_an_error_never_a_negative_result(monkeypatch, status, headers):
    fake_github(monkeypatch, lambda r: httpx.Response(status, headers=headers, json={"message": "API rate limit exceeded for 1.2.3.4. (But here's the good news...)", "documentation_url": "https://docs.github.com/rest/overview/resources-in-the-rest-api#rate-limiting"}))
    out = asyncio.run(gh.run_github("torvalds"))
    assert out["found"] is None          # unknown, NOT False
    assert out["found"] is not False
    assert out["error_code"] == "rate_limited"
    assert "rate limit" in out["error"].lower() and "minute" in out["error"]
    assert out["retry_after"] >= 1
    # the human message carries no URL; raw detail stays in error_detail
    assert "http" not in out["error"] and "docs.github.com" not in out["error"]


def test_rate_limited_answers_are_not_cached(monkeypatch):
    answers = iter([httpx.Response(403, json={}), httpx.Response(200, json=USER)])
    fake_github(monkeypatch, lambda r: next(answers))
    assert asyncio.run(gh.run_github("torvalds"))["found"] is None
    assert asyncio.run(gh.run_github("torvalds"))["found"] is True


def test_404_is_a_real_not_found(monkeypatch):
    fake_github(monkeypatch, lambda r: httpx.Response(404, json={"message": "Not Found"}))
    out = asyncio.run(gh.run_github("nobody-here"))
    assert out["found"] is False and "error" not in out


def test_success_is_cached_case_insensitively(monkeypatch):
    calls = []
    fake_github(monkeypatch, lambda r: httpx.Response(200, json=USER), calls)
    a = asyncio.run(gh.run_github("torvalds"))
    b = asyncio.run(gh.run_github("Torvalds"))
    assert a["found"] and a["name"] == "Linus Torvalds" and a["avatar_url"]
    assert b["cached"] is True and len(calls) == 1


def test_token_is_sent_only_when_configured(monkeypatch):
    calls = []
    fake_github(monkeypatch, lambda r: httpx.Response(200, json=USER), calls)
    asyncio.run(gh.run_github("a"))
    assert "authorization" not in calls[0].headers
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_test_token")
    asyncio.run(gh.run_github("b"))
    assert calls[1].headers["authorization"] == "Bearer ghp_test_token"


def test_network_and_server_errors_are_unknown_not_missing(monkeypatch):
    def boom(request):
        raise httpx.ConnectTimeout("timed out")
    fake_github(monkeypatch, boom)
    out = asyncio.run(gh.run_github("torvalds"))
    assert out["found"] is None and out["error_code"] == "timeout"
    gh.clear_cache_for_tests()
    fake_github(monkeypatch, lambda r: httpx.Response(502, text="bad gateway"))
    out = asyncio.run(gh.run_github("torvalds"))
    assert out["found"] is None and out["error_code"] == "upstream"


def test_github_route_validates_the_username():
    with TestClient(app) as c:
        for bad in ("", "--proxy=http://x", "a b", "a/b", "x" * 65, "../etc"):
            assert c.post("/api/recon/github", json={"username": bad}).status_code in (400, 422), bad


# A name GitHub cannot hold is answered here and never becomes a request path.
import pytest as _pytest
from modules import github as _gh


@_pytest.mark.parametrize("name", ["..", ".", "a.b", "x_y", "-lead", "a" * 40])
def test_a_name_github_cannot_hold_makes_no_request(monkeypatch, name):
    import asyncio

    def boom(*a, **k):
        raise AssertionError("no request may be made")

    monkeypatch.setattr(_gh.httpx, "AsyncClient", boom)
    for fn in (_gh.run_github, _gh.run_github_deep):
        out = asyncio.run(fn(name))
        assert out["found"] is False and out["username"] == name and "note" in out
