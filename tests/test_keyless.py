import asyncio

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from core import house_key as hk
from main import app
from modules import ai_provider


@pytest.fixture(autouse=True)
def _reset(monkeypatch):
    hk.reset_counters_for_tests()
    ai_provider.clear_cache_for_tests()
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("HOUSE_KEY_ENABLED", raising=False)
    yield


# ---- key resolution -------------------------------------------------------

def test_user_key_always_wins_and_has_no_quota():
    r = hk.resolve_ai_key("sk-user", "anthropic", "1.1.1.1", "analysis")
    assert r.source == "user" and r.api_key == "sk-user" and r.provider == "anthropic" and r.remaining is None
    r2 = hk.resolve_ai_key("AIza-user", "gemini", "1.1.1.1", "analysis")
    assert r2.provider == "gemini"


def test_no_user_key_and_no_house_key_is_401():
    with pytest.raises(HTTPException) as e:
        hk.resolve_ai_key(None, "anthropic", "1.1.1.1", "analysis")
    assert e.value.status_code == 401


def test_house_key_used_with_per_ip_quota(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "AIza-house")
    monkeypatch.setenv("HOUSE_QUOTA_ANALYSIS", "2")
    r1 = hk.resolve_ai_key(None, "anthropic", "9.9.9.9", "analysis")
    assert r1.source == "house" and r1.provider == "gemini" and r1.api_key == "AIza-house" and r1.remaining == 1
    r2 = hk.resolve_ai_key(None, None, "9.9.9.9", "analysis")
    assert r2.remaining == 0
    with pytest.raises(HTTPException) as e:
        hk.resolve_ai_key(None, None, "9.9.9.9", "analysis")
    assert e.value.status_code == 429 and "Retry-After" in e.value.headers
    # a different IP is unaffected
    assert hk.resolve_ai_key(None, None, "8.8.8.8", "analysis").remaining == 1


def test_deepdive_bucket_is_separate_and_tighter(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "AIza-house")
    assert hk.resolve_ai_key(None, None, "9.9.9.9", "deepdive").remaining == 0
    with pytest.raises(HTTPException):
        hk.resolve_ai_key(None, None, "9.9.9.9", "deepdive")
    # analysis bucket still has its own allowance
    assert hk.resolve_ai_key(None, None, "9.9.9.9", "analysis").remaining == 4


def test_global_quota_and_kill_switch(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "AIza-house")
    monkeypatch.setenv("HOUSE_QUOTA_GLOBAL", "1")
    hk.resolve_ai_key(None, None, "1.1.1.1", "analysis")
    with pytest.raises(HTTPException) as e:
        hk.resolve_ai_key(None, None, "2.2.2.2", "analysis")
    assert e.value.status_code == 429
    monkeypatch.setenv("HOUSE_KEY_ENABLED", "false")
    with pytest.raises(HTTPException) as e:
        hk.resolve_ai_key(None, None, "3.3.3.3", "analysis")
    assert e.value.status_code == 401


# ---- quota endpoint -------------------------------------------------------

def test_quota_endpoint_off_and_on(monkeypatch):
    with TestClient(app) as c:
        assert c.get("/api/quota").json() == {"house_ai": False}
        monkeypatch.setenv("GEMINI_API_KEY", "AIza-house")
        body = c.get("/api/quota", headers={"x-forwarded-for": "5.5.5.5"}).json()
        assert body["house_ai"] is True
        assert body["remaining"] == {"analysis": 5, "deepdive": 1}
        assert body["limits"] == {"analysis": 5, "deepdive": 1}


def test_ai_endpoint_without_key_returns_401_when_house_off():
    with TestClient(app) as c:
        r = c.post("/api/analyze/summarize", json={"target": "x"})
        assert r.status_code == 401


def test_ai_endpoint_uses_house_key_and_counts(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "AIza-house")
    seen = {}

    async def fake_call_ai(api_key, provider, messages, max_tokens=2048, model=None):
        seen.update(api_key=api_key, provider=provider, model=model)
        return {"text": '{"short_summary": ["a"], "full_report": "r"}', "model": model, "input_tokens": 1, "output_tokens": 1}

    import routers.analyze as ra
    monkeypatch.setattr(ra, "call_ai", fake_call_ai)
    with TestClient(app) as c:
        r = c.post("/api/analyze/summarize", json={"target": "x", "sherlock": {"results": [{"site": "GitHub", "confidence": "high_confidence"}]}},
                   headers={"x-forwarded-for": "7.7.7.7"})
        assert r.status_code == 200, r.text
        assert seen == {"api_key": "AIza-house", "provider": "gemini", "model": "gemini-2.5-flash"}
        assert r.json()["ai_source"] == "house" and r.json()["free_remaining"] == 4
        assert c.get("/api/quota", headers={"x-forwarded-for": "7.7.7.7"}).json()["remaining"]["analysis"] == 4


# ---- AI result cache ------------------------------------------------------

def test_call_ai_caches_identical_prompts(monkeypatch):
    calls = []

    async def fake_gemini(api_key, messages, max_tokens, model):
        calls.append(1)
        return {"text": "ok", "model": "gemini-2.5-flash", "input_tokens": 1, "output_tokens": 1}

    monkeypatch.setattr(ai_provider, "_call_gemini", fake_gemini)
    msgs = [{"role": "user", "content": "hello"}]

    async def main():
        a = await ai_provider.call_ai("k1", "gemini", msgs)
        b = await ai_provider.call_ai("k2", "gemini", msgs)  # different key, same prompt -> cache hit
        c = await ai_provider.call_ai("k1", "gemini", [{"role": "user", "content": "other"}])
        return a, b, c

    a, b, c = asyncio.run(main())
    assert a["cached"] is False and b["cached"] is True and c["cached"] is False
    assert len(calls) == 2


# ---- InternetDB -----------------------------------------------------------

def test_internetdb_route_shapes_result(monkeypatch):
    import modules.internetdb as idb

    class FakeResp:
        status_code = 200
        def json(self):
            return {"ip": "1.2.3.4", "ports": [443, 22], "vulns": ["CVE-2024-1", "CVE-2023-9"], "hostnames": ["h.example"], "tags": ["cloud"], "cpes": ["cpe:/a:openbsd:openssh"]}

    class FakeClient:
        def __init__(self, *a, **k): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def get(self, url): return FakeResp()

    monkeypatch.setattr(idb.httpx, "AsyncClient", FakeClient)
    with TestClient(app) as c:
        r = c.post("/api/recon/internetdb", json={"target": "1.2.3.4"})
        body = r.json()
        assert r.status_code == 200 and body["found"] and body["ports"] == [22, 443]
        assert body["vulns"][0] == "CVE-2024-1" and body["source"] == "internetdb"


def test_gemini_key_sent_in_header_not_url(monkeypatch):
    seen = {}

    class R:
        status_code = 200
        def json(self):
            return {"candidates": [{"content": {"parts": [{"text": "ok"}]}}], "usageMetadata": {"promptTokenCount": 1, "candidatesTokenCount": 1}}

    class C:
        def __init__(self, *a, **k): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def post(self, url, json=None, headers=None):
            seen.update(url=url, headers=headers or {})
            return R()

    monkeypatch.setattr(ai_provider.httpx, "AsyncClient", C)
    asyncio.run(ai_provider._call_gemini("AQ.test-key", [{"role": "user", "content": "hi"}], 10, None))
    assert "key=" not in seen["url"] and "AQ." not in seen["url"]
    assert seen["headers"]["x-goog-api-key"] == "AQ.test-key"
