import asyncio

import anthropic
import httpx2
import pytest
from fastapi.testclient import TestClient

from core import ai_text
from core import house_key as hk
from main import app
from modules import ai_provider
from modules.ai_provider import AIError


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    for v in ("GEMINI_API_KEY", "HOUSE_KEY_ENABLED", "HOUSE_QUOTA_ANALYSIS", "ANTHROPIC_MODEL"):
        monkeypatch.delenv(v, raising=False)
    hk.reset_counters_for_tests()
    ai_provider.clear_cache_for_tests()
    yield
    hk.reset_counters_for_tests()
    ai_provider.clear_cache_for_tests()


IP = {"x-forwarded-for": "203.0.113.50"}
BODY = {"target": "example-user", "github": {"found": True, "name": "Someone"}}


def quota(c, headers=IP):
    return c.get("/api/quota", headers=headers).json()["remaining"]["analysis"]


# ---- JSON / fence helper ----------------------------------------------------

@pytest.mark.parametrize("text,expected", [
    ('{"a": 1}', {"a": 1}),
    ('```json\n{"a": 1}\n```', {"a": 1}),
    ('```\n{"a": 1}\n```', {"a": 1}),
    ('Here you go:\n```json\n{"a": 1}\n```', {"a": 1}),
    ('Sure. {"a": {"b": [1, 2]}} Hope that helps.', {"a": {"b": [1, 2]}}),
    ('```json\n{"a": 1}', {"a": 1}),                 # truncated: no closing fence
    ("no json here", None),
    ('{"a": 1', None),
    ("[1, 2, 3]", None),                              # arrays are not the shape any endpoint wants
    ("", None),
    (None, None),
])
def test_parse_json_object(text, expected):
    assert ai_text.parse_json_object(text) == expected


def test_strip_fences():
    assert ai_text.strip_fences("```markdown\n# Title\nbody\n```") == "# Title\nbody"
    assert ai_text.strip_fences("plain") == "plain"
    assert ai_text.strip_fences("```\nunterminated") == "unterminated"
    # fences in the middle of a report are content, not wrapping
    mid = "Intro\n```\ncode\n```\nOutro"
    assert ai_text.strip_fences(mid) == mid


def test_summary_and_report_shapes():
    assert ai_text.summary_and_report('```json\n{"short_summary": ["a", "b"], "full_report": "## R"}\n```') == (["a", "b"], "## R")
    bullets, report = ai_text.summary_and_report("## Heading\n- first point here\n- second point here\n| t | u |")
    assert bullets == ["first point here", "second point here"] and report.startswith("## Heading")
    bullets, report = ai_text.summary_and_report('{"short_summary": "only one", "full_report": "r"}')
    assert bullets == ["only one"] and report == "r"


def test_endpoints_share_the_helper():
    """The five copies of fence stripping are gone from the routers."""
    import inspect
    import routers.analyze as ra
    import routers.recon_infra as ri
    for mod in (ra, ri):
        src = inspect.getsource(mod)
        assert "json.loads" not in src and '.startswith("```")' not in src


# ---- cache is checked before quota, and keyed per caller ----------------------

def test_cache_hit_does_not_spend_a_free_call(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "AIza-house")
    calls = []

    async def fake_gemini(api_key, messages, max_tokens, model):
        calls.append(1)
        return {"text": "<summary>\n- one\n</summary><report>## R</report>", "model": model, "input_tokens": 3, "output_tokens": 4}

    monkeypatch.setattr(ai_provider, "_call_gemini", fake_gemini)
    with TestClient(app) as c:
        first = c.post("/api/analyze/summarize", json=BODY, headers=IP).json()
        assert first["cached"] is False and first["free_remaining"] == 4 and quota(c) == 4
        for _ in range(3):                                   # identical re-runs
            again = c.post("/api/analyze/summarize", json=BODY, headers=IP).json()
            assert again["cached"] is True and again["free_remaining"] == 4
        assert quota(c) == 4 and len(calls) == 1
        # a different caller gets the same cached answer and keeps their full allowance
        other = {"x-forwarded-for": "203.0.113.51"}
        assert c.post("/api/analyze/summarize", json=BODY, headers=other).json()["cached"] is True
        assert quota(c, other) == 5


def test_cached_answer_is_served_even_when_quota_is_used_up(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "AIza-house")
    monkeypatch.setenv("HOUSE_QUOTA_ANALYSIS", "1")

    async def fake_gemini(api_key, messages, max_tokens, model):
        return {"text": "<report>r</report>", "model": model, "input_tokens": 1, "output_tokens": 1}

    monkeypatch.setattr(ai_provider, "_call_gemini", fake_gemini)
    with TestClient(app) as c:
        assert c.post("/api/analyze/summarize", json=BODY, headers=IP).status_code == 200
        assert c.post("/api/analyze/summarize", json=BODY, headers=IP).json()["cached"] is True
        r = c.post("/api/analyze/summarize", json={**BODY, "target": "someone-else"}, headers=IP)
        assert r.status_code == 429 and "free" in r.json()["detail"].lower()


def test_user_key_answers_are_not_shared_and_house_answers_need_no_key(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "AIza-house")
    seen = []

    async def fake_gemini(api_key, messages, max_tokens, model):
        seen.append(api_key)
        return {"text": "<report>r</report>", "model": model or "gemini-2.5-flash", "input_tokens": 1, "output_tokens": 1}

    monkeypatch.setattr(ai_provider, "_call_gemini", fake_gemini)
    with TestClient(app) as c:
        mine = {**IP, "x-api-key": "user-key-A", "x-ai-provider": "gemini"}
        yours = {**IP, "x-api-key": "user-key-B", "x-ai-provider": "gemini"}
        assert c.post("/api/analyze/summarize", json=BODY, headers=mine).json()["cached"] is False
        assert c.post("/api/analyze/summarize", json=BODY, headers=mine).json()["cached"] is True
        assert c.post("/api/analyze/summarize", json=BODY, headers=yours).json()["cached"] is False
        assert c.post("/api/analyze/summarize", json=BODY, headers=IP).json()["cached"] is False   # house scope is separate too
        assert seen == ["user-key-A", "user-key-B", "AIza-house"]
        assert quota(c) == 4     # only the one house call counted


def test_failed_provider_call_refunds_the_free_call(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "AIza-house")

    async def down(api_key, messages, max_tokens, model):
        raise AIError("ai_upstream", "Gemini returned an error (503). Try again in a moment.", 502)

    monkeypatch.setattr(ai_provider, "_call_gemini", down)
    with TestClient(app) as c:
        r = c.post("/api/analyze/summarize", json=BODY, headers=IP)
        assert r.status_code == 502
        assert quota(c) == 5


# ---- typed errors instead of a bare 500 ----------------------------------------

ENDPOINTS = [
    ("/api/analyze/summarize", BODY),
    ("/api/analyze/deep-dive", BODY),
    ("/api/analyze/deep", {"target": "example.com"}),
    ("/api/analyze/correlate", {"targets": {"a": {}, "b": {}}}),
    ("/api/analyze/email-headers", {"header_analysis": {}}),
    ("/api/infra/summarize", {"target": "example.com"}),
]


@pytest.mark.parametrize("path,body", ENDPOINTS)
def test_bad_user_key_is_a_clear_401_on_every_ai_endpoint(monkeypatch, path, body):
    async def reject(api_key, messages, max_tokens, model):
        raise AIError("ai_invalid_key", "Anthropic rejected that API key. Check it in Settings.", 401)

    monkeypatch.setattr(ai_provider, "_call_anthropic", reject)
    with TestClient(app, raise_server_exceptions=False) as c:
        r = c.post(path, json=body, headers={**IP, "x-api-key": "sk-ant-wrong"})
        assert r.status_code == 401, r.text
        assert r.json() == {"detail": "Anthropic rejected that API key. Check it in Settings.", "code": "ai_invalid_key"}


def _status_error(cls, status, headers=None):
    req = httpx2.Request("POST", "https://api.anthropic.com/v1/messages")
    return cls(message="x", response=httpx2.Response(status, request=req, headers=headers or {}), body=None)


@pytest.mark.parametrize("exc,code,status", [
    (lambda: _status_error(anthropic.AuthenticationError, 401), "ai_invalid_key", 401),
    (lambda: _status_error(anthropic.PermissionDeniedError, 403), "ai_invalid_key", 403),
    (lambda: _status_error(anthropic.RateLimitError, 429, {"retry-after": "30"}), "ai_rate_limited", 429),
    (lambda: _status_error(anthropic.NotFoundError, 404), "ai_bad_model", 502),
    (lambda: _status_error(anthropic.BadRequestError, 400), "ai_bad_request", 502),
    (lambda: _status_error(anthropic.InternalServerError, 500), "ai_upstream", 502),
    (lambda: anthropic.APITimeoutError(request=httpx2.Request("POST", "https://api.anthropic.com/v1/messages")), "ai_timeout", 504),
    (lambda: anthropic.APIConnectionError(request=httpx2.Request("POST", "https://api.anthropic.com/v1/messages")), "ai_unreachable", 502),
])
def test_anthropic_exceptions_map_to_typed_errors(monkeypatch, exc, code, status):
    class Messages:
        async def create(self, **kw):
            raise exc()

    class Client:
        def __init__(self, **kw): self.messages = Messages()
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False

    monkeypatch.setattr(ai_provider.anthropic, "AsyncAnthropic", Client)
    with pytest.raises(AIError) as e:
        asyncio.run(ai_provider._call_anthropic("sk-ant-x", [{"role": "user", "content": "hi"}], 100, None))
    assert (e.value.code, e.value.status) == (code, status)
    assert "sk-ant" not in e.value.message


def _fake_anthropic(monkeypatch, message, seen):
    class Messages:
        async def create(self, **kw):
            seen.update(kw)
            return message

    class Client:
        def __init__(self, **kw):
            seen["client"] = kw
            self.messages = Messages()
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False

    monkeypatch.setattr(ai_provider.anthropic, "AsyncAnthropic", Client)


def _msg(blocks, stop_reason="end_turn"):
    ns = lambda **k: type("O", (), k)()
    return ns(content=[ns(**b) for b in blocks], stop_reason=stop_reason, model="claude-sonnet-5-5", usage=ns(input_tokens=10, output_tokens=20))


def test_anthropic_call_is_async_uses_configured_model_and_skips_thinking_blocks(monkeypatch):
    seen = {}
    _fake_anthropic(monkeypatch, _msg([{"type": "thinking", "thinking": ""}, {"type": "text", "text": "the answer"}]), seen)
    out = asyncio.run(ai_provider._call_anthropic("sk-ant-x", [{"role": "user", "content": "hi"}], 2048, None))
    assert out == {"text": "the answer", "model": "claude-sonnet-5-5", "input_tokens": 10, "output_tokens": 20}
    assert seen["model"] == ai_provider.DEFAULT_ANTHROPIC_MODEL and "20250514" not in seen["model"]
    assert seen["max_tokens"] > 2048                       # headroom for thinking tokens
    assert "temperature" not in seen and "thinking" not in seen
    assert asyncio.iscoroutinefunction(ai_provider._call_anthropic)

    monkeypatch.setenv("ANTHROPIC_MODEL", "claude-opus-5-5")
    asyncio.run(ai_provider._call_anthropic("sk-ant-x", [{"role": "user", "content": "hi"}], 2048, None))
    assert seen["model"] == "claude-opus-5-5"


def test_refusal_and_empty_answers_are_errors(monkeypatch):
    _fake_anthropic(monkeypatch, _msg([], stop_reason="refusal"), {})
    with pytest.raises(AIError) as e:
        asyncio.run(ai_provider._call_anthropic("k", [{"role": "user", "content": "hi"}], 100, None))
    assert e.value.code == "ai_refused"
    _fake_anthropic(monkeypatch, _msg([{"type": "thinking", "thinking": ""}]), {})
    with pytest.raises(AIError) as e:
        asyncio.run(ai_provider._call_anthropic("k", [{"role": "user", "content": "hi"}], 100, None))
    assert e.value.code == "ai_empty"


@pytest.mark.parametrize("status,body,code,http", [
    (400, '{"error": {"message": "API key not valid. Please pass a valid API key.", "status": "INVALID_ARGUMENT"}}', "ai_invalid_key", 401),
    (403, "{}", "ai_invalid_key", 401),
    (429, "{}", "ai_rate_limited", 429),
    (503, "overloaded", "ai_upstream", 502),
])
def test_gemini_errors_are_typed_and_never_log_the_key(monkeypatch, caplog, status, body, code, http):
    real = ai_provider.httpx.AsyncClient
    monkeypatch.setattr(ai_provider.httpx, "AsyncClient", lambda *a, **k: REAL(transport=ai_provider.httpx.MockTransport(lambda r: ai_provider.httpx.Response(status, text=body))))
    with caplog.at_level("WARNING"):
        with pytest.raises(AIError) as e:
            asyncio.run(ai_provider._call_gemini("AIzaSECRETKEY123", [{"role": "user", "content": "hi"}], 100, None))
    assert (e.value.code, e.value.status) == (code, http)
    for rec in caplog.records:
        blob = str(rec.__dict__)
        assert "AIza" not in blob and "key_prefix" not in blob


REAL = ai_provider.httpx.AsyncClient


# ---- the prompt only claims what the sources support -----------------------------

def _prompt_for(monkeypatch, body):
    captured = {}

    async def fake(api_key, messages, max_tokens, model):
        captured["prompt"] = messages[0]["content"]
        return {"text": "<report>r</report>", "model": "m", "input_tokens": 1, "output_tokens": 1}

    monkeypatch.setattr(ai_provider, "_call_anthropic", fake)
    with TestClient(app) as c:
        assert c.post("/api/analyze/summarize", json=body, headers={**IP, "x-api-key": "k"}).status_code == 200
    return captured["prompt"]


def test_failed_github_is_reported_as_failed_not_found_or_confirmed(monkeypatch):
    prompt = _prompt_for(monkeypatch, {
        "target": "torvalds",
        "github": {"username": "torvalds", "found": None, "error": "GitHub is rate limiting CrawlR. Try again in about 10 minutes.", "error_code": "rate_limited"},
        "accounts": [{"site": "Bluesky", "url": "https://bsky.app/profile/torvalds", "status": "matches", "sources": ["Maigret"]},
                     {"site": "Medium", "url": "https://medium.com/@torvalds", "status": "different", "sources": ["Maigret"], "note": "name on profile: Patricia Torvalds"},
                     {"site": "PayPal", "url": "https://paypal.me/torvalds", "status": "unverified", "sources": ["Maigret"]}],
        "source_status": {"Sherlock": "ok", "Maigret": "ok"},
    })
    data = prompt.split("Collected data:")[1]
    assert "FAILED" in data and "GitHub (GitHub is rate limiting" in data
    assert "GitHub profile" not in data                      # no profile line for a failed lookup
    assert "Sources that ran successfully: Maigret, Sherlock" in data
    assert "LINKED accounts" not in data                     # nothing was linked, so nothing is called linked
    assert "EXISTS (MATCHES) accounts (1)" in data and "Bluesky" in data.split("EXISTS (DIFFERENT PERSON)")[0]
    assert "EXISTS (DIFFERENT PERSON) accounts (1)" in data and "Patricia Torvalds" in data.split("EXISTS (DIFFERENT PERSON) accounts (1)")[1]
    assert "PayPal" in data.split("UNVERIFIED accounts (1)")[1]
    assert "PayPal" not in data.split("UNVERIFIED")[0]
    assert "never treat the failure as a negative result" in prompt
    assert "other people who share the handle" in prompt


def test_legacy_payload_without_ledger_still_separates_verified_from_possible(monkeypatch):
    prompt = _prompt_for(monkeypatch, {"target": "t", "sherlock": {"results": [
        {"site": "GitHub", "url": "https://github.com/t", "confidence": "major_platform", "verified": True},
        {"site": "Facebook", "url": "https://facebook.com/t", "confidence": "major_platform"},
        {"site": "Chess", "confidence": "false_positive"}]}})
    data = prompt.split("Collected data:")[1]
    assert "Accounts where a profile was read (1): GitHub" in data
    assert "UNVERIFIED accounts (1)" in data and "Facebook" in data
    assert "confirmed" not in data.lower() and "linked" not in data.lower()
