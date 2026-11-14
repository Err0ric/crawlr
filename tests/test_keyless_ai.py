"""The path for people who do not want to paste an API key: get the prompt, use any
assistant, paste the reply back. Neither endpoint calls a model or touches the quota."""
from fastapi.testclient import TestClient

from core import house_key as hk
from main import app
from modules import ai_provider

IP = {"x-forwarded-for": "203.0.113.90"}


def _no_model_calls(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("a model was called")
    monkeypatch.setattr(ai_provider, "call_ai", boom)
    monkeypatch.setattr(ai_provider, "_call_gemini", boom)
    monkeypatch.setattr(ai_provider, "_call_anthropic", boom)


def test_prompt_endpoint_needs_no_key_and_spends_nothing(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "AIza-house")
    hk.reset_counters_for_tests()
    _no_model_calls(monkeypatch)
    body = {"target": "jdoe", "accounts": [{"site": "Bluesky", "url": "https://bsky.app/profile/jdoe", "status": "confirmed", "sources": ["Maigret"]}],
            "github": {"found": None, "error": "GitHub is rate limiting CrawlR.", "error_code": "rate_limited"}}
    with TestClient(app) as c:
        r = c.post("/api/analyze/prompt", json=body, headers=IP)
        assert r.status_code == 200
        p = r.json()["prompt"]
        assert p.startswith("You are a senior OSINT investigator") and "<summary>" in p
        assert "CONFIRMED accounts (1)" in p and "FAILED" in p and "Target: jdoe" in p
        assert c.get("/api/quota", headers=IP).json()["remaining"]["analysis"] == 5
    hk.reset_counters_for_tests()


def test_prompt_matches_what_the_ai_endpoint_sends(monkeypatch):
    seen = {}

    async def fake(api_key, messages, max_tokens, model):
        seen["p"] = messages[0]["content"]
        return {"text": "<report>r</report>", "model": "m", "input_tokens": 1, "output_tokens": 1}

    monkeypatch.setattr(ai_provider, "_call_anthropic", fake)
    ai_provider.clear_cache_for_tests()
    body = {"target": "jdoe", "hibp": {"breaches": ["Adobe", "LinkedIn"]}, "active_techniques": True}
    with TestClient(app) as c:
        prompt = c.post("/api/analyze/prompt", json=body, headers=IP).json()["prompt"]
        assert c.post("/api/analyze/summarize", json=body, headers={**IP, "x-api-key": "k"}).status_code == 200
    assert prompt == seen["p"] and "Active techniques" in prompt


def test_recon_prompt_endpoint(monkeypatch):
    _no_model_calls(monkeypatch)
    with TestClient(app) as c:
        r = c.post("/api/infra/prompt", json={"target": "example.com", "email_posture": {"grade": "F", "spoofable": "yes", "findings": []}}, headers=IP)
        assert r.status_code == 200 and "Email security: grade F" in r.json()["prompt"] and "Target domain/IP: example.com" in r.json()["prompt"]


def test_pasted_reply_is_parsed_without_a_model(monkeypatch):
    _no_model_calls(monkeypatch)
    reply = "<summary>\n- Identity – likely a developer\n- Footprint – 3 accounts\n</summary>\n<profile>\nname: J Doe\nexposure: Low\n</profile>\n<report>\n## Case summary\nText.\n</report>"
    with TestClient(app) as c:
        d = c.post("/api/analyze/parse", json={"text": reply}, headers=IP).json()
        assert d["short_summary"] == ["Identity – likely a developer", "Footprint – 3 accounts"]
        assert d["summary"].startswith("## Case summary") and d["profile"] == {"name": "J Doe", "exposure": "Low"}
        assert d["ai_source"] == "pasted"
        # a chat assistant that ignored the format still renders
        d = c.post("/api/analyze/parse", json={"text": "Here is my analysis.\n\n## Findings\n- one thing of note"}, headers=IP).json()
        assert "## Findings" in d["summary"]
        # recon replies are JSON shaped
        d = c.post("/api/analyze/parse", json={"text": '```json\n{"short_summary": ["a"], "full_report": "## R"}\n```'}, headers=IP).json()
        assert d["short_summary"] == ["a"] and d["summary"] == "## R"
        assert c.post("/api/analyze/parse", json={"text": "   "}, headers=IP).status_code == 400
        assert c.post("/api/analyze/parse", json={"text": "x" * 120_001}, headers=IP).status_code == 422


def test_recon_prompt_accepts_internetdb_ports(monkeypatch):
    """InternetDB lists ports as plain numbers. The summary used to assume Shodan's objects and crash."""
    _no_model_calls(monkeypatch)
    idb = {"target": "example.com", "ip": "93.184.216.34", "found": True, "source": "internetdb", "ports": [80, 443], "vulns": ["CVE-2024-1"]}
    full = {"ip": "1.2.3.4", "ports": [{"port": 22, "transport": "tcp", "product": "OpenSSH", "version": "9.6"}]}
    with TestClient(app) as c:
        p = c.post("/api/infra/prompt", json={"target": "example.com", "shodan": idb}, headers=IP)
        assert p.status_code == 200 and "services: 80/tcp, 443/tcp" in p.json()["prompt"] and "CVE-2024-1" in p.json()["prompt"]
        p = c.post("/api/infra/prompt", json={"target": "example.com", "shodan": full}, headers=IP)
        assert "22/tcp (OpenSSH 9.6)" in p.json()["prompt"]


def test_deep_analysis_accepts_internetdb_ports(monkeypatch):
    seen = {}

    async def fake(api_key, messages, max_tokens, model):
        seen["p"] = messages[0]["content"]
        return {"text": "ok", "model": "m", "input_tokens": 1, "output_tokens": 1}

    monkeypatch.setattr(ai_provider, "_call_anthropic", fake)
    ai_provider.clear_cache_for_tests()
    with TestClient(app) as c:
        r = c.post("/api/analyze/deep", json={"target": "example.com", "shodan": {"ip": "1.2.3.4", "ports": [80, 443]}}, headers={**IP, "x-api-key": "k"})
        assert r.status_code == 200 and "80/tcp, 443/tcp" in seen["p"]
