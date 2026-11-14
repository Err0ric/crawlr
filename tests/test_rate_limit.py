from fastapi.testclient import TestClient

import middleware.observability as obs
import middleware.rate_limit as rl
from middleware.observability import client_ip
from middleware.rate_limit import RATE_LIMITS, RateLimitMiddleware, match_limit


class _Req:
    def __init__(self, headers=None, host="10.0.0.1"):
        self.headers = headers or {}
        self.client = type("C", (), {"host": host})()


def _mw():
    return RateLimitMiddleware(app=lambda scope, receive, send: None)


# ---- path matching ---------------------------------------------------------

def test_longest_prefix_wins():
    assert match_limit("/api/recon/sherlock")[0] == "/api/recon/sherlock"
    assert match_limit("/api/recon/github")[0] == "/api/recon"
    assert match_limit("/api/infra/portscan")[0] == "/api/infra/portscan"
    assert match_limit("/api/infra/summarize")[0] == "/api/infra/summarize"
    assert match_limit("/api/analyze/deep-dive")[0] == "/api/analyze"


def test_prefix_needs_a_path_separator():
    assert match_limit("/api/reconx") is None
    assert match_limit("/api/quota") is None


def test_previously_uncovered_endpoints_are_limited():
    for path in ("/api/recon/holehe", "/api/recon/scrape-profiles", "/api/recon/enrich", "/api/infra/portscan",
                 "/api/infra/dns", "/api/email/analyze", "/api/hash/hash", "/api/phone/lookup"):
        assert match_limit(path) is not None, path


# ---- limiting --------------------------------------------------------------

def test_rejects_over_the_limit_and_recovers_after_the_window():
    mw = _mw()
    limit, window = RATE_LIMITS["/api/recon/sherlock"]
    for i in range(limit):
        assert mw.check("1.1.1.1", "/api/recon/sherlock", now=100.0 + i) is None
    wait = mw.check("1.1.1.1", "/api/recon/sherlock", now=100.0 + limit)
    assert wait and 1 <= wait <= window + 1
    # another caller is unaffected, and so is another endpoint group for the same caller
    assert mw.check("2.2.2.2", "/api/recon/sherlock", now=100.0 + limit) is None
    assert mw.check("1.1.1.1", "/api/recon/github", now=100.0 + limit) is None
    # once the window has passed the caller is let back in
    assert mw.check("1.1.1.1", "/api/recon/sherlock", now=100.0 + limit + window + 1) is None


def test_rejected_requests_do_not_extend_the_block():
    mw = _mw()
    limit, window = RATE_LIMITS["/api/phone"]
    for i in range(limit):
        mw.check("1.1.1.1", "/api/phone/lookup", now=0.0)
    for i in range(50):  # hammering while blocked must not push the unblock time out
        assert mw.check("1.1.1.1", "/api/phone/lookup", now=1.0 + i * 0.1) is not None
    assert mw.check("1.1.1.1", "/api/phone/lookup", now=window + 1.0) is None


def test_key_table_is_bounded(monkeypatch):
    monkeypatch.setattr(rl, "MAX_KEYS", 100)
    mw = _mw()
    for i in range(1000):
        mw.check(f"10.0.{i // 250}.{i % 250}", "/api/hash/hash", now=float(i) * 0.001)
    assert len(mw._requests) <= 101


def test_expired_keys_are_swept(monkeypatch):
    monkeypatch.setattr(rl, "SWEEP_EVERY", 5)
    mw = _mw()
    for i in range(4):
        mw.check(f"10.0.0.{i}", "/api/hash/hash", now=0.0)
    for i in range(6):
        mw.check("9.9.9.9", "/api/hash/hash", now=10_000.0 + i)
    assert set(ip for ip, _ in mw._requests) == {"9.9.9.9"}


def test_429_response_over_http(monkeypatch):
    from main import app
    monkeypatch.setitem(rl.RATE_LIMITS, "/api/hash", (2, 60))
    with TestClient(app) as c:
        h = {"x-forwarded-for": "198.51.100.77"}
        codes = [c.post("/api/hash/hash", json={"hash": "nope"}, headers=h).status_code for _ in range(3)]
        assert codes == [400, 400, 429]
        r = c.post("/api/hash/hash", json={"hash": "nope"}, headers=h)
        assert r.status_code == 429 and int(r.headers["retry-after"]) >= 1
        assert r.json()["code"] == "rate_limited"
        # GET requests are never limited
        assert c.get("/api/health", headers=h).status_code == 200


# ---- client IP -------------------------------------------------------------

def test_client_ip_uses_the_hop_the_proxy_appended():
    # The caller controls everything left of the last entry; only the proxy's own entry is trusted.
    req = _Req(headers={"x-forwarded-for": "1.2.3.4, 203.0.113.9"})
    assert client_ip(req) == "203.0.113.9"


def test_spoofed_forwarded_for_cannot_change_identity():
    real = "203.0.113.9"
    a = client_ip(_Req(headers={"x-forwarded-for": f"8.8.8.8, {real}"}))
    b = client_ip(_Req(headers={"x-forwarded-for": f"9.9.9.9, 10.1.1.1, {real}"}))
    assert a == b == real


def test_client_ip_falls_back_to_socket_host():
    assert client_ip(_Req(host="192.0.2.5")) == "192.0.2.5"
    assert client_ip(_Req(headers={"x-forwarded-for": "not-an-ip"}, host="192.0.2.5")) == "192.0.2.5"


def test_proxy_hops_setting(monkeypatch):
    req = _Req(headers={"x-forwarded-for": "1.1.1.1, 2.2.2.2, 3.3.3.3"}, host="192.0.2.5")
    monkeypatch.setattr(obs, "TRUSTED_PROXY_HOPS", 2)
    assert client_ip(req) == "2.2.2.2"
    monkeypatch.setattr(obs, "TRUSTED_PROXY_HOPS", 0)   # no proxy: ignore the header entirely
    assert client_ip(req) == "192.0.2.5"
