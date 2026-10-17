from middleware.rate_limit import SoftRateLimitMiddleware, RATE_LIMITS, _get_client_ip


class _Req:
    def __init__(self, headers=None, host="10.0.0.1"):
        self.headers = headers or {}
        self.client = type("C", (), {"host": host})()


def _mw():
    return SoftRateLimitMiddleware(app=lambda scope, receive, send: None)


def test_match_limit_exact_and_subpath():
    mw = _mw()
    assert mw._match_limit("/api/phone/lookup") == RATE_LIMITS["/api/phone/lookup"]
    assert mw._match_limit("/api/phone/lookup/extra") == RATE_LIMITS["/api/phone/lookup"]


def test_match_limit_does_not_match_prefix_without_separator():
    mw = _mw()
    assert mw._match_limit("/api/phone/lookupx") is None
    assert mw._match_limit("/api/recon") is None


def test_client_ip_prefers_first_forwarded_hop():
    req = _Req(headers={"x-forwarded-for": "203.0.113.9, 10.0.0.2"})
    assert _get_client_ip(req) == "203.0.113.9"


def test_client_ip_falls_back_to_socket_host():
    assert _get_client_ip(_Req(host="192.0.2.5")) == "192.0.2.5"
