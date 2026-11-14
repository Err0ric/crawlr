import asyncio
import socket
import ssl

import httpx
import pytest

from core.errors import MESSAGES, classify, error_fields
from core.netguard import BlockedTarget

REQ = httpx.Request("GET", "https://api.example.com/v1/thing?email=someone@example.com")


def status_error(code):
    return httpx.HTTPStatusError(
        f"Client error '{code} Forbidden' for url 'https://api.example.com/v1/thing?email=someone@example.com'\n"
        f"For more information check: https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/{code}",
        request=REQ, response=httpx.Response(code, request=REQ))


@pytest.mark.parametrize("exc,code", [
    (status_error(403), "rate_limited"),
    (status_error(429), "rate_limited"),
    (status_error(401), "auth"),
    (status_error(404), "not_found"),
    (status_error(500), "upstream"),
    (httpx.ReadTimeout("slow"), "timeout"),
    (httpx.ConnectTimeout("slow"), "timeout"),
    (asyncio.TimeoutError(), "timeout"),
    (socket.timeout("timed out"), "timeout"),
    (httpx.ConnectError("[Errno 8] nodename nor servname provided, or not known"), "dns"),
    (httpx.ConnectError("[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed"), "tls"),
    (httpx.ConnectError("All connection attempts failed"), "unreachable"),
    (ssl.SSLCertVerificationError("hostname mismatch"), "tls"),
    (socket.gaierror(8, "nodename nor servname provided"), "dns"),
    (ConnectionRefusedError(61, "Connection refused"), "unreachable"),
    (BlockedTarget("127.0.0.1 is not a public address"), "blocked_target"),
    (ValueError("Expecting value: line 1 column 1"), "bad_response"),
    (RuntimeError("???"), "unknown"),
])
def test_classify(exc, code):
    assert classify(exc) == code


def test_message_is_short_and_human_with_raw_detail_kept_separately():
    f = error_fields(status_error(403))
    assert f["error"] == MESSAGES["rate_limited"]
    # nothing a user should not have to read: no URLs, no MDN link, no query string
    for junk in ("http", "developer.mozilla.org", "someone@example.com", "\n"):
        assert junk not in f["error"]
    assert len(f["error"]) < 90
    # the raw text is still available for the "details" toggle
    assert "developer.mozilla.org" in f["error_detail"] and f["error_detail"].startswith("HTTPStatusError")
    assert len(f["error_detail"]) <= 400


def test_explicit_code_and_message():
    f = error_fields(code="not_installed")
    assert f == {"error": MESSAGES["not_installed"], "error_code": "not_installed", "error_detail": ""}
    f = error_fields(code="timeout", message="Sherlock ran out of time.", detail="180s")
    assert f["error"] == "Sherlock ran out of time." and f["error_detail"] == "180s"


def test_every_message_is_free_of_em_dashes_and_urls():
    for msg in MESSAGES.values():
        assert "—" not in msg and "http" not in msg


def test_modules_return_mapped_errors(monkeypatch):
    """A failing upstream surfaces as {error, error_code, error_detail}, not str(exception)."""
    from modules import hibp

    real = httpx.AsyncClient
    monkeypatch.setattr(hibp.httpx, "AsyncClient", lambda *a, **k: real(transport=httpx.MockTransport(lambda r: httpx.Response(429))))
    out = asyncio.run(hibp.run_hibp("someone@example.com"))
    assert out["error_code"] == "rate_limited" and out["error"] == MESSAGES["rate_limited"]
    assert "someone@example.com" not in out["error"]
