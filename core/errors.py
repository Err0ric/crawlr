"""
Turn upstream exceptions into something a person can read.

Modules used to return `str(exception)`, which put full upstream URLs and
"For more information check: https://developer.mozilla.org/..." into the run
log. `error_fields` gives every module the same three keys instead:

  error         short human message, safe to show as-is
  error_code    stable machine code the UI can branch on
  error_detail  the raw exception text, shown only behind a "details" toggle
"""

import asyncio
import socket
import ssl

import httpx

from core.netguard import BlockedTarget

MESSAGES = {
    "rate_limited": "Rate limited by the source. Try again in a few minutes.",
    "timeout": "The source took too long to answer.",
    "unreachable": "Could not connect to the source.",
    "dns": "A name lookup failed. Check the spelling, or try again: DNS may be having trouble.",
    "tls": "The TLS handshake failed.",
    "blocked_target": "CrawlR only connects to public internet hosts.",
    "auth": "The source rejected the key. Check it in Settings.",
    "not_found": "The source has no record of this.",
    "upstream": "The source returned an error.",
    "bad_response": "The source sent a response CrawlR could not read.",
    "not_installed": "This tool is not installed on the server.",
    "busy": "CrawlR is at capacity right now. Try again in a minute.",
    "unknown": "Something went wrong with this source.",
}


def classify(exc: BaseException) -> str:
    if isinstance(exc, BlockedTarget):
        return "blocked_target"
    if isinstance(exc, httpx.HTTPStatusError):
        return classify_status(exc.response.status_code)
    if isinstance(exc, (httpx.TimeoutException, asyncio.TimeoutError, socket.timeout, TimeoutError)):
        return "timeout"
    if isinstance(exc, (ssl.SSLError, ssl.CertificateError)):
        return "tls"
    if isinstance(exc, httpx.ConnectError):
        text = str(exc).lower()
        if "certificate" in text or "ssl" in text or "tls" in text:
            return "tls"
        if "name or service not known" in text or "nodename nor servname" in text or "getaddrinfo" in text or "name resolution" in text:
            return "dns"
        return "unreachable"
    if isinstance(exc, (socket.gaierror, LookupError)) or type(exc).__name__ in ("NXDOMAIN", "NoAnswer", "NoNameservers"):
        return "dns"
    if isinstance(exc, (httpx.TransportError, ConnectionError, OSError)):
        return "unreachable"
    if isinstance(exc, (ValueError, KeyError)):
        return "bad_response"
    return "unknown"


def classify_status(status: int) -> str:
    if status in (403, 429):
        return "rate_limited"
    if status == 401:
        return "auth"
    if status == 404:
        return "not_found"
    return "upstream"


def error_fields(exc: BaseException | None = None, *, code: str | None = None, message: str | None = None, detail: str | None = None) -> dict:
    code = code or (classify(exc) if exc is not None else "unknown")
    raw = detail if detail is not None else (f"{type(exc).__name__}: {exc}" if exc is not None else "")
    return {
        "error": message or MESSAGES.get(code, MESSAGES["unknown"]),
        "error_code": code,
        "error_detail": raw[:400],
    }
