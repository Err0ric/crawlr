"""
Request-scoped middleware:

RequestContextMiddleware
    - assigns a request id (honors an incoming X-Request-ID, otherwise generates one)
    - stores it in the logging contextvar so every log line in the request carries it
    - echoes it back as X-Request-ID so a user can quote it in a bug report
    - emits one JSON access-log line per request with method, path, status, ms, client ip

SecurityHeadersMiddleware
    - adds the standard browser hardening headers to every response
    - CSP is tuned to what the page actually loads: everything is same-origin (fonts and d3
      are self-hosted), no inline scripts, images from https (favicons and avatars), and
      one cross-origin fetch (NHTSA's VIN decoder)

BodyLimitMiddleware
    - rejects request bodies over MAX_BODY_BYTES before they are read
"""

import ipaddress
import os
import re
import time
import uuid

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from core.logging import get_logger, request_id_var

log = get_logger("crawlr.access")


# How many proxies sit between the internet and this process. Railway's edge is one.
# Each trusted proxy appends the address it saw to X-Forwarded-For, so the real client is
# that many entries from the RIGHT. Entries further left are whatever the caller sent and
# must never be used for rate limits or quotas. Set to 0 to ignore the header entirely
# (direct exposure, no proxy).
TRUSTED_PROXY_HOPS = int(os.getenv("TRUSTED_PROXY_HOPS", "1"))


def _valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def client_ip(request: Request) -> str:
    """The caller's address as seen by the outermost trusted proxy."""
    peer = request.client.host if request.client else "unknown"
    if TRUSTED_PROXY_HOPS <= 0:
        return peer
    hops = [h.strip() for h in request.headers.get("x-forwarded-for", "").split(",") if h.strip()]
    if len(hops) >= TRUSTED_PROXY_HOPS:
        candidate = hops[-TRUSTED_PROXY_HOPS]
        # strip an optional port ("1.2.3.4:5678"); bracketed IPv6 keeps its colons
        if candidate.count(":") == 1:
            candidate = candidate.split(":")[0]
        candidate = candidate.strip("[]")
        if _valid_ip(candidate):
            return candidate
    return peer


_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


class RequestContextMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        incoming = request.headers.get("x-request-id", "")
        # only echo ids that are safe to put in a header and a log line
        rid = incoming if _REQUEST_ID_RE.match(incoming) else uuid.uuid4().hex[:12]
        token = request_id_var.set(rid)
        t0 = time.monotonic()
        status = 500
        try:
            response = await call_next(request)
            status = response.status_code
            response.headers["X-Request-ID"] = rid
            return response
        finally:
            ms = int((time.monotonic() - t0) * 1000)
            # skip static assets to keep the log signal high
            if not request.url.path.startswith("/static"):
                log.info(
                    "request",
                    extra={
                        "method": request.method,
                        "path": request.url.path,
                        "status": status,
                        "ms": ms,
                        "ip": client_ip(request),
                        "ua": request.headers.get("user-agent", "")[:120],
                    },
                )
            request_id_var.reset(token)


CSP = "; ".join([
    "default-src 'self'",
    # No inline scripts and no third-party script hosts: an injected <script> or
    # onerror= handler will not run. The UI is ES modules served from this origin.
    "script-src 'self'",
    # Inline style attributes are still used for small layout tweaks.
    "style-src 'self' 'unsafe-inline'",
    "font-src 'self'",
    "img-src 'self' data: https:",
    "connect-src 'self' https://vpic.nhtsa.dot.gov",
    "frame-ancestors 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "object-src 'none'",
])

SECURITY_HEADERS = {
    "Content-Security-Policy": CSP,
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
    "Cross-Origin-Opener-Policy": "same-origin",
}


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        for k, v in SECURITY_HEADERS.items():
            response.headers.setdefault(k, v)
        # Caching policy:
        #   /assets/<fingerprint>/...  the path changes whenever a file changes, so these are
        #                              cached for a year and never revalidated
        #   HTML and /static/...       stable URLs, so the browser must revalidate (a 304 when
        #                              unchanged) or it would keep running old code after a deploy
        #   /api/...                   left alone
        path = request.url.path
        if path.startswith("/assets/"):
            if response.status_code == 200:
                response.headers["Cache-Control"] = "public, max-age=31536000, immutable"
        elif not path.startswith("/api/"):
            response.headers.setdefault("Cache-Control", "no-cache")
        return response


MAX_BODY_BYTES = int(os.getenv("MAX_BODY_BYTES", str(2 * 1024 * 1024)))


class BodyLimitMiddleware(BaseHTTPMiddleware):
    """Refuse oversized uploads by their declared length. The largest legitimate body is an
    AI request carrying a full set of collected results, well under the default 2 MB."""

    async def dispatch(self, request: Request, call_next):
        length = request.headers.get("content-length")
        if length and length.isdigit() and int(length) > MAX_BODY_BYTES:
            from starlette.responses import JSONResponse
            return JSONResponse(status_code=413, content={"detail": "Request body is too large.", "code": "too_large"})
        return await call_next(request)
