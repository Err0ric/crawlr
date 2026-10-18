"""
Request-scoped middleware:

RequestContextMiddleware
    - assigns a request id (honors an incoming X-Request-ID, otherwise generates one)
    - stores it in the logging contextvar so every log line in the request carries it
    - echoes it back as X-Request-ID so a user can quote it in a bug report
    - emits one JSON access-log line per request with method, path, status, ms, client ip

SecurityHeadersMiddleware
    - adds the standard browser hardening headers to every response
    - CSP is tuned to what index.html actually loads (Google Fonts, cdnjs for d3 and jsPDF,
      inline styles/scripts, fetch to same origin)
"""

import time
import uuid

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from core.logging import get_logger, request_id_var

log = get_logger("crawlr.access")


def client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


class RequestContextMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        rid = request.headers.get("x-request-id") or uuid.uuid4().hex[:12]
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
    "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com",
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
    "font-src 'self' https://fonts.gstatic.com data:",
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
        # The app is served as unbundled ES modules with stable filenames, so a browser that
        # caches them heuristically keeps running old code after a deploy. "no-cache" makes it
        # revalidate every time; StaticFiles answers with ETag/Last-Modified, so an unchanged
        # file costs a 304, not a re-download.
        path = request.url.path
        if path.startswith("/static/") or not path.startswith("/api/"):
            response.headers.setdefault("Cache-Control", "no-cache")
        return response
