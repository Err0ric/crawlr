"""
The one cookie CrawlR sets: a random session ID that ties the minor check to the caller's own run.

core.profile_record keeps what the ordinary sources returned for a handle so that the adult and
dating pass can be held to the profile check on the server. That record belongs to whoever made
it. This middleware gives each visitor of the recon API a random ID for it:

  name        crawlr_run
  value       secrets.token_urlsafe(32): 256 random bits, issued by the server and by nobody else
  attributes  HttpOnly; SameSite=Strict; Path=/api; no Max-Age or Expires (it ends with the
              browser session); Secure whenever the request arrived over https

A cookie value the server did not issue (unknown to the store, expired, or the wrong shape) is
ignored and replaced, so a caller can neither choose an ID nor fix one for somebody else.

Secure and local development: the flag is set when the request's scheme is https, or when the
trusted proxy says so in X-Forwarded-Proto (production sits behind one). Over plain http, which
only happens on localhost and in the tests, it is left off so the cookie still works there.

The value is never logged, never put in a response body and used for nothing but that key.
Pure ASGI (not BaseHTTPMiddleware), so the ID is on the request before the route runs.
"""

from http.cookies import SimpleCookie

from core import profile_record
from middleware.observability import TRUSTED_PROXY_HOPS

COOKIE = "crawlr_run"
PREFIX = "/api/recon"


def _header(scope, name: bytes) -> str:
    for key, value in scope.get("headers") or []:
        if key == name:
            return value.decode("latin-1")
    return ""


def _cookie_value(scope) -> str:
    raw = _header(scope, b"cookie")
    if not raw or COOKIE not in raw:
        return ""
    try:
        jar = SimpleCookie()
        jar.load(raw)
    except Exception:  # noqa: BLE001 - a malformed Cookie header is no cookie
        return ""
    return jar[COOKIE].value if COOKIE in jar else ""


def is_https(scope) -> bool:
    if scope.get("scheme") == "https":
        return True
    if TRUSTED_PROXY_HOPS > 0:
        return _header(scope, b"x-forwarded-proto").split(",")[-1].strip().lower() == "https"
    return False


def set_cookie(session: str, secure: bool) -> str:
    return f"{COOKIE}={session}; HttpOnly; SameSite=Strict; Path=/api" + ("; Secure" if secure else "")


class RunSessionMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or not scope.get("path", "").startswith(PREFIX):
            return await self.app(scope, receive, send)
        session, issued = profile_record.open_session(_cookie_value(scope))
        scope.setdefault("state", {})["run_session"] = session
        if not issued:
            return await self.app(scope, receive, send)
        header = (b"set-cookie", set_cookie(session, is_https(scope)).encode("latin-1"))

        async def send_with_cookie(message):
            if message["type"] == "http.response.start":
                message = {**message, "headers": [*(message.get("headers") or []), header]}
            await send(message)

        await self.app(scope, receive, send_with_cookie)
