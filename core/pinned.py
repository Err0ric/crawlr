"""
One capped GET to a host this server chose, through the outbound guard.

For modules that ask a fixed public API (hn.algolia.com, web.archive.org, an allowlisted
Mastodon instance). The host is not typed by a visitor, but the request is still held to
core.netguard's rules: the name is resolved once, every address must be public, and the
connection goes to the vetted address with the right Host header and TLS name. Redirects are
never followed here; a caller that expects one reads `location` and decides.

The body is read by core.capfetch.read_body, the one bounded reader: the bytes on the wire,
inflated piece by piece against `max_bytes`, never past the end of the compressed body, with
the bytes on the wire capped too. No more than `max_bytes` is ever held, whatever
Content-Length said and however well the body was compressed. Only gzip is asked for. A body
in any other coding, one that does not inflate or one that stops before its end is an
httpx.DecodingError and never a body.

The whole call (name lookup, connection, headers and body) ends within `deadline` seconds,
however slowly the bytes arrive: past that it raises TimeoutError.
"""

import asyncio
from dataclasses import dataclass
from urllib.parse import urlsplit

import httpx

from core import capfetch
from core.netguard import BlockedTarget, _pin, resolve_public

USER_AGENT = "CrawlR/1.0 (+https://crawlr.lol)"
DEADLINE = 20.0               # seconds for one whole call, unless the caller names its own


@dataclass
class Got:
    status: int
    headers: httpx.Headers
    body: bytes = b""
    truncated: bool = False      # the server sent more than `body`: past the cap, or after the end of a compressed body

    @property
    def location(self) -> str:
        return self.headers.get("location", "")

    @property
    def retry_after(self) -> int | None:
        wait = self.headers.get("retry-after", "").strip()
        return int(wait) if wait.isascii() and wait.isdigit() and len(wait) <= 6 else None


async def get(client: httpx.AsyncClient, url: str, *, params: dict | None = None, headers: dict | None = None,
              max_bytes: int, read_statuses: tuple[int, ...] = (200,), deadline: float = DEADLINE) -> Got:
    """GET `url` (https, no port, no credentials). The body is read only for `read_statuses`.
    Raises BlockedTarget, LookupError, TimeoutError (the call took longer than `deadline`) or
    an httpx error; the caller turns those into a state. `truncated` is set when the server
    sent more than `body` holds; `body` is then the start of it."""
    full = str(httpx.URL(url, params=params)) if params else url
    parts = urlsplit(full)
    if parts.scheme != "https" or not parts.hostname or parts.username or parts.password or parts.port is not None:
        raise BlockedTarget("only plain https URLs are asked")
    async with asyncio.timeout(deadline):
        ip = (await resolve_public(parts.hostname, 443))[0]
        pinned, host_headers, extensions = _pin(full, ip)
        body, cut = b"", ""
        send = {"User-Agent": USER_AGENT, "Accept-Encoding": "gzip", **(headers or {}), **host_headers}
        async with client.stream("GET", pinned, headers=send, extensions=extensions, follow_redirects=False) as resp:
            if resp.status_code in read_statuses:
                # The bytes as they arrive: the client's own decoder would inflate a whole chunk
                # before any cap is looked at.
                try:
                    body, cut = await capfetch.read_body(resp.stream, capfetch.coding_of(resp.headers), max_bytes)
                except capfetch.BadEncoding:
                    raise httpx.DecodingError("body that cannot be read within the cap", request=resp.request) from None
            return Got(resp.status_code, resp.headers, body, bool(cut))
