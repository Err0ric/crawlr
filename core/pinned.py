"""
One capped GET to a host this server chose, through the outbound guard.

For modules that ask a fixed public API (hn.algolia.com, web.archive.org, an allowlisted
Mastodon instance). The host is not typed by a visitor, but the request is still held to
core.netguard's rules: the name is resolved once, every address must be public, and the
connection goes to the vetted address with the right Host header and TLS name. Redirects are
never followed here; a caller that expects one reads `location` and decides.

The body is read as a stream, after decoding, and reading stops at `max_bytes`: a larger body
is never held in memory, whatever Content-Length said and however well it was compressed.
"""

from dataclasses import dataclass
from urllib.parse import urlsplit

import httpx

from core.netguard import BlockedTarget, _pin, resolve_public

USER_AGENT = "CrawlR/1.0 (+https://crawlr.lol)"


@dataclass
class Got:
    status: int
    headers: httpx.Headers
    body: bytes = b""
    truncated: bool = False      # the body was longer than the cap; `body` is its start

    @property
    def location(self) -> str:
        return self.headers.get("location", "")

    @property
    def retry_after(self) -> int | None:
        wait = self.headers.get("retry-after", "").strip()
        return int(wait) if wait.isascii() and wait.isdigit() and len(wait) <= 6 else None


async def get(client: httpx.AsyncClient, url: str, *, params: dict | None = None, headers: dict | None = None,
              max_bytes: int, read_statuses: tuple[int, ...] = (200,)) -> Got:
    """GET `url` (https, no port, no credentials). The body is read only for `read_statuses`.
    Raises BlockedTarget, LookupError or an httpx error; the caller turns those into a state."""
    full = str(httpx.URL(url, params=params)) if params else url
    parts = urlsplit(full)
    if parts.scheme != "https" or not parts.hostname or parts.username or parts.password or parts.port is not None:
        raise BlockedTarget("only plain https URLs are asked")
    ip = (await resolve_public(parts.hostname, 443))[0]
    pinned, host_headers, extensions = _pin(full, ip)
    body = bytearray()
    truncated = False
    send = {"User-Agent": USER_AGENT, **(headers or {}), **host_headers}
    async with client.stream("GET", pinned, headers=send, extensions=extensions, follow_redirects=False) as resp:
        if resp.status_code in read_statuses:
            async for chunk in resp.aiter_bytes():
                body += chunk
                if len(body) > max_bytes:
                    truncated = True
                    del body[max_bytes:]
                    break
        return Got(resp.status_code, resp.headers, bytes(body), truncated)
