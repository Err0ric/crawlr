"""
Outbound request guard (SSRF protection).

Several modules fetch a URL or open a socket to a host the user typed. Without a
guard, that host can be 127.0.0.1, a *.railway.internal service, the cloud
metadata address, or a public name that resolves (or redirects) to one of them.

Rules enforced here, for every connection CrawlR makes to a user-supplied host:

  1. Resolve the name once.
  2. Reject it unless every address is globally routable (no private, loopback,
     link-local, CGNAT, ULA, multicast or reserved ranges, including IPv4
     addresses wrapped in IPv6).
  3. Connect to the vetted address itself, so a second DNS answer cannot swap
     the target after the check (DNS rebinding).
  4. Repeat 1 to 3 for every redirect hop.

Use `safe_fetch` for HTTP and `resolve_public` for raw sockets.
"""

import asyncio
import ipaddress
import socket
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

import httpx

BLOCKED_SUFFIXES = (".internal", ".local", ".localhost", ".lan", ".home.arpa", ".intranet", ".corp")
BLOCKED_NAMES = {"localhost", "metadata", "metadata.google.internal"}
MAX_REDIRECTS = 10


class BlockedTarget(ValueError):
    """The target is not a public internet host, so CrawlR will not connect to it."""


def is_public_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address):
        mapped = ip.ipv4_mapped or ip.sixtofour or (ip.teredo[1] if ip.teredo else None)
        if mapped is not None:
            ip = mapped
    return bool(ip.is_global) and not ip.is_multicast


def _literal(host: str) -> str | None:
    try:
        return str(ipaddress.ip_address(host.strip("[]")))
    except ValueError:
        return None


async def resolve_public(host: str, port: int = 443) -> list[str]:
    """Return the vetted public addresses for `host` (IPv4 first) or raise BlockedTarget."""
    host = (host or "").strip().rstrip(".").lower()
    if not host:
        raise BlockedTarget("empty host")
    lit = _literal(host)
    if lit is not None:
        if not is_public_ip(lit):
            raise BlockedTarget(f"{host} is not a public address")
        return [lit]
    if host in BLOCKED_NAMES or host.endswith(BLOCKED_SUFFIXES) or "." not in host:
        raise BlockedTarget(f"{host} is not a public hostname")
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as e:
        raise LookupError(f"{host} does not resolve") from e
    addrs: list[str] = []
    for _family, _type, _proto, _canon, sockaddr in infos:
        if sockaddr[0] not in addrs:
            addrs.append(sockaddr[0])
    if not addrs:
        raise LookupError(f"{host} does not resolve")
    # One private answer poisons the whole set: mixed answers are how rebinding hides.
    if not all(is_public_ip(a) for a in addrs):
        raise BlockedTarget(f"{host} resolves to a non-public address")
    return sorted(addrs, key=lambda a: ":" in a)


@dataclass
class Fetched:
    response: httpx.Response
    url: str                       # final URL as the user would see it (hostname, not the pinned IP)
    hops: list[dict] = field(default_factory=list)   # [{url, status_code, server, ip}]


def _pin(url: str, ip: str) -> tuple[str, dict, dict]:
    """Rewrite `url` to connect to `ip` while keeping the Host header and TLS name."""
    parts = urlsplit(url)
    host = parts.hostname or ""
    netloc_ip = f"[{ip}]" if ":" in ip else ip
    if parts.port:
        netloc_ip += f":{parts.port}"
    pinned = parts._replace(netloc=netloc_ip).geturl()
    host_header = host if not parts.port else f"{host}:{parts.port}"
    extensions = {}
    if parts.scheme == "https" and _literal(host) is None:
        extensions["sni_hostname"] = host
    return pinned, {"Host": host_header}, extensions


async def safe_fetch(
    client: httpx.AsyncClient,
    url: str,
    *,
    method: str = "GET",
    headers: dict | None = None,
    follow_redirects: bool = True,
    max_redirects: int = MAX_REDIRECTS,
) -> Fetched:
    """
    Fetch `url` with the SSRF rules above. The client must not follow redirects
    on its own; this function walks them so each hop is vetted and pinned.
    Raises BlockedTarget for a non-public hop and httpx errors for transport failures.
    """
    hops: list[dict] = []
    current = url
    for _ in range(max_redirects + 1):
        parts = urlsplit(current)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise BlockedTarget("only http and https URLs are allowed")
        if parts.username or parts.password:
            raise BlockedTarget("URLs with credentials are not allowed")
        port = parts.port or (443 if parts.scheme == "https" else 80)
        ip = (await resolve_public(parts.hostname, port))[0]
        pinned, host_headers, extensions = _pin(current, ip)
        resp = await client.request(
            method, pinned,
            headers={**(headers or {}), **host_headers},
            extensions=extensions,
            follow_redirects=False,
        )
        hops.append({"url": current, "status_code": resp.status_code, "server": resp.headers.get("server", ""), "ip": ip})
        location = resp.headers.get("location", "")
        if not (follow_redirects and resp.is_redirect and location):
            return Fetched(response=resp, url=current, hops=hops)
        current = urljoin(current, location)
    raise httpx.TooManyRedirects(f"more than {max_redirects} redirects", request=resp.request)
