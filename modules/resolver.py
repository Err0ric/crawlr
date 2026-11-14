"""Hostname resolution helpers. Blocking DNS work runs in a thread so it never stalls the event loop."""

import asyncio
import ipaddress

import dns.resolver

from core.netguard import BlockedTarget, is_public_ip


def _literal(value: str) -> str | None:
    try:
        return str(ipaddress.ip_address(value.strip().strip("[]")))
    except ValueError:
        return None


def _resolve_blocking(domain: str) -> str:
    """Public DNS first (8.8.8.8, 1.1.1.1), then the system resolver; tries www. as a fallback."""
    public = dns.resolver.Resolver()
    public.nameservers = ["8.8.8.8", "1.1.1.1"]
    system = dns.resolver.Resolver()
    for r in (public, system):
        r.timeout = 3
        r.lifetime = 4
        for target in (domain, f"www.{domain}"):
            try:
                return str(r.resolve(target, "A")[0])
            except Exception:
                continue
    raise dns.resolver.NXDOMAIN(f"Could not resolve {domain}")


async def resolve_domain(domain: str) -> str:
    """Resolve a domain to one IPv4 address. An IP literal is returned as-is."""
    lit = _literal(domain)
    if lit is not None:
        return lit
    return await asyncio.to_thread(_resolve_blocking, domain.strip().rstrip(".").lower())


async def resolve_public_ip(domain: str) -> str:
    """Like resolve_domain, but refuses private, loopback, link-local and reserved addresses.
    Use this before opening a socket to a user-supplied host."""
    ip = await resolve_domain(domain)
    if not is_public_ip(ip):
        raise BlockedTarget(f"{domain} is not a public address")
    return ip
