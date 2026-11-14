"""
One shared crt.sh query per domain.

Two modules read certificate transparency for the same domain during a recon run (the
subdomain finder and the passive harvester). crt.sh is a free service that is often slow,
so the answer is fetched once and shared: concurrent callers wait on the same request,
and the result is kept in memory for a few minutes. Infrastructure data only, never
written to disk, gone on restart.
"""

import asyncio
import time

import httpx

from core.logging import get_logger

log = get_logger(__name__)

TTL = 600
MAX_ENTRIES = 200
TIMEOUT = 25.0
_cache: dict[str, tuple[float, list]] = {}
_inflight: dict[str, asyncio.Future] = {}


def clear_cache_for_tests() -> None:
    _cache.clear()
    _inflight.clear()


async def _fetch(domain: str) -> list:
    async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=True) as client:
        resp = await client.get(
            "https://crt.sh/", params={"q": f"%.{domain}", "output": "json"},
            headers={"User-Agent": "Mozilla/5.0 (compatible; CrawlR/1.0; +https://crawlr.lol)"},
        )
    if resp.status_code == 429:
        raise RuntimeError("rate limited")
    resp.raise_for_status()
    data = resp.json()
    return data if isinstance(data, list) else []


async def fetch_crtsh(domain: str) -> list:
    """Raw crt.sh rows for %.domain. Raises on failure so each caller can report it."""
    domain = domain.lower().strip(".")
    hit = _cache.get(domain)
    if hit and time.time() - hit[0] < TTL:
        return hit[1]
    pending = _inflight.get(domain)
    if pending is not None:
        return await asyncio.shield(pending)
    fut = asyncio.get_running_loop().create_future()
    _inflight[domain] = fut
    try:
        rows = await _fetch(domain)
        if len(_cache) >= MAX_ENTRIES:
            _cache.pop(min(_cache, key=lambda k: _cache[k][0]), None)
        _cache[domain] = (time.time(), rows)
        fut.set_result(rows)
        return rows
    except Exception as e:
        log.warning("crt.sh query failed", extra={"err": type(e).__name__})   # no target in the log
        fut.set_exception(e)
        fut.exception()   # mark retrieved so an unawaited future does not warn
        raise
    finally:
        _inflight.pop(domain, None)
