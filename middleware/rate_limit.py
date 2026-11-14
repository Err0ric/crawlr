"""
Per-IP rate limiting for the API.

Every POST under /api is counted against a sliding window for the caller's IP and the
most specific matching path group. Over the limit, the request is rejected with 429 and
a Retry-After header.

The client IP comes from middleware.observability.client_ip, which reads the hop that
the platform proxy appended rather than a value the caller can set.

Counters live in memory, which is right for a single instance. The table is swept and
capped so a flood of distinct addresses cannot grow it without bound.
"""

import time

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from core.logging import get_logger
from middleware.observability import client_ip

log = get_logger(__name__)

# path prefix -> (max requests per window, window seconds). The longest matching prefix wins.
RATE_LIMITS = {
    # subprocess tools: each run fans out hundreds of outbound requests
    "/api/recon/sherlock": (6, 60),
    "/api/recon/maigret": (6, 60),
    "/api/recon/holehe": (6, 60),
    "/api/recon/harvester": (6, 60),
    # active techniques
    "/api/recon/scrape-profiles": (4, 60),
    "/api/infra/portscan": (6, 60),
    "/api/infra/lookalikes": (4, 60),     # a few hundred DNS queries per call
    "/api/infra/takeover": (6, 60),
    "/api/infra/subdomains": (6, 60),     # wordlist and CT lookups, plus a recheck of up to 60 names
    # fan-out lookups: up to 8 GitHub API calls, or up to 30 image downloads, per request
    "/api/recon/github-deep": (10, 60),
    "/api/recon/avatar-hash": (10, 60),
    "/api/recon/platform-check": (10, 60),   # up to 6 page fetches plus canaries per call
    "/api/recon/adult-check": (10, 60),      # opt-in: up to 7 fetches plus a canary per call, 300 KB each, cached for a day
    "/api/recon/verify-links": (12, 60),     # up to 25 page fetches per call, 300 KB each, cached for a day
    # AI (the free tier has its own daily quota on top of this)
    "/api/analyze": (20, 60),
    "/api/infra/summarize": (20, 60),
    # everything else, by area. One recon run is about a dozen /api/infra calls.
    "/api/recon": (60, 60),
    "/api/infra": (90, 60),
    "/api/email": (30, 60),
    "/api/hash": (30, 60),
    "/api/phone": (15, 60),
}
MAX_KEYS = 20_000
SWEEP_EVERY = 500      # requests between sweeps
LONGEST_WINDOW = max(w for _, w in RATE_LIMITS.values())


def match_limit(path: str):
    """Return (group, limit, window) for the most specific matching prefix, or None."""
    best = None
    for prefix, (limit, window) in RATE_LIMITS.items():
        if (path == prefix or path.startswith(prefix + "/")) and (best is None or len(prefix) > len(best[0])):
            best = (prefix, limit, window)
    return best


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app):
        super().__init__(app)
        # {(ip, group): [timestamp, ...]}
        self._requests: dict[tuple[str, str], list[float]] = {}
        self._since_sweep = 0

    # kept for callers and tests that used the old name
    def _match_limit(self, path: str):
        m = match_limit(path)
        return (m[1], m[2]) if m else None

    def _sweep(self, now: float) -> None:
        cutoff = now - LONGEST_WINDOW
        for key in [k for k, stamps in self._requests.items() if not stamps or stamps[-1] <= cutoff]:
            del self._requests[key]
        if len(self._requests) > MAX_KEYS:
            # Still too many live keys: drop the ones idle the longest.
            oldest = sorted(self._requests, key=lambda k: self._requests[k][-1])
            for key in oldest[: len(self._requests) - MAX_KEYS]:
                del self._requests[key]

    def check(self, ip: str, path: str, now: float | None = None) -> int | None:
        """Record a request. Returns None when allowed, or seconds to wait when over the limit."""
        m = match_limit(path)
        if m is None:
            return None
        group, limit, window = m
        now = time.monotonic() if now is None else now
        self._since_sweep += 1
        if self._since_sweep >= SWEEP_EVERY or len(self._requests) > MAX_KEYS:
            self._since_sweep = 0
            self._sweep(now)
        key = (ip, group)
        stamps = [t for t in self._requests.get(key, ()) if t > now - window]
        if len(stamps) >= limit:
            self._requests[key] = stamps
            return max(1, int(stamps[0] + window - now) + 1)
        stamps.append(now)
        self._requests[key] = stamps
        return None

    async def dispatch(self, request: Request, call_next):
        if request.method != "POST":
            return await call_next(request)
        ip = client_ip(request)
        wait = self.check(ip, request.url.path)
        if wait is not None:
            log.warning("rate limited", extra={"ip": ip, "path": request.url.path, "retry_after_s": wait})
            return JSONResponse(
                status_code=429,
                content={"detail": f"Too many requests. Try again in {wait} seconds.", "code": "rate_limited"},
                headers={"Retry-After": str(wait)},
            )
        return await call_next(request)


# Old name, still imported in places.
SoftRateLimitMiddleware = RateLimitMiddleware
