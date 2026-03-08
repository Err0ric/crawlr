"""
Soft rate limiter middleware for FastAPI.

Instead of returning 429 errors, this adds progressive delays when
an IP exceeds the configured request limit for a given endpoint group.
Reads real client IP from X-Forwarded-For (Railway proxy).
"""

import asyncio
import time
from collections import defaultdict
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse


# Rate limit configs: path prefix -> (max_requests_per_window, window_seconds)
RATE_LIMITS = {
    "/api/recon/sherlock": (10, 60),
    "/api/recon/maigret": (10, 60),
    "/api/analyze/summarize": (20, 60),
    "/api/analyze/deep-dive": (20, 60),
    "/api/analyze/deep": (20, 60),
    "/api/analyze/correlate": (20, 60),
    "/api/analyze/email-headers": (20, 60),
    "/api/infra/summarize": (20, 60),
}


def _get_client_ip(request: Request) -> str:
    """Extract real client IP from X-Forwarded-For or fall back to client host."""
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


class SoftRateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app):
        super().__init__(app)
        # Track: {(ip, path_group): [timestamp, ...]}
        self._requests: dict[tuple[str, str], list[float]] = defaultdict(list)

    def _match_limit(self, path: str):
        """Return (limit, window) if path is rate-limited, else None."""
        for prefix, config in RATE_LIMITS.items():
            if path == prefix or path.startswith(prefix + "/"):
                return config
        return None

    def _clean_window(self, key: tuple[str, str], window: float):
        """Remove timestamps older than the window."""
        cutoff = time.monotonic() - window
        self._requests[key] = [t for t in self._requests[key] if t > cutoff]

    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        config = self._match_limit(path)

        if config is None or request.method == "GET":
            return await call_next(request)

        limit, window = config
        ip = _get_client_ip(request)
        key = (ip, path)

        self._clean_window(key, window)
        count = len(self._requests[key])

        delay = 0.0
        throttled = False
        if count >= limit:
            over = count - limit + 1
            delay = min(over * 1.5, 10.0)  # 1.5s per request over, max 10s
            throttled = True
            await asyncio.sleep(delay)

        self._requests[key].append(time.monotonic())

        response = await call_next(request)

        if throttled:
            response.headers["X-RateLimit-Delayed"] = str(round(delay, 1))

        return response
