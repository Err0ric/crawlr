"""
GitHub profile lookup.

A 403 or 429 from GitHub means "rate limited", not "no such user": the anonymous API allows
60 requests an hour per IP, which a shared host burns through quickly. Those responses are
reported as an error with a retry hint and never as a negative result.

GITHUB_TOKEN (optional, server-side) raises the limit to 5,000 an hour. A fine-grained token
with no scopes is enough; it only reads public profiles. Results are cached in memory so a
re-run does not spend another request.
"""

import os
import time
from collections import OrderedDict
from urllib.parse import quote

import httpx

from core.errors import error_fields
from core.logging import get_logger

log = get_logger(__name__)

CACHE_TTL = int(os.getenv("GITHUB_CACHE_TTL", "3600"))
CACHE_MAX = 1000
_cache: "OrderedDict[str, tuple[float, dict]]" = OrderedDict()


def clear_cache_for_tests() -> None:
    _cache.clear()


def _cache_get(key: str) -> dict | None:
    hit = _cache.get(key)
    if not hit:
        return None
    ts, val = hit
    if time.time() - ts > CACHE_TTL:
        _cache.pop(key, None)
        return None
    _cache.move_to_end(key)
    return val


def _cache_put(key: str, val: dict) -> None:
    _cache[key] = (time.time(), val)
    _cache.move_to_end(key)
    while len(_cache) > CACHE_MAX:
        _cache.popitem(last=False)


def _retry_after(resp: httpx.Response) -> int:
    """Seconds until GitHub will answer again, from Retry-After or X-RateLimit-Reset."""
    try:
        if resp.headers.get("retry-after"):
            return max(1, int(resp.headers["retry-after"]))
        if resp.headers.get("x-ratelimit-reset"):
            return max(1, int(resp.headers["x-ratelimit-reset"]) - int(time.time()))
    except ValueError:
        pass
    return 600


def _headers() -> dict:
    h = {
        "User-Agent": "CrawlR/1.0 (+https://crawlr.lol)",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    token = os.getenv("GITHUB_TOKEN")
    if token:
        h["Authorization"] = f"Bearer {token}"
    return h


async def run_github(username: str, timeout: int = 10) -> dict:
    key = username.lower()
    cached = _cache_get(key)
    if cached is not None:
        return {**cached, "cached": True}

    url = f"https://api.github.com/users/{quote(username, safe='')}"
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.get(url, headers=_headers())
    except Exception as e:
        return {"username": username, "found": None, **error_fields(e)}

    if resp.status_code == 404:
        result = {"username": username, "found": False}
        _cache_put(key, result)
        return result

    if resp.status_code in (403, 429):
        wait = _retry_after(resp)
        mins = max(1, round(wait / 60))
        log.warning("github rate limited", extra={"retry_after_s": wait, "authenticated": bool(os.getenv("GITHUB_TOKEN"))})
        return {
            "username": username,
            "found": None,   # unknown: this is not a "no such user" answer
            "retry_after": wait,
            **error_fields(
                code="rate_limited",
                message=f"GitHub is rate limiting CrawlR. Try again in about {mins} minute{'s' if mins != 1 else ''}.",
                detail=f"HTTP {resp.status_code} from api.github.com",
            ),
        }

    if resp.status_code != 200:
        return {"username": username, "found": None, **error_fields(code="upstream", detail=f"HTTP {resp.status_code} from api.github.com")}

    try:
        data = resp.json()
    except ValueError as e:
        return {"username": username, "found": None, **error_fields(e)}

    result = {
        "username": username,
        "found": True,
        "name": data.get("name") or "",
        "bio": data.get("bio") or "",
        "location": data.get("location") or "",
        "company": data.get("company") or "",
        "email": data.get("email") or "",
        "blog": data.get("blog") or "",
        "public_repos": data.get("public_repos", 0),
        "followers": data.get("followers", 0),
        "profile_url": data.get("html_url", ""),
        "avatar_url": data.get("avatar_url", ""),
        "created_at": data.get("created_at", ""),
    }
    _cache_put(key, result)
    return result
