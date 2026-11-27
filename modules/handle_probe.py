"""
Handle probe: a light look at one handle that is close to the one being investigated.

The investigator clicks "Check" on one similar handle, and this asks a small, fixed set of
sources that return profile data, concurrently:

  GitHub          the profile lookup (modules/github.py, cached there)
  Platform check  Facebook, Instagram, X, Threads, TikTok, Reddit and Discord
                  (modules/platform_check.py, cached there; LinkedIn is left out because it
                  never answers a server)
  Bluesky         the public profile lookup for {handle}.bsky.social, read by its profile
                  source (modules/profiles/bluesky.py). It answers without a key: recorded on
                  2026-11-14 as tests/fixtures/probe/bluesky_profile.json (HTTP 200) and
                  bluesky_not_found.json (HTTP 400, "Profile not found").

It never runs Sherlock or Maigret and never touches an adult or dating site. Pictures of the
profiles that were read go through modules/avatar_hash.py in the same request, so the answer
carries a hash, the placeholder flag, the small grayscale thumbnail and `avatar_state` ("ok",
"default", "none" or "failed": there is a picture and it could not be read), and never a picture
URL: the investigator's browser does not contact a picture host.

Per uncached probe: 1 GitHub request, 5 page fetches plus up to 3 canaries (shared, kept for
ten minutes), 1 Reddit request (up to 3 with the optional Reddit credentials), 1 Discord
request, 1 Bluesky request and at most 3 picture downloads.

Every source keeps its own state in `sources`, so a blocked site is never read as absent:
  found, taken, not_found, blocked, unknown, rate_limited, failed, not_asked
"""

import asyncio
import re
import time
from collections import OrderedDict

import httpx

from core.errors import classify
from core.logging import get_logger
from modules.avatar_hash import run_avatar_hash
from modules.github import run_github
from modules.platform_check import run_platform_check
from modules.profiles import bluesky

log = get_logger(__name__)

PLATFORMS = ("Facebook", "Instagram", "X", "Threads", "TikTok", "Reddit", "Discord")
SOURCES = ("GitHub", *PLATFORMS, "Bluesky")
TIMEOUT = 12
MAX_LINKS = 6

CACHE_TTL_OK = 24 * 3600
CACHE_TTL_PARTIAL = 600      # a source failed or was rate limited: keep it only long enough to stop a retry loop
CACHE_MAX = 1000
_cache: "OrderedDict[str, tuple[float, dict]]" = OrderedDict()   # handle -> (expires_at, result)


def clear_cache_for_tests() -> None:
    _cache.clear()


def _cache_get(key: str) -> dict | None:
    hit = _cache.get(key)
    if not hit:
        return None
    if time.time() > hit[0]:
        _cache.pop(key, None)
        return None
    _cache.move_to_end(key)
    return hit[1]


def _cache_put(key: str, val: dict, ttl: int) -> None:
    _cache[key] = (time.time() + ttl, val)
    _cache.move_to_end(key)
    while len(_cache) > CACHE_MAX:
        _cache.popitem(last=False)


def _text(value, cap: int) -> str:
    return " ".join(str(value).split())[:cap] if isinstance(value, str) else ""


def _count(value) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None


def _profile(site: str, url: str, **fields) -> dict:
    return {"site": site, "url": url, "state": "found", "name": _text(fields.get("name"), 100), "bio": _text(fields.get("bio"), 300),
            "location": _text(fields.get("location"), 100), "created": _text(fields.get("created"), 40),
            "followers": _count(fields.get("followers")), "note": _text(fields.get("note"), 40),
            "links": [u for u in (_text(x, 300) for x in fields.get("links") or []) if u][:MAX_LINKS],
            "_avatar": fields.get("avatar") or ""}


async def _github(username: str) -> tuple[dict, list[dict]]:
    d = await run_github(username)
    if d.get("error") or d.get("error_code"):
        return {"GitHub": "rate_limited" if d.get("error_code") == "rate_limited" else "failed"}, []
    if not d.get("found"):
        return {"GitHub": "not_found"}, []
    tw = str(d.get("twitter_username") or "").lstrip("@")
    links = [d.get("blog") or "", f"https://x.com/{tw}" if re.fullmatch(r"[A-Za-z0-9_]{1,15}", tw) else ""]
    return {"GitHub": "found"}, [_profile("GitHub", d.get("profile_url") or f"https://github.com/{username}", name=d.get("name"), bio=d.get("bio"),
                                          location=d.get("location"), created=d.get("created_at"), followers=d.get("followers"),
                                          links=links, avatar=d.get("avatar_url"))]


async def _platforms(username: str) -> tuple[dict, list[dict]]:
    out = await run_platform_check(username, only=PLATFORMS)
    states, profiles = {}, []
    for r in out.get("results") or []:
        site, state = r.get("platform"), r.get("state")
        if site not in PLATFORMS:
            continue
        states[site] = "rate_limited" if r.get("error_code") == "rate_limited" else state if state in ("found", "taken", "not_found", "blocked", "unknown") else "unknown"
        if state == "found":
            profiles.append(_profile(site, r.get("url") or "", name=r.get("display_name"), bio=r.get("bio"), created=r.get("created"),
                                     note=r.get("note"), avatar=r.get("avatar_url")))
    return states, profiles


async def _bluesky(username: str) -> tuple[dict, list[dict]]:
    """Bluesky through its profile source (modules/profiles/bluesky.py), as a probe row."""
    if not bluesky.HANDLE_RE.fullmatch(username):
        return {"Bluesky": "not_asked"}, []       # not a name bsky.social can hold, so nothing is requested
    async with httpx.AsyncClient(timeout=TIMEOUT) as client:
        res = await bluesky.read(client, username)
    if res.state != "found" or not res.profile:
        return {"Bluesky": res.state if res.state != "found" else "unknown"}, []
    p = res.profile
    return {"Bluesky": "found"}, [_profile("Bluesky", p["url"], name=p["display_name"], bio=p["bio"], created=p["created"],
                                           followers=p["followers"], avatar=p["_avatar"])]


async def _guarded(label: str, coro, names: tuple[str, ...]) -> tuple[dict, list[dict]]:
    """One group of sources, never raising. A failure marks each of its sources "failed"."""
    try:
        return await asyncio.wait_for(coro, TIMEOUT + 8)
    except Exception as e:  # noqa: BLE001
        # The source and an error code only. The handle is never logged.
        log.warning("handle probe source did not answer", extra={"source": label, "error_code": classify(e)})
        return {n: "failed" for n in names}, []


async def run_handle_probe(username: str) -> dict:
    """{username, profiles: [...], sources: {name: state}, cached}. See the module docstring."""
    key = username.lower()
    cached = _cache_get(key)
    if cached is not None:
        return {**cached, "username": username, "cached": True}

    groups = await asyncio.gather(
        _guarded("GitHub", _github(username), ("GitHub",)),
        _guarded("Platform check", _platforms(username), PLATFORMS),
        _guarded("Bluesky", _bluesky(username), ("Bluesky",)),
    )
    sources: dict[str, str] = {}
    profiles: list[dict] = []
    for states, rows in groups:
        sources.update(states)
        profiles.extend(rows)
    sources = {n: sources.get(n, "failed") for n in SOURCES}

    # Pictures are fetched and hashed here, through the outbound guard, and only the hash, the
    # placeholder flag and the thumbnail leave the server.
    images = [{"id": p["site"], "url": p["_avatar"]} for p in profiles if isinstance(p["_avatar"], str) and p["_avatar"].startswith("https://") and len(p["_avatar"]) <= 600]
    hashed = {}
    if images:
        try:
            hashed = {r["id"]: r for r in (await run_avatar_hash(images)).get("results", [])}
        except Exception as e:  # noqa: BLE001
            log.warning("handle probe pictures failed", extra={"error_code": classify(e)})
    asked = {i["id"] for i in images}
    for p in profiles:
        h = hashed.get(p["site"]) or {}
        p.pop("_avatar")
        p["avatar_hash"] = h.get("hash", "") if not h.get("error") else ""
        p["avatar_default"] = bool(h.get("default")) if p["avatar_hash"] else False
        p["thumb"] = h.get("thumb", "") if p["avatar_hash"] and not p["avatar_default"] else ""
        # "failed": the profile has a picture and it could not be fetched or read. That is not
        # the same as having none, and the page says "could not be compared".
        p["avatar_state"] = ("default" if p["avatar_default"] else "ok") if p["avatar_hash"] else "failed" if p["site"] in asked else "none"
    pictures_ok = all(p["avatar_state"] != "failed" for p in profiles)

    result = {"username": username, "profiles": profiles, "sources": sources, "cached": False}
    # "blocked" is how a site treats every server (Reddit, Threads), so it is kept for the day.
    # A source that failed, timed out or was rate limited is asked again sooner.
    # A picture that could not be read is retried sooner too: the comparison depends on it.
    settled = pictures_ok and all(s in ("found", "taken", "not_found", "not_asked", "blocked") for s in sources.values())
    _cache_put(key, result, CACHE_TTL_OK if settled else CACHE_TTL_PARTIAL)
    return result
