"""
Profile sources: what a handle's public record says on sites with an official, keyless API.

The username tools say that an account exists. These sources read the record itself: the name,
the bio, the location, the links and the accounts on other sites that the profile names. One
file per source in this package; `SOURCES` below is the registry and `run_profiles` asks them
all at once, each with its own time limit, so one slow or broken source costs the others nothing.

  GitLab, Keybase, Hacker News, Mastodon (mastodon.social), Docker Hub, npm, dev.to, Lichess,
  Chess.com, Codeberg, Bluesky, Wikipedia, Gravatar, Codeforces, Lobsters, Hugging Face

Every host is a fixed constant and no redirect is followed. None of them is an adult or dating
site (tests/test_profiles.py asks core.adult_sites). Per uncached call: one request per source
(three small ones to Hacker News; a second one to Docker Hub for an organization and to Hugging
Face for a handle typed in another case), so at most 20, and one picture download per profile
that has one, through modules/avatar_hash.py and so through core.netguard.

The answer:

  {username, cached,
   profiles: [{site, source, handle, url, state: "found", display_name, name, bio, location,
               company, website, links, emails, created, last_active, accounts, stats,
               followers, items, note, avatar_hash, avatar_default, thumb, avatar_state
               [, guard]}],
   sources:  {id: {site, state[, note][, error, error_code, error_detail]}}}

Each source keeps its own state, so a site that refused is never read as an absent account:
found, not_found, blocked, rate_limited, unknown, failed, and not_asked for a handle the site
cannot hold. A profile carries a hash, the placeholder flag, a small grayscale thumbnail and
`avatar_state` ("ok", "default", "none" or "failed"), and never a picture address. `guard`,
when present, is the whole bio for the minor guard's content check (core.profile_record), as
on a Maigret row; the page reads it and does not keep it.

Nothing about the handle or a profile is logged: only source IDs, states, codes and counts.
"""

import asyncio
import time
from collections import OrderedDict

import httpx

from core.errors import classify, error_fields
from core.logging import get_logger
from modules.avatar_hash import run_avatar_hash

from . import (base, bluesky, chesscom, codeberg, codeforces, devto, dockerhub, gitlab, gravatar, hackernews, huggingface, keybase,
               lichess, lobsters, mastodon, npm, wikipedia)

log = get_logger(__name__)

SOURCES = (gitlab, keybase, hackernews, mastodon, dockerhub, npm, devto, lichess, chesscom, codeberg, bluesky, wikipedia,
           gravatar, codeforces, lobsters, huggingface)
STATES = ("found", "not_found", "blocked", "rate_limited", "unknown", "failed", "not_asked")
SETTLED = ("found", "not_found", "blocked", "not_asked")     # asking again today would not change these

SOURCE_TIMEOUT = 8.0          # seconds for one source, all of its requests together
TOTAL_TIMEOUT = 12.0          # seconds for all sources
PICTURES_TIMEOUT = 12.0       # seconds for all pictures

CACHE_TTL_OK = 24 * 3600
CACHE_TTL_PARTIAL = 600       # a source failed or was rate limited: keep it only long enough to stop a retry loop
CACHE_MAX = 1000
_cache: "OrderedDict[str, tuple[float, dict]]" = OrderedDict()   # handle as typed -> (expires_at, result)


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


def _timed_out() -> base.Result:
    return base.failed("timeout", "TimeoutError")


async def _ask(src, client: httpx.AsyncClient, username: str) -> base.Result:
    """One source, never raising."""
    if not src.HANDLE_RE.fullmatch(username):
        return base.Result("not_asked")       # not a name this site can hold, so nothing is requested
    try:
        return await asyncio.wait_for(src.read(client, username), SOURCE_TIMEOUT)
    except base.SourceError as e:
        return base.failed(e.code, e.detail)
    except asyncio.CancelledError:
        raise
    except Exception as e:  # noqa: BLE001
        # The class name only: an exception message can carry the request URL, and the URL
        # carries the handle.
        return base.Result("failed", error=error_fields(code=classify(e), detail=type(e).__name__))


async def _pictures(profiles: list[dict]) -> None:
    """Hash each profile's picture on the server and replace its address with the hash, the
    placeholder flag, the thumbnail and `avatar_state`."""
    images = [{"id": p["source"], "url": p["_avatar"]} for p in profiles if p["_avatar"]]
    hashed = {}
    if images:
        try:
            done = await asyncio.wait_for(run_avatar_hash(images), PICTURES_TIMEOUT)
            hashed = {r["id"]: r for r in done.get("results", [])}
        except Exception as e:  # noqa: BLE001
            log.warning("profile pictures failed", extra={"error_code": classify(e)})
    asked = {i["id"] for i in images}
    for p in profiles:
        h = hashed.get(p["source"]) or {}
        p.pop("_avatar")
        known_default = p.pop("_avatar_default")
        p["avatar_hash"] = h.get("hash", "") if not h.get("error") else ""
        p["avatar_default"] = bool(h.get("default")) if p["avatar_hash"] else known_default
        p["thumb"] = h.get("thumb", "") if p["avatar_hash"] and not p["avatar_default"] else ""
        # "failed": the profile has a picture and it could not be fetched or read. That is not
        # the same as having none.
        p["avatar_state"] = ("default" if p["avatar_default"] else "ok") if p["avatar_hash"] else "failed" if p["source"] in asked else "default" if known_default else "none"


async def run_profiles(username: str) -> dict:
    """Ask every source for one handle. See the module docstring for the answer's shape. The
    caller validates the handle first (core.validate.username)."""
    cached = _cache_get(username)
    if cached is not None:
        return {**cached, "cached": True}

    async with httpx.AsyncClient(timeout=httpx.Timeout(SOURCE_TIMEOUT, connect=5.0), follow_redirects=False) as client:
        tasks = [asyncio.ensure_future(_ask(src, client, username)) for src in SOURCES]
        _done, pending = await asyncio.wait(tasks, timeout=TOTAL_TIMEOUT)
        for t in pending:
            t.cancel()
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)
    results = [t.result() if not t.cancelled() and t.exception() is None else _timed_out() for t in tasks]

    sources: dict[str, dict] = {}
    profiles: list[dict] = []
    settled = True
    for src, res in zip(SOURCES, results):
        state = res.state if res.state in STATES else "unknown"
        if state == "found" and not res.profile:
            state = "unknown"
        entry = {"site": src.SITE, "state": state}
        if res.note:
            entry["note"] = res.note
        if res.error and state in ("failed", "rate_limited"):
            entry.update(res.error)
        sources[src.ID] = entry
        if state == "found":
            profiles.append(dict(res.profile))
        if not (res.settled if res.settled is not None else state in SETTLED):
            settled = False
        if state in ("failed", "rate_limited"):
            # The source and an error code only. The handle is never logged.
            log.warning("profile source did not answer", extra={"source": src.ID, "state": state, "error_code": entry.get("error_code", "")})

    await _pictures(profiles)
    pictures_ok = all(p["avatar_state"] != "failed" for p in profiles)
    tally = {s: sum(1 for e in sources.values() if e["state"] == s) for s in STATES}
    log.info("profile sources answered", extra={"asked": len(SOURCES) - tally["not_asked"], **{k: v for k, v in tally.items() if v}})

    result = {"username": username, "profiles": profiles, "sources": sources, "cached": False}
    # "blocked" is how a site treats every server, so it is kept for the day. A source that
    # failed, timed out or was rate limited is asked again sooner, and so is a picture that
    # could not be read.
    _cache_put(username, result, CACHE_TTL_OK if settled and pictures_ok else CACHE_TTL_PARTIAL)
    return result
