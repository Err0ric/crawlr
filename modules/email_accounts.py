"""
Email to accounts: who is behind an address, from free public sources with no key.

Three requests per uncached address, run together with 8 seconds each:

  github_commits   modules/github_email.py   commits whose author line carries the address
  github_users     modules/github_email.py   profiles that show the address publicly
  openpgp          modules/openpgp_keys.py   a key published for the address on keys.openpgp.org

Each source keeps its own state in `sources`: `ok` (answered, has rows), `none` (answered,
nothing), `rate_limited` or `failed`. A rate limit is never `none`.

Every account row says how it was found in `how`:

  commit_author          GitHub attributes commits carrying the address to this account. The
                         account has the address confirmed on GitHub, so this is a strong tie.
  public_profile_email   GitHub's user search matched the address on the account's profile.
                         The search row carries no address, so the profile was not seen to
                         show it: `confirmed` is false and `how_note` says so. Unconfirmed in a
                         second way for an organization (see `account_type`).

`confirmed` is true on a commit_author row (each commit was checked to carry the address).
An account found both ways is one row: `how` is the stronger one and `hows` lists both. The
names inside commits and user IDs are self-declared and stay labeled as such; an account that
carries the address is still not proof of who types on it.

A complete answer is cached for a day, one with a source that did not answer for ten minutes.
"""

import asyncio
import os
import time
from collections import OrderedDict

import httpx

from core.errors import classify, error_fields
from core.logging import get_logger
from modules import github, github_email, openpgp_keys

log = get_logger(__name__)

SOURCE_TIMEOUT = 8.0
CACHE_TTL_OK = int(os.getenv("EMAIL_ACCOUNTS_CACHE_TTL", "86400"))
CACHE_TTL_PARTIAL = 600     # a source did not answer: keep it only long enough to stop a retry loop
CACHE_MAX = 500
_cache: "OrderedDict[str, tuple[float, dict]]" = OrderedDict()   # address -> (expires_at, result)

SOURCES = ("github_commits", "github_users", "openpgp")


def clear_cache_for_tests() -> None:
    _cache.clear()
    github.clear_quota_for_tests()


def _cache_get(key: str) -> dict | None:
    hit = _cache.get(key)
    if not hit:
        return None
    expires, val = hit
    if time.time() > expires:
        _cache.pop(key, None)
        return None
    _cache.move_to_end(key)
    return val


def _cache_put(key: str, val: dict, ttl: int) -> None:
    _cache[key] = (time.time() + ttl, val)
    _cache.move_to_end(key)
    while len(_cache) > CACHE_MAX:
        _cache.popitem(last=False)


async def _guard(label: str, coro, empty: dict) -> dict:
    """A source that hangs or crashes is `failed`. It never takes the other sources with it."""
    try:
        return await asyncio.wait_for(coro, SOURCE_TIMEOUT)
    except Exception as e:
        fields = error_fields(code=classify(e), detail=type(e).__name__)
        log.warning("email accounts source did not answer", extra={"source": label, "error_code": fields["error_code"]})
        return {**empty, "source": {"state": "failed", **fields}}


def merge_accounts(from_commits: list[dict], from_profiles: list[dict]) -> list[dict]:
    """One row per login. A login found both ways keeps its commit facts and lists both ways."""
    rows = {a["login"].casefold(): {**a, "hows": list(a["hows"])} for a in from_commits}
    for a in from_profiles:
        key = a["login"].casefold()
        if key in rows:
            if "public_profile_email" not in rows[key]["hows"]:
                rows[key]["hows"].append("public_profile_email")
            rows[key]["account_type"] = rows[key]["account_type"] or a["account_type"]
            rows[key]["confirmed"] = bool(rows[key].get("confirmed") or a.get("confirmed"))
        else:
            rows[key] = {**a, "hows": list(a["hows"])}
    return list(rows.values())


async def run_email_accounts(email: str) -> dict:
    key = email.casefold()
    cached = _cache_get(key)
    if cached is not None:
        return {**cached, "email": email, "cached": True}

    no_commits = {"accounts": [], "unattributed": github_email.read_commits({}, email)["unattributed"]}
    async with httpx.AsyncClient(timeout=SOURCE_TIMEOUT) as client:
        commits, users, pgp = await asyncio.gather(
            _guard("github_commits", github_email.commits(client, email), no_commits),
            _guard("github_users", github_email.users(client, email), {"accounts": []}),
            _guard("openpgp", _openpgp(client, email), {"keys": []}),
        )

    sources = {"github_commits": commits["source"], "github_users": users["source"], "openpgp": pgp["source"]}
    result = {
        "email": email,
        "cached": False,
        "accounts": merge_accounts(commits["accounts"], users["accounts"]),
        "unattributed": commits["unattributed"],
        "keys": pgp["keys"],
        "sources": sources,
    }
    complete = all(s["state"] in ("ok", "none") for s in sources.values())
    # States and counts only. The address, the logins and the names are never logged.
    log.info("email accounts finished", extra={
        "states": {k: v["state"] for k, v in sources.items()},
        "accounts": len(result["accounts"]), "keys": len(result["keys"]),
        "unattributed_commits": result["unattributed"]["commits_seen"],
    })
    _cache_put(key, result, CACHE_TTL_OK if complete else CACHE_TTL_PARTIAL)
    return result


async def _openpgp(client: httpx.AsyncClient, email: str) -> dict:
    out = await openpgp_keys.lookup(client, email)
    keys = out.pop("keys")
    for k in keys:
        # keys.openpgp.org publishes a user ID only after its address was confirmed by mail.
        k["how"] = "keyserver_verified_address"
    return {"source": {**out, "count": len(keys)} if out["state"] == "ok" else out, "keys": keys}
