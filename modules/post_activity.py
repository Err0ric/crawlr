"""
When an account posts, from the public post times of one site. One site per call, on a click.

The reading is the one modules/github_activity.py makes for GitHub events (the counting and the
estimate are shared: modules/activity_pattern.py): posts per UTC hour and per weekday and,
when the data supports it, a range of UTC offsets that would put the longest quiet stretch at
night. A hint, never a place.

Sources (all keyless, all checked against the live APIs on 2026-11-27 with project accounts):

  hackernews   GET https://hn.algolia.com/api/v1/search_by_date
                   tags=author_<id>  hitsPerPage=1000  attributesToRetrieve=created_at_i,_tags
                   attributesToHighlight=[]
               One request: the newest 1000 stories and comments, about 100 KB. `nbHits` is how
               many the index holds. An unknown id and an account that never posted both answer
               with no hits, so only then one more request asks the official API whether the id
               exists (GET https://hacker-news.firebaseio.com/v0/user/<id>/created.json: a
               number, or `null`). Ids are case sensitive and asked as typed.
  mastodon     GET https://<instance>/api/v1/accounts/lookup?acct=<handle>   (404: no account)
               GET https://<instance>/api/v1/accounts/<id>/statuses?limit=40[&max_id=<last id>]
               Up to MASTODON_PAGES pages of 40: public posts, replies and boosts. Only a local
               account on an instance modules/profiles/mastodon.py allows is asked. An account
               marked as a bot is counted and gets no estimate.
  lobsters     GET https://lobste.rs/~<handle>.json                         (404: no account)
               GET https://lobste.rs/~<handle>/stories.json, then /stories/page/<n>.json
               Up to LOBSTERS_PAGES pages of 25 submitted stories. Lobsters has no public
               per-user list of comments (/~<handle>/threads.json is a 404), so comments are
               not counted, and the story list of an unknown handle is a 500, which is why the
               account is asked for first.

Only posts from the WINDOW_DAYS days (365) before the newest post are counted: a pattern over
many years mixes moves and clock changes. Older posts that were read are reported as
`read.outside_window` and nothing else is done with them.

States: `ok` (posts were counted), `none` (the account exists and no post was listed),
`not_found` (the site's own answer that there is no such account, or a handle the site cannot
hold, which is answered with a `note` and without a request), `rate_limited`, `failed`.
`found` is True, False or None. A failure is never "none" and never "not found".
run_post_activity never raises.

`complete` is False when a page after the first was rate limited or failed: the counts are
then from the pages that did answer. `read.capped` is True when the page cap was reached and
the account has more posts than were read; that is not a failure.

After a 429 the host is left alone for the time it asked for (or a minute), and the answer is
`rate_limited` without a request. Nothing about the account is logged: states and counts only.
"""

import json
import os
import time
from collections import Counter, OrderedDict
from datetime import datetime, timedelta, timezone

import httpx

from core import pinned
from core.errors import classify, error_fields
from core.logging import get_logger
from core.validate import HOSTNAME_RE
from modules.activity_pattern import _when, estimate_offset, histogram
from modules.profiles import hackernews, lobsters, mastodon

log = get_logger(__name__)

TIMEOUT = 10.0
WINDOW_DAYS = 365
MAX_TYPES = 8

HN_SEARCH = "https://hn.algolia.com/api/v1/search_by_date"
HN_USER = "https://hacker-news.firebaseio.com/v0/user/{}/created.json"
HN_HITS = 1000                # the index's own maximum for one page
HN_KINDS = ("comment", "story", "poll", "pollopt", "job")
MASTODON_PER_PAGE = 40        # the API's maximum
MASTODON_PAGES = 5            # 200 statuses, six requests with the lookup
LOBSTERS_PER_PAGE = 25
LOBSTERS_PAGES = 4            # 100 stories, five requests with the account

MAX_JSON = 512 * 1024         # Hacker News and Lobsters answers
MAX_JSON_MASTODON = 3_000_000  # one page of 40 statuses was 380 KB

CACHE_TTL_OK = int(os.getenv("POST_ACTIVITY_CACHE_TTL", "86400"))
CACHE_TTL_PARTIAL = 600
CACHE_MAX = 1000
BACKOFF_DEFAULT = 60
BACKOFF_MAX = 3600

SITES = {
    "hackernews": {"name": "Hacker News", "handle": hackernews.HANDLE_RE, "things": "public posts",
                   "counts": "Stories and comments, the newest 1000 at most."},
    "mastodon": {"name": "Mastodon", "handle": mastodon.HANDLE_RE, "things": "public posts",
                 "counts": "Public posts, replies and boosts, the newest 200 at most."},
    "lobsters": {"name": "Lobsters", "handle": lobsters.HANDLE_RE, "things": "submitted stories",
                 "counts": "Submitted stories only, the newest 100 at most. Lobsters has no public list of a user's comments."},
}

NOT_A_HANDLE = "{site} cannot hold this handle, so nothing was asked."
BOT_REASON = {"code": "bot_account",
              "text": "The account is marked as automated, so its hours say nothing about a person's day."}

_cache: "OrderedDict[tuple, tuple[float, dict]]" = OrderedDict()
_quiet_until: dict[str, float] = {}       # host -> time before which it is not asked again


class _Stop(Exception):
    """A request ended the read. `state` is not_found, rate_limited or failed."""

    def __init__(self, state: str, fields: dict | None = None, retry_after: int | None = None):
        super().__init__(state)
        self.state, self.fields, self.retry_after = state, fields or {}, retry_after


def clear_cache_for_tests() -> None:
    _cache.clear()
    _quiet_until.clear()


def _transport() -> httpx.AsyncBaseTransport | None:
    """None for the real network. Tests replace this with a mock."""
    return None


def mastodon_instances() -> tuple[str, ...]:
    """The instances modules/profiles/mastodon.py reads (its `INSTANCES`), and no other. Read at
    call time, so the list is written in one place."""
    hosts = tuple(h.lower() for h in getattr(mastodon, "INSTANCES", ()) if isinstance(h, str) and HOSTNAME_RE.fullmatch(h))
    return hosts or (mastodon.HOST,)


def default_instance() -> str:
    hosts = mastodon_instances()
    return mastodon.HOST if mastodon.HOST in hosts else hosts[0]


# --------------------------------------------------------------------------------------
# Cache and backoff
# --------------------------------------------------------------------------------------
def _cache_get(key: tuple) -> dict | None:
    hit = _cache.get(key)
    if not hit:
        return None
    expires, val = hit
    if time.time() > expires:
        _cache.pop(key, None)
        return None
    _cache.move_to_end(key)
    return val


def _cache_put(key: tuple, val: dict, ttl: int) -> None:
    _cache[key] = (time.time() + ttl, val)
    _cache.move_to_end(key)
    while len(_cache) > CACHE_MAX:
        _cache.popitem(last=False)


def _backoff_left(host: str) -> int:
    left = _quiet_until.get(host, 0) - time.time()
    if left <= 0:
        _quiet_until.pop(host, None)
        return 0
    return int(left) + 1


# --------------------------------------------------------------------------------------
# One request
# --------------------------------------------------------------------------------------
async def _json(client: httpx.AsyncClient, url: str, params: dict | None = None, *, cap: int | None = None,
                not_found: tuple[int, ...] = ()) -> object:
    """The parsed JSON body of a 200, or _Stop. Error details name the host and the status,
    never the path or the query: those hold the handle."""
    host = url.split("/")[2]
    left = _backoff_left(host)
    if left:
        raise _Stop("rate_limited", error_fields(code="rate_limited", detail=f"{host} asked for a pause"), left)
    try:
        got = await pinned.get(client, url, params=params, headers={"Accept": "application/json"}, max_bytes=cap or MAX_JSON)
    except Exception as e:  # noqa: BLE001
        raise _Stop("failed", error_fields(code=classify(e), detail=type(e).__name__)) from None
    if got.status in not_found:
        raise _Stop("not_found")
    if got.status == 429:
        wait = min(got.retry_after or BACKOFF_DEFAULT, BACKOFF_MAX)
        _quiet_until[host] = time.time() + wait
        raise _Stop("rate_limited", error_fields(code="rate_limited", detail=f"HTTP 429 from {host}"), wait)
    if got.status != 200:
        # A 401 or a 403 is a site that will not answer here. That is a failure, not an absence.
        raise _Stop("failed", error_fields(code="upstream", detail=f"HTTP {got.status} from {host}"))
    if got.truncated:
        raise _Stop("failed", error_fields(code="bad_response", detail=f"Response too large from {host}"))
    try:
        return json.loads(got.body.decode("utf-8"))
    except (ValueError, RecursionError):
        raise _Stop("failed", error_fields(code="bad_response", detail=f"Unreadable response from {host}")) from None


def _bad(host: str) -> _Stop:
    return _Stop("failed", error_fields(code="bad_response", detail=f"Unreadable response from {host}"))


class _Read:
    """What a site's pages gave: rows of (id, time, kind)."""

    def __init__(self):
        self.rows: list[tuple[str, datetime, str]] = []
        self.pages = 0
        self.requests = 0
        self.later = "ok"            # what happened to a page after the first
        self.capped = False
        self.available: int | None = None
        self.bot = False


# --------------------------------------------------------------------------------------
# The sites
# --------------------------------------------------------------------------------------
async def _hackernews(client, username: str, instance: str) -> _Read:
    out = _Read()
    out.requests = 1
    data = await _json(client, HN_SEARCH, {
        "tags": f"author_{username}", "hitsPerPage": str(HN_HITS),
        "attributesToRetrieve": "created_at_i,_tags", "attributesToHighlight": "[]",
    })
    hits = data.get("hits") if isinstance(data, dict) else None
    if not isinstance(hits, list):
        raise _bad("hn.algolia.com")
    out.pages = 1
    own = f"author_{username}"
    for hit in hits:
        if not isinstance(hit, dict):
            continue
        tags = hit.get("_tags") if isinstance(hit.get("_tags"), list) else []
        stamp = hit.get("created_at_i")
        if own not in tags or isinstance(stamp, bool) or not isinstance(stamp, int):
            continue
        try:
            when = datetime.fromtimestamp(stamp, tz=timezone.utc)
        except (ValueError, OverflowError, OSError):
            continue
        kind = next((k for k in HN_KINDS if k in tags), "")
        out.rows.append((str(hit.get("objectID") or ""), when, kind))
    total = data.get("nbHits")
    if isinstance(total, int) and not isinstance(total, bool) and total >= 0:
        out.available = total
        out.capped = total > len(hits)
    if not out.rows:
        # No post in the index: the official API says whether the id exists at all.
        out.requests = 2
        created = await _json(client, HN_USER.format(username))
        if created is None:
            raise _Stop("not_found")
        if isinstance(created, bool) or not isinstance(created, int):
            raise _bad("hacker-news.firebaseio.com")
    return out


async def _mastodon(client, username: str, instance: str) -> _Read:
    out = _Read()
    base = f"https://{instance}/api/v1/accounts"
    out.requests = 1
    account = await _json(client, f"{base}/lookup", {"acct": username}, not_found=(404,))
    d = account if isinstance(account, dict) else {}
    handle, ident = d.get("username"), d.get("id")
    if (not isinstance(handle, str) or handle.lower() != username.lower() or d.get("acct") != handle
            or not isinstance(ident, str) or not ident.isascii() or not ident.isdigit() or len(ident) > 24):
        raise _bad(instance)
    out.bot = d.get("bot") is True
    total = d.get("statuses_count")
    out.available = total if isinstance(total, int) and not isinstance(total, bool) and total >= 0 else None
    max_id = ""
    for page in range(1, MASTODON_PAGES + 1):
        params = {"limit": str(MASTODON_PER_PAGE), **({"max_id": max_id} if max_id else {})}
        out.requests += 1
        try:
            rows = await _json(client, f"{base}/{ident}/statuses", params, cap=MAX_JSON_MASTODON)
            if not isinstance(rows, list):
                raise _bad(instance)
        except _Stop as stop:
            if page == 1:
                raise
            out.later = stop.state
            break
        out.pages += 1
        last = ""
        for row in rows:
            if not isinstance(row, dict):
                continue
            rid = row.get("id")
            rid = rid if isinstance(rid, str) and rid.isascii() and rid.isdigit() and len(rid) <= 24 else ""
            last = rid or last
            when = _when(row.get("created_at"))
            if when is None:
                continue
            kind = "boost" if row.get("reblog") else "reply" if row.get("in_reply_to_id") else "post"
            out.rows.append((rid, when, kind))
        if len(rows) < MASTODON_PER_PAGE or not last or last == max_id:
            break
        max_id = last
        if page == MASTODON_PAGES:
            out.capped = True
    return out


async def _lobsters(client, username: str, instance: str) -> _Read:
    out = _Read()
    out.requests = 1
    account = await _json(client, f"https://lobste.rs/~{username}.json", not_found=(404,))
    handle = account.get("username") if isinstance(account, dict) else None
    if not isinstance(handle, str) or handle.lower() != username.lower() or not lobsters.HANDLE_RE.fullmatch(handle):
        raise _bad("lobste.rs")
    for page in range(1, LOBSTERS_PAGES + 1):
        url = f"https://lobste.rs/~{handle}/stories.json" if page == 1 else f"https://lobste.rs/~{handle}/stories/page/{page}.json"
        out.requests += 1
        try:
            rows = await _json(client, url)
            if not isinstance(rows, list):
                raise _bad("lobste.rs")
        except _Stop as stop:
            if page == 1:
                raise
            out.later = stop.state
            break
        out.pages += 1
        for row in rows:
            if not isinstance(row, dict):
                continue
            when = _when(row.get("created_at"))
            if when is not None:
                rid = row.get("short_id")
                out.rows.append((rid if isinstance(rid, str) else "", when, "story"))
        if len(rows) < LOBSTERS_PER_PAGE:
            break
        if page == LOBSTERS_PAGES:
            out.capped = True
    return out


_READERS = {"hackernews": _hackernews, "mastodon": _mastodon, "lobsters": _lobsters}


# --------------------------------------------------------------------------------------
# Counting
# --------------------------------------------------------------------------------------
def summarize(rows: list[tuple[str, datetime, str]], things: str = "public posts", bot: bool = False,
              now: datetime | None = None) -> dict:
    """Counts over (id, time, kind) rows. Pure. A row seen twice (a new post between two page
    requests shifts the pages by one) is counted once, a time in the future is dropped, and only
    the WINDOW_DAYS days before the newest post are counted."""
    now = now or datetime.now(timezone.utc)
    seen: set[str] = set()
    kept: list[tuple[datetime, str]] = []
    for ident, when, kind in rows:
        if when > now + timedelta(days=1):
            continue
        if ident:
            if ident in seen:
                continue
            seen.add(ident)
        kept.append((when, kind))
    newest = max((w for w, _ in kept), default=None)
    floor = newest - timedelta(days=WINDOW_DAYS) if newest else None
    inside = [(w, k) for w, k in kept if w > floor] if newest else []
    counts = histogram(w for w, _ in inside)
    types = Counter(k for _, k in inside if k)
    if not inside:
        estimate, reason = None, None
    elif bot:
        estimate, reason = None, dict(BOT_REASON)
    else:
        estimate, reason = estimate_offset(counts["hours_utc"], counts["events"], counts["window"]["active_days"],
                                           counts["window"]["days"], things)
    return {
        **counts,
        "types": [{"type": t, "count": c} for t, c in sorted(types.items(), key=lambda kv: (-kv[1], kv[0]))[:MAX_TYPES]],
        "estimate": estimate,
        "estimate_reason": reason,
        "read": {"posts": len(kept), "outside_window": len(kept) - len(inside)},
    }


# --------------------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------------------
def _head(site: str, username: str, instance: str) -> dict:
    out = {"site": site, "site_name": SITES[site]["name"], "username": username}
    if site == "mastodon":
        out["instance"] = instance
    return out


async def run_post_activity(site: str, username: str, instance: str = "") -> dict:
    """The posting pattern of one account on one site. Never raises: see the module docstring.
    `site` must be a key of SITES and, for Mastodon, `instance` one of mastodon_instances();
    the router checks both."""
    try:
        return await _run(site, username, instance)
    except Exception as e:  # noqa: BLE001
        # The class name only: an exception text can carry the request URL, and the URL carries the handle.
        fields = error_fields(code=classify(e), detail=type(e).__name__)
        log.warning("post activity did not answer", extra={"error_code": fields["error_code"]})
        name = SITES.get(site, {}).get("name", "") if isinstance(site, str) else ""
        return {"site": site if name else "", "site_name": name, "username": username if isinstance(username, str) else "",
                "found": None, "state": "failed", "cached": False, **fields}


async def _run(site: str, username: str, instance: str) -> dict:
    if site not in SITES:
        raise ValueError("unknown site")
    spec = SITES[site]
    if site == "mastodon":
        instance = (instance or default_instance()).lower()
        if instance not in mastodon_instances():
            raise ValueError("instance not allowed")
    else:
        instance = ""
    head = _head(site, username, instance)
    if not spec["handle"].fullmatch(username):
        return {**head, "found": False, "state": "not_found", "cached": False, "note": NOT_A_HANDLE.format(site=spec["name"])}
    # Hacker News ids are case sensitive; the other two are not.
    key = (site, instance, username if site == "hackernews" else username.lower())
    cached = _cache_get(key)
    if cached is not None:
        return {**cached, "username": username, "cached": True}

    try:
        async with httpx.AsyncClient(timeout=TIMEOUT, transport=_transport()) as client:
            read = await _READERS[site](client, username, instance)
    except _Stop as stop:
        if stop.state == "not_found":
            result = {**head, "found": False, "state": "not_found", "cached": False}
            _cache_put(key, result, CACHE_TTL_OK)
            log.info("post activity finished", extra={"site": site, "state": "not_found"})
            return result
        log.warning("post activity did not answer", extra={"site": site, "state": stop.state, "error_code": stop.fields.get("error_code")})
        out = {**head, "found": None, "state": stop.state, "cached": False, **stop.fields}
        if stop.state == "rate_limited":
            out["retry_after"] = stop.retry_after or BACKOFF_DEFAULT
        return out

    summary = summarize(read.rows, spec["things"], read.bot)
    summary["read"].update({"capped": read.capped, "available": read.available})
    result = {
        **head,
        "found": True,
        "state": "ok" if summary["events"] else "none",
        "cached": False,
        "complete": read.later == "ok",       # False when a later page was rate limited or failed
        "pages": read.pages,
        "unit": spec["things"],
        "counts": spec["counts"],
        "window_days_max": WINDOW_DAYS,
        "bot": read.bot,
        **summary,
    }
    if read.later != "ok":
        result["later_pages"] = read.later
    # States and counts only. The handle, the instance and the hours are never logged.
    log.info("post activity finished", extra={
        "site": site, "state": result["state"], "events": summary["events"], "pages": read.pages,
        "complete": result["complete"], "estimate": bool(summary["estimate"]),
    })
    _cache_put(key, result, CACHE_TTL_OK if result["complete"] else CACHE_TTL_PARTIAL)
    return result
