"""
When a GitHub account is active, from its public event feed.

One to three requests: GET /users/{login}/events/public?per_page=100, then page 2 and page 3
only while the page before was full. GitHub keeps about 90 days and at most 300 events, and
answers 422 past the last page it serves, which is read as the end. The token and the rate
limit handling are the ones in modules/github.py; a 403 or 429 is `rate_limited`, never
"no activity".

States: `ok` (events came back), `none` (the account exists and has no public events in the
window), `not_found` (404: no such account, or a handle GitHub cannot hold, which is answered
here with a `note` and without a request), `rate_limited`, `failed`. `found` is True, False
or None the way run_github reports it. run_github_activity never raises: anything unexpected,
in a request or in the counting, is `failed` with the error fields.

A handle is checked against GitHub's own login rule before anything is requested, so a name
with a dot or an underscore, or "." and "..", never reaches the API. When GitHub's headers
have said the allowance is spent (modules.github.note_quota), the answer is `rate_limited`
without another request until the allowance resets.

What comes back is counted, not interpreted: events per UTC hour and per weekday, event types
and the repositories touched most.

The one interpretation is `estimate`, a range of UTC offsets that would put the account's
longest quiet stretch at night. It is a hint and is worded as one. It is only made when

  - there are at least ESTIMATE_MIN_EVENTS events (40)
  - on at least ESTIMATE_MIN_DAYS different UTC days (10)
  - and one quiet stretch of QUIET_MIN_HOURS to QUIET_MAX_HOURS hours (6 to 12) stands out:
    an hour is quiet when it holds at most 2% of the events, and no second quiet stretch may
    come within an hour of the longest.

Otherwise `estimate` is null and `estimate_reason` says why. The range assumes one person who
sleeps at least six hours inside the quiet stretch with the middle of that sleep between 02:00
and 05:00 local time, so a quiet stretch of L hours starting at hour s UTC gives the offsets
5 - s - L to 2 - s. Shift work, scheduled jobs, bots and shared accounts all break it. An
offset is never a place: no city, no country and no time zone name is derived from it.

Offsets are written in -11..+12, one name per clock time (UTC+13 and UTC+14 show the same
clock time as UTC-11 and UTC-10, a day ahead). `utc_offsets` lists them going east. A range
that crosses the date line is two runs, and the label says so: "UTC+11 to UTC+12 or UTC-11 to
UTC-9", never "UTC+11 to UTC-9". `utc_offset_from` and `utc_offset_to` are the first and the
last of `utc_offsets`, the west and east ends going east; `crosses_date_line` is true when
the first is the larger number, and then the two are not the ends of one run of numbers.
"""

import os
import time
from collections import Counter, OrderedDict
from datetime import datetime, timezone
from urllib.parse import quote

import httpx

from core.errors import classify, error_fields
from core.logging import get_logger
from modules import github
from modules.github import LOGIN_RE, REPO_RE, api_headers, is_rate_limit, note_quota, quota_wait, rate_limited_fields, retry_after

log = get_logger(__name__)

API = "https://api.github.com"
HOST = "api.github.com"
TIMEOUT = 8.0
PER_PAGE = 100
MAX_PAGES = 3
TOP_REPOS = 10
MAX_TYPES = 20

ESTIMATE_MIN_EVENTS = 40
ESTIMATE_MIN_DAYS = 10
QUIET_SHARE = 0.02          # an hour with at most this share of the events is quiet
QUIET_MIN_HOURS = 6
QUIET_MAX_HOURS = 12
SLEEP_HOURS = 6             # the block assumed to sit inside the quiet stretch
MIDSLEEP_LOCAL = (2, 5)     # local hours the middle of that block is assumed to fall between

CACHE_TTL_OK = int(os.getenv("GITHUB_ACTIVITY_CACHE_TTL", "86400"))
CACHE_TTL_PARTIAL = 600     # a later page did not answer: keep it only long enough to stop a retry loop
CACHE_MAX = 500
_cache: "OrderedDict[str, tuple[float, dict]]" = OrderedDict()   # login -> (expires_at, result)

WEEKDAYS = ("Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday")

REASONS = {
    "too_few_events": "Too few public events to say anything about hours: {events} seen, {need} needed.",
    "too_few_days": "The events fall on too few days to show a daily pattern: {days} seen, {need} needed.",
    "no_quiet_window": "No quiet stretch of {need} hours or more: the account is active around the clock.",
    "quiet_window_too_long": "The account is only active in a few hours of the day, so the quiet stretch "
                             "({hours} hours) is too long to place a night in.",
    "ambiguous_quiet_window": "Two quiet stretches of about the same length, so neither can be called the night.",
}


NOT_A_LOGIN = "GitHub cannot hold this handle: a login is 1 to 39 letters, digits or hyphens, so nothing was asked."


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


def _when(value) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        d = datetime.fromisoformat(value.replace("Z", "+00:00"))
        # A date at the edge of the calendar with an offset cannot be moved to UTC.
        return d.astimezone(timezone.utc) if d.tzinfo is not None else None
    except (ValueError, OverflowError):
        return None


def _iso(d: datetime) -> str:
    return d.strftime("%Y-%m-%dT%H:%M:%SZ")


def _hh(hour: int) -> str:
    return f"{hour % 24:02d}:00"


def _utc(offset: int) -> str:
    return "UTC" if offset == 0 else f"UTC{offset:+d}"


def _name(offset: int) -> int:
    """An offset as its one name in -11..+12."""
    return (offset + 11) % 24 - 11


def offsets_label(offsets: list[int]) -> str:
    """Offsets listed going east, as words. A list that crosses the date line (+12 then -11) is
    two runs joined by "or", so it cannot be read as one span from the first to the last."""
    runs: list[list[int]] = []
    for o in offsets:
        if runs and o == runs[-1][-1] + 1:
            runs[-1].append(o)
        else:
            runs.append([o])
    return " or ".join(_utc(r[0]) if len(r) == 1 else f"{_utc(r[0])} to {_utc(r[-1])}" for r in runs)


def quiet_runs(hours: list[int]) -> list[tuple[int, int]]:
    """Circular runs of quiet hours as (start hour, length), longest first."""
    total = sum(hours)
    limit = int(total * QUIET_SHARE)
    quiet = [h <= limit for h in hours]
    if all(quiet) or not any(quiet):
        return []
    # Start walking just after an active hour so no run is split across midnight.
    origin = next(i for i in range(24) if not quiet[i]) + 1
    runs: list[tuple[int, int]] = []
    start, length = None, 0
    for step in range(24):
        hour = (origin + step) % 24
        if quiet[hour]:
            start = hour if start is None else start
            length += 1
        elif start is not None:
            runs.append((start, length))
            start, length = None, 0
    if start is not None:
        runs.append((start, length))
    return sorted(runs, key=lambda r: (-r[1], r[0]))


def estimate_offset(hours: list[int], events: int, active_days: int, window_days: int) -> tuple[dict | None, dict | None]:
    """(estimate, reason). Exactly one of the two is None."""

    def no(code: str, **kw) -> tuple[None, dict]:
        return None, {"code": code, "text": REASONS[code].format(**kw)}

    if events < ESTIMATE_MIN_EVENTS:
        return no("too_few_events", events=events, need=ESTIMATE_MIN_EVENTS)
    if active_days < ESTIMATE_MIN_DAYS:
        return no("too_few_days", days=active_days, need=ESTIMATE_MIN_DAYS)
    runs = quiet_runs(hours)
    if not runs or runs[0][1] < QUIET_MIN_HOURS:
        return no("no_quiet_window", need=QUIET_MIN_HOURS)
    start, length = runs[0]
    if length > QUIET_MAX_HOURS:
        return no("quiet_window_too_long", hours=length)
    if len(runs) > 1 and runs[1][1] >= length - 1:
        return no("ambiguous_quiet_window")

    # The middle of the assumed sleep can sit anywhere the block still fits in the quiet stretch.
    low = MIDSLEEP_LOCAL[0] - (start + length - SLEEP_HOURS // 2)
    high = MIDSLEEP_LOCAL[1] - (start + SLEEP_HOURS // 2)
    offsets = [_name(low + i) for i in range(high - low + 1)]     # going east, each in -11..+12
    end = (start + length) % 24
    return {
        "utc_offset_from": offsets[0],
        "utc_offset_to": offsets[-1],
        "utc_offsets": offsets,
        "crosses_date_line": offsets[0] > offsets[-1],
        "label": offsets_label(offsets),
        "quiet_start_hour": start,
        "quiet_end_hour": end,                         # the first active hour after the stretch
        "quiet_hours": length,
        "quiet_events": sum(hours[(start + i) % 24] for i in range(length)),
        "basis": (f"Based on {events} public events over {window_days} day{'s' if window_days != 1 else ''} "
                  f"({active_days} with activity). The longest quiet stretch is {_hh(start)} to {_hh(end)} UTC."),
        "assumption": ("Assumes one person who sleeps at least 6 hours inside the quiet stretch, with the middle "
                       "of that sleep between 02:00 and 05:00 local time."),
        "caveat": ("A hint, not a fact. Shift work, scheduled jobs, bots and shared accounts all break it, "
                   "and a UTC offset is not a place."),
    }, None


def summarize(events: list[dict]) -> dict:
    """Counts over a list of raw events. Rows without a readable time are dropped."""
    hours, weekdays = [0] * 24, [0] * 7
    types: Counter = Counter()
    repos: Counter = Counter()
    days: set = set()
    first = last = None
    seen: set[str] = set()
    count = 0
    for ev in events:
        if not isinstance(ev, dict):
            continue
        d = _when(ev.get("created_at"))
        if d is None:
            continue
        ident = str(ev.get("id") or "")
        if ident:
            if ident in seen:        # a new event between two page requests shifts the pages by one
                continue
            seen.add(ident)
        count += 1
        hours[d.hour] += 1
        weekdays[d.weekday()] += 1
        days.add(d.date())
        first = d if first is None or d < first else first
        last = d if last is None or d > last else last
        kind = ev.get("type")
        if isinstance(kind, str) and kind.isascii() and kind.isalnum() and len(kind) <= 60:
            types[kind] += 1
        repo = (ev.get("repo") or {}).get("name") if isinstance(ev.get("repo"), dict) else None
        if isinstance(repo, str) and REPO_RE.fullmatch(repo):
            repos[repo] += 1

    window_days = (last.date() - first.date()).days + 1 if count else 0
    estimate, reason = estimate_offset(hours, count, len(days), window_days) if count else (None, None)
    return {
        "events": count,
        "window": {"first": _iso(first) if first else "", "last": _iso(last) if last else "",
                   "days": window_days, "active_days": len(days)},
        "hours_utc": hours,                    # index 0 is 00:00 to 00:59 UTC
        "weekdays_utc": weekdays,              # index 0 is Monday
        "weekday_labels": list(WEEKDAYS),
        "types": [{"type": t, "count": c} for t, c in sorted(types.items(), key=lambda kv: (-kv[1], kv[0]))[:MAX_TYPES]],
        "repos": [{"name": r, "url": f"https://github.com/{r}", "count": c}
                  for r, c in sorted(repos.items(), key=lambda kv: (-kv[1], kv[0]))[:TOP_REPOS]],
        "estimate": estimate,
        "estimate_reason": reason,
    }


async def _page(client: httpx.AsyncClient, login: str, page: int) -> tuple[str, object, httpx.Response | None]:
    """(state, rows, response). State is ok, end, not_found, rate_limited or failed."""
    url = f"{API}/users/{quote(login, safe='')}/events/public"
    try:
        resp = await client.get(url, params={"per_page": str(PER_PAGE), "page": str(page)},
                                headers=api_headers(), follow_redirects=False)
    except Exception as e:
        return "failed", error_fields(code=classify(e), detail=type(e).__name__), None
    note_quota(resp, "core")
    if resp.status_code == 404:
        return "not_found", None, resp
    if is_rate_limit(resp):
        return "rate_limited", None, resp
    if resp.status_code == 422 and page > 1:
        return "end", None, resp           # GitHub refuses pages past the ones it keeps
    if resp.status_code != 200:
        return "failed", error_fields(code="upstream", detail=f"HTTP {resp.status_code} from {HOST}"), resp
    try:
        rows = resp.json()
    except ValueError:
        rows = None
    if not isinstance(rows, list):
        return "failed", error_fields(code="bad_response", detail=f"Unreadable response from {HOST}"), resp
    return "ok", rows, resp


async def run_github_activity(username: str) -> dict:
    """The activity pattern of one account. Never raises: see the module docstring."""
    try:
        return await _run(username)
    except Exception as e:  # noqa: BLE001
        # The class name only: an exception text can carry the request URL, and the URL carries the login.
        fields = error_fields(code=classify(e), detail=type(e).__name__)
        log.warning("github activity did not answer", extra={"error_code": fields["error_code"]})
        return {"username": username if isinstance(username, str) else "", "found": None, "state": "failed", "cached": False, **fields}


def _allowance_spent(username: str, wait: int) -> dict:
    return {"username": username, "found": None, "state": "rate_limited", "retry_after": wait, "cached": False,
            **rate_limited_fields(wait, f"The {HOST} allowance is spent")}


async def _run(username: str) -> dict:
    if not LOGIN_RE.fullmatch(username):
        # Not a name GitHub can hold ("a.b", "x_y", "." or ".."), so no request is made: a dot
        # segment in the path would ask for another endpoint.
        return {"username": username, "found": False, "state": "not_found", "cached": False, "note": NOT_A_LOGIN}
    key = username.lower()
    cached = _cache_get(key)
    if cached is not None:
        return {**cached, "username": username, "cached": True}
    wait = quota_wait("core")
    if wait:
        return _allowance_spent(username, wait)

    events: list[dict] = []
    pages = 0
    later = "ok"            # what happened to a page after the first
    async with httpx.AsyncClient(timeout=TIMEOUT) as client:
        for page in range(1, MAX_PAGES + 1):
            if page > 1 and quota_wait("core"):
                later = "rate_limited"      # the page before spent the allowance: do not ask to be refused
                break
            state, payload, resp = await _page(client, username, page)
            if page == 1 and state != "ok":
                return _first_page_failed(username, state, payload, resp)
            if state != "ok":
                later = "ok" if state in ("end", "not_found") else state
                break
            pages += 1
            events.extend(payload)
            if len(payload) < PER_PAGE:
                break

    summary = summarize(events)
    result = {
        "username": username,
        "found": True,
        "state": "ok" if summary["events"] else "none",
        "cached": False,
        "complete": later == "ok",          # False when a later page was rate limited or failed
        "pages": pages,
        **summary,
    }
    if later != "ok":
        result["later_pages"] = later
    # States and counts only. The login, the repositories and the hours are never logged.
    log.info("github activity finished", extra={
        "state": result["state"], "events": summary["events"], "pages": pages, "complete": result["complete"],
        "estimate": bool(summary["estimate"]),
    })
    _cache_put(key, result, CACHE_TTL_OK if result["complete"] else CACHE_TTL_PARTIAL)
    return result


def _first_page_failed(username: str, state: str, payload, resp: httpx.Response | None) -> dict:
    if state == "not_found":
        result = {"username": username, "found": False, "state": "not_found", "cached": False}
        _cache_put(username.lower(), result, CACHE_TTL_OK)
        return result
    if state == "rate_limited":
        wait = retry_after(resp)
        log.warning("github activity rate limited", extra={"retry_after_s": wait, "authenticated": bool(os.getenv("GITHUB_TOKEN"))})
        return {"username": username, "found": None, "state": "rate_limited", "retry_after": wait,
                **rate_limited_fields(wait, f"HTTP {resp.status_code} from {HOST}")}
    log.warning("github activity did not answer", extra={"error_code": payload["error_code"]})
    return {"username": username, "found": None, "state": "failed", **payload}
