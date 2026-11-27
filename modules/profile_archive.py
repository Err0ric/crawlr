"""
Profile archive: does the Internet Archive hold copies of one profile page?

A bio or a link that was removed from a profile often survives in a web archive. For one
profile URL a case already found, on a click, this asks the Wayback Machine's CDX index which
captures it holds and answers with the first and last capture, how many days have one, and
links to a few snapshots spread over time. The investigator opens the snapshots by hand.

What this module does and does not touch:

  * one GET to https://web.archive.org/cdx/search/cdx per uncached URL, nothing else;
  * the archived page itself is never fetched, and neither is the profile's own host;
  * a URL on an adult or dating site is refused before any request (core.adult_sites). There
    is no opt-in here, so there is no way to turn that off.

The request (checked against the live API on 2026-11-26 with an organisation's page):

  url=<the profile URL>  matchType=exact  output=json  fl=timestamp,digest
  filter=statuscode:200  collapse=timestamp:8  limit=10000

  * `matchType=exact` matches the archive's canonical key for the URL, so http and https, and
    "www." or not, are one page.
  * `collapse=timestamp:8` keeps the first capture of each day. A busy page has thousands of
    captures (6,086 for the page checked, 335 KB); by day that was 2,558 rows and 140 KB, and
    the first and last rows were the same captures. So `count` is days with a capture.
  * `limit=10000` is more than 27 years of daily captures. If the archive ever returns that
    many rows the list was cut at the newest end, and `truncated` says so.
  * captures exist: HTTP 200, a JSON list whose first row is the header ["timestamp","digest"].
  * no captures: HTTP 200 and the body `[]`.
  * a request the server does not accept: HTTP 400, text/plain, empty body.
  * 429 is the archive's rate limit answer (not provoked here; taken from its documentation).
  * `filter=statuscode:200` counts captures of the page itself. A profile the archive only
    ever saw as a redirect or an error answers `none`, and the `none` answer's `note` says
    exactly that, so it is not read as "never archived".
  * a URL with `*` in it is refused as `bad_url`: the index reads a trailing `*` as a prefix
    query over every address that starts the same way, which is not one profile page.

The body is read by core.capfetch.read_body, the one bounded reader: gzip is the only coding
asked for, it is inflated here against MAX_BODY and never by the HTTP client, and a body past
MAX_BODY, in another coding, or that does not inflate to its end is `failed`. The whole call
ends within DEADLINE seconds.

An address inside a web archive (archive.org and its subdomains) is not a profile page and is
refused as `bad_url`: the page it wraps would never be checked. A host name written anywhere
in the path or the query is checked against the adult and dating list as well as the host.

States:

  ok            captures exist
  none          the archive answered and holds no capture of this URL
  rate_limited  the archive refused the request for now
  failed        the archive could not be asked or sent something unreadable
  refused       no request was made: the URL is on an adult or dating site, or is not a plain
                web address on a public named host (see `reason`)

A failure is never "none". Nothing from the URL is logged.
"""

import asyncio
import json
import os
import re
import time
import unicodedata
from collections import OrderedDict
from urllib.parse import unquote, unquote_to_bytes, urlsplit, urlunsplit

import httpx

from core import adult_sites, capfetch
from core.errors import classify_status, error_fields
from core.logging import get_logger
from core.validate import HOSTNAME_RE, is_ip

log = get_logger(__name__)

CDX_URL = "https://web.archive.org/cdx/search/cdx"
SNAPSHOT_BASE = "https://web.archive.org/web/"
TIMEOUT = 8                   # seconds per connect or read
DEADLINE = 20                 # seconds for the whole call
MAX_URL = 600
ROW_LIMIT = 10_000            # rows asked for: one per day with a capture
MAX_BETWEEN = 4               # snapshots offered between the first and the last
MAX_BODY = 2_000_000          # bytes; 10,000 rows are about 550 KB

CACHE_TTL = int(os.getenv("PROFILE_ARCHIVE_CACHE_TTL", str(24 * 3600)))    # ok, none
CACHE_TTL_SOFT = 600                                                        # rate_limited, failed
CACHE_MAX = 2000

# The only strings a refused answer's `note` can hold.
REFUSALS = {
    "adult_site": "CrawlR does not look up archived copies of pages on adult or dating sites.",
    "bad_url": "This is not a plain http or https web address, so it was not looked up.",
    "not_public_host": "This address is not on a public named host, so it was not looked up.",
}

_TS = re.compile(r"^\d{14}$")
_BAD_CHARS = re.compile(r"[\s<>\"'`\\^{}|*]|[\x00-\x1f\x7f]")
_ARCHIVE_SITES = ("archive.org",)       # and every host under it: an address there wraps another address
_UNQUOTE_ROUNDS = 4                     # a path still changing after this many decodings is not a plain one
_HOST_SHAPED = re.compile(r"(?<![a-z0-9.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.){1,8}[a-z]{2,24}(?![a-z0-9-])")
NONE_NOTE = ("The archive holds no capture of the page itself. Captures that were a redirect or an error are not counted, "
             "so the address may still appear in the archive.")


# --------------------------------------------------------------------------------------
# The URL
# --------------------------------------------------------------------------------------
def _decoded(text: str) -> str | None:
    """`text` with its percent-encoding taken off, layer by layer, or None when it never
    settles. What a server further along may read out of an address is checked, not only
    what is written."""
    for _ in range(_UNQUOTE_ROUNDS):
        once = unquote(text)
        if once == text:
            return text
        text = once
    return None


def _plain_path(path: str) -> bool:
    """Does the path mean the same before and after it is tidied? Not when any reading of it
    (as written, decoded, or decoded by a reader that takes a look-alike for a dot) has a "."
    or ".." segment or an empty one. Segments are split at "/" and at a backslash, a ";"
    parameter is left off, and spaces, control and invisible characters do not hide a segment."""
    decoded = _decoded(path)
    if decoded is None:
        return False
    # The same decoding on bytes, for the two-byte spelling of "." that a lenient decoder accepts.
    data = path.encode("utf-8", "replace")
    for _ in range(_UNQUOTE_ROUNDS):
        data = unquote_to_bytes(data)
    lenient = data.replace(b"\xc0\xae", b".").decode("utf-8", "replace")
    for form in {path, decoded, lenient}:
        for reading in {form, unicodedata.normalize("NFKC", form)}:      # full-width and other compatibility forms of ".", "/"
            segments = re.split(r"[/\\]", reading)[1:]
            names = ["".join(ch for ch in s.split(";")[0] if ch > " " and ch != "\x7f" and unicodedata.category(ch) != "Cf") for s in segments]
            if any(n in (".", "..") for n in names) or "" in segments[:-1]:
                return False
    return True


def _names_adult_site(parts) -> bool:
    """Is a host name on the adult and dating list written anywhere in the path or the query?
    Such an address is one step from that site whatever host serves it."""
    rest = _decoded(f"{parts.path}?{parts.query}")
    if rest is None:
        return True                          # cannot be read to the bottom: not looked up
    rest = unicodedata.normalize("NFKC", rest).lower()
    return any(adult_sites.is_adult_site(url=f"https://{m.group(0)}/") for m in _HOST_SHAPED.finditer(rest))


def check_url(url: str) -> tuple[str, str]:
    """(clean URL, "") when the URL may be looked up, else ("", a key of REFUSALS).

    A profile link is a plain web address: http or https, a named public host, no credentials
    and no port. The fragment is dropped (it is never part of an archived address). Path and
    query keep their case. The path is taken as written, so one that only means something
    after it is tidied (a "." or ".." segment, spelled out or percent-encoded once or several
    times, behind an encoded slash or a backslash, with a ";" parameter, or an empty segment)
    is not a plain address and is refused: the address that is looked up is exactly the
    address that was checked. An address inside a web archive is refused too, and so is one
    that names an adult or dating site in its path or query."""
    raw = (url or "").strip()
    if not raw or len(raw) > MAX_URL or _BAD_CHARS.search(raw):
        return "", "bad_url"
    try:
        parts = urlsplit(raw)
        port = parts.port
    except ValueError:
        return "", "bad_url"
    if parts.scheme.lower() not in ("http", "https") or not parts.hostname:
        return "", "bad_url"
    if parts.username or parts.password or port is not None:
        return "", "bad_url"
    host = parts.hostname.lower().rstrip(".")
    if is_ip(host) or not HOSTNAME_RE.fullmatch(host) or not host.isascii():
        return "", "not_public_host"
    if not _plain_path(parts.path or "/"):
        return "", "bad_url"
    clean = urlunsplit((parts.scheme.lower(), host, parts.path or "/", parts.query, ""))
    if adult_sites.is_adult_site(url=clean) or _names_adult_site(parts):
        return "", "adult_site"
    if any(host == site or host.endswith("." + site) for site in _ARCHIVE_SITES):
        return "", "bad_url"
    return clean, ""


def snapshot_url(timestamp: str, url: str) -> str:
    """The Wayback Machine address of one capture: /web/<14 digits>/<the original URL>."""
    return f"{SNAPSHOT_BASE}{timestamp}/{url}"


def iso(timestamp: str) -> str:
    """A CDX timestamp (YYYYMMDDhhmmss, UTC) as ISO 8601."""
    t = timestamp
    return f"{t[:4]}-{t[4:6]}-{t[6:8]}T{t[8:10]}:{t[10:12]}:{t[12:14]}Z"


# --------------------------------------------------------------------------------------
# Reading the index
# --------------------------------------------------------------------------------------
def parse_rows(data) -> list[tuple[str, str]] | None:
    """[(timestamp, digest)] in time order from a CDX JSON answer, or None when the answer is
    not the shape the API sends. `[]` is a real answer: no captures."""
    if not isinstance(data, list):
        return None
    if not data:
        return []
    header = data[0]
    if not isinstance(header, list) or "timestamp" not in header:
        return None
    t_at = header.index("timestamp")
    d_at = header.index("digest") if "digest" in header else -1
    rows = []
    for row in data[1:]:
        if not isinstance(row, list) or len(row) <= t_at or not isinstance(row[t_at], str) or not _TS.fullmatch(row[t_at]):
            continue
        digest = row[d_at] if 0 <= d_at < len(row) and isinstance(row[d_at], str) else ""
        rows.append((row[t_at], digest))
    rows.sort(key=lambda r: r[0])
    return rows


def pick_snapshots(timestamps: list[str], between: int = MAX_BETWEEN) -> list[str]:
    """The first capture, the last, and up to `between` from the years strictly between them:
    one per year, the years spread evenly over the span. `timestamps` is in time order."""
    if not timestamps:
        return []
    first, last = timestamps[0], timestamps[-1]
    if first == last:
        return [first]
    by_year: dict[str, str] = {}
    for ts in timestamps:
        if first[:4] < ts[:4] < last[:4]:
            by_year.setdefault(ts[:4], ts)          # the first capture of that year
    years = sorted(by_year)
    if len(years) > between:
        step = (len(years) + 1) / (between + 1)
        years = [years[int((n + 1) * step + 0.5) - 1] for n in range(between)]
    return [first] + [by_year[y] for y in years] + [last]


def _base(url: str, state: str) -> dict:
    return {"url": url, "state": state, "count": 0, "first": None, "last": None,
            "snapshots": [], "distinct_versions": 0, "truncated": False}


def build_answer(url: str, rows: list[tuple[str, str]]) -> dict:
    """The answer for a parsed index reply. Pure."""
    if not rows:
        return {**_base(url, "none"), "note": NONE_NOTE}
    stamps = [ts for ts, _ in rows]
    digests = {d for _, d in rows if d}
    return {
        **_base(url, "ok"),
        "count": len(rows),                          # days with at least one capture
        "first": iso(stamps[0]),
        "last": iso(stamps[-1]),
        "snapshots": [{"timestamp": iso(ts), "url": snapshot_url(ts, url)} for ts in pick_snapshots(stamps)],
        "distinct_versions": len(digests) or 1,      # different page contents among the counted captures
        "truncated": len(rows) >= ROW_LIMIT,
    }


def _problem(url: str, exc: BaseException | None = None, code: str | None = None) -> dict:
    # Only the exception's type is kept as detail: its text can hold the URL.
    fields = error_fields(exc, code=code, detail=type(exc).__name__ if exc is not None else "")
    state = "rate_limited" if fields["error_code"] == "rate_limited" else "failed"
    return {**_base(url, state), **fields}


# --------------------------------------------------------------------------------------
# Network
# --------------------------------------------------------------------------------------
def _transport() -> httpx.AsyncBaseTransport | None:
    """None for the real network. Tests replace this with a mock."""
    return None


async def _ask(url: str) -> dict:
    params = {
        "url": url, "matchType": "exact", "output": "json", "fl": "timestamp,digest",
        "filter": "statuscode:200", "collapse": "timestamp:8", "limit": str(ROW_LIMIT),
    }
    body, cut = b"", ""
    try:
        async with asyncio.timeout(DEADLINE):
            async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=False, transport=_transport()) as client:
                # Only gzip is asked for, and the bytes are taken as they come off the wire:
                # the bounded reader inflates them against the cap, never the HTTP client.
                async with client.stream("GET", CDX_URL, params=params, headers={"Accept-Encoding": "gzip"}) as resp:
                    status = resp.status_code
                    if status == 200:
                        body, cut = await capfetch.read_body(resp.stream, capfetch.coding_of(resp.headers), MAX_BODY)
    except capfetch.BadEncoding:
        return _problem(url, code="bad_response")
    except Exception as e:  # noqa: BLE001 - every failure becomes a state with a code
        return _problem(url, e)
    if status != 200:
        return _problem(url, code=classify_status(status))
    if cut:
        return _problem(url, code="bad_response")       # a list that was not read whole is not a list
    try:
        rows = parse_rows(json.loads(body.decode("utf-8")))
    except (ValueError, RecursionError):
        rows = None
    if rows is None:
        return _problem(url, code="bad_response")
    return build_answer(url, rows)


# --------------------------------------------------------------------------------------
# Cache
# --------------------------------------------------------------------------------------
_cache: "OrderedDict[str, tuple[float, dict]]" = OrderedDict()


def clear_cache_for_tests() -> None:
    _cache.clear()


def _cache_get(key: str) -> dict | None:
    hit = _cache.get(key)
    if not hit:
        return None
    ttl = CACHE_TTL if hit[1]["state"] in ("ok", "none") else min(CACHE_TTL, CACHE_TTL_SOFT)
    if time.time() - hit[0] > ttl:
        _cache.pop(key, None)
        return None
    _cache.move_to_end(key)
    return {**hit[1], "snapshots": [dict(s) for s in hit[1]["snapshots"]]}


def _cache_put(key: str, answer: dict) -> None:
    _cache[key] = (time.time(), {**answer, "snapshots": [dict(s) for s in answer["snapshots"]]})
    _cache.move_to_end(key)
    while len(_cache) > CACHE_MAX:
        _cache.popitem(last=False)


# --------------------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------------------
async def run_profile_archive(url: str) -> dict:
    """{url, state, count, first, last, snapshots: [{timestamp, url}], distinct_versions,
    truncated, cached} for one profile URL. `refused` adds `reason` and `note`; `failed` and
    `rate_limited` add the three core.errors fields."""
    clean, reason = check_url(url)
    if reason:
        # The URL is not echoed: it was not accepted, so it is not this module's to repeat.
        log.info("profile archive", extra={"state": "refused", "reason": reason})
        return {**_base("", "refused"), "reason": reason, "note": REFUSALS[reason], "cached": False}
    cached = _cache_get(clean)
    if cached is not None:
        return {**cached, "cached": True}
    answer = await _ask(clean)
    _cache_put(clean, answer)
    # State and counts only: no URL, host or handle is logged.
    log.info("profile archive", extra={"state": answer["state"], "captures": answer["count"]})
    return {**answer, "cached": False}
