"""
Archive diff: what changed on one profile page between two Internet Archive captures.

modules/profile_archive.py lists the captures of a profile URL. For two of those capture
times, on a click, this fetches both archived copies, reads the text and the links out of each,
and answers with what the older copy had and the newer one lacks (`removed`) and the other way
round (`added`). A bio line or a link that was taken off a profile shows up under `removed`.

What this module touches:

  * two GETs to https://web.archive.org/web/<14 digits>id_/<the profile URL> per uncached
    pair, and nothing else. `id_` is the archive's raw form: the page as it was captured,
    without the archive's toolbar and without rewritten links.
  * The profile's own host is never contacted. Every request goes through core.pinned, so
    through core.netguard, and only ever to web.archive.org.
  * The URL is checked by modules.profile_archive.check_url, the same check the capture list
    makes: a plain http or https address of a public named host, and never an adult or dating
    site. There is no opt-in here.

What the archive answers (checked live on 2026-11-27 with a public figure's profile):

  * a capture at exactly that time: 200 with the page.
  * no capture at exactly that time: 302 to the nearest one, same URL shape. That hop is
    followed (MAX_HOPS at most, web.archive.org only) and the answer names the capture that
    was really read. A redirect to another page (the capture itself was a redirect, to a login
    page for one) is not followed: that side is `none` with `reason: "redirect"`.
  * no capture of the URL at all: 404.
  * 429: the archive's rate limit.

Reading a capture: the body is read as a stream up to MAX_BODY (2 MB) and the rest is dropped;
`truncated` says so. Each capture, redirects included, is given DEADLINE seconds. Only an HTML
or plain text body is read. The bytes become text through core.charset (a short list of real
charsets, UTF-8 for any other label) and the page is parsed on the parse pool
(core.parsepool): one parse at a time for the whole server, each within a CPU budget, so a
large or awkward capture never holds up other requests. A page that is not read to its end
within that budget is `truncated` too. When the pool is full the answer is `failed` with the
code `busy`, and that answer is not kept. A body that is not text in the charset it was read
in (UTF-16 without a byte order mark, a binary file) is `failed`, never an empty page. Text is
pulled out with the
standard library's html.parser: script, style, noscript, template, svg and head content is
left out, block elements end a line, and every line is cleaned to plain text (no control
characters, no direction overrides) and clipped to LINE_MAX characters. Links are the `href`
of each `a` element, made absolute against the profile URL and kept only when they are a plain
http or https address of a named host that is not an adult or dating site, not an image and
not on a picture or asset host (avatars.*, cdn.*, static.* and the like).

The difference is by line and by link, not by position: a line that moved is not a change. A
line that appears in both copies is in neither list. Lists are capped (MAX_LINES_OUT,
MAX_LINKS_OUT); `total` is the number before the cap.

Everything returned is outside data written by anyone: plain strings, never markup.

States:

  ok            both captures were read and they differ
  same          both captures were read and no text line or link differs
  none          a capture is missing (`missing` lists "from", "to" or both)
  rate_limited  the archive refused a request for now
  failed        the archive could not be asked, or sent something that could not be read
  refused       no request was made: the URL is not one this server looks up, or a capture time
                is not a time (see `reason`)

A failure is never "none". Nothing from the URL or the pages is logged.
"""

import asyncio
import os
import re
import time
from collections import OrderedDict
from datetime import datetime
from html.parser import HTMLParser
from urllib.parse import unquote, urldefrag, urljoin, urlsplit

import httpx

from core import charset, inflight, parsepool, pinned
from core.errors import classify, error_fields
from core.logging import get_logger
from core.netguard import BlockedTarget
from modules import profile_archive
from modules.profiles import base

log = get_logger(__name__)

HOST = "web.archive.org"
RAW_BASE = f"https://{HOST}/web/"
TIMEOUT = 20                  # seconds per connect or read; the archive is slow to open an old capture
DEADLINE = 30                 # seconds for one capture as a whole, redirects included
FEED = 32_768                 # characters handed to the parser between two looks at the CPU budget
MAX_BODY = 2_000_000          # bytes read from one capture, after decoding
MAX_HOPS = 2
LINE_MAX = 300                # characters kept of one line of text
MAX_LINES_READ = 5000         # lines read from one capture
MAX_LINKS_READ = 2000
MAX_LINES_OUT = 120           # lines returned per side
MAX_LINKS_OUT = 60
MAX_TITLE = 200
MAX_HIDDEN_DEPTH = 64         # nested hidden elements remembered by name; deeper ones are only counted
ROW_CLIP = 16 * LINE_MAX      # characters of one line that are looked at; a real line of text is far shorter
PIECES = 4096                 # pieces of text held one by one before they are joined into one string

CACHE_TTL = int(os.getenv("ARCHIVE_DIFF_CACHE_TTL", str(24 * 3600)))    # ok, same, none: a capture does not change
CACHE_TTL_SOFT = 600                                                     # rate_limited
CACHE_TTL_FAILED = 60                                                    # failed: the archive often answers on a second try
CACHE_MAX = 300

REFUSALS = {
    **profile_archive.REFUSALS,
    "bad_timestamp": "A capture time must be one the capture list returned, so nothing was fetched.",
    "same_timestamp": "Both capture times are the same capture, so there is nothing to compare.",
}
SIDE_NOTES = {
    "missing": "The archive holds no capture of this address at or near that time.",
    "redirect": "That capture is a redirect to another page, not the profile itself.",
    "not_a_page": "That capture is not an HTML or text page, so it was not read.",
}

_STAMP = re.compile(r"^\d{14}$")
_ISO = re.compile(r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})Z$")
_RAW_LOCATION = re.compile(r"^(?:https?://web\.archive\.org)?/web/(\d{14})id_/(https?://.+)$", re.I | re.S)
_WAYBACK_LINK = re.compile(r"^(?:https?:)?(?://web\.archive\.org)?/web/\d{1,14}(?:[a-z]{2}_)?/(https?://.+)$", re.I | re.S)
_PAGE_TYPES = ("text/html", "application/xhtml+xml", "text/plain")
# Hosts that serve pictures and page assets, by their first label. A picture address is never returned.
_ASSET_HOST = re.compile(r"^(?:avatars?|images?|imgs?|pbs|media|cdn|static|assets)\d*[.-]", re.I)


# --------------------------------------------------------------------------------------
# Inputs
# --------------------------------------------------------------------------------------
def stamp(value) -> str:
    """A capture time as the archive's 14 digits, or "". Accepts what the capture list
    returns (`2019-03-04T05:06:07Z`) and the 14 digit form inside a snapshot address."""
    v = value.strip() if isinstance(value, str) else ""
    m = _ISO.fullmatch(v)
    if m:
        v = "".join(m.groups())
    if not _STAMP.fullmatch(v):
        return ""
    try:
        when = datetime.strptime(v, "%Y%m%d%H%M%S")
    except ValueError:
        return ""
    # The archive starts in 1996. A time past tomorrow is not a capture.
    return v if 1996 <= when.year and when.timestamp() < time.time() + 86400 else ""


def raw_url(timestamp: str, url: str) -> str:
    return f"{RAW_BASE}{timestamp}id_/{url}"


def _unchanged_on_the_wire(timestamp: str, url: str) -> bool:
    """Will the request path be this capture of this address and nothing else? The HTTP client
    tidies a path before it sends it, so the tidied path is compared with the one meant
    (percent-encoding aside: the client may encode a character, which changes no segment)."""
    meant = f"/web/{timestamp}id_/{url}"
    try:
        sent = httpx.URL(raw_url(timestamp, url)).raw_path.decode("ascii")
    except (httpx.InvalidURL, UnicodeError, ValueError):
        return False
    return unquote(sent) == unquote(meant) and sent.count("/") == meant.count("/")


def _same_page(a: str, b: str) -> bool:
    """Do two addresses name the same page the way the archive keys it: scheme, "www." and a
    trailing slash aside?"""
    def key(u: str) -> tuple:
        p = urlsplit(u)
        host = (p.hostname or "").lower().rstrip(".")
        return (host[4:] if host.startswith("www.") else host, p.path.rstrip("/"), p.query)
    try:
        return key(a) == key(b)
    except ValueError:
        return False


# --------------------------------------------------------------------------------------
# Reading a page
# --------------------------------------------------------------------------------------
class _Page(HTMLParser):
    _BREAKS = frozenset({
        "p", "br", "li", "ul", "ol", "div", "tr", "td", "th", "table", "blockquote", "pre", "section", "article", "header",
        "footer", "nav", "aside", "main", "form", "dl", "dt", "dd", "hr", "figure", "figcaption", "address", "details",
        "summary", "h1", "h2", "h3", "h4", "h5", "h6", "title", "option", "button", "label",
    })
    _HIDDEN = frozenset({"script", "style", "noscript", "template", "svg", "head", "iframe", "object", "canvas", "select", "textarea"})

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []        # the newest pieces of text; older ones are joined in `_joined`
        self._joined: list[str] = []
        self.links: list[str] = []
        self.title: list[str] = []
        self._title_len = 0
        self._hidden: list[str] = []      # open hidden elements, MAX_HIDDEN_DEPTH at most
        self._deeper = 0                  # hidden elements opened past that depth: counted, not named
        self._in_title = False

    def handle_starttag(self, tag, attrs):
        if tag == "title" and self._hidden == ["head"]:
            self._in_title = True
        elif tag in self._HIDDEN:
            if len(self._hidden) < MAX_HIDDEN_DEPTH:
                self._hidden.append(tag)
            else:
                self._deeper += 1
        elif tag == "body":
            self._hidden.clear()          # a head that was never closed ends here
            self._deeper = 0
        elif tag in self._BREAKS:
            self.parts.append("\n")
        elif tag == "a" and not self._hidden and len(self.links) < MAX_LINKS_READ:
            href = dict(attrs).get("href")
            if isinstance(href, str) and href.strip():
                self.links.append(href.strip())

    def text(self) -> str:
        """All the text collected so far, as one string."""
        self._pack()
        return "".join(self._joined)

    def _pack(self) -> None:
        # A page can be made of millions of tiny pieces; held one by one they would cost many
        # times the page. They are joined as they come.
        self._joined.append("".join(self.parts))
        self.parts = []

    def handle_startendtag(self, tag, attrs):
        if tag not in self._HIDDEN:       # <script/> opens nothing
            self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag):
        if tag == "title":
            self._in_title = False
        elif tag in self._HIDDEN:
            if self._deeper:
                self._deeper -= 1         # past the depth that is remembered, a close ends the innermost
            elif tag in self._hidden:
                while self._hidden.pop() != tag:
                    pass
        elif tag in self._BREAKS:
            self.parts.append("\n")

    def handle_data(self, data):
        if self._in_title:
            if self._title_len < ROW_CLIP:
                self.title.append(data[:ROW_CLIP])
                self._title_len += len(data)
        elif not self._hidden:
            self.parts.append(data)
            if len(self.parts) >= PIECES:
                self._pack()


def _link(href: str, page_url: str) -> str:
    """An `href` as a plain absolute address, or "". A link the archive rewrote is unwrapped."""
    m = _WAYBACK_LINK.match(href)
    if m:
        href = m.group(1)
    try:
        absolute = urldefrag(urljoin(page_url, href))[0]
    except ValueError:
        return ""
    if not re.match(r"^https?://", absolute, re.I):
        return ""                         # mailto:, javascript:, tel: and the rest
    if _ASSET_HOST.match(urlsplit(absolute).hostname or ""):
        return ""
    return base.safe_link(absolute)


class NotText(ValueError):
    """The capture's bytes are not text in the charset they were read in."""


def _rows(raw: str):
    """The lines of `raw`, one at a time, each clipped to ROW_CLIP characters: the text is
    never split into a list of lines, and a line is never taken apart whole."""
    at = 0
    while True:
        end = raw.find("\n", at)
        if end < 0:
            yield raw[at:at + ROW_CLIP]
            return
        yield raw[at:min(end, at + ROW_CLIP)]
        at = end + 1


def extract(body: bytes, content_type: str, page_url: str, budget: parsepool.Budget | None = None) -> dict:
    """{title, lines, links} from one capture's bytes. Pure. Lines and links are unique and in
    page order. The page's own charset label never picks the codec: core.charset does.
    The work stops when `budget` (CPU time of this thread) is spent, with what was read up to
    there; `budget.cut` then says so. Raises NotText for a body that is not text."""
    budget = budget or parsepool.Budget()
    text = charset.decode(body, content_type)
    if charset.not_text(text):
        raise NotText()
    kind = (content_type or "").split(";")[0].strip().lower()
    title, hrefs = "", []
    if kind == "text/plain":
        raw = text
    else:
        parser = _Page()
        try:
            # In pieces, so the budget is looked at however the markup is written.
            for at in range(0, len(text), FEED):
                if budget.over(parsepool.READ_SHARE):
                    break
                parser.feed(text[at:at + FEED])
            if not budget.cut:
                parser.close()
        except Exception:  # noqa: BLE001  (a broken page is read as far as it goes)
            pass
        raw, hrefs = parser.text(), parser.links
        title = base.clean("".join(parser.title)[:ROW_CLIP], MAX_TITLE)
    lines, seen = [], set()
    for n, row in enumerate(_rows(raw)):
        if n % 512 == 0 and budget.over():
            break
        line = base.clean(row, LINE_MAX)
        if line and line not in seen:
            seen.add(line)
            lines.append(line)
            if len(lines) >= MAX_LINES_READ:
                break
    links, have = [], set()
    for href in hrefs:
        url = _link(href, page_url)
        if url and url not in have:
            have.add(url)
            links.append(url)
    return {"title": title, "lines": lines, "links": links}


# --------------------------------------------------------------------------------------
# The difference
# --------------------------------------------------------------------------------------
def _only(a: list[str], b: list[str]) -> list[str]:
    other = set(b)
    return [x for x in a if x not in other]


def _side(lines: list[str], links: list[str], page_url: str) -> dict:
    host = (urlsplit(page_url).hostname or "").lower()
    rows = [{"url": u, "external": not _same_site(u, host)} for u in links]
    rows.sort(key=lambda r: not r["external"])            # links that leave the site first; the sort is stable
    return {
        "text": lines[:MAX_LINES_OUT], "text_total": len(lines),
        "links": rows[:MAX_LINKS_OUT], "links_total": len(rows),
    }


def _same_site(url: str, host: str) -> bool:
    other = (urlsplit(url).hostname or "").lower()
    strip = lambda h: h[4:] if h.startswith("www.") else h      # noqa: E731
    return strip(other) == strip(host)


def diff(older: dict, newer: dict, page_url: str) -> dict:
    """{removed, added} between two `extract` results. Pure."""
    return {
        "removed": _side(_only(older["lines"], newer["lines"]), _only(older["links"], newer["links"]), page_url),
        "added": _side(_only(newer["lines"], older["lines"]), _only(newer["links"], older["links"]), page_url),
    }


def guard_texts(answer: dict) -> list[str]:
    """The text of an answer in pieces the minor guard's content check can read
    (core.profile_record keeps 2000 characters of a bio): the title of the older capture, the
    title of the newer one when it differs, the removed lines, then the added ones, exactly as
    returned. Every state that carries text counts: a title comes back with `same`, and with
    `none` when one of the two captures was read."""
    if not isinstance(answer, dict):
        return []
    lines: list[str] = []
    for key in ("from", "to"):
        side = answer.get(key)
        title = side.get("title") if isinstance(side, dict) else ""
        if isinstance(title, str) and title and title not in lines:
            lines.append(title)
    for key in ("removed", "added"):
        side = answer.get(key)
        lines += [t for t in (side.get("text") if isinstance(side, dict) else None) or [] if isinstance(t, str) and t]
    chunks, current = [], ""
    for line in lines:
        if current and len(current) + 1 + len(line) > 2000:
            chunks.append(current)
            current = ""
        current = f"{current}\n{line}" if current else line
    if current:
        chunks.append(current)
    return chunks


# --------------------------------------------------------------------------------------
# Network
# --------------------------------------------------------------------------------------
def _transport() -> httpx.AsyncBaseTransport | None:
    """None for the real network. Tests replace this with a mock."""
    return None


def _capture(state: str, asked: str, **more) -> dict:
    return {"state": state, "asked": asked, "timestamp": asked, **more}


async def _fetch(client: httpx.AsyncClient, url: str, asked: str) -> dict:
    """One capture: {state, asked, timestamp, ...}. `state` is ok, none, rate_limited or
    failed; an ok capture carries `body`, `content_type` and `truncated`."""
    try:
        return await asyncio.wait_for(_hops(client, url, asked), DEADLINE)
    except Exception as e:  # noqa: BLE001 - every failure becomes a state with a code
        # Only the exception's type is kept as detail: its text can hold the URL.
        return _capture("failed", asked, **error_fields(code=classify(e), detail=type(e).__name__))


async def _hops(client: httpx.AsyncClient, url: str, asked: str) -> dict:
    current = asked
    for _ in range(MAX_HOPS + 1):
        if not _unchanged_on_the_wire(current, url):
            raise BlockedTarget("the request would not be for this capture")
        got = await pinned.get(client, raw_url(current, url), max_bytes=MAX_BODY, deadline=DEADLINE,
                               headers={"Accept": "text/html,application/xhtml+xml,text/plain;q=0.8"})
        if got.status in (301, 302, 303, 307, 308):
            m = _RAW_LOCATION.match(got.location.strip())
            if not m or not _same_page(m.group(2), url):
                return _capture("none", asked, reason="redirect")
            if m.group(1) == current:
                return _capture("failed", asked, **error_fields(code="bad_response", detail=f"Redirect loop at {HOST}"))
            current = m.group(1)
            continue
        if got.status == 404:
            return _capture("none", asked, reason="missing")
        if got.status == 429:
            return _capture("rate_limited", asked, retry_after=got.retry_after,
                            **error_fields(code="rate_limited", detail=f"HTTP 429 from {HOST}"))
        if got.status != 200:
            return _capture("failed", asked, **error_fields(code="upstream", detail=f"HTTP {got.status} from {HOST}"))
        ctype = got.headers.get("content-type", "")
        if ctype.split(";")[0].strip().lower() not in _PAGE_TYPES:
            return _capture("none", asked, reason="not_a_page")
        return {"state": "ok", "asked": asked, "timestamp": current, "body": got.body, "content_type": ctype,
                "truncated": got.truncated}
    return _capture("failed", asked, **error_fields(code="bad_response", detail=f"Too many redirects at {HOST}"))


def _describe(side: dict, url: str, page: dict | None) -> dict:
    """The public part of one capture: when, where to open it, how much was read."""
    ts = side["timestamp"]
    out = {
        "state": side["state"],
        "timestamp": profile_archive.iso(ts),
        "asked": profile_archive.iso(side["asked"]),
        "exact": ts == side["asked"],                       # False: the archive answered with the nearest capture
        "url": profile_archive.snapshot_url(ts, url),
        "bytes": len(side.get("body") or b""),
        "truncated": bool(side.get("truncated")),
        "title": page["title"] if page else "",
        "text_lines": len(page["lines"]) if page else 0,
        "links": len(page["links"]) if page else 0,
    }
    if side["state"] == "none":
        out["reason"] = side.get("reason", "missing")
        out["note"] = SIDE_NOTES[out["reason"]]
    return out


def _empty_side() -> dict:
    return {"text": [], "text_total": 0, "links": [], "links_total": 0}


def _base(url: str, state: str) -> dict:
    return {"url": url, "state": state, "from": None, "to": None, "removed": _empty_side(), "added": _empty_side(), "complete": False}


def _read(body: bytes, content_type: str, url: str) -> tuple[dict, bool]:
    """(the page, whether reading it stopped at the CPU budget). Runs on the parse pool."""
    budget = parsepool.Budget()
    return extract(body, content_type, url, budget), budget.cut


async def _page(side: dict, url: str) -> dict | None:
    """The text and links of a capture that was fetched. A capture that could not be read
    (the pool is full, or its bytes are not text) becomes a failed one, here, with a code."""
    if side["state"] != "ok":
        return None
    try:
        page, cut = await parsepool.run(_read, side["body"], side["content_type"], url)
    except Exception as e:  # noqa: BLE001 - never a page with nothing on it
        side.update(state="failed", body=b"", truncated=False,
                    **error_fields(code="busy" if isinstance(e, parsepool.Busy) else "bad_response", detail=type(e).__name__))
        return None
    side["truncated"] = bool(side["truncated"] or cut)
    return page


async def _ask(url: str, older: str, newer: str) -> dict:
    async with httpx.AsyncClient(timeout=TIMEOUT, transport=_transport()) as client:
        a, b = await asyncio.gather(_fetch(client, url, older), _fetch(client, url, newer))
    # On the parse pool: decoding and parsing 2 MB takes a moment, and nothing else should wait on it.
    pages = list(await asyncio.gather(*(_page(s, url) for s in (a, b))))
    out = _base(url, "ok")
    out["from"], out["to"] = _describe(a, url, pages[0]), _describe(b, url, pages[1])
    states = (a["state"], b["state"])
    for bad in ("rate_limited", "failed"):
        if bad in states:
            side = a if a["state"] == bad else b
            out["state"] = bad
            out.update({k: side[k] for k in ("error", "error_code", "error_detail")})
            if bad == "rate_limited":
                out["retry_after"] = max((s.get("retry_after") or 0 for s in (a, b)), default=0) or 60
            return out
    if "none" in states:
        out["state"] = "none"
        out["missing"] = [name for name, s in (("from", a), ("to", b)) if s["state"] == "none"]
        return out
    if a["timestamp"] == b["timestamp"]:
        # Both times led to one capture: there is one copy, so nothing to compare.
        out["state"] = "same"
        out["complete"] = True
        out["note"] = "The archive answered both times with the same capture."
        return out
    out.update(diff(pages[0], pages[1], url))
    changed = any(out[k][f] for k in ("removed", "added") for f in ("text_total", "links_total"))
    out["state"] = "ok" if changed else "same"
    # False when a capture was cut at the size cap or a list at its own: there may be more.
    out["complete"] = not (a["truncated"] or b["truncated"] or any(
        out[k]["text_total"] > MAX_LINES_OUT or out[k]["links_total"] > MAX_LINKS_OUT for k in ("removed", "added")))
    return out


# --------------------------------------------------------------------------------------
# Cache
# --------------------------------------------------------------------------------------
_cache: "OrderedDict[tuple, tuple[float, dict]]" = OrderedDict()
_pending: dict = {}           # pairs being fetched right now (core.inflight)


def clear_cache_for_tests() -> None:
    _cache.clear()
    _pending.clear()


def _copy(answer: dict) -> dict:
    out = dict(answer)
    for key in ("from", "to"):
        out[key] = dict(answer[key]) if answer[key] else None
    for key in ("removed", "added"):
        out[key] = {**answer[key], "text": list(answer[key]["text"]), "links": [dict(r) for r in answer[key]["links"]]}
    return out


def _cache_get(key: tuple) -> dict | None:
    hit = _cache.get(key)
    if not hit:
        return None
    state = hit[1]["state"]
    ttl = CACHE_TTL if state in ("ok", "same", "none") else min(CACHE_TTL, CACHE_TTL_FAILED if state == "failed" else CACHE_TTL_SOFT)
    if time.time() - hit[0] > ttl:
        _cache.pop(key, None)
        return None
    _cache.move_to_end(key)
    return _copy(hit[1])


def _cache_put(key: tuple, answer: dict) -> None:
    _cache[key] = (time.time(), _copy(answer))
    _cache.move_to_end(key)
    while len(_cache) > CACHE_MAX:
        _cache.popitem(last=False)


# --------------------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------------------
def _refused(reason: str) -> dict:
    # The URL is not echoed: it was not accepted, so it is not this module's to repeat.
    log.info("archive diff", extra={"state": "refused", "reason": reason})
    return {**_base("", "refused"), "reason": reason, "note": REFUSALS[reason], "cached": False}


async def run_archive_diff(url: str, from_time: str, to_time: str) -> dict:
    """What changed on `url` between two captures. Never raises. The two times may come in
    either order: `from` in the answer is always the older one, and `swapped` says when the
    request had them the other way round."""
    try:
        clean, reason = profile_archive.check_url(url)
        if reason:
            return _refused(reason)
        a, b = stamp(from_time), stamp(to_time)
        if not a or not b:
            return _refused("bad_timestamp")
        if a == b:
            return _refused("same_timestamp")
        swapped = a > b
        older, newer = (b, a) if swapped else (a, b)
        key = (clean, older, newer)
        cached = _cache_get(key)
        if cached is not None:
            return {**cached, "swapped": swapped, "cached": True}
        async def fresh() -> dict:
            answer = await _ask(clean, older, newer)
            if answer.get("error_code") != "busy":      # a full pool says nothing about the captures: not kept
                _cache_put(key, answer)
            # States and sizes only: no URL, host, title or line of text is logged.
            log.info("archive diff", extra={"state": answer["state"], "removed": answer["removed"]["text_total"],
                                            "added": answer["added"]["text_total"]})
            return answer

        # The same pair asked for twice at once is fetched once; each caller gets its own copy.
        answer = _copy(await inflight.shared(_pending, key, fresh))
        return {**answer, "swapped": swapped, "cached": False}
    except Exception as e:  # noqa: BLE001
        fields = error_fields(code=classify(e), detail=type(e).__name__)
        log.warning("archive diff did not answer", extra={"error_code": fields["error_code"]})
        return {**_base("", "failed"), **fields, "cached": False}
