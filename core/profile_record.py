"""
What the ordinary sources returned for a handle, kept for a short while.

The adult and dating pass may only start after the profiles found for a handle have been read
and checked for signs of a minor (core.adult_guard.gate). The page does that check itself; this
record is what lets the server do it too, so a direct API call is held to the same rule.

  open_session(cookie value)     the visitor's random session ID (see below)
  bind(session)                  whose record this request reads and writes
  note(handle, source, answer)   called by the router after an ordinary source answered: keeps
                                 the profile text the content check reads, and how the source
                                 went (ok or failed)
  ran(handle)                    did a source that reads profiles answer for this handle?
  texts(handle)                  the profile entries on record, for core.minor_rules.Engine.scan
  verdict(handle, compute)       the content check's answer for the record as it stands, computed
                                 once per change; a block, once found, stays for the TTL

Rule for "the profiles could be read": at least one profile reader (Maigret or the platform
check; the list is `sources.profile_readers` in the rules file, which the page reads too)
answered without an error for this handle inside the TTL. Sherlock, GitHub or enrichment alone is
not enough: with nothing to read, a clean check would mean nothing. A site that blocked the
platform check is not a failure of that source. A later success clears an earlier failure.

Text is added, never replaced: a source that answers again with fewer rows (or a caller that asks
it about fewer sites) does not make the record forget a bio. The record is bounded; when it is
full the oldest text that carries no signal goes first, and text that produced a signal is never
dropped. A block is sticky: once the check has blocked, it stays blocked for that visitor and
handle until the record expires.

The record belongs to the visitor who made it: the key is a random session ID together with the
handle. The ID is issued here (`open_session`), travels in one cookie set by
middleware/run_session.py, and is bound to the request by the routers (`bind`). So one visitor
cannot learn from an adult path's answer whether somebody else looked a handle up, and cannot be
refused or let through on the strength of another visitor's run. A value this module did not
issue is never a session: it is ignored and a new ID is issued.

In memory, per process, bounded: a restart, a second worker process, a lapsed TTL or a lost
cookie loses the record, and the result is always a refusal ("run the ordinary sources first"),
never a bypass. Nothing here is logged: the keys hold session IDs and handles, and the values
are profile text.
"""

import re
import secrets
import time
from collections import OrderedDict
from contextvars import ContextVar

from core import adult_sites, minor_rules

TTL = 30 * 60             # seconds
MAX_HANDLES = 2000
MAX_SESSIONS = 5000       # live session IDs; the oldest goes first
SESSION_BYTES = 32        # 256 random bits
_SESSION_SHAPE = re.compile(r"^[A-Za-z0-9_-]{43}$")     # what secrets.token_urlsafe(32) returns
MAX_ENTRIES = 60          # profile entries kept per source, per handle
MAX_RECORD = 150          # profile entries kept per handle, all sources together
NAME_MAX = 200
BIO_MAX = 2000            # the scan reads the whole bio, not the 300 characters a row shows
TEXT_MAX = 1000
FIELD_MAX = 40
SOURCES = ("sherlock", "maigret", "github", "platform_check", "enricher")
BIRTH_KEYS = ("birthday", "birth_date", "birthdate", "born", "dob", "date_of_birth")

_store: "OrderedDict[str, dict]" = OrderedDict()
_sessions: "OrderedDict[str, float]" = OrderedDict()     # session ID -> when it was last seen
_client: ContextVar[str] = ContextVar("crawlr_record_session", default="")


def profile_readers() -> tuple[str, ...]:
    """The sources that read profiles, from the rules file. None without it: nothing passes."""
    engine = minor_rules.ENGINE
    return tuple(server for server, _page in engine.profile_readers) if engine else ()


def text_order() -> tuple[str, ...]:
    engine = minor_rules.ENGINE
    return tuple(server for server, _page in engine.text_order) if engine else ()


def open_session(value: str = "") -> tuple[str, bool]:
    """(session ID, was it issued just now). `value` is what the caller's cookie holds. It is
    kept only if this process issued it and it has been seen inside the TTL; anything else (no
    cookie, a made-up value, an expired or evicted ID) gets a fresh random ID."""
    now = _now()
    value = value if isinstance(value, str) else ""
    seen = _sessions.get(value) if _SESSION_SHAPE.match(value) else None
    if seen is not None and now - seen <= TTL:
        _sessions[value] = now
        _sessions.move_to_end(value)
        return value, False
    if seen is not None:
        del _sessions[value]
    session = secrets.token_urlsafe(SESSION_BYTES)
    _sessions[session] = now
    while len(_sessions) > MAX_SESSIONS:
        _sessions.popitem(last=False)
    return session, True


def bind(session: str) -> None:
    """Whose record this request reads and writes. Called once at the top of each route that
    notes an answer or starts an adult pass, with the session ID the middleware put on the
    request. Without one the request gets an ID nobody else has, so it has no record."""
    _client.set(str(session or "") or secrets.token_urlsafe(SESSION_BYTES))


def _now() -> float:
    """Monotonic seconds. A function so the tests can move the clock."""
    return time.monotonic()


def _key(handle) -> str:
    name = str(handle or "").strip().lstrip("@").lower()
    return f"{_client.get()}|{name}" if name else ""


def _failed(answer) -> bool:
    return not isinstance(answer, dict) or bool(answer.get("error") or answer.get("error_code"))


def guard_fields(row: dict) -> dict:
    """The guard-only part of a profile row: `guard` holds what the content check reads and the
    page must not keep (the whole bio, other text fields, a birth date, an age)."""
    g = row.get("guard")
    return g if isinstance(g, dict) else {}


def _entry(source, url, name="", bio="", text="", extra: dict | None = None) -> dict | None:
    site = str(source or "")[:80]
    address = str(url or "")[:600]
    if adult_sites.is_adult_site(site, address):
        return None
    out = {"source": site, "url": address, "name": str(name or "")[:NAME_MAX], "bio": str(bio or "")[:BIO_MAX], "text": str(text or "")[:TEXT_MAX]}
    for key in (*BIRTH_KEYS, "age"):
        value = (extra or {}).get(key)
        if value not in (None, ""):
            out[key] = str(value)[:FIELD_MAX]
    return out if any(v for k, v in out.items() if k not in ("source", "url")) else None


def lines(*parts) -> str:
    """Several short text fields as one text, one per line (a line break ends a clause)."""
    return "\n".join(str(p).strip() for p in parts if isinstance(p, str) and p.strip())


def entries_of(source: str, answer: dict) -> list[dict]:
    """The profile entries one answer holds: only what the content check reads. The page's
    profileTexts (static/v2/js/evidence.js) reads the same fields in the same order, and
    tests/test_minor_parity.py compares the two."""
    rows: list[dict | None] = []
    if source == "maigret":
        for r in answer.get("results") or []:
            if not isinstance(r, dict) or r.get("adult") or r.get("confidence") == "false_positive":
                continue
            p = r.get("profile") if isinstance(r.get("profile"), dict) else {}
            g = guard_fields(p)
            rows.append(_entry(r.get("site") or r.get("name"), r.get("url"), p.get("name"), g.get("bio") or p.get("bio"), lines(p.get("location"), g.get("text")), g))
    elif source == "github":
        if answer.get("found"):
            rows.append(_entry("GitHub", answer.get("profile_url"), answer.get("name"), answer.get("bio"), lines(answer.get("company"), answer.get("location"))))
    elif source == "platform_check":
        for r in answer.get("results") or []:
            if isinstance(r, dict) and r.get("state") == "found":
                rows.append(_entry(r.get("platform"), r.get("url"), r.get("display_name"), r.get("bio"), "", guard_fields(r)))
    elif source == "enricher":
        for p in answer.get("profiles") or []:
            if isinstance(p, dict):
                rows.append(_entry(p.get("platform"), p.get("url"), p.get("display_name"), p.get("bio"), "", guard_fields(p)))
    return [r for r in rows if r]


def _carries_signal(handle, entry: dict) -> bool:
    engine = minor_rules.ENGINE
    if engine is None:
        return True
    from core import adult_guard          # late: adult_guard imports this module
    return bool(engine.scan([entry], handle, adult_guard._today())["signals"])


def _live(handle) -> dict | None:
    key = _key(handle)
    rec = _store.get(key)
    if rec is None:
        return None
    if _now() - rec["at"] > TTL:
        del _store[key]
        return None
    return rec


def _add(handle, rec: dict, source: str, new: list[dict]) -> None:
    """Add entries to the record's text for one source: a union, bounded. When full, the oldest
    entry that carries no signal goes first. An entry that produced a signal is never dropped."""
    kept: list[dict] = rec["texts"].setdefault(source, [])
    have = {tuple(sorted(e["e"].items())) for e in kept}
    for entry in new:
        ident = tuple(sorted(entry.items()))
        if ident in have:
            continue
        have.add(ident)
        kept.append({"e": entry, "sig": _carries_signal(handle, entry)})
        rec["version"] += 1

    def trim(pool: list[dict], limit: int) -> None:
        while len(pool) > limit:
            victim = next((x for x in pool if not x["sig"]), None)
            if victim is None:
                break                       # only signal text is left: nothing is forgotten
            for lst in rec["texts"].values():
                if any(x is victim for x in lst):
                    lst[:] = [x for x in lst if x is not victim]
            pool[:] = [x for x in pool if x is not victim]
            rec["version"] += 1

    trim(kept, MAX_ENTRIES)
    everything = [x for lst in rec["texts"].values() for x in lst]
    trim(everything, MAX_RECORD)
    # A hostile caller could still fill a record with signal text. It is capped hard; by then
    # the record blocks anyway, and the block is sticky.
    for lst in rec["texts"].values():
        del lst[MAX_ENTRIES * 2:]


def note(handle, source: str, answer) -> None:
    """Record one ordinary source's answer for a handle: how it went, and the text it returned.
    A failed answer is recorded as failed and adds no text."""
    key = _key(handle)
    if not key or source not in SOURCES:
        return
    rec = _live(handle) or {"at": 0.0, "done": {}, "texts": {}, "version": 0, "checked": -1, "block": None}
    rec["at"] = _now()
    if _failed(answer):
        rec["done"][source] = "failed"
    else:
        rec["done"][source] = "ok"        # a later success clears an earlier failure
        _add(handle, rec, source, entries_of(source, answer))
    _store[key] = rec
    _store.move_to_end(key)
    while len(_store) > MAX_HANDLES:
        _store.popitem(last=False)


def outcomes(handle) -> dict[str, str]:
    """{source: "ok" | "failed"} for the sources that have answered for this handle."""
    rec = _live(handle)
    return dict(rec["done"]) if rec else {}


def ran(handle) -> bool:
    done = outcomes(handle)
    return any(done.get(s) == "ok" for s in profile_readers())


def completed(handle) -> list[str]:
    return sorted(s for s, state in outcomes(handle).items() if state == "ok")


def texts(handle) -> list[dict]:
    rec = _live(handle)
    if not rec:
        return []
    order = [*text_order(), *(s for s in SOURCES if s not in text_order())]
    return [x["e"] for source in order for x in rec["texts"].get(source, [])]


def verdict(handle, compute):
    """The block on record for this handle, or None. `compute()` runs the content check and
    returns a block (a dict) or None; it is called only when the record changed since the last
    answer, so a request that checks many links pays for one scan. A block stays until the
    record expires, whatever is noted afterwards."""
    rec = _live(handle)
    if rec is None:
        return None
    if rec["block"] is None and rec["checked"] != rec["version"]:
        rec["block"] = compute()
        rec["checked"] = rec["version"]
    return rec["block"]


def clear() -> None:
    _store.clear()
    _sessions.clear()
    _client.set("")
