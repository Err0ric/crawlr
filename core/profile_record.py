"""
What the ordinary sources returned for a handle, kept for a short while.

The adult and dating pass may only start after the profiles found for a handle have been read
and checked for signs of a minor (core.adult_guard.gate). The page does that check itself; this
record is what lets the server do it too, so a direct API call is held to the same rule.

  note(handle, source, answer)   called by the router after an ordinary source answered: keeps
                                 the profile text the content check reads (a display name, a
                                 bio, a birth or age field) with the site's name and address,
                                 and notes that the source completed
  ran(handle)                    has a mainstream source completed for this handle inside the TTL?
  texts(handle)                  the profile entries on record, for core.minor_rules.Engine.scan

Rule for "the mainstream pass has run": at least one of Sherlock, Maigret, GitHub or the
platform check answered without an error for this handle in the last TTL seconds. Those are the
four sources of an ordinary username run, so the page's own run always satisfies it unless
every one of them was switched off or failed.

The record belongs to the caller who made it: the key is the client's address together with the
handle (`bind`, called by the routers). So one client cannot learn from an adult path's answer
whether somebody else looked a handle up, and cannot be refused or let through on the strength of
another client's run.

In memory, per process, bounded: a restart, a second worker process, a lapsed TTL or a client
whose address changed loses the record, and the result is always a refusal ("run the ordinary
sources first"), never a bypass. Nothing here is logged: the keys hold handles and the values
are profile text.
"""

import time
from collections import OrderedDict
from contextvars import ContextVar

from core import adult_sites

TTL = 30 * 60             # seconds
MAX_HANDLES = 2000
MAX_ENTRIES = 120         # profile entries kept per source, per handle
NAME_MAX = 200
BIO_MAX = 600
FIELD_MAX = 40
MAINSTREAM = ("sherlock", "maigret", "github", "platform_check")
SOURCES = (*MAINSTREAM, "enricher")
BIRTH_KEYS = ("birthday", "birth_date", "birthdate", "born", "dob", "date_of_birth")

_store: "OrderedDict[str, dict]" = OrderedDict()
_client: ContextVar[str] = ContextVar("crawlr_record_client", default="")


def bind(client: str) -> None:
    """Whose record this request reads and writes. Called once at the top of each route that
    notes an answer or starts an adult pass, with the caller's address."""
    _client.set(str(client or "")[:64])


def _now() -> float:
    """Monotonic seconds. A function so the tests can move the clock."""
    return time.monotonic()


def _key(handle) -> str:
    name = str(handle or "").strip().lstrip("@").lower()
    return f"{_client.get()}|{name}" if name else ""


def _failed(answer) -> bool:
    return not isinstance(answer, dict) or bool(answer.get("error") or answer.get("error_code"))


def _entry(source, url, name="", bio="", extra: dict | None = None) -> dict | None:
    site = str(source or "")[:80]
    address = str(url or "")[:600]
    if adult_sites.is_adult_site(site, address):
        return None
    out = {"source": site, "url": address, "name": str(name or "")[:NAME_MAX], "bio": str(bio or "")[:BIO_MAX]}
    for key in (*BIRTH_KEYS, "age"):
        value = (extra or {}).get(key)
        if value not in (None, ""):
            out[key] = str(value)[:FIELD_MAX]
    return out if any(v for k, v in out.items() if k not in ("source", "url")) else None


def _texts(source: str, answer: dict) -> list[dict]:
    """The profile entries one answer holds. Only what the content check reads."""
    rows: list[dict | None] = []
    if source == "maigret":
        for r in answer.get("results") or []:
            if not isinstance(r, dict) or r.get("adult") or r.get("confidence") == "false_positive":
                continue
            p = r.get("profile") if isinstance(r.get("profile"), dict) else {}
            rows.append(_entry(r.get("site"), r.get("url"), p.get("name"), p.get("bio"), p))
    elif source == "enricher":
        for p in answer.get("profiles") or []:
            if isinstance(p, dict):
                rows.append(_entry(p.get("platform"), p.get("url"), p.get("display_name"), p.get("bio"), p))
    elif source == "platform_check":
        for r in answer.get("results") or []:
            if isinstance(r, dict) and r.get("state") == "found":
                rows.append(_entry(r.get("platform"), r.get("url"), r.get("display_name"), r.get("bio"), r))
    elif source == "github":
        if answer.get("found"):
            rows.append(_entry("GitHub", answer.get("profile_url"), answer.get("name"), answer.get("bio")))
    return [r for r in rows if r][:MAX_ENTRIES]


def _live(handle) -> dict | None:
    key = _key(handle)
    rec = _store.get(key)
    if rec is None:
        return None
    if _now() - rec["at"] > TTL:
        del _store[key]
        return None
    return rec


def note(handle, source: str, answer) -> None:
    """Record one ordinary source's answer for a handle. A failed answer records nothing."""
    key = _key(handle)
    if not key or source not in SOURCES or _failed(answer):
        return
    rec = _live(handle) or {"at": 0.0, "done": {}, "texts": {}}
    now = _now()
    rec["at"] = now
    rec["done"][source] = now
    rec["texts"][source] = _texts(source, answer)
    _store[key] = rec
    _store.move_to_end(key)
    while len(_store) > MAX_HANDLES:
        _store.popitem(last=False)


def ran(handle) -> bool:
    rec = _live(handle)
    return bool(rec) and any(s in rec["done"] for s in MAINSTREAM)


def completed(handle) -> list[str]:
    rec = _live(handle)
    return sorted(rec["done"]) if rec else []


def texts(handle) -> list[dict]:
    rec = _live(handle)
    if not rec:
        return []
    return [entry for source in SOURCES for entry in rec["texts"].get(source, [])]


def clear() -> None:
    _store.clear()
