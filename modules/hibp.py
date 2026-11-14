"""
Breach exposure for an email address, from XposedOrNot (free, no key).

Two calls: `check-email` returns the names of the breaches an address appears in, and the
public breach catalogue returns the date, the exposed data classes, the record count and a
reference link for every breach XposedOrNot knows. The catalogue is the same for every
address, so it is fetched once and kept in memory for a day.

If the catalogue cannot be fetched the names are still returned, with `details` set to
"unavailable": a breach name with no date is still evidence, and a failed detail lookup is
not a reason to drop it.

The file keeps its old name (it once pointed at Have I Been Pwned, whose email API is paid).
"""

import asyncio
import time
from urllib.parse import quote

import httpx

from core.errors import error_fields

SOURCE = "XposedOrNot"
CHECK_URL = "https://api.xposedornot.com/v1/check-email/{email}"
CATALOGUE_URL = "https://api.xposedornot.com/v1/breaches"
BREACH_PAGE = "https://xposedornot.com/breach/{name}"
HEADERS = {"User-Agent": "Crawlr/0.1"}

CATALOGUE_TTL = 24 * 3600
CATALOGUE_RETRY = 300          # after a failed fetch, wait this long before asking again
_catalogue: dict = {"at": 0.0, "failed_at": 0.0, "by_name": None}
_catalogue_lock = asyncio.Lock()


def clear_cache_for_tests() -> None:
    global _catalogue_lock
    _catalogue.update(at=0.0, failed_at=0.0, by_name=None)
    _catalogue_lock = asyncio.Lock()      # a lock belongs to the event loop that first used it


def index_catalogue(payload) -> dict[str, dict]:
    """The catalogue response as {lowercased breach name: entry}."""
    rows = payload.get("exposedBreaches") if isinstance(payload, dict) else payload
    out = {}
    for row in rows or []:
        if isinstance(row, dict) and row.get("breachID"):
            out[str(row["breachID"]).lower()] = row
    return out


async def _load_catalogue(client: httpx.AsyncClient) -> dict[str, dict] | None:
    """The cached catalogue, refreshed once a day. None when it has never been fetched and
    cannot be now. A stale copy is better than none, so a failed refresh keeps the old one."""
    now = time.time()
    cached = _catalogue["by_name"]
    if cached is not None and now - _catalogue["at"] < CATALOGUE_TTL:
        return cached
    if now - _catalogue["failed_at"] < CATALOGUE_RETRY:
        return cached
    async with _catalogue_lock:
        if _catalogue["by_name"] is not None and time.time() - _catalogue["at"] < CATALOGUE_TTL:
            return _catalogue["by_name"]
        try:
            resp = await client.get(CATALOGUE_URL, headers=HEADERS)
            resp.raise_for_status()
            by_name = index_catalogue(resp.json())
            if not by_name:
                raise ValueError("empty breach catalogue")
        except Exception:
            _catalogue["failed_at"] = time.time()
            return _catalogue["by_name"]
        _catalogue.update(at=time.time(), failed_at=0.0, by_name=by_name)
        return by_name


def _safe_reference(url) -> str:
    url = str(url or "").strip()
    return url if url.startswith(("https://", "http://")) and len(url) < 500 else ""


def breach_row(name: str, entry: dict | None) -> dict:
    """One breach in the response shape. With no catalogue entry every detail is empty or null."""
    entry = entry or {}
    date = str(entry.get("breachedDate") or "")[:10]
    if not (len(date) == 10 and date[:4].isdigit() and date[4] == "-"):
        date = ""
    records = entry.get("exposedRecords")
    verified, sensitive = entry.get("verified"), entry.get("sensitive")
    return {
        "name": name,
        "date": date,
        "year": int(date[:4]) if date else None,
        "data_classes": [str(x) for x in (entry.get("exposedData") or []) if x][:30],
        "records": records if isinstance(records, int) and not isinstance(records, bool) and records > 0 else None,
        "verified": verified if isinstance(verified, bool) else None,
        "sensitive": sensitive if isinstance(sensitive, bool) else None,
        "domain": str(entry.get("domain") or "").strip().lower(),
        "type": str(entry.get("breachType") or ""),
        "url": _safe_reference(entry.get("referenceURL")) or BREACH_PAGE.format(name=quote(name, safe="")),
    }


def build_breaches(names: list[str], catalogue: dict[str, dict] | None) -> list[dict]:
    """Rows for the given names, newest first, undated last. Order within a date is by name."""
    rows = [breach_row(n, (catalogue or {}).get(n.lower())) for n in names]
    dated = sorted((r for r in rows if r["date"]), key=lambda r: r["name"].lower())
    dated.sort(key=lambda r: r["date"], reverse=True)
    return dated + sorted((r for r in rows if not r["date"]), key=lambda r: r["name"].lower())


def _names(data) -> list[str]:
    raw = (data or {}).get("breaches") if isinstance(data, dict) else None
    if isinstance(raw, list) and raw and isinstance(raw[0], list):
        raw = raw[0]
    if isinstance(raw, str):
        raw = [raw]
    out = []
    for n in raw or []:
        n = str(n).strip()
        if n and n not in out:
            out.append(n)
    return out


async def run_hibp(email: str, timeout: int = 15) -> dict:
    url = CHECK_URL.format(email=quote(email, safe="@"))
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.get(url, headers=HEADERS)
            if resp.status_code == 404:
                return {"email": email, "total": 0, "source": SOURCE, "breaches": [], "details": "ok"}
            resp.raise_for_status()
            names = _names(resp.json())
            catalogue = await _load_catalogue(client) if names else {}
    except Exception as e:
        return {"email": email, "total": 0, "source": SOURCE, "breaches": [], **error_fields(e)}
    return {
        "email": email,
        "total": len(names),
        "source": SOURCE,
        "breaches": build_breaches(names, catalogue),
        "details": "unavailable" if catalogue is None else "ok",
    }
