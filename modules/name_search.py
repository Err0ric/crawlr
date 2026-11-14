"""
Search public sources for a person's name.

A name is shared by many people, so everything this returns is a candidate to look at, never
a finding about one person. Each row says where it came from and how well its name fits.

Sources (all free, no key, no account, official JSON APIs; nothing is scraped):

  Wikidata   humans (instance of Q5) whose labels or aliases fit, with the English Wikipedia
             link when there is one. Two requests: a search, then labels for the hits.
  GitHub     accounts whose profile name fits (`fullname:` user search). One request. The
             search API returns the login only, so these rows carry no name or bio. Honours
             GITHUB_TOKEN. Anonymous search allows 10 requests a minute per IP.
  ORCID      researcher records by given and family name. One request.
  OpenAlex   author records with their last known institution. One request. Without a key
             OpenAlex shares a small daily budget per IP; when it is spent the source is
             reported as rate limited.
  Bluesky    public profile search. One request, no login.

What leaves the server: the name is necessarily sent to each source, because it is the search.
The optional qualifiers (location, employer, keyword) are never sent anywhere. They are only
compared with what came back, to rank and annotate rows.

What comes back: text only. No avatar or image URL is passed on, every URL in the response is
built here from an ID that was checked against a pattern, and public email addresses that a
source includes (ORCID) are dropped.

States per source: `ok` (rows kept), `none` (the source answered and nothing fit), `failed`
and `rate_limited` (the source did not answer, so nothing is known). A 403 or 429 is always
`rate_limited`, never `none`.

A one-word name matches thousands of people, so it only asks Wikidata, GitHub for the account
with exactly that login, and Bluesky for profiles whose name or handle is exactly that word.

`handles` are spellings a person with this name might use as a username. They are built
locally and nothing is checked or fetched for them.

The name is never logged.
"""

import asyncio
import os
import re
import time
import unicodedata
from collections import OrderedDict
from urllib.parse import quote

import httpx
from fastapi import HTTPException

from core import validate
from core.boilerplate import clean_bio
from core.errors import classify, classify_status, error_fields
from core.logging import get_logger

log = get_logger(__name__)

SOURCE_TIMEOUT = 8.0
PER_SOURCE = 8
MAX_CANDIDATES = 30
MAX_HANDLES = 12
DESCRIPTION_MAX = 240
BLUESKY_FETCH = 25          # one request; most rows only mention the name and are dropped

CACHE_TTL_OK = 24 * 3600
CACHE_TTL_PARTIAL = 600     # a source failed: keep it only long enough to stop a retry loop
CACHE_MAX = 1000
_cache: "OrderedDict[tuple, tuple[float, dict]]" = OrderedDict()   # key -> (expires_at, result)

USER_AGENT = "CrawlR/1.0 (+https://crawlr.lol)"
GITHUB_URL = "https://api.github.com/search/users"
WIKIDATA_URL = "https://www.wikidata.org/w/api.php"
ORCID_URL = "https://pub.orcid.org/v3.0/expanded-search/"
OPENALEX_URL = "https://api.openalex.org/authors"
BLUESKY_URL = "https://public.api.bsky.app/xrpc/app.bsky.actor.searchActors"

RANK = {"exact": 0, "tokens": 1, "partial": 2}
QUALIFIERS = ("location", "employer", "keyword")

_GITHUB_LOGIN_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$")
_QID_RE = re.compile(r"^Q[1-9]\d{0,11}$")
_ORCID_RE = re.compile(r"^\d{4}-\d{4}-\d{4}-\d{3}[\dX]$")
_OPENALEX_RE = re.compile(r"^A\d{1,15}$")
_BSKY_HANDLE_RE = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}$")

_IMAGE_URL_RE = re.compile(r"https?://\S+?\.(?:png|jpe?g|gif|webp|svg|avif|bmp|ico)(?:\?\S*)?(?=\s|$)", re.I)

# Letters that NFKD does not break into a base letter and an accent.
_ASCII_MAP = str.maketrans({
    "ß": "ss", "æ": "ae", "œ": "oe", "ø": "o", "đ": "d", "ð": "d", "ł": "l", "þ": "th", "ı": "i", "ħ": "h",
})


def clear_cache_for_tests() -> None:
    _cache.clear()


class _SourceError(Exception):
    """A source answered, but not with something usable."""

    def __init__(self, code: str, detail: str):
        super().__init__(detail)
        self.code = code
        self.detail = detail


# ---- names --------------------------------------------------------------------------

def fold(text: str) -> str:
    """Lowercase, accents removed, punctuation out: the form two spellings are compared in."""
    s = unicodedata.normalize("NFKD", str(text or "")).casefold().translate(_ASCII_MAP)
    s = "".join(ch for ch in s if unicodedata.category(ch) != "Mn")
    s = s.replace("'", "").replace("’", "").replace("ʼ", "")
    return " ".join("".join(ch if ch.isalnum() else " " for ch in s).split())


def parse_name(name: str) -> dict:
    """First word is the given name, last word the family name, anything between is middle."""
    parts = name.split()
    if len(parts) < 2:
        return {"given": parts[0] if parts else "", "middle": "", "family": "", "single_token": True}
    return {"given": parts[0], "middle": " ".join(parts[1:-1]), "family": parts[-1], "single_token": False}


def _ascii(part: str) -> str:
    """One name part as handle characters: 'O'Brien' -> 'obrien', 'Müller' -> 'muller'.
    Scripts with no ASCII form come out empty; nothing is transliterated."""
    s = unicodedata.normalize("NFKD", part.casefold().translate(_ASCII_MAP))
    return "".join(ch for ch in s if ch.isascii() and ch.isalnum())


def handle_patterns(parsed: dict) -> list[dict]:
    """Usernames a person with this name might use. Suggestions only: nothing is looked up."""
    g, f = _ascii(parsed["given"]), _ascii(parsed["family"])
    m = "".join(_ascii(p) for p in parsed["middle"].split())
    mi = m[:1]
    if parsed["single_token"]:
        rows = [(g, "name")]
    elif not g or not f:
        rows = []
    else:
        rows = [
            (g + f, "givenfamily"), (f"{g}.{f}", "given.family"), (f"{g}_{f}", "given_family"),
            (g[0] + f, "gfamily"), (g + f[0], "givenf"), (f + g, "familygiven"),
            (f"{f}.{g}", "family.given"), (f"{g}-{f}", "given-family"),
        ]
        if mi:
            rows += [
                (g + mi + f, "givenmfamily"), (f"{g}.{mi}.{f}", "given.m.family"),
                (g[0] + mi + f, "gmfamily"), (g + m + f, "givenmiddlefamily"),
            ]
    out: list[dict] = []
    seen: set[str] = set()
    for value, pattern in rows:
        try:
            value = validate.username(value)
        except HTTPException:
            continue
        if len(value) < 2 or value in seen:
            continue
        seen.add(value)
        out.append({"value": value, "pattern": pattern})
    return out[:MAX_HANDLES]


class Query:
    """The validated name and qualifiers, with the folded forms the matching uses."""

    def __init__(self, name: str, location: str = "", employer: str = "", keyword: str = ""):
        self.name = name
        self.parsed = parse_name(name)
        self.single = self.parsed["single_token"]
        self.folded = fold(name)
        self.words = self.folded.split()
        self.given = fold(self.parsed["given"])
        self.family = fold(self.parsed["family"])
        self.qualifiers = {"location": _text(location, 80), "employer": _text(employer, 80), "keyword": _text(keyword, 80)}
        self._qualifier_rx = {
            k: re.compile(rf"(?<!\w){re.escape(fold(v))}(?!\w)") for k, v in self.qualifiers.items() if fold(v)
        }
        self.handles = handle_patterns(self.parsed)
        # Handles that spell out both names; a profile using one of them fits the name.
        self.full_handles = {h["value"] for h in self.handles
                             if h["pattern"] not in ("gfamily", "givenf", "gmfamily")}

    def cache_key(self) -> tuple:
        return (self.folded, *(fold(self.qualifiers[k]) for k in QUALIFIERS))

    def match(self, names: list[str], handle: str = "") -> str | None:
        """How well the best of `names` fits: exact, tokens (every word present), partial
        (family name plus the given initial), or None."""
        best = None
        for raw in names:
            words = fold(raw).split()
            if not words:
                continue
            if " ".join(words) == self.folded:
                return "exact"
            if set(self.words) <= set(words):
                best = "tokens"
            elif (best is None and not self.single and self.family and self.family in words
                  and any(w[:1] == self.given[:1] for w in words if w != self.family)):
                best = "partial"
        if best != "tokens" and handle and handle.casefold() in self.full_handles:
            best = "tokens"
        return best

    def qualifier_hits(self, *fields: str) -> list[str]:
        text = fold(" \n ".join(f for f in fields if f))
        return [k for k in QUALIFIERS if k in self._qualifier_rx and self._qualifier_rx[k].search(text)]


# ---- shared pieces ------------------------------------------------------------------

def _text(value, cap: int) -> str:
    """Plain text from a source: one line, no control characters, capped."""
    if not isinstance(value, str):
        return ""
    s = "".join(" " if unicodedata.category(ch) in ("Cc", "Cf", "Zl", "Zp") else ch for ch in value)
    return " ".join(s.split())[:cap].strip()


def _candidate(q: Query, *, source: str, kind: str, name: str, handle: str, url: str, match: str,
               description: str = "", location: str = "", affiliation: str = "") -> dict:
    # Text only: a picture link someone put in their bio is not passed on either.
    description = _text(_IMAGE_URL_RE.sub("", description or ""), DESCRIPTION_MAX)
    location, affiliation = _text(location, 120), _text(affiliation, 200)
    return {
        "source": source, "kind": kind, "name": _text(name, 120), "handle": handle, "url": url,
        "description": description, "location": location, "affiliation": affiliation,
        "name_match": match,
        "qualifier_hits": q.qualifier_hits(location, affiliation, description),
    }


def _rows(value) -> list[dict]:
    return [x for x in value if isinstance(x, dict)] if isinstance(value, list) else []


def _int(value) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None


async def _get_json(client: httpx.AsyncClient, url: str, params: dict, headers: dict | None = None,
                    host: str = "", ok_statuses: tuple = (200,)) -> tuple[int, object]:
    resp = await client.get(url, params=params, headers={"User-Agent": USER_AGENT, **(headers or {})})
    if resp.status_code not in ok_statuses:
        raise _SourceError(classify_status(resp.status_code) if resp.status_code != 404 else "upstream",
                           f"HTTP {resp.status_code} from {host}")
    try:
        return resp.status_code, resp.json()
    except ValueError:
        raise _SourceError("bad_response", f"Unreadable response from {host}") from None


# ---- sources ------------------------------------------------------------------------
# Each returns (candidates in the source's own order, total the source reports or None).

async def _wikidata(client: httpx.AsyncClient, q: Query) -> tuple[list[dict], int | None]:
    host = "www.wikidata.org"
    _, found = await _get_json(client, WIKIDATA_URL, {
        "action": "query", "list": "search", "srsearch": f"{q.name} haswbstatement:P31=Q5",
        "srlimit": str(PER_SOURCE), "srprop": "", "format": "json",
    }, host=host)
    query = found.get("query") if isinstance(found, dict) else None
    if not isinstance(query, dict):
        raise _SourceError("bad_response", f"Unreadable response from {host}")
    ids = [r["title"] for r in _rows(query.get("search")) if _QID_RE.fullmatch(str(r.get("title") or ""))]
    total = _int((query.get("searchinfo") or {}).get("totalhits"))
    if not ids:
        return [], total

    _, got = await _get_json(client, WIKIDATA_URL, {
        "action": "wbgetentities", "ids": "|".join(ids), "props": "labels|aliases|descriptions|sitelinks",
        "sitefilter": "enwiki", "format": "json",
    }, host=host)
    entities = got.get("entities") if isinstance(got, dict) else None
    if not isinstance(entities, dict):
        raise _SourceError("bad_response", f"Unreadable response from {host}")

    out = []
    for qid in ids:
        ent = entities.get(qid)
        if not isinstance(ent, dict):
            continue
        labels = ent.get("labels") if isinstance(ent.get("labels"), dict) else {}
        aliases = ent.get("aliases") if isinstance(ent.get("aliases"), dict) else {}
        names = [str(v.get("value") or "") for v in labels.values() if isinstance(v, dict)]
        names += [str(a.get("value") or "") for rows in aliases.values() for a in _rows(rows)]
        match = q.match(names)
        if not match:
            continue
        shown = next((str(labels[lang].get("value") or "") for lang in ("en", "mul")
                      if isinstance(labels.get(lang), dict) and labels[lang].get("value")), "")
        if not shown:
            # No English label: show the spelling that fit the search.
            shown = next((n for n in names if q.match([n]) == match), names[0] if names else "")
        desc = (ent.get("descriptions") or {}).get("en") if isinstance(ent.get("descriptions"), dict) else None
        cand = _candidate(
            q, source="Wikidata", kind="public_figure", name=shown, handle=qid,
            url=f"https://www.wikidata.org/wiki/{qid}", match=match,
            description=clean_bio(str((desc or {}).get("value") or "")),
        )
        title = ((ent.get("sitelinks") or {}).get("enwiki") or {}).get("title") if isinstance(ent.get("sitelinks"), dict) else None
        if isinstance(title, str) and title.strip():
            # Built from the article title, so the link can only ever point at English Wikipedia.
            cand["_wikipedia"] = "https://en.wikipedia.org/wiki/" + quote(title.strip().replace(" ", "_")[:300], safe="_(),.-'")
        out.append(cand)
    return out, total


def _github_headers() -> dict:
    h = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    token = os.getenv("GITHUB_TOKEN")
    if token:
        h["Authorization"] = f"Bearer {token}"
    return h


async def _github(client: httpx.AsyncClient, q: Query) -> tuple[list[dict], int | None]:
    if q.single:
        # Only the account with exactly this login. GitHub answers 422 when there is none.
        login = q.handles[0]["value"] if q.handles else ""
        if not _GITHUB_LOGIN_RE.fullmatch(login):
            return [], 0
        search, match = f"user:{login}", "exact"
    else:
        search, match = f'fullname:"{q.name}" type:user', "tokens"
    status, data = await _get_json(client, GITHUB_URL, {"q": search, "per_page": str(PER_SOURCE)},
                                   headers=_github_headers(), host="api.github.com", ok_statuses=(200, 422))
    if status == 422:
        if q.single:
            return [], 0
        raise _SourceError("upstream", "HTTP 422 from api.github.com")
    if not isinstance(data, dict) or not isinstance(data.get("items"), list):
        raise _SourceError("bad_response", "Unreadable response from api.github.com")
    out = []
    for item in _rows(data["items"]):
        login = str(item.get("login") or "")
        if not _GITHUB_LOGIN_RE.fullmatch(login) or item.get("type") not in (None, "User"):
            continue
        # The search API returns no profile name or bio. GitHub matched the name; the row
        # says "tokens" because the exact spelling cannot be confirmed without more requests.
        out.append(_candidate(q, source="GitHub", kind="account", name="", handle=login,
                              url=f"https://github.com/{login}", match=match))
    return out, _int(data.get("total_count"))


async def _orcid(client: httpx.AsyncClient, q: Query) -> tuple[list[dict], int | None]:
    host = "pub.orcid.org"
    _, data = await _get_json(client, ORCID_URL, {
        "q": f'given-names:"{q.parsed["given"]}" AND family-name:"{q.parsed["family"]}"', "rows": str(PER_SOURCE),
    }, headers={"Accept": "application/json"}, host=host)
    if not isinstance(data, dict) or "num-found" not in data:
        raise _SourceError("bad_response", f"Unreadable response from {host}")
    out = []
    for row in _rows(data.get("expanded-result")):
        oid = str(row.get("orcid-id") or "")
        if not _ORCID_RE.fullmatch(oid):
            continue
        full = " ".join(str(row.get(k) or "").strip() for k in ("given-names", "family-names")).strip()
        credit = str(row.get("credit-name") or "").strip()
        other = [str(n) for n in row.get("other-name") or [] if isinstance(n, str)] if isinstance(row.get("other-name"), list) else []
        match = q.match([full, credit, *other])
        if not match:
            continue
        inst = [str(i) for i in row.get("institution-name") or [] if isinstance(i, str) and i.strip()] if isinstance(row.get("institution-name"), list) else []
        # The record's public email addresses are in the response and are left there.
        out.append(_candidate(q, source="ORCID", kind="researcher", name=full or credit, handle=oid,
                              url=f"https://orcid.org/{oid}", match=match, affiliation="; ".join(inst[:3])))
    return out, _int(data.get("num-found"))


async def _openalex(client: httpx.AsyncClient, q: Query) -> tuple[list[dict], int | None]:
    host = "api.openalex.org"
    _, data = await _get_json(client, OPENALEX_URL, {
        "search": q.name, "per-page": str(PER_SOURCE),
        "select": "id,display_name,display_name_alternatives,works_count,last_known_institutions,topics",
    }, host=host)
    if not isinstance(data, dict) or not isinstance(data.get("results"), list):
        raise _SourceError("bad_response", f"Unreadable response from {host}")
    out = []
    for row in _rows(data["results"]):
        aid = str(row.get("id") or "").rsplit("/", 1)[-1]
        if not _OPENALEX_RE.fullmatch(aid):
            continue
        name = str(row.get("display_name") or "")
        alts = [str(n) for n in row.get("display_name_alternatives") or [] if isinstance(n, str)] if isinstance(row.get("display_name_alternatives"), list) else []
        match = q.match([name, *alts])
        if not match:
            continue
        inst = next(iter(_rows(row.get("last_known_institutions"))), {})
        topics = [str(t.get("display_name")) for t in _rows(row.get("topics"))[:3] if t.get("display_name")]
        works = _int(row.get("works_count"))
        parts = []
        if works is not None:
            parts.append(f"{works} work{'' if works == 1 else 's'} indexed.")
        if topics:
            parts.append("Topics: " + ", ".join(topics) + ".")
        out.append(_candidate(q, source="OpenAlex", kind="researcher", name=name, handle=aid,
                              url=f"https://openalex.org/{aid}", match=match, description=" ".join(parts),
                              location=str(inst.get("country_code") or ""), affiliation=str(inst.get("display_name") or "")))
    return out, _int((data.get("meta") or {}).get("count") if isinstance(data.get("meta"), dict) else None)


async def _bluesky(client: httpx.AsyncClient, q: Query) -> tuple[list[dict], int | None]:
    host = "public.api.bsky.app"
    _, data = await _get_json(client, BLUESKY_URL, {"q": q.name, "limit": str(BLUESKY_FETCH)}, host=host)
    if not isinstance(data, dict) or not isinstance(data.get("actors"), list):
        raise _SourceError("bad_response", f"Unreadable response from {host}")
    out = []
    for actor in _rows(data["actors"]):
        handle = str(actor.get("handle") or "").lower()
        if handle == "handle.invalid" or not _BSKY_HANDLE_RE.fullmatch(handle) or len(handle) > 253:
            continue
        display = str(actor.get("displayName") or "")
        local = handle.split(".", 1)[0]
        if q.single:
            # Exactly this word as the profile name or the handle, nothing looser.
            match = "exact" if fold(display) == q.folded or local in q.full_handles else None
        else:
            match = q.match([display], handle=local)
        if not match:
            continue
        out.append(_candidate(q, source="Bluesky", kind="account", name=display, handle=handle,
                              url=f"https://bsky.app/profile/{handle}", match=match,
                              description=clean_bio(str(actor.get("description") or ""), "bluesky", handle, display)))
    return out, None       # the search reports no total


SOURCES = (("Wikidata", _wikidata), ("GitHub", _github), ("ORCID", _orcid), ("OpenAlex", _openalex), ("Bluesky", _bluesky))
SINGLE_TOKEN_SOURCES = ("Wikidata", "GitHub", "Bluesky")


async def _run_source(label: str, fn, client: httpx.AsyncClient, q: Query) -> dict:
    """One source, never raising: {state, rows, total} plus the error fields when it failed."""
    try:
        rows, total = await asyncio.wait_for(fn(client, q), SOURCE_TIMEOUT)
    except _SourceError as e:
        fields = error_fields(code=e.code, detail=e.detail)
    except Exception as e:
        # The class name only: an exception message can carry the request URL, and the
        # request URL carries the name.
        fields = error_fields(code=classify(e), detail=type(e).__name__)
    else:
        return {"state": "ok", "rows": rows, "total": total}
    limited = fields["error_code"] == "rate_limited"
    # Source and error code only. The name and the qualifiers are never logged.
    log.warning("name search source did not answer", extra={"source": label, "error_code": fields["error_code"]})
    return {"state": "rate_limited" if limited else "failed", "rows": [], "total": None, **fields}


def _sort_key(c: dict) -> tuple:
    return (RANK[c["name_match"]], -len(c["qualifier_hits"]))


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


async def run_name_search(name: str, location: str = "", employer: str = "", keyword: str = "") -> dict:
    """`name` must already have been through core.validate.person_name."""
    q = Query(name, location, employer, keyword)
    key = q.cache_key()
    cached = _cache_get(key)
    if cached is not None:
        return {**cached, "cached": True}

    active = [(label, fn) for label, fn in SOURCES if not q.single or label in SINGLE_TOKEN_SOURCES]
    async with httpx.AsyncClient(timeout=SOURCE_TIMEOUT) as client:
        results = await asyncio.gather(*(_run_source(label, fn, client, q) for label, fn in active))

    # Stable sorts: a source's own order breaks ties, then the order of SOURCES.
    kept: list[dict] = []
    for res in results:
        kept += sorted(res["rows"], key=_sort_key)[:PER_SOURCE]
    kept = sorted(kept, key=_sort_key)[:MAX_CANDIDATES]

    notable = None
    wikidata = [c for c in kept if c["source"] == "Wikidata" and c["name_match"] == "exact"]
    pick = next((c for c in wikidata if c.get("_wikipedia")), wikidata[0] if wikidata else None)
    if pick:
        notable = {"name": pick["name"], "description": pick["description"], "url": pick["url"],
                   "wikipedia": pick.get("_wikipedia", "")}

    sources = {}
    for (label, _fn), res in zip(active, results):
        if res["state"] != "ok":
            sources[label] = {"state": res["state"], "count": 0, "total": None,
                              **{k: res[k] for k in ("error", "error_code", "error_detail")}}
            continue
        count = sum(1 for c in kept if c["source"] == label)
        sources[label] = {"state": "ok" if count else "none", "count": count, "total": res["total"]}

    result = {
        "name": q.name,
        "parsed": q.parsed,
        "candidates": [{k: v for k, v in c.items() if not k.startswith("_")} for c in kept],
        "sources": sources,
        "handles": q.handles,
        "notable": notable,
        "cached": False,
    }
    complete = all(s["state"] in ("ok", "none") for s in sources.values())
    _cache_put(key, result, CACHE_TTL_OK if complete else CACHE_TTL_PARTIAL)
    return result
