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

States per source: `ok` (the source has rows that fit), `none` (the source answered and nothing
fit), `failed` and `rate_limited` (the source did not answer, so nothing is known). A 403 or 429
is always `rate_limited`, never `none`. A source that was not asked for this kind of name has no
entry at all. `count` is how many rows fit and `shown` how many of them are in `candidates`: the
list is capped, and the cap takes rows from every source in turn so none with a match shows zero.

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

# Picture links are not text. A Markdown image goes whole; a URL goes when it ends in an image
# extension, whatever punctuation follows it. static/v2/js/names.js applies the same two rules,
# and tests/fixtures/name_text.json holds the pairs both sides must agree on.
_MD_IMAGE_RE = re.compile(r"!\[[^\]\n]*\]\([^)\n]*\)")
_IMAGE_URL_RE = re.compile(r"https?://[^\s<>\"'()\[\]]*\.(?:png|jpe?g|gif|webp|svg|avif|bmp|ico)(?:[?#][^\s<>\"'()\[\]]*)?(?![A-Za-z0-9_-])", re.I)


def strip_images(text: str) -> str:
    return " ".join(_IMAGE_URL_RE.sub(" ", _MD_IMAGE_RE.sub(" ", str(text or ""))).split())


# Letters that NFKD does not break into a base letter and an accent.
_ASCII_MAP = str.maketrans({
    "ß": "ss", "æ": "ae", "œ": "oe", "ø": "o", "đ": "d", "ð": "d", "ł": "l", "þ": "th", "ı": "i", "ħ": "h",
})


def clear_cache_for_tests() -> None:
    _cache.clear()


class _NotAsked(Exception):
    """This source has nothing to be asked for this kind of name."""


class _SourceError(Exception):
    """A source answered, but not with something usable."""

    def __init__(self, code: str, detail: str):
        super().__init__(detail)
        self.code = code
        self.detail = detail


# ---- names --------------------------------------------------------------------------

_ACCENT_SCRIPTS = ("LATIN ", "GREEK ", "CYRILLIC ")
# Characters that sit inside a word without being part of its spelling: apostrophes, the middle
# dot, and the zero width joiners. Removed, not turned into a space.
_INSIDE_WORD = str.maketrans("", "", "'\u2019\u02bc\u00b7\u200c\u200d")


def fold(text: str) -> str:
    """Lowercase, punctuation out, and accents removed from Latin, Greek and Cyrillic letters:
    the form two spellings are compared in. In every other script a combining mark is part of the
    letter (a Devanagari vowel sign, a Japanese voicing mark, a Thai vowel), so it stays.
    static/v2/js/names.js has the same function; tests/fixtures/name_text.json checks both."""
    s = unicodedata.normalize("NFKD", str(text or "")).casefold().translate(_ASCII_MAP).translate(_INSIDE_WORD)
    out, accents = [], False
    for ch in s:
        if unicodedata.category(ch) in ("Mn", "Mc"):
            if not accents:
                out.append(ch)
        elif ch.isalnum():
            out.append(ch)
            accents = unicodedata.name(ch, "").startswith(_ACCENT_SCRIPTS)
        else:
            out.append(" ")
            accents = False
    return " ".join("".join(out).split())


# Generational and professional suffixes, compared without periods and in lowercase. Ordinals
# with a digit ("3rd") never get here: the validator refuses digits.
SUFFIXES = frozenset({"jr", "sr", "ii", "iii", "iv", "phd", "md", "esq"})


def parse_name(name: str) -> dict:
    """First word is the given name, last word the family name, anything between is middle.
    Trailing suffixes (Jr., Sr, II, III, IV, PhD, MD, Esq) are set aside in `suffix`: they are not
    a family name, and they stay out of the queries and the handles."""
    parts = name.split()
    suffix: list[str] = []
    while len(parts) > 1 and parts[-1].replace(".", "").casefold() in SUFFIXES:
        suffix.insert(0, parts.pop())
    if len(parts) < 2:
        return {"given": parts[0] if parts else "", "middle": "", "family": "", "suffix": " ".join(suffix), "single_token": True}
    return {"given": parts[0], "middle": " ".join(parts[1:-1]), "family": parts[-1], "suffix": " ".join(suffix), "single_token": False}


def core_name(name: str, parsed: dict) -> str:
    """The name without its suffix: what is searched for and matched against."""
    return " ".join(p for p in (parsed["given"], parsed["middle"], parsed["family"]) if p) or name


_OPERATORS = frozenset({"AND", "OR", "NOT"})


def plain_query(text: str) -> str:
    """A name for a full-text search box. A word that is a boolean operator in capitals is
    lowercased, which makes it an ordinary word for Wikidata's and OpenAlex's search: "Or Cohen"
    is a real name and must be searchable, not refused and not read as an operator."""
    return " ".join(w.lower() if w in _OPERATORS else w for w in text.split())


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
        # Searched and matched without the suffix: "John Smith Jr." is looked for as John Smith.
        self.core = core_name(name, self.parsed)
        self.folded = fold(self.core)
        self.full = fold(name)
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
        # The name as typed (after validation), not its folded form: the answer carries the
        # spelling, its parts and its handles, so "José García" and "Jose Garcia" are two entries.
        return (" ".join(self.name.casefold().split()), *(fold(self.qualifiers[k]) for k in QUALIFIERS))

    def match(self, names: list[str], handle: str = "") -> str | None:
        """How well the best of `names` fits: exact, tokens (every word present), partial
        (the family name plus the bare initial of the given name, "L. Torvalds"), or None.
        Another given name that starts with the same letter is a different person."""
        best = None
        for raw in names:
            words = fold(raw).split()
            if not words:
                continue
            if " ".join(words) in (self.folded, self.full):
                return "exact"
            if set(self.words) <= set(words):
                best = "tokens"
            elif (best is None and not self.single and self.family and self.family in words
                  and self.given[:1] in words):
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
    # Zero width joiners are part of the spelling in Arabic-script and Indic names, so they stay.
    s = "".join(" " if unicodedata.category(ch) in ("Cc", "Cf", "Zl", "Zp") and ch not in "\u200c\u200d" else ch for ch in value)
    return " ".join(s.split())[:cap].strip()


def _candidate(q: Query, *, source: str, kind: str, name: str, handle: str, url: str, match: str,
               description: str = "", location: str = "", affiliation: str = "") -> dict:
    # Text only: a picture link someone put in their bio is not passed on either.
    description = _text(strip_images(description or ""), DESCRIPTION_MAX)
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
        "action": "query", "list": "search", "srsearch": f"{plain_query(q.core)} haswbstatement:P31=Q5",
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
            # No login can be spelled from this name, so GitHub is not asked. That is not "none".
            raise _NotAsked()
        search, match = f"user:{login}", "exact"
    else:
        search, match = f'fullname:"{q.core}" type:user', "tokens"
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
        "search": plain_query(q.core), "per-page": str(PER_SOURCE),
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
    _, data = await _get_json(client, BLUESKY_URL, {"q": q.core, "limit": str(BLUESKY_FETCH)}, host=host)
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
    except _NotAsked:
        return {"state": "not_asked", "rows": [], "total": None}
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


def _fair_cap(per_source: list[list[dict]], limit: int) -> list[dict]:
    """At most `limit` rows, taken one from each source in turn (each source's best first), so a
    source with matches is never cut to zero by the others. Then ranked as one list."""
    if sum(len(rows) for rows in per_source) <= limit:
        picked = [c for rows in per_source for c in rows]
    else:
        picked, depth = [], 0
        while len(picked) < limit and any(depth < len(rows) for rows in per_source):
            for rows in per_source:
                if depth < len(rows) and len(picked) < limit:
                    picked.append(rows[depth])
            depth += 1
        order = {id(c): i for i, c in enumerate(c for rows in per_source for c in rows)}
        picked.sort(key=lambda c: order[id(c)])        # back to source order, so ties rank as before
    return sorted(picked, key=_sort_key)


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
        # The key ignores case, so the spelling and its parts are this request's, not the stored one's.
        return {**cached, "name": q.name, "parsed": q.parsed, "cached": True}

    active = [(label, fn) for label, fn in SOURCES if not q.single or label in SINGLE_TOKEN_SOURCES]
    async with httpx.AsyncClient(timeout=SOURCE_TIMEOUT) as client:
        results = await asyncio.gather(*(_run_source(label, fn, client, q) for label, fn in active))

    # Stable sorts: a source's own order breaks ties, then the order of SOURCES.
    best = [sorted(res["rows"], key=_sort_key)[:PER_SOURCE] for res in results]
    kept = _fair_cap(best, MAX_CANDIDATES)

    notable = None
    wikidata = [c for c in kept if c["source"] == "Wikidata" and c["name_match"] == "exact"]
    pick = next((c for c in wikidata if c.get("_wikipedia")), wikidata[0] if wikidata else None)
    if pick:
        notable = {"name": pick["name"], "description": pick["description"], "url": pick["url"],
                   "wikipedia": pick.get("_wikipedia", "")}

    sources = {}
    for (label, _fn), res, rows in zip(active, results, best):
        if res["state"] == "not_asked":
            continue                # no entry: a source that was not asked did not say "none"
        if res["state"] != "ok":
            sources[label] = {"state": res["state"], "count": 0, "shown": 0, "total": None,
                              **{k: res[k] for k in ("error", "error_code", "error_detail")}}
            continue
        # State and count come from the source's own rows, before the cap on the whole list.
        shown = sum(1 for c in kept if c["source"] == label)
        sources[label] = {"state": "ok" if rows else "none", "count": len(rows), "shown": shown, "total": res["total"]}

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
