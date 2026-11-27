"""
Public document metadata: who wrote the files a domain publishes, and with what.

PDFs and Office files carry the name of the account that made them, the software, and often
a company name. On a click, for one domain, this finds documents the site has published and
reads the metadata inside each.

Finding. One GET to the Internet Archive's CDX index for every address under the domain that
ends in .pdf, .docx, .xlsx or .pptx (checked against the live API on 2026-11-27 with two open
source projects' sites):

  url=<domain>/*  output=json  fl=original,timestamp,endtimestamp,mimetype,length
  filter=statuscode:200  filter=original:.*\\.(pdf|docx|xlsx|pptx)$  (case-insensitive)
  collapse=urlkey  showSkipCount=true  lastSkipTimestamp=true  limit=1500

  * the index sorts by address, not by time. `collapse=urlkey` gives one row per address and
    `lastSkipTimestamp` adds `endtimestamp`, the last capture of that address, so the rows can
    be put newest first here. Past LIST_LIMIT rows the list is cut by address, and
    `listing_truncated` says so;
  * the archive treats "www" and no "www" as one site, so both come back. Any other host in
    an answer is dropped;
  * `length` is the size of the archive's stored record. A document stored as larger than
    MAX_DOC_BYTES is put last, since it would only come back `too_large`;
  * only the list is used. No archived copy is fetched.

Reading. Up to MAX_DOCS documents, newest first, are fetched from the live site: this module
REQUESTS THE TARGET'S OWN SITE. Each GET goes through core.netguard.safe_fetch one hop at a
time. A redirect is followed only while it stays on the domain or a subdomain of it, on the
port a document may be listed on (80 or 443, no credentials), and every hop is vetted and
pinned again; a redirect anywhere else is not followed. The body is capped
at MAX_DOC_BYTES (core.capfetch), each document at DOC_DEADLINE seconds, three at a time. After
a 429 from the site no further document is requested. The parsing is modules/doc_parse.py,
run on the parse pool (core.parsepool): one file at a time for the whole server. When the pool
is full a document is `failed` with the code `busy`, and an answer with such a document is not
kept at all. The same answer is given, before any request for it, to a document that would be
one more than MAX_HELD held in memory at once: that count is for the whole server, whoever
asks, so the bytes of fetched files never add up past it (two full runs fit side by side).

An adult or dating site is refused before any request: names from its files would tie people
to it, and there is no opt-in on this path.

Per-document states:

  ok            metadata was read and at least one field is set
  none          the file was read and declares nothing
  blocked       the site refused the request (401, 403, 451 or a challenge)
  rate_limited  the site answered 429, or an earlier document did and this one was not asked
  failed        the document could not be fetched (gone, moved to another site, timeout, a web
                page in its place); `error_code` says which
  too_large     the file is over the size cap and was not read
  unparsed      the file was fetched but its metadata could not be read; `reason` says why

Overall states: `ok` when at least one document is ok; `none` when the archive lists no
document, or every listed document was read and declares nothing; `rate_limited` or `failed`
when the archive could not be asked; otherwise the most common state among the documents
(ties go to blocked, rate_limited, failed, too_large, unparsed, in that order); `refused` for
an adult or dating site. A failure is never "none".

An answer is kept for a day only when every document in it settled: it was read, or it will
read the same way tomorrow (too large, unparsed, gone, a web page in its place, moved to
another site). When a document was blocked, rate limited or did not answer, the whole answer
is kept for ten minutes, like a failure, so the next look asks again.

Every name is self-declared text from inside a file. Neither the domain nor any name, title
or address is logged.
"""

import asyncio
import copy
import json
import os
import re
import time
from collections import OrderedDict
from urllib.parse import urljoin, urlsplit

import httpx

from core import adult_sites, inflight, parsepool
from core.capfetch import BadEncoding, CappedTransport, TooLarge, release
from core.errors import classify_status, error_fields
from core.logging import get_logger
from core.netguard import safe_fetch
from core.validate import HOSTNAME_RE, is_public_suffix
from modules import doc_parse

log = get_logger(__name__)

UA = "Mozilla/5.0 (compatible; CrawlR/1.0; +https://crawlr.lol)"
CDX_URL = "https://web.archive.org/cdx/search/cdx"
CDX_TIMEOUT = 40              # seconds: the index scans every capture under the domain (21.6 s for python.org)
LIST_LIMIT = 1500             # rows asked for: one per document address
MAX_LIST_BYTES = 2_000_000
MAX_DOCS = 8
MAX_DOC_BYTES = 8_000_000
DOC_TIMEOUT = 8               # seconds per connect or read
DOC_DEADLINE = 15             # seconds per document, redirects included
MAX_REDIRECTS = 4
CONCURRENCY = 3
MAX_HELD = 2 * CONCURRENCY    # documents being fetched or waiting to be read, in the whole process
MAX_URL = 600
TYPES = ("pdf", "docx", "xlsx", "pptx")

CACHE_TTL = int(os.getenv("DOC_METADATA_CACHE_TTL", str(24 * 3600)))    # ok, none
CACHE_TTL_SOFT = 600
CACHE_MAX = 500

NAMES_NOTE = ("Names, companies and software come from text saved inside each file. The author's software wrote it, "
              "or somebody typed over it. Nothing verifies it, and a file may have been made by someone outside the organization.")
NO_LISTING_NOTE = ("The Internet Archive lists no PDF or Office document under this domain. Documents it never captured "
                   "are not seen here, so this is not proof the site publishes none.")
ADULT_NOTE = "CrawlR does not read documents from adult or dating sites."
PRIORITY = ("blocked", "rate_limited", "failed", "too_large", "unparsed")
# A failed document whose answer will be the same tomorrow. Every other failure may be passing.
SETTLED_FAILURES = ("not_found", "off_site", "not_document")

_TS = re.compile(r"^\d{14}$")
_BAD_CHARS = re.compile(r"[\s<>\"'`\\^{}|]|[\x00-\x1f\x7f]")
_WWW = re.compile(r"^www\d{0,2}\.")
_EXT = re.compile(r"\.(pdf|docx|xlsx|pptx)$", re.I)


# --------------------------------------------------------------------------------------
# The list
# --------------------------------------------------------------------------------------
def _bare(host: str) -> str:
    """A host without its leading "www" label, when what is left is still a site's name. A
    name whose remainder is a shared suffix ("www.com", "www2.net", "www.co.uk") is a site
    called "www" and is kept whole: it never stands for everything under that suffix."""
    name = host.lower().rstrip(".")
    rest = _WWW.sub("", name)
    if rest == name or not HOSTNAME_RE.fullmatch(rest) or is_public_suffix(rest):
        return name
    return rest


def on_target(host: str, domain: str) -> bool:
    """Is `host` the domain the investigator typed, or a subdomain of it ("www" ignored)?"""
    host, base = _bare(host or ""), _bare(domain)
    return bool(host) and (host == base or host.endswith("." + base))


def _iso(ts: str) -> str:
    return f"{ts[:4]}-{ts[4:6]}-{ts[6:8]}T{ts[8:10]}:{ts[10:12]}:{ts[12:14]}Z"


def pick_candidates(data, domain: str, limit: int = MAX_DOCS) -> tuple[list[dict], int, int] | None:
    """([{url, type, last_archived}], how many distinct documents the list held, how many of
    those the archive stored as larger than the size cap) from a CDX JSON answer, newest
    capture first. Documents the archive stored as larger than MAX_DOC_BYTES go last: they
    would only come back `too_large`. None when the answer is not the shape the API sends.
    `[]` is a real answer: nothing listed. Pure."""
    if not isinstance(data, list):
        return None
    if not data:
        return [], 0, 0
    header = data[0]
    if not isinstance(header, list) or "original" not in header:
        return None
    at = {name: header.index(name) for name in ("original", "timestamp", "endtimestamp", "length") if name in header}
    best: dict[tuple[str, str], dict] = {}
    for row in data[1:]:
        if not isinstance(row, list):
            continue
        cell = lambda name: row[at[name]] if name in at and at[name] < len(row) and isinstance(row[at[name]], str) else ""
        raw = cell("original")
        stamp = max((t for t in (cell("timestamp"), cell("endtimestamp")) if _TS.fullmatch(t)), default="")
        if not raw or not stamp or len(raw) > MAX_URL or _BAD_CHARS.search(raw):
            continue
        try:
            parts = urlsplit(raw)
            port = parts.port
        except ValueError:
            continue
        host = (parts.hostname or "").lower()
        ext = _EXT.search(parts.path)
        if parts.scheme not in ("http", "https") or parts.username or parts.password or port not in (None, 80, 443):
            continue
        if not ext or parts.query or not host.isascii() or not on_target(host, domain):
            continue
        # A document is always asked for over https, on the host the archive saw it on.
        key = (_bare(host), parts.path)
        # `length` is the stored (compressed) record: for these formats, close to the file's size.
        size = int(cell("length")) if cell("length").isdigit() and len(cell("length")) < 12 else 0
        row_out = {"url": f"https://{host}{parts.path}", "type": ext.group(1).lower(), "last_archived": stamp, "large": size > MAX_DOC_BYTES}
        if key not in best or stamp > best[key]["last_archived"]:
            best[key] = row_out
    ranked = sorted(best.values(), key=lambda r: (not r["large"], r["last_archived"], r["url"]), reverse=True)
    rows = [{"url": r["url"], "type": r["type"], "last_archived": _iso(r["last_archived"])} for r in ranked[:limit]]
    return rows, len(ranked), sum(1 for r in ranked if r["large"])


# --------------------------------------------------------------------------------------
# Network
# --------------------------------------------------------------------------------------
def _inner_transport() -> httpx.AsyncBaseTransport:
    """The real network transport. Tests replace this with a mock."""
    return httpx.AsyncHTTPTransport(retries=0)


def _client(max_bytes: int, timeout: float) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=CappedTransport(_inner_transport(), max_bytes), timeout=timeout)


def _error(exc: BaseException | None = None, *, code: str | None = None, message: str | None = None) -> dict:
    # Only the exception's type is kept as detail: its text can hold the host or the address.
    return error_fields(exc, code=code, message=message, detail=type(exc).__name__ if exc is not None else "")


async def _list(domain: str) -> tuple[str, dict]:
    """("ok", {candidates, listed, listing_truncated}) or ("rate_limited" | "failed", error fields)."""
    query = httpx.QueryParams([
        ("url", f"{domain}/*"), ("output", "json"), ("fl", "original,timestamp,endtimestamp,mimetype,length"),
        ("filter", "statuscode:200"), ("filter", r"original:(?i).*\.(pdf|docx|xlsx|pptx)$"),
        ("collapse", "urlkey"), ("showSkipCount", "true"), ("lastSkipTimestamp", "true"), ("limit", str(LIST_LIMIT)),
    ])
    try:
        async with _client(MAX_LIST_BYTES, CDX_TIMEOUT) as client:
            got = await asyncio.wait_for(
                safe_fetch(client, f"{CDX_URL}?{query}", follow_redirects=False, headers={"User-Agent": UA}),
                timeout=CDX_TIMEOUT + 5,
            )
    except (TooLarge, BadEncoding) as e:
        return "failed", _error(e, code="bad_response")
    except Exception as e:  # noqa: BLE001 - every failure becomes a state with a code
        fields = _error(e)
        return ("rate_limited" if fields["error_code"] == "rate_limited" else "failed"), fields
    status = release(got.response).status_code
    if status != 200:
        fields = _error(code=classify_status(status))
        return ("rate_limited" if fields["error_code"] == "rate_limited" else "failed"), fields
    try:
        data = json.loads(got.response.content.decode("utf-8"))
        picked = pick_candidates(data, domain)
    except (ValueError, RecursionError):
        picked = None
    if picked is None:
        return "failed", _error(code="bad_response")
    rows = max(0, len(data) - 1)
    return "ok", {"candidates": picked[0], "listed": picked[1], "listed_too_large": picked[2], "listing_truncated": rows >= LIST_LIMIT}


def _doc(candidate: dict, state: str, **extra) -> dict:
    return {
        "url": candidate["url"], "type": candidate["type"], "state": state, "size": None,
        "last_archived": candidate["last_archived"], "parsed": False, "reason": "", "reason_text": "", "sources": [],
        **{k: "" for k in doc_parse.FIELDS}, **extra,
    }


def _challenge(resp: httpx.Response) -> bool:
    if resp.headers.get("cf-mitigated"):
        return True
    return resp.status_code == 503 and "cloudflare" in resp.headers.get("server", "").lower()


async def _fetch(client: httpx.AsyncClient, url: str, domain: str) -> httpx.Response | dict:
    """The response for a document, or error fields when a redirect leaves the target's site."""
    current = url
    for _ in range(MAX_REDIRECTS + 1):
        got = await safe_fetch(
            client, current, follow_redirects=False,
            headers={"User-Agent": UA, "Accept": "*/*", "Accept-Encoding": "identity"},
        )
        resp = release(got.response)         # up to 8 MB: freed as soon as it is read, or passed over
        location = resp.headers.get("location", "")
        if not (resp.is_redirect and location):
            return resp
        # The next hop is held to the rule a listed document is: the target's own hosts, a plain
        # web address, the usual port and no credentials.
        try:
            nxt = urljoin(current, location)
            parts = urlsplit(nxt)
            plain = parts.port in (None, 80, 443) and not parts.username and not parts.password
        except ValueError:
            plain = False
        if not plain or parts.scheme not in ("http", "https") or not on_target(parts.hostname or "", domain):
            return _error(code="off_site", message="The document now redirects to another site, so it was not fetched.")
        current = nxt
    return _error(code="upstream", message="The document redirects too many times.")


_held = 0                     # documents in memory right now, all requests together


async def _read_one(client: httpx.AsyncClient, candidate: dict, domain: str, limited: asyncio.Event) -> dict:
    global _held
    if limited.is_set():
        return _doc(candidate, "rate_limited", **_error(code="rate_limited", message="The site was limiting requests, so this document was not asked for."))
    if _held >= MAX_HELD:
        # Not asked for at all: unknown, never "declares nothing", and the answer is not kept.
        return _doc(candidate, "failed", **_error(code="busy"))
    _held += 1
    try:
        return await _fetch_and_read(client, candidate, domain, limited)
    finally:
        _held -= 1


async def _fetch_and_read(client: httpx.AsyncClient, candidate: dict, domain: str, limited: asyncio.Event) -> dict:
    try:
        resp = await asyncio.wait_for(_fetch(client, candidate["url"], domain), timeout=DOC_DEADLINE)
    except TooLarge as e:
        return _doc(candidate, "too_large", size=e.declared or None,
                    **_error(code="too_large", message="The file is larger than 8 MB, so it was not read."))
    except BadEncoding as e:
        return _doc(candidate, "failed", **_error(e, code="bad_response"))
    except Exception as e:  # noqa: BLE001 - every failure becomes a state with a code
        return _doc(candidate, "failed", **_error(e))
    if isinstance(resp, dict):
        return _doc(candidate, "failed", **resp)
    status = resp.status_code
    if status == 429:
        limited.set()
        return _doc(candidate, "rate_limited", **_error(code="rate_limited"))
    if status in (401, 403, 451) or _challenge(resp):
        return _doc(candidate, "blocked", **_error(code="blocked", message="The site refused the request for this document."))
    if status in (404, 410):
        return _doc(candidate, "failed", **_error(code="not_found", message="The site no longer serves this document."))
    if status != 200:
        return _doc(candidate, "failed", **_error(code="upstream"))
    body = resp.content
    if doc_parse.sniff(body) == "html":
        return _doc(candidate, "failed", size=len(body),
                    **_error(code="not_document", message="The site answered with a web page instead of the document."))
    # On the parse pool, off the event loop: reading an 8 MB file takes a moment and nothing else should wait on it.
    try:
        parsed = await parsepool.run(doc_parse.parse_document, body, candidate["type"])
    except parsepool.Busy as e:
        # The file was fetched and not read: unknown, never "declares nothing".
        return _doc(candidate, "failed", size=len(body), **_error(e, code="busy"))
    fields = parsed["fields"]
    if not parsed["parsed"]:
        state = "unparsed"
    else:
        state = "ok" if any(fields.values()) else "none"
    return _doc(candidate, state, size=len(body), type=parsed["type"] or candidate["type"], parsed=parsed["parsed"],
                reason=parsed["reason"], reason_text=doc_parse.REASONS.get(parsed["reason"], ""), sources=parsed["sources"], **fields)


async def _read_all(candidates: list[dict], domain: str) -> list[dict]:
    gate = asyncio.Semaphore(CONCURRENCY)
    limited = asyncio.Event()

    async def one(client, candidate):
        async with gate:
            return await _read_one(client, candidate, domain, limited)

    async with _client(MAX_DOC_BYTES, DOC_TIMEOUT) as client:
        return list(await asyncio.gather(*(one(client, c) for c in candidates)))


# --------------------------------------------------------------------------------------
# The answer
# --------------------------------------------------------------------------------------
def _tally(rows: list[tuple[str, str, int]]) -> list[dict]:
    """[(name, role, document index)] -> distinct names, most documents first. Case and spacing
    do not make a different name."""
    seen: "OrderedDict[str, dict]" = OrderedDict()
    for name, role, index in rows:
        if not name:
            continue
        entry = seen.setdefault(name.casefold(), {"name": name, "roles": [], "docs": set()})
        if role and role not in entry["roles"]:
            entry["roles"].append(role)
        entry["docs"].add(index)
    out = [{"name": e["name"], "roles": e["roles"], "documents": len(e["docs"])} for e in seen.values()]
    return sorted(out, key=lambda e: -e["documents"])


def summarize(documents: list[dict]) -> dict:
    """Distinct names, software and companies over the documents that were read. Pure."""
    people, software, companies = [], [], []
    for i, d in enumerate(documents):
        if d["state"] != "ok":
            continue
        people += [(d["author"], "author", i), (d["last_modified_by"], "last_modified_by", i)]
        software += [(d["creator_software"], "creator_software", i), (d["producer"], "producer", i)]
        companies.append((d["company"], "", i))
    authors = [{**a, "self_declared": True} for a in _tally(people)]
    named = [{"name": c["name"], "documents": c["documents"], "self_declared": True} for c in _tally(companies)]
    return {"authors": authors, "software": _tally(software), "companies": named, "note": NAMES_NOTE if authors or named else ""}


def overall_state(documents: list[dict]) -> str:
    states = [d["state"] for d in documents]
    if "ok" in states:
        return "ok"
    if all(s == "none" for s in states):
        return "none"
    rest = [s for s in states if s != "none"]
    return max(PRIORITY, key=lambda s: (rest.count(s), -PRIORITY.index(s)))


def findings_for(documents: list[dict], summary: dict) -> list[dict]:
    """`info` rows only: a name inside a public file is a lead, never a risk flag."""
    out = []
    read = sum(1 for d in documents if d["state"] == "ok")
    if summary["authors"]:
        names = ", ".join(a["name"] for a in summary["authors"][:6])
        more = len(summary["authors"]) - 6
        out.append({"level": "info", "title": f"{len(summary['authors'])} self-declared author name{'s' if len(summary['authors']) != 1 else ''} in {read} public document{'s' if read != 1 else ''}",
                    "detail": names + (f" and {more} more" if more > 0 else "") + ". Text from inside the files, not verified."})
    if summary["companies"]:
        out.append({"level": "info", "title": "Company named in document metadata",
                    "detail": ", ".join(c["name"] for c in summary["companies"][:6]) + ". Text from inside the files, not verified."})
    if summary["software"]:
        out.append({"level": "info", "title": "Software that made the documents",
                    "detail": ", ".join(s["name"] for s in summary["software"][:8]) + "."})
    return out


def _guard(documents: list[dict], summary: dict) -> dict:
    """Guard-only text: every free-text value read from the files, one per line, for the page's
    content check. The page removes `guard` before a case is stored, exported or sent to an AI."""
    lines: list[str] = []
    for value in ([a["name"] for a in summary["authors"]] + [c["name"] for c in summary["companies"]]
                  + [d["title"] for d in documents if d["state"] == "ok"]):
        if value and value not in lines:
            lines.append(value)
    text = "\n".join(lines)[:4000]
    return {"text": text} if text else {}


def _base(domain: str, state: str) -> dict:
    return {
        "domain": domain, "state": state, "requests_target": True, "source": "Internet Archive CDX index",
        "listed": 0, "listed_too_large": 0, "listing_truncated": False, "documents": [], "counts": {},
        "summary": {"authors": [], "software": [], "companies": [], "note": ""}, "findings": [], "guard": {}, "note": "",
    }


async def _run(domain: str) -> dict:
    listing_state, listing = await _list(domain)
    if listing_state != "ok":
        return {**_base(domain, listing_state), **listing}
    if not listing["candidates"]:
        return {**_base(domain, "none"), "listing_truncated": listing["listing_truncated"], "note": NO_LISTING_NOTE}
    documents = await _read_all(listing["candidates"], domain)
    summary = summarize(documents)
    counts: dict[str, int] = {}
    for d in documents:
        counts[d["state"]] = counts.get(d["state"], 0) + 1
    return {
        **_base(domain, overall_state(documents)),
        "listed": listing["listed"], "listed_too_large": listing["listed_too_large"], "listing_truncated": listing["listing_truncated"],
        "documents": documents, "counts": counts, "summary": summary,
        "findings": findings_for(documents, summary), "guard": _guard(documents, summary),
    }


# --------------------------------------------------------------------------------------
# Cache
# --------------------------------------------------------------------------------------
_cache: "OrderedDict[str, tuple[float, dict]]" = OrderedDict()
_pending: dict = {}           # domains being read right now (core.inflight)


def clear_cache_for_tests() -> None:
    global _held
    _cache.clear()
    _pending.clear()
    _held = 0


def settled(answer: dict) -> bool:
    """Is this an answer that will read the same for the rest of the day? Only when the list
    was read and no document in it was blocked, rate limited or failed in a passing way."""
    if answer.get("state") not in ("ok", "none"):
        return False
    for d in answer.get("documents") or []:
        if d["state"] in ("blocked", "rate_limited"):
            return False
        if d["state"] == "failed" and d.get("error_code") not in SETTLED_FAILURES:
            return False
    return True


def _cache_get(key: str) -> dict | None:
    hit = _cache.get(key)
    if not hit:
        return None
    ttl = CACHE_TTL if settled(hit[1]) else min(CACHE_TTL, CACHE_TTL_SOFT)
    if time.time() - hit[0] > ttl:
        _cache.pop(key, None)
        return None
    _cache.move_to_end(key)
    return copy.deepcopy(hit[1])


def _cache_put(key: str, answer: dict) -> None:
    _cache[key] = (time.time(), copy.deepcopy(answer))
    _cache.move_to_end(key)
    while len(_cache) > CACHE_MAX:
        _cache.popitem(last=False)


# --------------------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------------------
async def run_doc_metadata(domain: str) -> dict:
    """{domain, state, requests_target, source, listed, listed_too_large, listing_truncated, documents, counts,
    summary, findings, guard, note, cached}. `domain` has been through core.validate.host."""
    if adult_sites.is_adult_site(url=f"https://{domain}/"):
        log.info("doc metadata", extra={"state": "refused"})
        return {**_base(domain, "refused"), "requests_target": False, "reason": "adult_site", "note": ADULT_NOTE, "cached": False}
    cached = _cache_get(domain)
    if cached is not None:
        return {**cached, "cached": True}
    async def fresh() -> dict:
        answer = await _run(domain)
        if not any(d.get("error_code") == "busy" for d in answer["documents"]):     # a full pool says nothing about a file: not kept
            _cache_put(domain, answer)
        # States and counts only: no domain, address, name or title is logged.
        log.info("doc metadata", extra={"state": answer["state"], "documents": len(answer["documents"]), "read": answer["counts"].get("ok", 0)})
        return answer

    # The same domain asked for twice at once is read once; each caller gets its own copy.
    answer = copy.deepcopy(await inflight.shared(_pending, domain, fresh))
    return {**answer, "cached": False}
