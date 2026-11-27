"""Bounded work on outside data: where the reading of a compressed body stops, how long one
fetch may take, where heavy parsing runs and how much of it may wait, how much CPU one page
and how much hand-reading one file may take, what counts as text, which addresses the archive
is asked about, and which handle an archived page is filed under.

Everything is served by mock transports: no network and no DNS. Every name, host, handle and
document here is invented."""

import asyncio
import gzip
import importlib
import inspect
import json
import threading
import time
import zlib
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from core import adult_sites, capfetch, charset, errors, pinned, profile_record
from core import netguard as ng
from main import app
import middleware.rate_limit as rl
from middleware.rate_limit import match_limit
from modules import archive_diff as ad
from modules import doc_metadata as dm
from modules import doc_parse as dp
from modules import profile_archive as pa
from modules import tracker_ids as ti
from modules.profiles import base
from routers import analyze as an
from tests import docfiles as df

FIX = Path(__file__).parent / "fixtures"
HOME = (FIX / "tracker_ids" / "home_full.html").read_text(encoding="utf-8")
OLDER = (FIX / "archive_diff" / "older.html").read_bytes()
NEWER = (FIX / "archive_diff" / "newer.html").read_bytes()
DOMAIN = "larkspur-tide.example"
HANDLE = "mara-quillfeather"
URL = f"https://codeplace.example/{HANDLE}"
T1, T2 = "20190304050607", "20240102030405"
ISO1, ISO2 = "2019-03-04T05:06:07Z", "2024-01-02T03:04:05Z"
ARCHIVE = "web.archive.org"
ADULT = sorted(adult_sites.PLATFORMS)[0]            # a host on the adult and dating list
PAGE = b"<html><head><title>A page</title></head><body><p>hello there</p></body></html>"
LIMITS = dict(rl.RATE_LIMITS)                       # as shipped: the fixture below lifts some of them for the requests made here
TAGGED = "<html><head><script>gtag('config','G-ABCD123456');</script></head><body><p>hello</p></body></html>"


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    def wipe():
        for module in (ad, dm, ti, pa):
            module.clear_cache_for_tests()
        profile_record.clear()

    async def public(host, port=443):
        return ["93.184.216.34"]

    monkeypatch.setattr(pinned, "resolve_public", public)
    monkeypatch.setattr(ng, "resolve_public", public)
    for path in ("archive-diff", "profile-archive", "tracker-ids", "doc-metadata"):
        monkeypatch.setitem(rl.RATE_LIMITS, f"/api/recon/{path}", (1000, 60))
    wipe()
    yield
    wipe()


@pytest.fixture()
def c():
    with TestClient(app, client=("bounded-work.test", 50001)) as client:
        yield client


@pytest.fixture()
def pool():
    """core.parsepool, with nothing left in it afterwards."""
    module = importlib.import_module("core.parsepool")
    yield module
    assert module.pending() == 0


# ---- helpers ----------------------------------------------------------------------------------

class Wire(httpx.AsyncByteStream):
    """Chunks as they come off the wire. `after` is sent again and again, `limit` times at
    most, once the listed chunks are out; `pulled` counts how many of those were asked for."""

    def __init__(self, *chunks: bytes, after: bytes = b"", limit: int = 0, pause: float = 0.0):
        self.chunks, self.after, self.limit, self.pause, self.pulled = chunks, after, limit, pause, 0

    async def __aiter__(self):
        for chunk in self.chunks:
            yield chunk
        while self.pulled < self.limit:
            self.pulled += 1
            await asyncio.sleep(self.pause)
            yield self.after


def answer(wire: Wire, coding: str = "gzip", ctype: str = "text/html", status: int = 200):
    headers = {"content-type": ctype, **({"content-encoding": coding} if coding else {})}
    return lambda request: httpx.Response(status, stream=wire, headers=headers)


def fixed_get(handler, **kw):
    """core.pinned.get against a mock archive."""
    async def go():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            return await pinned.get(client, f"https://{ARCHIVE}/web/{T1}id_/{URL}", **kw)
    return asyncio.run(go())


def capped_get(handler, max_bytes: int, truncate: bool) -> httpx.Response:
    """One GET through core.capfetch.CappedTransport."""
    async def go():
        async with httpx.AsyncClient(transport=capfetch.CappedTransport(httpx.MockTransport(handler), max_bytes, truncate=truncate)) as client:
            return await client.get(f"https://{DOMAIN}/")
    return asyncio.run(go())


def home(monkeypatch, handler):
    monkeypatch.setattr(ti, "_inner_transport", lambda: httpx.MockTransport(handler if callable(handler) else lambda r: handler))


def page(body, content_type: str = "text/html; charset=utf-8") -> httpx.Response:
    return httpx.Response(200, content=body.encode("utf-8") if isinstance(body, str) else body, headers={"content-type": content_type})


def captures(monkeypatch, pages: dict, calls: list | None = None):
    """Archived copies: {timestamp: httpx.Response | callable(request)}; any other time is a 404."""
    def handler(request: httpx.Request) -> httpx.Response:
        if calls is not None:
            calls.append(request.url.raw_path.decode())
        hit = pages.get(request.url.raw_path.decode()[5:19])
        if hit is None:
            return httpx.Response(404)
        return hit(request) if callable(hit) else hit

    monkeypatch.setattr(ad, "_transport", lambda: httpx.MockTransport(handler))


def both(monkeypatch, older=OLDER, newer=NEWER, ctype="text/html; charset=utf-8", calls=None):
    captures(monkeypatch, {T1: lambda r: page(older, ctype), T2: lambda r: page(newer, ctype)}, calls)


def index(monkeypatch, handler, calls: list | None = None):
    def wrapped(request):
        if calls is not None:
            calls.append(request)
        return handler(request)

    monkeypatch.setattr(pa, "_transport", lambda: httpx.MockTransport(wrapped))


def files(monkeypatch, served: dict, calls: list | None = None):
    """The archive's list and the target's files for modules.doc_metadata: path -> bytes."""
    rows = [[f"https://{DOMAIN}{path}", f"2024010100{n:04d}", f"2026010100{n:04d}", "application/pdf", "100"] for n, path in enumerate(served)]
    listing = json.dumps([["original", "timestamp", "endtimestamp", "mimetype", "length"], *rows])

    def handler(request: httpx.Request) -> httpx.Response:
        if calls is not None:
            calls.append(request)
        if request.headers["host"] == ARCHIVE:
            return httpx.Response(200, text=listing, headers={"content-type": "application/json"})
        return httpx.Response(200, content=served[request.url.path], headers={"content-type": "application/octet-stream"})

    monkeypatch.setattr(dm, "_inner_transport", lambda: httpx.MockTransport(handler))


def diff(url=URL):
    return asyncio.run(ad.run_archive_diff(url, ISO1, ISO2))


def ticking(monkeypatch, pool, *times: float):
    """The CPU clock reads these times, one per look, and then stays at the last one."""
    left = list(times)

    def clock():
        return left.pop(0) if len(left) > 1 else left[0]

    monkeypatch.setattr(pool, "_clock", clock)


# ---- a compressed body is read to its end and not a byte further ------------------------------------

def test_reading_stops_where_the_compressed_body_ends():
    wire = Wire(gzip.compress(PAGE), after=b"\xaa" * 1024, limit=2000)
    got = fixed_get(answer(wire), max_bytes=100_000)
    assert got.body == PAGE and got.truncated is True          # more was sent than was kept, and it says so
    assert wire.pulled <= 4                                    # a look at whether anything follows, never the rest

    wire = Wire(gzip.compress(PAGE), after=b"\xaa" * 1024, limit=2000)
    resp = capped_get(answer(wire), 100_000, truncate=True)
    assert resp.content == PAGE and capfetch.was_capped(resp) is True and wire.pulled <= 4

    wire = Wire(gzip.compress(PAGE), after=b"\xaa" * 1024, limit=2000)
    with pytest.raises(capfetch.BadEncoding):                  # a document with something after its end is not a document
        capped_get(answer(wire), 100_000, truncate=False)
    assert wire.pulled <= 4


def test_bytes_after_the_end_are_never_inflated_or_kept(monkeypatch):
    fed = []
    real = zlib.decompressobj

    class Watched:
        def __init__(self, *a):
            self._z = real(*a)

        def decompress(self, data, max_length=0):
            fed.append(len(data))
            return self._z.decompress(data, max_length)

        def __getattr__(self, name):
            return getattr(self._z, name)

    monkeypatch.setattr(zlib, "decompressobj", Watched)
    first = gzip.compress(PAGE)
    got = fixed_get(answer(Wire(first, after=b"\xaa" * 1024, limit=50)), max_bytes=100_000)
    assert got.body == PAGE and fed == [len(first)]

    # a second compressed body right behind the first, in the same chunk or the next one
    for wire in (Wire(first + gzip.compress(b"<p>second</p>")), Wire(first, gzip.compress(b"<p>second</p>"))):
        got = fixed_get(answer(wire), max_bytes=100_000)
        assert got.body == PAGE and got.truncated is True
    # and a body with nothing after it is whole
    got = fixed_get(answer(Wire(first[:30], first[30:])), max_bytes=100_000)
    assert got.body == PAGE and got.truncated is False


def test_a_compressed_body_that_stops_before_its_end_is_an_error(monkeypatch):
    half = gzip.compress(PAGE * 50)[:60]
    with pytest.raises(httpx.DecodingError):
        fixed_get(answer(Wire(half)), max_bytes=100_000)
    for truncate in (True, False):
        with pytest.raises(capfetch.BadEncoding):
            capped_get(answer(Wire(half)), 100_000, truncate=truncate)
    # so a capture or a home page that came that way failed: it is never an empty page
    captures(monkeypatch, {T1: answer(Wire(half)), T2: lambda r: page(NEWER)})
    out = diff()
    assert out["state"] == "failed" and out["error_code"] == "bad_response" and out["from"]["state"] == "failed"
    home(monkeypatch, answer(Wire(half)))
    out = asyncio.run(ti.run_tracker_ids(DOMAIN))
    assert out["state"] == "failed" and out["error_code"] == "bad_response"
    # an empty body is still an empty body
    assert fixed_get(answer(Wire()), max_bytes=1000).body == b""


def test_the_bytes_on_the_wire_are_capped_as_well_as_the_inflated_ones():
    start = gzip.compress(b"")[:10]                             # a gzip header
    nothing = b"\x00\x00\x00\xff\xff" * 2000                    # 10 KB of blocks that inflate to no bytes at all
    cap = 1000
    wire = Wire(start, after=nothing, limit=5000)
    with pytest.raises(httpx.DecodingError):
        fixed_get(answer(wire), max_bytes=cap)
    assert wire.pulled * len(nothing) <= capfetch.raw_allowance(cap) + len(nothing)
    for truncate in (True, False):
        wire = Wire(start, after=nothing, limit=5000)
        with pytest.raises(capfetch.BadEncoding):
            capped_get(answer(wire), cap, truncate=truncate)
        assert wire.pulled * len(nothing) <= capfetch.raw_allowance(cap) + len(nothing)
    # the allowance is never in the way of a real body, however badly it compresses
    noise = bytes(range(256)) * 400
    assert fixed_get(answer(Wire(gzip.compress(noise, compresslevel=0))), max_bytes=len(noise)).body == noise


def test_every_capped_fetch_reads_through_the_one_reader(monkeypatch):
    seen = []
    real = capfetch.read_body

    async def spy(chunks, coding, max_bytes):
        seen.append(max_bytes)
        return await real(chunks, coding, max_bytes)

    monkeypatch.setattr(capfetch, "read_body", spy)
    fixed_get(lambda r: page(PAGE), max_bytes=1234)
    capped_get(lambda r: page(PAGE), 2345, truncate=True)
    index(monkeypatch, lambda r: httpx.Response(200, text="[]"))
    assert asyncio.run(pa.run_profile_archive(URL))["state"] == "none"
    assert seen == [1234, 2345, pa.MAX_BODY]
    for module in (pinned, pa, ad, ti, dm):
        assert "decompressobj" not in Path(module.__file__).read_text(encoding="utf-8")


def test_a_fetched_body_is_freed_without_waiting_for_the_cycle_collector(monkeypatch):
    import gc
    import weakref

    async def fetched(location: str | None):
        def handler(request):
            if location and request.url.path == "/a.pdf":
                return httpx.Response(302, headers={"location": location}, content=b"x" * 5000)
            return httpx.Response(200, content=df.pdf())

        async with dm._client(dm.MAX_DOC_BYTES, dm.DOC_TIMEOUT) as client:
            return weakref.ref(await dm._fetch(client, f"https://{DOMAIN}/a.pdf", DOMAIN))

    monkeypatch.setattr(dm, "_inner_transport", lambda: httpx.MockTransport(lambda r: httpx.Response(200, content=df.pdf())))
    seen: list = []
    real = httpx.Response.__init__

    def tracked(self, *a, **k):
        real(self, *a, **k)
        seen.append(weakref.ref(self))

    gc.collect()
    gc.disable()
    try:
        assert asyncio.run(fetched(None))() is None             # the document's response is gone once nobody holds it
        monkeypatch.setattr(httpx.Response, "__init__", tracked)
        home(monkeypatch, lambda r: httpx.Response(302, headers={"location": "/next"}, content=b"x" * 5000) if r.url.path == "/" else page(HOME))
        assert asyncio.run(ti.run_tracker_ids(DOMAIN))["state"] == "ok"
        monkeypatch.setattr(httpx.Response, "__init__", real)
        assert len(seen) >= 4 and all(ref() is None for ref in seen)        # both hops, as the site sent them and as they were read
    finally:
        gc.enable()


# ---- one fetch from a fixed host ends within a deadline, however slowly the bytes come --------------

def test_a_fixed_host_fetch_has_an_overall_deadline(monkeypatch):
    assert 0 < inspect.signature(pinned.get).parameters["deadline"].default <= 30
    drip = lambda: Wire(b"<p>", after=b" ", limit=400, pause=0.02)      # noqa: E731 - each read arrives in time; the body never ends
    began = time.monotonic()
    with pytest.raises(TimeoutError):
        fixed_get(answer(drip(), coding=""), max_bytes=100_000, deadline=0.2)
    assert time.monotonic() - began < 3

    assert 0 < ad.DEADLINE <= 30
    monkeypatch.setattr(ad, "DEADLINE", 0.2)
    captures(monkeypatch, {T1: answer(drip(), coding=""), T2: lambda r: page(NEWER)})
    began = time.monotonic()
    out = diff()
    assert out["state"] == "failed" and out["error_code"] == "timeout" and time.monotonic() - began < 3

    assert 0 < pa.DEADLINE <= 30
    monkeypatch.setattr(pa, "DEADLINE", 0.2)
    index(monkeypatch, answer(drip(), coding="", ctype="application/json"))
    out = asyncio.run(pa.run_profile_archive(URL))
    assert out["state"] == "failed" and out["error_code"] == "timeout"


# ---- the capture list is read through the same reader ----------------------------------------------

def test_the_capture_list_is_inflated_against_its_cap_and_never_by_the_http_client(monkeypatch):
    async def never(self, *a, **k):
        raise AssertionError("the body must not be decoded by the HTTP client")
        yield b""

    monkeypatch.setattr(httpx.Response, "aiter_bytes", never)
    calls: list = []
    listing = json.dumps([["timestamp", "digest"], [T1, "D1"], [T2, "D2"]]).encode()
    index(monkeypatch, answer(Wire(gzip.compress(listing)), ctype="application/json"), calls)
    out = asyncio.run(pa.run_profile_archive(URL))
    assert out["state"] == "ok" and out["count"] == 2
    assert calls[0].headers["accept-encoding"] == "gzip"

    packed = gzip.compress(b" " * 30_000_000)
    assert len(packed) < 60_000
    for wire, coding in ((Wire(packed), "gzip"), (Wire(gzip.compress(listing)[:40]), "gzip"), (Wire(listing), "br")):
        pa.clear_cache_for_tests()
        index(monkeypatch, answer(wire, coding=coding, ctype="application/json"))
        out = asyncio.run(pa.run_profile_archive(URL))
        assert out["state"] == "failed" and out["error_code"] == "bad_response" and out["count"] == 0


# ---- heavy parsing: one small pool of its own, and a queue that says "busy" --------------------------

def test_heavy_parsing_runs_on_its_own_single_worker(monkeypatch, pool):
    assert pool.WORKERS == 1 and 1 <= pool.MAX_PENDING <= 16
    jobs: list = []
    real = pool.run

    async def spy(fn, *args):
        jobs.append(fn.__name__)
        return await real(fn, *args)

    def not_here(*a, **k):
        raise AssertionError("heavy parsing must not use the default executor")

    monkeypatch.setattr(pool, "run", spy)
    monkeypatch.setattr(asyncio, "to_thread", not_here)
    names = []
    real_extract = ad.extract
    monkeypatch.setattr(ad, "extract", lambda *a, **k: names.append(threading.current_thread().name) or real_extract(*a, **k))

    home(monkeypatch, page(HOME))
    assert asyncio.run(ti.run_tracker_ids(DOMAIN))["state"] == "ok"
    both(monkeypatch)
    assert diff()["state"] == "ok"
    files(monkeypatch, {"/a.pdf": df.pdf(), "/b.docx": df.office("docx")})
    assert asyncio.run(dm.run_doc_metadata(DOMAIN))["counts"] == {"ok": 2}
    assert sorted(jobs) == ["_parse", "_read", "_read", "parse_document", "parse_document"]
    assert len(names) == 2 and all(name.startswith("parse") for name in names)


def test_one_job_runs_at_a_time_and_a_full_pool_refuses_at_once(monkeypatch, pool):
    monkeypatch.setattr(pool, "MAX_PENDING", 3)
    gate = threading.Event()
    running, most = [0], [0]

    def job(n):
        running[0] += 1
        most[0] = max(most[0], running[0])
        gate.wait(5)
        running[0] -= 1
        return n

    async def go():
        waiting = [asyncio.ensure_future(pool.run(job, n)) for n in range(3)]
        await asyncio.sleep(0.05)
        assert pool.pending() == 3
        began = time.monotonic()
        with pytest.raises(pool.Busy):
            await pool.run(job, 99)                 # refused now: it does not wait for a place
        assert time.monotonic() - began < 0.5 and pool.pending() == 3
        gate.set()
        assert await asyncio.gather(*waiting) == [0, 1, 2]
        assert await pool.run(job, 7) == 7          # and there is room again
    asyncio.run(go())
    assert most[0] == 1 and pool.pending() == 0
    assert errors.classify(pool.Busy()) == "busy" and errors.error_fields(pool.Busy())["error"] == errors.MESSAGES["busy"]


def test_a_full_pool_is_a_failure_with_the_busy_code_and_is_not_kept(monkeypatch, pool):
    home(monkeypatch, page(HOME))
    both(monkeypatch)
    files(monkeypatch, {"/a.pdf": df.pdf()})
    monkeypatch.setattr(pool, "MAX_PENDING", 0)
    out = asyncio.run(ti.run_tracker_ids(DOMAIN))
    assert out["state"] == "failed" and out["error_code"] == "busy" and out["error"] == errors.MESSAGES["busy"] and out["ids"] == []
    out = diff()
    assert out["state"] == "failed" and out["error_code"] == "busy" and out["removed"]["text"] == [] and out["complete"] is False
    out = asyncio.run(dm.run_doc_metadata(DOMAIN))
    assert out["state"] == "failed" and out["counts"] == {"failed": 1} and out["documents"][0]["error_code"] == "busy"
    assert out["documents"][0]["parsed"] is False and out["summary"]["authors"] == []
    # none of the three was kept: with room again, each is read, at once
    monkeypatch.setattr(pool, "MAX_PENDING", 8)
    out = asyncio.run(ti.run_tracker_ids(DOMAIN))
    assert out["state"] == "ok" and out["cached"] is False
    out = diff()
    assert out["state"] == "ok" and out["cached"] is False
    out = asyncio.run(dm.run_doc_metadata(DOMAIN))
    assert out["state"] == "ok" and out["cached"] is False


def test_documents_held_in_memory_are_counted_for_the_whole_server(monkeypatch, pool):
    assert 1 <= dm.MAX_HELD <= 6 and dm.CONCURRENCY <= dm.MAX_HELD
    served = {f"/{n}.pdf": df.pdf() for n in "abcdef"}
    asked: list = []
    most = [0]
    real = dm._fetch

    async def watched(client, url, domain):
        most[0] = max(most[0], dm._held)
        return await real(client, url, domain)

    monkeypatch.setattr(dm, "_fetch", watched)
    files(monkeypatch, served, asked)
    monkeypatch.setattr(dm, "_held", dm.MAX_HELD - 1)          # other requests hold all but one place
    out = asyncio.run(dm.run_doc_metadata(DOMAIN))
    busy = [d for d in out["documents"] if d.get("error_code") == "busy"]
    assert most[0] == dm.MAX_HELD and len(busy) >= 1 and out["counts"].get("ok", 0) >= 1
    assert all(d["state"] == "failed" and d["size"] is None for d in busy)
    assert len([r for r in asked if r.headers["host"] != ARCHIVE]) == len(served) - len(busy)      # a busy document was never asked for
    assert dm._held == dm.MAX_HELD - 1                           # every place taken here was given back
    # and the answer was not kept: with room, every document is read
    monkeypatch.setattr(dm, "_held", 0)
    out = asyncio.run(dm.run_doc_metadata(DOMAIN))
    assert out["cached"] is False and out["counts"] == {"ok": 6} and dm._held == 0


# ---- one page is read within a CPU budget ------------------------------------------------------------

def test_a_capture_is_read_within_a_cpu_budget_and_says_when_it_was_cut(monkeypatch, pool):
    long = ("<html><body>" + "".join(f"<p>line number {n}</p>" for n in range(20_000)) + "</body></html>").encode()
    assert len(long) > 8 * ad.FEED
    whole = ad.extract(long, "text/html", URL)
    assert len(whole["lines"]) == ad.MAX_LINES_READ
    budget = pool.Budget()
    assert ad.extract(long, "text/html", URL, budget)["lines"] == whole["lines"] and budget.cut is False

    # a slow machine: the share of the budget for walking the markup is gone after two pieces
    ticking(monkeypatch, pool, 0.0, 0.3, 0.6, 0.9)
    budget = pool.Budget(1.0)
    part = ad.extract(long, "text/html", URL, budget)
    assert budget.cut is True and 0 < len(part["lines"]) < 4000 and part["lines"] == whole["lines"][:len(part["lines"])]
    # and with the whole budget gone nothing more is done at all
    ticking(monkeypatch, pool, 0.0, 5.0)
    budget = pool.Budget(1.0)
    assert ad.extract(long, "text/html", URL, budget)["lines"] == [] and budget.cut is True

    ticking(monkeypatch, pool, 0.0, 0.3, 0.6, 0.9)
    both(monkeypatch, older=long, newer=NEWER)
    out = diff()
    assert out["from"]["truncated"] is True and out["from"]["text_lines"] == len(part["lines"]) and out["complete"] is False
    assert out["state"] == "ok"


def test_a_home_page_cut_at_the_budget_is_never_none(monkeypatch, pool):
    filler = "".join(f"<p>paragraph {n}</p>" for n in range(20_000))
    early = "<html><head><script>gtag('config','G-ABCD123456');</script></head><body>" + filler + "</body></html>"
    late = "<html><body>" + filler + "<script>gtag('config','G-ABCD123456');</script></body></html>"
    assert [r["value"] for r in ti.extract_ids(late)] == ["G-ABCD123456"]

    ticking(monkeypatch, pool, 0.0, 0.3, 0.6, 0.9)
    home(monkeypatch, page(early))
    out = asyncio.run(ti.run_tracker_ids(DOMAIN))
    assert out["state"] == "ok" and out["count"] == 1 and out["truncated"] is True and ti.CUT_NOTE in out["note"]

    ti.clear_cache_for_tests()
    ticking(monkeypatch, pool, 0.0, 0.3, 0.6, 0.9)
    home(monkeypatch, page(late))
    out = asyncio.run(ti.run_tracker_ids(DOMAIN))
    # part of the page was never looked at, so "no ID" would be a guess
    assert out["state"] == "failed" and out["error_code"] == "bad_response" and out["error"] == ti.SLOW_PAGE


def test_the_parsing_one_address_can_cause_in_a_minute(pool):
    """The ceiling, stated: 4 comparisons of 2 captures and 10 home pages a minute are 18 page
    parses of at most 1 CPU second each, and 2 document runs of 8 files are 16 file parses,
    each bounded by its size, its entry count and its hand-read allowance (measured at under
    0.3 s on a development machine). All of it runs on one thread, one job at a time. A change
    to a limit, a budget or a count has to change these numbers too."""
    def per_minute(path: str) -> float:
        limit, window = LIMITS[match_limit(path)[0]]
        return limit * 60 / window

    assert (per_minute("/api/recon/archive-diff"), per_minute("/api/recon/tracker-ids"), per_minute("/api/recon/doc-metadata")) == (4, 10, 2)
    pages = per_minute("/api/recon/archive-diff") * 2 + per_minute("/api/recon/tracker-ids")
    assert pages * pool.JOB_SECONDS <= 18.0
    assert per_minute("/api/recon/doc-metadata") * dm.MAX_DOCS <= 16
    assert dm.MAX_DOC_BYTES <= 8_000_000 and dp.MAX_ENTRIES <= 20_000 and dp.MAX_WORK <= 1_000_000
    assert pool.WORKERS == 1


# ---- one file is read by hand within an allowance ----------------------------------------------------

def test_an_archive_with_too_many_entries_is_refused_before_it_is_opened(monkeypatch):
    def opened(*a, **k):
        raise AssertionError("the archive must not be opened")

    real = dp.zipfile.ZipFile
    monkeypatch.setattr(dp.zipfile, "ZipFile", opened)
    crowded = b"PK\x03\x04" + b"\x00" * 26 + b"PK\x01\x02" * (dp.MAX_ENTRIES + 1)
    out = dp.parse_document(crowded, "docx")
    assert out["parsed"] is False and out["reason"] == "zip_bomb"
    monkeypatch.setattr(dp.zipfile, "ZipFile", real)
    assert dp.parse_document(df.office("docx"), "docx")["fields"]["author"] == "Odalys Brandtmoor"


def test_a_dictionary_is_read_once_however_many_markers_lead_to_it(monkeypatch):
    reads = []
    real = dp._read_dict
    monkeypatch.setattr(dp, "_read_dict", lambda data, p, work: reads.append(p) or real(data, p, work))
    body = b"1 0 obj << " + b"/Type /ObjStm " * 100 + b"/Count 1 " * 500 + b">>\nendobj\n"
    out = dp.parse_document(b"%PDF-1.5\n" + body + b"trailer << /Info 9 0 R >>\n%%EOF\n", "pdf")
    assert out["parsed"] is False and out["reason"] == "compressed"
    assert len(reads) == 1


def test_a_pdf_that_asks_for_more_hand_reading_than_its_allowance_is_unparsed(monkeypatch):
    tokens = [0]
    real = dp._token

    def counted(data, p, end):
        tokens[0] += 1
        return real(data, p, end)

    monkeypatch.setattr(dp, "_token", counted)
    units = b"".join(b"%d 0 obj << /Type /ObjStm " % n + b"/Count 1 " * 6000 + b">>\nendobj\n" for n in range(1, 40))
    out = dp.parse_document(b"%PDF-1.5\n" + units + b"trailer << /Info 99 0 R >>\n%%EOF\n", "pdf")
    assert out["parsed"] is False and out["reason"] == "bad_pdf" and not any(out["fields"].values())
    assert tokens[0] <= dp.MAX_WORK
    # a real file uses a sliver of the allowance
    monkeypatch.setattr(dp, "_token", real)
    assert dp.parse_document(df.pdf(info_in_file=False, extra_objects=(df.object_stream(),)))["fields"]["author"] == "Odalys Brandtmoor"


def _xmp(body: bytes, schema: bool = True) -> bytes:
    spaces = (b"xmlns:x='adobe:ns:meta/' xmlns:rdf='http://www.w3.org/1999/02/22-rdf-syntax-ns#' xmlns:dc='http://purl.org/dc/elements/1.1/'"
              + (b" xmlns:pdf='http://ns.adobe.com/pdf/1.3/'" if schema else b""))
    names = b"<rdf:RDF><rdf:Description><dc:creator><rdf:Seq><rdf:li>Odalys Brandtmoor</rdf:li></rdf:Seq></dc:creator></rdf:Description></rdf:RDF>"
    return b"<x:xmpmeta " + spaces + b">" + names + body + b"</x:xmpmeta>"


@pytest.mark.parametrize("packets", [_xmp(b" " * (dp.MAX_XMP + 1000)), _xmp(b"") * 2, _xmp(b"", schema=False)],
                         ids=["oversized", "repeated", "not in the PDF schema"])
def test_a_pdf_whose_metadata_packet_cannot_be_tied_to_it_is_unparsed(packets):
    out = dp.parse_document(b"%PDF-1.4\n" + packets + b"\n%%EOF\n", "pdf")
    assert out["parsed"] is False and out["reason"] == "bad_pdf" and dp.REASONS["bad_pdf"]
    # one packet in the PDF schema is the document's own, and a file with no packet declares nothing
    assert dp.parse_document(b"%PDF-1.4\n" + _xmp(b"") + b"\n%%EOF\n", "pdf")["fields"]["author"] == "Odalys Brandtmoor"
    assert dp.parse_document(df.pdf(None))["parsed"] is True


# ---- text: one pass for a one-byte charset, UTF-16 by its mark, and never a page of NULs -------------

def test_a_one_byte_charset_is_decoded_through_its_table(monkeypatch):
    every = bytes(range(256)) * 3
    one_byte = [codec for codec in sorted(charset.ALLOWED) if codec.startswith(("cp125", "iso8859_", "koi8_", "mac_"))]
    assert len(one_byte) >= 20 and set(one_byte) == set(charset._TABLES)
    for codec in one_byte:
        assert len(charset._TABLES[codec]) == 256
        label = next(label for label, known in charset._LABELS.items() if known == codec)
        assert charset.decode(every, f"text/html; charset={label}") == every.decode(codec, "replace")
    calls = []
    real = charset.codecs.charmap_decode
    monkeypatch.setattr(charset.codecs, "charmap_decode", lambda *a: calls.append(len(a[2])) or real(*a))
    assert charset.decode(b"\x8e" * 5000, "text/html; charset=windows-1258") == "�" * 5000
    assert calls == [256]                                       # the table, once: no per-byte error handling


@pytest.mark.parametrize("codec", ["utf-16", "utf-16-le", "utf-16-be"])
def test_a_page_that_opens_with_a_utf16_mark_is_read_as_utf16(monkeypatch, codec):
    mark = {"utf-16": b"", "utf-16-le": b"\xff\xfe", "utf-16-be": b"\xfe\xff"}[codec]
    body = mark + TAGGED.encode(codec)
    for ctype in ("text/html", "text/html; charset=utf-8", "text/html; charset=windows-1252"):
        assert charset.decode(body, ctype) == TAGGED
    assert charset.decode(body + b"\x00", "text/html") in (TAGGED, TAGGED + "�")       # an odd byte at the end never raises
    home(monkeypatch, page(body, "text/html"))
    out = asyncio.run(ti.run_tracker_ids(DOMAIN))
    assert out["state"] == "ok" and [r["value"] for r in out["ids"]] == ["G-ABCD123456"]
    assert ad.extract(body, "text/html", URL)["lines"] == ["hello"]


def test_a_page_that_is_not_text_is_a_failure_and_never_an_empty_page(monkeypatch):
    unmarked = TAGGED.encode("utf-16-le")
    assert charset.not_text(charset.decode(unmarked, "text/html")) is True
    assert charset.not_text(charset.decode(HOME.encode() + b"\x00", "text/html")) is False        # a stray NUL is still a page
    assert charset.not_text("") is False

    home(monkeypatch, page(unmarked, "text/html"))
    out = asyncio.run(ti.run_tracker_ids(DOMAIN))
    assert out["state"] == "failed" and out["error_code"] == "bad_response" and out["ids"] == []
    now = ti.time.time()
    monkeypatch.setattr(ti.time, "time", lambda: now + ti.CACHE_TTL_SOFT + 5)
    assert asyncio.run(ti.run_tracker_ids(DOMAIN))["cached"] is False                          # kept as a failure, briefly
    monkeypatch.undo()

    with pytest.raises(ValueError):
        ad.extract(unmarked, "text/html", URL)


def test_a_capture_that_is_not_text_fails_that_side_of_the_comparison(monkeypatch):
    both(monkeypatch, older=TAGGED.encode("utf-16-le"), newer=NEWER)
    out = diff()
    assert out["state"] == "failed" and out["error_code"] == "bad_response"
    assert out["from"]["state"] == "failed" and out["from"]["text_lines"] == 0 and out["to"]["state"] == "ok"
    assert out["removed"]["text"] == [] and out["added"]["text"] == []


# ---- which addresses the archive is asked about ------------------------------------------------------

@pytest.mark.parametrize("url, reason", [
    (f"https://web.archive.org/web/2020/https:/codeplace.example/{HANDLE}", "bad_url"),
    (f"https://web.archive.org/web/20200101000000id_/https://codeplace.example/{HANDLE}", "bad_url"),
    (f"https://WEB.Archive.Org/web/2020/codeplace.example/{HANDLE}", "bad_url"),
    (f"https://archive.org/details/{HANDLE}", "bad_url"),
    (f"https://wayback.archive.org/web/2020/codeplace.example/{HANDLE}", "bad_url"),
    (f"https://web.archive.org/web/2020/https:/{ADULT}/users/{HANDLE}", "adult_site"),
    (f"https://codeplace.example/out/https:/{ADULT}/users/{HANDLE}", "adult_site"),
    (f"https://codeplace.example/out/www.{ADULT.upper()}/{HANDLE}", "adult_site"),
    (f"https://codeplace.example/{HANDLE}?next=https://{ADULT}/{HANDLE}", "adult_site"),
    (f"https://codeplace.example/{HANDLE}?next=https%3A%2F%2F{ADULT}%2F{HANDLE}", "adult_site"),
    (f"https://codeplace.example/{HANDLE}?next=https%253A%252F%252F{ADULT}%252F{HANDLE}", "adult_site"),
])
def test_an_address_inside_an_archive_or_one_that_names_an_adult_site_is_refused(monkeypatch, c, url, reason):
    assert pa.check_url(url) == ("", reason)
    asked: list = []
    index(monkeypatch, lambda r: httpx.Response(200, text="[]"), asked)
    captures(monkeypatch, {T1: lambda r: page(OLDER), T2: lambda r: page(NEWER)}, asked)
    out = c.post("/api/recon/profile-archive", json={"url": url}).json()
    assert out["state"] == "refused" and out["reason"] == reason and out["url"] == ""
    out = c.post("/api/recon/archive-diff", json={"url": url, "from": ISO1, "to": ISO2, "username": HANDLE}).json()
    assert out["state"] == "refused" and out["reason"] == reason
    assert asked == []


@pytest.mark.parametrize("path", [
    "/a%2f..%2fb", "/a%2F%2e%2e%2Fb", "/a%5c..%5cb", "/a%5C%2e%2e%5Cb", "/%252e%252e/b", "/a/%25252e%25252e/b", "/a%252f..%252fb",
    "/a/..;/b", "/a/..;x=1/b", "/a/.;x/b", "/a/%2e%2e;/b", "/a/..%20/b", "/a/%20../b", "/a/..%09/b", "/a/..%00/b", "/a%2f%2fb",
    "/a/%" + "25" * 6 + "2e/b", "/\uff0e\uff0e/b", "/a/\u2024\u2024/b", "/a/.%E2%80%8B./b", "/a/%ef%bc%8e%ef%bc%8e/b", "/a/%c0%ae%c0%ae/b", "/a/%C0%AE/b",
])
def test_a_path_that_reads_as_dot_segments_once_decoded_is_refused(monkeypatch, c, path):
    url = f"https://codeplace.example{path}"
    assert pa.check_url(url) == ("", "bad_url")
    asked: list = []
    index(monkeypatch, lambda r: httpx.Response(200, text="[]"), asked)
    captures(monkeypatch, {}, asked)
    assert c.post("/api/recon/profile-archive", json={"url": url}).json()["reason"] == "bad_url"
    assert c.post("/api/recon/archive-diff", json={"url": url, "from": ISO1, "to": ISO2, "username": HANDLE}).json()["reason"] == "bad_url"
    assert asked == []


@pytest.mark.parametrize("url", [
    URL, f"https://codeplace.example/users/{HANDLE};tab=posts", "https://codeplace.example/a;b/c", "https://codeplace.example/wiki/User%3AMara",
    "https://codeplace.example/x%2Fy", "https://codeplace.example/100%25/x", "https://codeplace.example/a%20b", "https://codeplace.example/v1.2/a.b",
    "https://codeplace.example/a/.../b", "https://codeplace.example/u?ref=codeplace.example&x=..", "https://archive.example/u", "https://notarchive.org/u",
])
def test_a_plain_address_is_still_looked_up(url):
    assert pa.check_url(url) == (url, "")



# ---- prompts: no text that cannot be written out ------------------------------------------------------

def test_a_field_is_written_without_surrogates_or_direction_overrides():
    assert an._cell("a\ud800b\udfffc", 50) == "abc"
    assert an._cell("abc‮⁦def﻿", 50) == "abcdef"
    assert an._BIDI == base._BIDI
    assert an._cell("line one\nline two | x", 50) == "line one line two / x"


@pytest.mark.parametrize("extra", [
    {"target": "sam\ud800example"},
    {"profile_sources": {"profiles": [{"site": "Code\udc00place", "status": "linked", "url": URL, "bio": "hello \udfff there"}]}},
    {"post_activity": [{"state": "failed", "site": "Forum", "note": "\ud800"}]},
    {"commit_emails": [{"site": "Forge", "addresses": [{"email": "\ud800@larkspur-tide.example"}]}]},
    {"source_status": {"Code\ud800place": "failed: \udbff"}},
    {"github_activity": {"state": "ok", "summary": "\ud800"}},
], ids=["target", "profile_sources", "post_activity", "commit_emails", "source_status", "github_activity"])
def test_a_request_with_an_unpaired_surrogate_still_gets_a_prompt(c, extra):
    body = json.dumps({"target": HANDLE, "target_type": "username", **extra})
    assert "\\ud" in body
    r = c.post("/api/analyze/prompt", content=body, headers={"content-type": "application/json"})
    assert r.status_code == 200
    prompt = r.json()["prompt"]
    assert prompt and not any(0xD800 <= ord(ch) <= 0xDFFF for ch in prompt)
    prompt.encode("utf-8")


def test_surrogates_are_taken_out_at_any_depth_without_recursion():
    deep: object = "x\ud800y"
    for _ in range(5000):
        deep = {"k\udc00": [deep]}
    out = an._without_surrogates(deep)
    for _ in range(5000):
        assert list(out) == ["k"]
        out = out["k"][0]
    assert out == "xy"
    assert an._without_surrogates({"a": 1, "b": None, "c": ["plain", 2.5, True]}) == {"a": 1, "b": None, "c": ["plain", 2.5, True]}


def test_no_em_dash_in_the_new_code_or_this_file(pool):
    for path in (pool.__file__, capfetch.__file__, pinned.__file__, charset.__file__, __file__):
        assert chr(0x2014) not in Path(path).read_text(encoding="utf-8")
