"""Reading outside data within fixed bounds: which charsets a page may be read in, where the
parsing runs, how deep a page may nest, which addresses are asked of the archive, how much of a
compressed body is ever held, and when an answer is settled enough to keep for a day.

Everything is served by mock transports: no network and no DNS. Every name, host, handle and
document here is invented."""

import asyncio
import encodings.aliases
import gzip
import io
import json
import threading
import weakref
import zipfile
import zlib
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from core import charset, inflight, pinned, profile_record
from core import netguard as ng
from main import app
import middleware.rate_limit as rl
from modules import archive_diff as ad
from modules import commit_emails as ce
from modules import doc_metadata as dm
from modules import doc_parse as dp
from modules import profile_archive as pa
from modules import tracker_ids as ti
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
PUBLIC_IP = "93.184.216.34"
ARCHIVE = "web.archive.org"
NOT_CHARSETS = ("punycode", "idna", "zlib_codec", "zlib", "base64", "base64_codec", "hex", "hex_codec", "bz2", "bz2_codec",
                "rot13", "rot_13", "uu", "uu_codec", "quopri", "quopri_codec", "unicode_escape", "raw_unicode_escape",
                "utf-7", "utf_7", "utf-16", "utf-32", "undefined", "mbcs", "oem", "nonsense", "", "a" * 40)


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    def wipe():
        for module in (ad, dm, ti, pa, ce):
            module.clear_cache_for_tests()
        profile_record.clear()

    async def public(host, port=443):
        return [PUBLIC_IP]

    monkeypatch.setattr(pinned, "resolve_public", public)
    monkeypatch.setattr(ng, "resolve_public", public)
    for path in ("archive-diff", "profile-archive", "tracker-ids", "doc-metadata"):
        monkeypatch.setitem(rl.RATE_LIMITS, f"/api/recon/{path}", (1000, 60))
    wipe()
    yield
    wipe()


@pytest.fixture()
def c():
    # Its own client address, so the requests made here do not count against another file's limits.
    with TestClient(app, client=("bounded-reads.test", 50000)) as client:
        yield client


# ---- helpers ----------------------------------------------------------------------------------

def home(monkeypatch, answer, calls: list | None = None):
    """The target's home page for modules.tracker_ids: httpx.Response | callable(request)."""
    def handler(request: httpx.Request) -> httpx.Response:
        if calls is not None:
            calls.append(request)
        return answer(request) if callable(answer) else answer

    monkeypatch.setattr(ti, "_inner_transport", lambda: httpx.MockTransport(handler))


def page(body: bytes | str, content_type: str = "text/html; charset=utf-8") -> httpx.Response:
    return httpx.Response(200, content=body.encode("utf-8") if isinstance(body, str) else body, headers={"content-type": content_type})


def captures(monkeypatch, pages: dict, calls: list | None = None):
    """Archived copies for modules.archive_diff: {timestamp: (status, body, headers)}."""
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.raw_path.decode()
        if calls is not None:
            calls.append(path)
        status, body, headers = pages.get(path[5:19], (404, b"", {}))
        return httpx.Response(status, content=body, headers=headers)

    monkeypatch.setattr(ad, "_transport", lambda: httpx.MockTransport(handler))


def both(monkeypatch, calls=None, older=OLDER, newer=NEWER, ctype="text/html; charset=utf-8"):
    captures(monkeypatch, {T1: (200, older, {"content-type": ctype}), T2: (200, newer, {"content-type": ctype})}, calls)


def index(monkeypatch, calls: list):
    """The archive's capture index for modules.profile_archive: every request is recorded."""
    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return httpx.Response(200, text="[]", headers={"content-type": "application/json"})

    monkeypatch.setattr(pa, "_transport", lambda: httpx.MockTransport(handler))


def cdx(*urls: str) -> str:
    rows = [[u, f"2024010100{n:04d}", f"2026010100{n:04d}", "application/pdf", "100"] for n, u in enumerate(urls)]
    return json.dumps([["original", "timestamp", "endtimestamp", "mimetype", "length"], *rows])


def documents(monkeypatch, listing: str, files: dict, calls: list | None = None):
    """The archive's list and the target's files for modules.doc_metadata. files: path ->
    bytes | httpx.Response | callable(request); a path not listed is a 404."""
    def handler(request: httpx.Request) -> httpx.Response:
        if calls is not None:
            calls.append(request)
        if request.headers["host"] == ARCHIVE:
            return httpx.Response(200, text=listing, headers={"content-type": "application/json"})
        hit = files.get(request.url.path)
        if hit is None:
            return httpx.Response(404, text="not here")
        if callable(hit):
            return hit(request)
        return httpx.Response(200, content=hit, headers={"content-type": "application/octet-stream"}) if isinstance(hit, bytes) else hit

    monkeypatch.setattr(dm, "_inner_transport", lambda: httpx.MockTransport(handler))


def off_the_loop(monkeypatch, module, name: str) -> list:
    """Record the thread every call of `module.name` runs on."""
    real, seen = getattr(module, name), []

    def spy(*args, **kwargs):
        seen.append(threading.current_thread())
        return real(*args, **kwargs)

    monkeypatch.setattr(module, name, spy)
    return seen


# ---- charsets: a page's own label never picks the codec ------------------------------------------

def test_a_label_only_ever_selects_a_listed_charset():
    names = set(encodings.aliases.aliases) | set(encodings.aliases.aliases.values()) | set(NOT_CHARSETS)
    for name in names:
        for variant in (name, name.upper(), name.replace("_", "-")):
            assert charset.pick(variant) in charset.ALLOWED
            assert charset.choose(b"<meta charset='%s'>" % variant.encode(), f"text/html; charset={variant}") in charset.ALLOWED
    for name in NOT_CHARSETS:
        assert charset.pick(name) == "utf-8"
    assert charset.pick(None) == "utf-8" and charset.pick(7) == "utf-8"
    assert "utf-8" in charset.ALLOWED and len(charset.ALLOWED) < 50
    # every listed codec exists and is a plain text charset
    for codec in charset.ALLOWED:
        assert "é".encode(codec, "replace").decode(codec, "replace")


def test_real_charsets_are_read_and_a_page_never_fails_to_decode():
    assert charset.decode("José Müller".encode("latin-1"), "text/html; charset=ISO-8859-1") == "José Müller"
    assert charset.decode(b"<meta charset='windows-1252'>Jos\xe9", "text/html") == "<meta charset='windows-1252'>José"
    assert charset.decode("日本語".encode("shift_jis"), "text/html; charset=Shift_JIS") == "日本語"
    assert charset.decode("Привет".encode("cp1251"), "text/html;charset=windows-1251") == "Привет"
    assert charset.decode("中文".encode("gbk"), "text/html; charset=GBK") == "中文"
    # the header's label wins, an unknown one is passed over for the next, and broken bytes never raise
    assert charset.decode(b"<meta charset=koi8-r>h\xc3\xa9", "text/html; charset=utf-8").endswith("hé")
    assert charset.decode(b"<meta charset=windows-1252>Jos\xe9", "text/html; charset=nonsense").endswith("José")
    for name in NOT_CHARSETS:
        assert charset.decode("<p>hé</p>".encode(), f"text/html; charset={name}") == "<p>hé</p>"
    assert charset.decode(b"\xff\xfe\x00broken", "text/html; charset=utf-8")
    assert charset.decode(b"\x81\x81\x81", "text/html; charset=shift_jis")


@pytest.mark.parametrize("label", ["punycode", "zlib_codec", "idna", "base64", "utf-7", "undefined"])
def test_a_home_page_with_a_label_that_is_not_a_charset_is_read_as_utf8(monkeypatch, c, label):
    home(monkeypatch, page(HOME, f"text/html; charset={label}"))
    out = asyncio.run(ti.run_tracker_ids(DOMAIN))
    assert out["state"] == "ok" and out["count"] == 14
    ti.clear_cache_for_tests()
    r = c.post("/api/recon/tracker-ids", json={"domain": DOMAIN})
    assert r.status_code == 200 and r.json()["state"] == "ok" and r.json()["count"] == 14


@pytest.mark.parametrize("label", ["punycode", "zlib_codec", "idna", "base64", "utf-7"])
def test_a_capture_with_a_label_that_is_not_a_charset_is_read_as_utf8(monkeypatch, label):
    for ctype, body in ((f"text/html; charset={label}", "<p>hé</p>"), ("text/html", f"<meta charset='{label}'><p>hé</p>")):
        assert ad.extract(body.encode(), ctype, URL)["lines"] == ["hé"]


def test_both_readers_decode_through_the_one_allowlist(monkeypatch):
    seen = []
    real = charset.decode
    monkeypatch.setattr(charset, "decode", lambda body, ctype="": seen.append(ctype) or real(body, ctype))
    ad.extract(b"<p>x</p>", "text/html; charset=koi8-r", URL)
    home(monkeypatch, page(HOME, "text/html; charset=windows-1252"))
    asyncio.run(ti.run_tracker_ids(DOMAIN))
    assert seen == ["text/html; charset=koi8-r", "text/html; charset=windows-1252"]
    for module in (ad, ti):
        source = Path(module.__file__).read_text(encoding="utf-8")
        assert ".text\n" not in source and "resp.text" not in source and "codecs.lookup" not in source


# ---- parsing a fetched page runs in a thread, not on the event loop ------------------------------

def test_a_home_page_is_decoded_and_parsed_off_the_event_loop(monkeypatch):
    parsed, decoded = off_the_loop(monkeypatch, ti, "extract_ids"), off_the_loop(monkeypatch, charset, "decode")
    home(monkeypatch, page(HOME))
    assert asyncio.run(ti.run_tracker_ids(DOMAIN))["count"] == 14
    assert len(parsed) == 1 and len(decoded) == 1
    assert all(t is not threading.main_thread() for t in parsed + decoded)


def test_both_captures_are_decoded_and_parsed_off_the_event_loop(monkeypatch):
    parsed, decoded = off_the_loop(monkeypatch, ad, "extract"), off_the_loop(monkeypatch, charset, "decode")
    both(monkeypatch)
    assert asyncio.run(ad.run_archive_diff(URL, ISO1, ISO2))["state"] == "ok"
    assert len(parsed) == 2 and len(decoded) == 2
    assert all(t is not threading.main_thread() for t in parsed + decoded)


# ---- nesting: what a page can make the reader remember is bounded --------------------------------

@pytest.mark.parametrize("opened", ["svg", "template", "select", "object"])
def test_the_hidden_element_stack_is_bounded_however_deep_a_page_nests(opened):
    parser = ad._Page()
    deepest = 0
    for chunk in (f"<{opened}>" * 3000, "</head>" * 3000, "</iframe>" * 3000, f"<{opened}>" * 3000):
        parser.feed(chunk)
        deepest = max(deepest, len(parser._hidden))
    assert deepest <= ad.MAX_HIDDEN_DEPTH <= 64


def test_deep_nesting_still_hides_and_shows_the_right_text():
    deep = ad.MAX_HIDDEN_DEPTH * 3
    body = "<p>before</p>" + "<svg>" * deep + "inside" + "</svg>" * (deep - 1) + "still inside</svg><p>after</p>"
    assert ad.extract(body.encode(), "text/html", URL)["lines"] == ["before", "after"]
    # never closed: hidden to the end, and a body tag still starts the visible page
    assert ad.extract(("<p>a</p>" + "<svg>" * deep + "<p>lost</p>").encode(), "text/html", URL)["lines"] == ["a"]
    assert ad.extract(("<head>" + "<svg>" * deep + "<body><p>seen</p>").encode(), "text/html", URL)["lines"] == ["seen"]
    # ordinary pages read as before
    assert ad.extract(b"<head><title>t</title><style>x</style></head><body><p>one<script>no</script></p><svg><svg>no</svg>no</svg>two", "text/html", URL) == {
        "title": "t", "lines": ["one", "two"], "links": []}


# ---- addresses asked of the archive ---------------------------------------------------------------

DOTTED = [
    "https://codeplace.example/a/../b",
    "https://codeplace.example/../b",
    "https://codeplace.example/a/./b",
    "https://codeplace.example/a/..",
    "https://codeplace.example/.",
    "https://codeplace.example/a/%2e%2e/b",
    "https://codeplace.example/a/%2E%2E/b",
    "https://codeplace.example/a/.%2e/b",
    "https://codeplace.example/a/%2e/b",
    "https://codeplace.example/a//b",
    "https://codeplace.example//b",
    "https://codeplace.example/a/../../other.example/b",
]
PLAIN = [
    "https://codeplace.example/a.b/c..d/.well-known/x",
    "https://codeplace.example/a/...",
    "https://codeplace.example/@mara/posts?next=../x&u=a//b",
    "https://codeplace.example/~mara/v1.2/",
]


@pytest.mark.parametrize("url", DOTTED)
def test_a_path_with_dot_segments_or_an_empty_segment_is_refused(url):
    assert pa.check_url(url) == ("", "bad_url")


@pytest.mark.parametrize("url", PLAIN)
def test_dots_inside_a_segment_and_in_a_query_are_part_of_a_plain_address(url):
    assert pa.check_url(url) == (url, "")


@pytest.mark.parametrize("url", DOTTED)
def test_both_archive_endpoints_refuse_such_a_path_before_any_request(monkeypatch, c, url):
    asked: list = []
    index(monkeypatch, asked)
    both(monkeypatch, asked)
    r = c.post("/api/recon/profile-archive", json={"url": url})
    assert r.status_code == 200 and (r.json()["state"], r.json()["reason"], r.json()["url"]) == ("refused", "bad_url", "")
    r = c.post("/api/recon/archive-diff", json={"url": url, "from": ISO1, "to": ISO2, "username": HANDLE})
    assert r.status_code == 200 and (r.json()["state"], r.json()["reason"], r.json()["url"]) == ("refused", "bad_url", "")
    assert asked == []
    profile_record.bind(c.cookies.get("crawlr_run"))
    assert profile_record.texts(HANDLE) == []


def test_the_address_sent_to_the_archive_is_the_one_that_was_checked(monkeypatch):
    asked: list = []
    both(monkeypatch, asked)
    for url in PLAIN + [URL, "https://codeplace.example/café/日本?q=a b"]:
        clean = pa.check_url(url)[0] or url
        ad.clear_cache_for_tests()
        asked.clear()
        asyncio.run(ad._ask(clean, T1, T2))
        assert len(asked) == 2 and all(p.startswith(f"/web/{t}id_/https://codeplace.example/") for p, t in zip(sorted(asked), (T1, T2)))
        assert all(p.count("/") == f"/web/{T1}id_/{clean}".count("/") for p in asked)


@pytest.mark.parametrize("url", ["https://codeplace.example/a/../b", "https://codeplace.example/a/./b", "https://codeplace.example/a/../../../cdx/x"])
def test_a_request_whose_path_would_change_on_the_way_out_is_never_sent(monkeypatch, url):
    # Past the check on purpose: the fetch holds the same line on its own.
    monkeypatch.setattr(pa, "check_url", lambda u: (u, ""))
    asked: list = []
    both(monkeypatch, asked)
    out = asyncio.run(ad.run_archive_diff(url, ISO1, ISO2))
    assert asked == [] and out["state"] == "failed" and out["error_code"] == "blocked_target"
    assert out["removed"]["text"] == [] and out["added"]["text"] == [] and out["from"]["title"] == "" and out["to"]["title"] == ""


# ---- compressed bodies: the cap is on what is held, chunk by chunk --------------------------------

class _Wire(httpx.AsyncByteStream):
    def __init__(self, *chunks: bytes):
        self.chunks, self.sent = chunks, 0

    async def __aiter__(self):
        for chunk in self.chunks:
            self.sent += 1
            yield chunk


def _one(response_for, **kw):
    async def go():
        async with httpx.AsyncClient(transport=httpx.MockTransport(response_for)) as client:
            return await pinned.get(client, f"https://{ARCHIVE}/web/{T1}id_/{URL}", **kw)
    return asyncio.run(go())


def test_a_compressed_body_is_inflated_against_the_cap_and_never_whole(monkeypatch):
    held = []
    real = zlib.decompressobj

    class Watched:
        def __init__(self, *a):
            self._z = real(*a)

        def decompress(self, data, max_length=0):
            out = self._z.decompress(data, max_length)
            held.append((max_length, len(out)))
            return out

        def __getattr__(self, name):
            return getattr(self._z, name)

    monkeypatch.setattr(pinned.zlib, "decompressobj", Watched)

    async def never(self, *a, **k):
        raise AssertionError("the body must not be decoded by the HTTP client")
        yield b""

    monkeypatch.setattr(httpx.Response, "aiter_bytes", never)
    packed = gzip.compress(b"<p>first line</p>" + b" " * 30_000_000)
    assert len(packed) < 60_000
    wire = _Wire(packed)
    got = _one(lambda r: httpx.Response(200, stream=wire, headers={"content-encoding": "gzip", "content-type": "text/html"}), max_bytes=2000)
    assert got.truncated is True and len(got.body) == 2000 and got.body.startswith(b"<p>first line</p>")
    # every inflate call was given a limit, and none returned more than the cap allows
    assert held and all(0 < limit <= 2001 and size <= limit for limit, size in held)


@pytest.mark.parametrize("coding, pack", [("gzip", gzip.compress), ("x-gzip", gzip.compress), ("deflate", zlib.compress), ("identity", bytes), ("", bytes)])
def test_gzip_deflate_and_plain_bodies_are_read_whole_when_they_fit(coding, pack):
    body = b"<p>" + b"all of it " * 500 + b"</p>"
    packed = pack(body)
    headers = {"content-type": "text/html", **({"content-encoding": coding} if coding else {})}
    got = _one(lambda r: httpx.Response(200, stream=_Wire(packed[:40], packed[40:]), headers=headers), max_bytes=len(body))
    assert got.body == body and got.truncated is False and got.status == 200
    cut = _one(lambda r: httpx.Response(200, stream=_Wire(packed), headers=headers), max_bytes=100)
    assert cut.body == body[:100] and cut.truncated is True


@pytest.mark.parametrize("coding", ["br", "zstd", "compress", "gzip, br", "gzip, gzip"])
def test_a_coding_that_cannot_be_bounded_is_an_error_and_never_a_body(coding):
    seen = []

    def answer(request):
        seen.append(request.headers.get("accept-encoding", ""))
        return httpx.Response(200, stream=_Wire(b"\x00" * 64), headers={"content-encoding": coding})

    with pytest.raises(httpx.DecodingError):
        _one(answer, max_bytes=1000)
    # and none of them is asked for
    assert seen and all("br" not in s and "zstd" not in s for s in seen)


def test_a_body_that_does_not_inflate_is_an_error_and_a_capture_then_fails(monkeypatch):
    with pytest.raises(httpx.DecodingError):
        _one(lambda r: httpx.Response(200, stream=_Wire(b"not gzip at all"), headers={"content-encoding": "gzip"}), max_bytes=1000)
    captures(monkeypatch, {T1: (200, b"not gzip at all", {"content-type": "text/html", "content-encoding": "gzip"}),
                           T2: (200, NEWER, {"content-type": "text/html"})})
    out = asyncio.run(ad.run_archive_diff(URL, ISO1, ISO2))
    assert out["state"] == "failed" and out["error_code"] == "bad_response" and out["removed"]["text"] == []


def test_a_body_is_only_read_for_the_statuses_asked_for():
    wire = _Wire(b"x" * 10)
    got = _one(lambda r: httpx.Response(404, stream=wire, headers={"content-encoding": "br"}), max_bytes=1000)
    assert got.status == 404 and got.body == b"" and wire.sent == 0


# ---- Office files: which archive members are opened -----------------------------------------------

@pytest.mark.parametrize("method", [zipfile.ZIP_BZIP2, zipfile.ZIP_LZMA])
def test_a_member_packed_with_anything_but_store_or_deflate_is_never_opened(monkeypatch, method):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", b"<Types/>")
        zf.writestr("word/document.xml", b"<w:document/>")
        zf.writestr(zipfile.ZipInfo("docProps/core.xml"), df.core_xml(), compress_type=method)
        zf.writestr("docProps/app.xml", df.app_xml())
    opened = []
    real = zipfile.ZipFile.open

    def spy(self, name, *a, **k):
        info = name if isinstance(name, zipfile.ZipInfo) else self.getinfo(name)
        opened.append(info.compress_type)
        return real(self, name, *a, **k)

    monkeypatch.setattr(zipfile.ZipFile, "open", spy)
    out = dp.parse_document(buf.getvalue(), "docx")
    assert method not in opened
    assert out["parsed"] is False and out["reason"] == "bad_zip" and out["fields"]["author"] == ""
    # the usual two methods are read as before
    for usual in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", usual) as zf:
            zf.writestr("word/document.xml", b"<w:document/>")
            zf.writestr("docProps/core.xml", df.core_xml())
        assert dp.parse_document(buf.getvalue(), "docx")["fields"]["author"] == "Odalys Brandtmoor"


# ---- PDF: metadata that could not be read is not "declares nothing" -------------------------------

def _unreadable_packets() -> dict:
    return {
        "xml_entities": df.xmp_packet().replace(b"<rdf:RDF", b'<!DOCTYPE x [<!ENTITY a "aaaa">]><rdf:RDF').replace(b"Annual report 2021", b"&a;"),
        "bad_xml": df.xmp_packet().replace(b"</rdf:RDF>", b""),
    }


@pytest.mark.parametrize("reason", ["xml_entities", "bad_xml"])
@pytest.mark.parametrize("info", [None, b"<< >>", b"<< /Trapped /False >>"])
def test_a_pdf_whose_only_metadata_could_not_be_parsed_is_unparsed(reason, info):
    out = dp.parse_document(df.pdf(info, xmp=_unreadable_packets()[reason]))
    assert out["parsed"] is False and out["reason"] == reason and reason in dp.REASONS
    assert out["fields"] == {k: "" for k in dp.FIELDS} and out["sources"] == [] and "aaaa" not in json.dumps(out)


def test_such_a_pdf_is_an_unparsed_document_and_the_answer_is_not_none(monkeypatch):
    documents(monkeypatch, cdx(f"https://{DOMAIN}/a.pdf"), {"/a.pdf": df.pdf(None, xmp=_unreadable_packets()["bad_xml"])})
    out = asyncio.run(dm.run_doc_metadata(DOMAIN))
    assert out["state"] == "unparsed" and out["counts"] == {"unparsed": 1}
    assert out["documents"][0]["reason"] == "bad_xml" and out["documents"][0]["reason_text"]


def test_readable_metadata_still_counts_next_to_a_packet_that_does_not():
    for packet in _unreadable_packets().values():
        out = dp.parse_document(df.pdf(b"<< /Author (Teodor Vashenko) >>", xmp=packet))
        assert out["parsed"] is True and out["sources"] == ["info"] and out["fields"]["author"] == "Teodor Vashenko"
    assert dp.parse_document(df.pdf(None))["parsed"] is True        # no metadata at all is still "declares nothing"
    assert dp.parse_document(df.pdf(None, xmp=df.xmp_packet()))["fields"]["title"] == "Annual report 2021"


# ---- which hosts belong to the domain that was typed -----------------------------------------------

@pytest.mark.parametrize("typed, host, ok", [
    ("www.com", "www.com", True), ("www.com", "files.www.com", True),
    ("www.com", "larkspur-tide.com", False), ("www.com", "com", False), ("www.com", "a.b.com", False),
    ("www2.net", "larkspur-tide.net", False), ("www2.net", "www2.net", True),
    ("www.co.uk", "larkspur-tide.co.uk", False), ("www.co.uk", "co.uk", False), ("www.co.uk", "www.co.uk", True),
    ("www1.com.au", "larkspur-tide.com.au", False),
    ("larkspur-tide.co.uk", "www.larkspur-tide.co.uk", True), ("www.larkspur-tide.co.uk", "files.larkspur-tide.co.uk", True),
    ("www.larkspur-tide.co.uk", "other.co.uk", False),
    (f"www.{DOMAIN}", DOMAIN, True), (f"www2.{DOMAIN}", f"files.{DOMAIN}", True), (DOMAIN, f"www.{DOMAIN}", True),
    (DOMAIN, "www.example", False), (DOMAIN, "other.example", False),
])
def test_a_www_name_is_never_read_as_a_whole_suffix(typed, host, ok):
    assert dm.on_target(host, typed) is ok


def test_documents_listed_under_another_name_of_the_suffix_are_not_fetched(monkeypatch):
    calls: list = []
    documents(monkeypatch, cdx("https://larkspur-tide.com/a.pdf", "https://files.other.com/b.pdf", "https://www.com/c.pdf"),
              {"/a.pdf": df.pdf(), "/b.pdf": df.pdf(), "/c.pdf": df.pdf()}, calls)
    out = asyncio.run(dm.run_doc_metadata("www.com"))
    assert [d["url"] for d in out["documents"]] == ["https://www.com/c.pdf"]
    assert {r.headers["host"] for r in calls} == {ARCHIVE, "www.com"}


# ---- how long an answer is kept --------------------------------------------------------------------

def _later(monkeypatch, module, seconds: float):
    now = module.time.time()
    monkeypatch.setattr(module.time, "time", lambda: now + seconds)


@pytest.mark.parametrize("unsettled", [httpx.Response(403, text="no"), httpx.Response(429, text="slow"), httpx.Response(500, text="oops"),
                                       httpx.ReadTimeout("t")], ids=["blocked", "rate_limited", "failed", "timeout"])
def test_an_answer_with_a_document_that_did_not_answer_is_kept_only_briefly(monkeypatch, unsettled):
    def second(request):
        if isinstance(unsettled, Exception):
            raise unsettled
        return unsettled

    calls: list = []
    listing = cdx(f"https://{DOMAIN}/a.pdf", f"https://{DOMAIN}/b.pdf")
    documents(monkeypatch, listing, {"/b.pdf": df.pdf(), "/a.pdf": second}, calls)
    first = asyncio.run(dm.run_doc_metadata(DOMAIN))
    assert first["state"] == "ok" and first["counts"].get("ok") == 1 and len(first["documents"]) == 2
    assert asyncio.run(dm.run_doc_metadata(DOMAIN))["cached"] is True
    _later(monkeypatch, dm, dm.CACHE_TTL_SOFT + 5)
    n = len(calls)
    documents(monkeypatch, listing, {"/b.pdf": df.pdf(), "/a.pdf": df.pdf()}, calls)
    again = asyncio.run(dm.run_doc_metadata(DOMAIN))
    assert again["cached"] is False and len(calls) > n and again["counts"] == {"ok": 2}


def test_an_answer_whose_documents_all_settled_is_kept_for_the_day(monkeypatch):
    calls: list = []
    listing = cdx(*(f"https://{DOMAIN}/{n}.pdf" for n in "abcde"))
    files = {"/a.pdf": df.pdf(), "/b.pdf": df.pdf(None), "/c.pdf": df.pdf(info_in_file=False, extra_objects=(df.object_stream(parms=df.PREDICTOR),)),
             "/d.pdf": httpx.Response(404, text="gone"), "/e.pdf": httpx.Response(200, text="<html>moved</html>")}
    documents(monkeypatch, listing, files, calls)
    first = asyncio.run(dm.run_doc_metadata(DOMAIN))
    assert first["state"] == "ok" and sorted(d["state"] for d in first["documents"]) == ["failed", "failed", "none", "ok", "unparsed"]
    n = len(calls)
    _later(monkeypatch, dm, dm.CACHE_TTL - 60)
    assert asyncio.run(dm.run_doc_metadata(DOMAIN))["cached"] is True and len(calls) == n


# ---- PDF markers: only the last few are ever kept --------------------------------------------------

class _Counted:
    """A compiled pattern whose matches are counted while they are alive."""

    def __init__(self, real):
        self.real, self.alive, self.most = real, weakref.WeakSet(), 0

    def finditer(self, *args):
        for m in self.real.finditer(*args):
            held = _Held(m)
            self.alive.add(held)
            self.most = max(self.most, len(self.alive))
            yield held
            del held

    def findall(self, *args):
        raise AssertionError("every match at once")

    def __getattr__(self, name):
        return getattr(self.real, name)


class _Held:
    def __init__(self, m):
        self._m = m

    def __getattr__(self, name):
        return getattr(self._m, name)


@pytest.mark.parametrize("name, marker", [("_OBJSTM", b"/Type /ObjStm "), ("_CATALOG", b"/Type /Catalog "), ("_INFO_REF", b"/Info 9 0 R ")])
def test_a_file_full_of_markers_never_has_them_all_in_memory(monkeypatch, name, marker):
    monkeypatch.setattr(dp, "MAX_MARKERS", 8)
    counted = _Counted(getattr(dp, name))
    monkeypatch.setattr(dp, name, counted)
    # the trailer names an Info object that is not in the file, so every kind of marker is looked for
    data = df.pdf(info_in_file=False).replace(b"%%EOF", marker * 400 + b"\n%%EOF")
    out = dp.parse_document(data)
    assert isinstance(out["parsed"], bool)
    assert 0 < counted.most <= 8 + 2


def test_the_last_marker_still_wins():
    assert dp.parse_document(df.pdf())["fields"]["author"] == "Odalys Brandtmoor"
    out = dp.parse_document(df.pdf(info_in_file=False, extra_objects=(df.object_stream(),)))
    assert out["parsed"] is True and out["fields"]["author"] == "Odalys Brandtmoor"


# ---- a document's redirect stays on the ports a document may be asked on ---------------------------

@pytest.mark.parametrize("location", [f"https://{DOMAIN}:8443/a.pdf", f"http://files.{DOMAIN}:6379/a.pdf", f"https://www.{DOMAIN}:22/",
                                      f"https://user:pw@{DOMAIN}/b.pdf"])
def test_a_redirect_to_another_port_of_the_site_is_not_followed(monkeypatch, location):
    calls: list = []
    documents(monkeypatch, cdx(f"https://{DOMAIN}/a.pdf"),
              {"/a.pdf": lambda r: httpx.Response(302, headers={"location": location}) if r.url.port is None else httpx.Response(200, content=df.pdf()),
               "/b.pdf": df.pdf(), "/": df.pdf()}, calls)
    out = asyncio.run(dm.run_doc_metadata(DOMAIN))
    site = [r for r in calls if r.headers["host"] != ARCHIVE]
    assert len(site) == 1 and site[0].url.port is None
    doc = out["documents"][0]
    assert doc["state"] == "failed" and doc["error_code"] == "off_site" and doc["author"] == ""


def test_a_redirect_on_the_usual_ports_of_the_site_is_still_followed(monkeypatch):
    for location in (f"https://www.{DOMAIN}/b.pdf", f"https://{DOMAIN}:443/b.pdf", "/b.pdf"):
        dm.clear_cache_for_tests()
        documents(monkeypatch, cdx(f"https://{DOMAIN}/a.pdf"),
                  {"/a.pdf": httpx.Response(301, headers={"location": location}), "/b.pdf": df.pdf()})
        assert asyncio.run(dm.run_doc_metadata(DOMAIN))["documents"][0]["state"] == "ok"


# ---- the same question asked twice at once is one piece of work ------------------------------------

def test_shared_runs_the_work_once_per_key_and_forgets_it_afterwards():
    pending: dict = {}
    runs = []

    async def work(key):
        runs.append(key)
        await asyncio.sleep(0)
        if key == "bad":
            raise ValueError("no")
        return {"key": key}

    async def go():
        a, b, other = await asyncio.gather(*(inflight.shared(pending, k, lambda k=k: work(k)) for k in ("x", "x", "y")))
        assert a is b and a == {"key": "x"} and other == {"key": "y"} and runs == ["x", "y"] and pending == {}
        failed = await asyncio.gather(*(inflight.shared(pending, "bad", lambda: work("bad")) for _ in range(2)), return_exceptions=True)
        assert all(isinstance(e, ValueError) for e in failed) and runs.count("bad") == 1 and pending == {}
        await inflight.shared(pending, "x", lambda: work("x"))          # nothing is kept: a later call works again
        assert runs.count("x") == 2
        # one caller going away does not take the work from the other
        first = asyncio.ensure_future(inflight.shared(pending, "z", lambda: work("z")))
        second = asyncio.ensure_future(inflight.shared(pending, "z", lambda: work("z")))
        await asyncio.sleep(0)
        first.cancel()
        assert await second == {"key": "z"} and runs.count("z") == 1

    asyncio.run(go())
    asyncio.run(inflight.shared(pending, "x", lambda: work("x")))        # and a new event loop starts clean
    assert pending == {}


def test_identical_requests_at_once_fetch_once(monkeypatch):
    async def together(make, n=4):
        return await asyncio.gather(*(make() for _ in range(n)))

    calls: list = []
    home(monkeypatch, page(HOME), calls)
    answers = asyncio.run(together(lambda: ti.run_tracker_ids(DOMAIN)))
    assert len(calls) == 1 and [a["count"] for a in answers] == [14] * 4 and all(a["state"] == "ok" for a in answers)

    calls = []
    both(monkeypatch, calls)
    answers = asyncio.run(together(lambda: ad.run_archive_diff(URL, ISO1, ISO2)))
    assert len(calls) == 2 and all(a["state"] == "ok" and a["swapped"] is False for a in answers)
    assert asyncio.run(ad.run_archive_diff(URL, ISO2, ISO1))["swapped"] is True

    calls = []
    documents(monkeypatch, cdx(f"https://{DOMAIN}/a.pdf"), {"/a.pdf": df.pdf()}, calls)
    answers = asyncio.run(together(lambda: dm.run_doc_metadata(DOMAIN)))
    assert len(calls) == 2 and all(a["state"] == "ok" and len(a["documents"]) == 1 for a in answers)
    # each caller holds its own answer: changing one does not change another, or the cached copy
    answers[0]["documents"].clear()
    assert len(answers[1]["documents"]) == 1 and len(asyncio.run(dm.run_doc_metadata(DOMAIN))["documents"]) == 1


# ---- archive diff: every piece of returned text is on the minor guard's record ---------------------

def _record(client, handle=HANDLE) -> list[dict]:
    profile_record.bind(client.cookies.get("crawlr_run"))
    return profile_record.texts(handle)


def test_the_diff_is_only_made_for_a_named_handle(monkeypatch, c):
    asked: list = []
    both(monkeypatch, asked)
    for body in ({"url": URL, "from": ISO1, "to": ISO2}, {"url": URL, "from": ISO1, "to": ISO2, "username": ""}):
        assert c.post("/api/recon/archive-diff", json=body).status_code == 422
    for bad in ("   ", "no/slash", "@"):
        assert c.post("/api/recon/archive-diff", json={"url": URL, "from": ISO1, "to": ISO2, "username": bad}).status_code == 400
    assert asked == []


def test_the_titles_of_both_captures_are_part_of_the_guard_text(monkeypatch, c):
    both(monkeypatch)
    out = c.post("/api/recon/archive-diff", json={"url": URL, "from": ISO1, "to": ISO2, "username": HANDLE}).json()
    assert out["state"] == "ok" and out["from"]["title"] and out["to"]["title"] and out["from"]["title"] != out["to"]["title"]
    texts = _record(c)
    assert len(texts) == 1 and texts[0]["source"] == "Internet Archive" and texts[0]["url"] == out["from"]["url"]
    assert texts[0]["bio"].split("\n") == [out["from"]["title"], out["to"]["title"], *out["removed"]["text"], *out["added"]["text"]]
    assert ad.guard_texts(out) == [texts[0]["bio"]]


def test_a_title_that_states_an_age_under_18_closes_the_adult_pass(monkeypatch, c):
    from core import adult_guard
    older = OLDER.replace(b"(Mara Quillfeather)", b"(Mara, 15 years old)")
    assert older != OLDER
    both(monkeypatch, older=older)
    c.post("/api/recon/profile-archive", json={"url": "https://codeplace.example/"})        # sets the session cookie
    profile_record.bind(c.cookies.get("crawlr_run"))
    profile_record.note(HANDLE, "maigret", {"results": []})
    assert adult_guard.gate(HANDLE) is None
    out = c.post("/api/recon/archive-diff", json={"url": URL, "from": ISO1, "to": ISO2, "username": HANDLE}).json()
    assert "15 years old" in out["from"]["title"] and "15 years old" not in json.dumps([out["removed"], out["added"]])
    profile_record.bind(c.cookies.get("crawlr_run"))
    status, body = adult_guard.gate(HANDLE)
    assert status == 400 and body["code"] == "minor_guard" and body["source"] == "Internet Archive"


def test_titles_are_recorded_when_nothing_differs_and_when_one_capture_is_missing(monkeypatch, c):
    same = b"<html><head><title>Mara, born 2012</title></head><body><p>hello</p></body></html>"
    both(monkeypatch, older=same, newer=same)
    out = c.post("/api/recon/archive-diff", json={"url": URL, "from": ISO1, "to": ISO2, "username": HANDLE}).json()
    assert out["state"] == "same" and out["from"]["title"] == "Mara, born 2012"
    assert [t["bio"] for t in _record(c)] == ["Mara, born 2012"]

    profile_record.clear()
    ad.clear_cache_for_tests()
    captures(monkeypatch, {T1: (200, same, {"content-type": "text/html"})})
    out = c.post("/api/recon/archive-diff", json={"url": URL, "from": ISO1, "to": ISO2, "username": HANDLE}).json()
    assert out["state"] == "none" and out["missing"] == ["to"] and out["from"]["title"] == "Mara, born 2012"
    assert [t["bio"] for t in _record(c)] == ["Mara, born 2012"]


def test_guard_texts_alone():
    side = lambda text: {"text": text, "text_total": len(text), "links": [], "links_total": 0}      # noqa: E731
    base = {"state": "ok", "from": {"title": "One", "url": "u"}, "to": {"title": "One", "url": "v"}, "removed": side(["a", "b"]), "added": side(["c"])}
    assert ad.guard_texts(base) == ["One\na\nb\nc"]                                        # a title both copies share is read once
    assert ad.guard_texts({**base, "from": {"title": ""}, "to": {"title": "Two"}}) == ["Two\na\nb\nc"]
    long = {**base, "removed": side(["x" * 300] * 20)}
    chunks = ad.guard_texts(long)
    assert len(chunks) > 1 and all(len(chunk) <= 2000 for chunk in chunks) and "\n".join(chunks).split("\n") == ["One", *["x" * 300] * 20, "c"]
    for nothing in (None, "x", {}, {"state": "refused", "from": None, "to": None, "removed": side([]), "added": side([])},
                    {"state": "failed", "from": {"title": ""}, "to": {"title": ""}, "removed": side([]), "added": side([])}):
        assert ad.guard_texts(nothing) == []


# ---- commit emails: a repository GitLab would not show is not an empty one -------------------------

def test_a_gitlab_repository_that_answers_not_found_is_unknown_and_the_answer_is_partial(monkeypatch):
    from tests import test_commit_emails as helpers
    helpers.world(monkeypatch, helpers.gitlab_pages())
    out = asyncio.run(ce.run_commit_emails("gitlab", helpers.H))
    assert [r["state"] for r in out["repos"]] == ["ok", "ok", "unknown"] and out["complete"] is False
    assert out["emails_state"] == "found" and 0 < helpers.ttl("gitlab") <= ce.CACHE_TTL_PARTIAL
    # nothing read and one repository unreadable: unknown, never none, and not kept for the day
    ce.clear_cache_for_tests()
    pages = helpers.gitlab_pages()
    pages["gitlab.com/api/v4/users/1000001/projects"] = helpers.j(200, json.dumps([p for p in json.loads(helpers.fx("gitlab_projects.json")) if p.get("id") == 3000005]))
    helpers.world(monkeypatch, pages)
    out = asyncio.run(ce.run_commit_emails("gitlab", helpers.H))
    assert [r["state"] for r in out["repos"]] == ["unknown"] and out["emails"] == []
    assert out["emails_state"] == "unknown" and out["complete"] is False and 0 < helpers.ttl("gitlab") <= ce.CACHE_TTL_PARTIAL


def test_no_em_dash_in_the_new_modules_or_this_file():
    for path in (charset.__file__, inflight.__file__, pinned.__file__, __file__):
        assert chr(0x2014) not in Path(path).read_text(encoding="utf-8")
