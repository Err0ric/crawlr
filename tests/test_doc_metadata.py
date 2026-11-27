"""Public document metadata. The files are built in tests/docfiles.py, the archive's list
comes from tests/fixtures/doc_metadata, and both are served by a mock transport: no network
and no DNS. Every person, company, title and host is invented."""

import asyncio
import io
import json
import struct
import zipfile
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from fastapi.testclient import TestClient

from core import adult_sites
from core import netguard as ng
from core.netguard import BlockedTarget
from main import app
import middleware.rate_limit as rl
from middleware.rate_limit import match_limit
from modules import doc_metadata as dm
from modules import doc_parse as dp
from tests import docfiles as df

FIXTURES = Path(__file__).parent / "fixtures" / "doc_metadata"
CDX_OK = (FIXTURES / "cdx_ok.json").read_text(encoding="utf-8")
CDX_NONE = (FIXTURES / "cdx_none.json").read_text(encoding="utf-8")
DOMAIN = "larkspur-tide.example"
PUBLIC_IP = "93.184.216.34"
ARCHIVE = "web.archive.org"
EMPTY = {k: "" for k in dp.FIELDS}


@pytest.fixture(autouse=True)
def _clean():
    dm.clear_cache_for_tests()
    yield
    dm.clear_cache_for_tests()


@pytest.fixture(scope="module")
def c():
    with TestClient(app) as client:
        yield client


def cdx(*urls: str) -> str:
    rows = [[u, f"2024010100{n:04d}", f"2026010100{n:04d}", "application/pdf", "100"] for n, u in enumerate(urls)]
    return json.dumps([["original", "timestamp", "endtimestamp", "mimetype", "length"], *rows])


def file(body: bytes, status: int = 200, **headers) -> httpx.Response:
    return httpx.Response(status, content=body, headers={"content-type": "application/octet-stream", **headers})


def serve(monkeypatch, listing, files: dict | None = None, calls: list | None = None, private: tuple = ()):
    """listing: (status, text) | Exception for the archive. files: path -> httpx.Response |
    bytes | Exception | callable(request) on any other host; a path not listed is a 404."""
    async def resolve(host, port=443):
        if host in private:
            raise BlockedTarget("not public")
        return [PUBLIC_IP]

    def handler(request: httpx.Request) -> httpx.Response:
        if calls is not None:
            calls.append(request)
        if request.headers["host"] == ARCHIVE:
            if isinstance(listing, Exception):
                raise listing
            return httpx.Response(listing[0], text=listing[1], headers={"content-type": "application/json"})
        hit = (files or {}).get(request.url.path)
        if hit is None:
            return httpx.Response(404, text="not here")
        if isinstance(hit, Exception):
            raise hit
        if callable(hit):
            return hit(request)
        return file(hit) if isinstance(hit, bytes) else hit

    monkeypatch.setattr(ng, "resolve_public", resolve)
    monkeypatch.setattr(dm, "_inner_transport", lambda: httpx.MockTransport(handler))


def run(domain: str = DOMAIN) -> dict:
    return asyncio.run(dm.run_doc_metadata(domain))


def one(monkeypatch, answer, **kw) -> dict:
    """The row for a single listed document served as `answer`."""
    serve(monkeypatch, (200, cdx(f"https://{DOMAIN}/a.pdf")), {"/a.pdf": answer}, **kw)
    out = run()
    assert len(out["documents"]) == 1
    return out


# --------------------------------------------------------------------------------------
# Parsing: Office
# --------------------------------------------------------------------------------------
def test_docx_core_and_app_properties():
    out = dp.parse_document(df.office("docx"), "docx")
    assert out == {"type": "docx", "parsed": True, "reason": "", "sources": ["core", "app"], "fields": {
        "title": "Spring price list", "author": "Odalys Brandtmoor", "last_modified_by": "Teodor Vashenko",
        "creator_software": "Microsoft Office Word 16.0000", "producer": "", "company": "Larkspur Tide Supply Ltd",
        "created": "2024-03-04T09:15:00Z", "modified": "2025-11-20T16:42:10Z"}}


@pytest.mark.parametrize("kind", ["docx", "xlsx", "pptx"])
def test_the_type_comes_from_the_archive_not_the_address(kind):
    assert dp.parse_document(df.office(kind), "pdf")["type"] == kind


def test_an_office_file_with_no_properties_is_read_and_empty():
    out = dp.parse_document(df.office("xlsx", core=None, app=None))
    assert out["parsed"] is True and out["reason"] == "" and out["fields"] == EMPTY and out["sources"] == []


def test_a_zip_bomb_in_the_metadata_is_not_unpacked():
    bomb = df.office(core=b"<a>" + b" " * 30_000_000 + b"</a>")
    assert len(bomb) < 100_000
    out = dp.parse_document(bomb)
    assert out["parsed"] is False and out["reason"] == "zip_bomb" and out["fields"] == EMPTY


def test_a_zip_bomb_that_lies_about_its_size_is_not_unpacked():
    size = 30_000_003
    bomb = df.office(core=b"<a>" + b" " * (size - 7) + b"</a>")
    lie = bomb.replace(struct.pack("<L", size), struct.pack("<L", 900))
    assert lie != bomb and zipfile.ZipFile(io.BytesIO(lie)).getinfo("docProps/core.xml").file_size == 900
    out = dp.parse_document(lie)
    assert out["parsed"] is False and out["reason"] in ("zip_bomb", "bad_zip", "bad_xml")


BILLION_LAUGHS = (b'<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">'
                  b'<!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">]>'
                  b'<cp:coreProperties ' + df.CORE_NS.encode() + b'><dc:creator>&lol3;</dc:creator></cp:coreProperties>')
EXTERNAL = (b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
            b'<cp:coreProperties ' + df.CORE_NS.encode() + b'><dc:creator>&xxe;</dc:creator></cp:coreProperties>')
HIDDEN_DOCTYPE = ('<?xml version="1.0" encoding="cp037"?>'.encode("ascii")
                  + '<!DOCTYPE x [<!ENTITY a "aaaa">]><x>&a;</x>'.encode("cp037"))


@pytest.mark.parametrize("core, reason", [
    (BILLION_LAUGHS, "xml_entities"),
    (EXTERNAL, "xml_entities"),
    (HIDDEN_DOCTYPE, "bad_xml"),                              # the declared encoding is not honoured
    (df.core_xml().decode().encode("utf-16"), "bad_xml"),
    (b"<cp:coreProperties><unclosed>", "bad_xml"),
    (b"\x00\x01\x02 not xml", "bad_xml"),
])
def test_hostile_xml_is_refused(core, reason):
    for member in ("core", "app"):
        out = dp.parse_document(df.office(**{member: core}))
        assert out["parsed"] is False and out["reason"] == reason and out["fields"] == EMPTY


def test_an_entity_is_never_expanded_or_resolved():
    out = dp.parse_document(df.office(core=EXTERNAL))
    assert "root" not in json.dumps(out) and "lol" not in json.dumps(dp.parse_document(df.office(core=BILLION_LAUGHS)))


@pytest.mark.parametrize("data, reason", [
    (b"PK\x03\x04 this is not an archive", "bad_zip"),
    (df.office()[:200], "bad_zip"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 600, "legacy_office"),
    (b"GIF89a" + b"\x00" * 100, "unknown_format"),
    (b"", "unknown_format"),
])
def test_files_that_are_not_readable_documents(data, reason):
    out = dp.parse_document(data, "docx")
    assert out["parsed"] is False and out["reason"] == reason


def test_a_zip_that_is_not_an_office_file():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("readme.txt", "hello")
    assert dp.parse_document(buf.getvalue())["reason"] == "unknown_format"


def test_text_is_one_capped_line():
    out = dp.parse_document(df.office(core=df.core_xml(author="Odalys\n\tBrandtmoor\u202e  " + "x" * 900)))
    assert out["fields"]["author"].startswith("Odalys Brandtmoor") and len(out["fields"]["author"]) <= dp.TEXT_MAX
    assert "\n" not in out["fields"]["author"] and "\u202e" not in out["fields"]["author"]


# --------------------------------------------------------------------------------------
# Parsing: PDF
# --------------------------------------------------------------------------------------
def test_pdf_info_dictionary():
    out = dp.parse_document(df.pdf())
    assert out == {"type": "pdf", "parsed": True, "reason": "", "sources": ["info"], "fields": {
        "title": "Annual report (2021)", "author": "Odalys Brandtmoor", "last_modified_by": "",
        "creator_software": "Quillwriter 7.2", "producer": "Tidewater PDF Library 3.1", "company": "Larkspur Tide Supply Ltd",
        "created": "2021-02-27T10:00:00+01:00", "modified": "2021-03-01T08:30:00Z"}}


def test_pdf_string_forms():
    utf16 = b"\xfe\xff" + "Ødalys Brándtmoor".encode("utf-16-be")
    info = (b"<</Title<" + utf16.hex().encode() + b">/Author 7 0 R/Producer(Tide\\053water \\\r\nPDF)/Creator(a\\tb (nested (deep)) c)"
            b"/Keywords[(x) <</Author (decoy)>>]/Extra<</Author (decoy two)>>% a comment /Author (decoy three)\n/ModDate(D:2021)>>")
    out = dp.parse_document(df.pdf(info, extra_objects=(b"<< /Nothing 1 >>", b"(Teodor Vashenko)")))
    f = out["fields"]
    assert f["title"] == "Ødalys Brándtmoor" and f["author"] == "Teodor Vashenko" and f["producer"] == "Tide+water PDF"
    assert f["creator_software"] == "a b (nested (deep)) c" and f["modified"] == "2021" and "decoy" not in json.dumps(out)


def test_an_edited_pdf_uses_the_last_info_object():
    first = df.pdf()
    update = (b"4 0 obj\n<< /Author (Teodor Vashenko) /Producer (Second Pass 2.0) >>\nendobj\n"
              b"trailer\n<< /Size 5 /Root 1 0 R /Info 4 0 R /Prev 10 >>\nstartxref\n0\n%%EOF\n")
    out = dp.parse_document(first + update)
    assert out["fields"]["author"] == "Teodor Vashenko" and out["fields"]["title"] == ""


def test_pdf_xmp_packet_named_by_the_catalog():
    out = dp.parse_document(df.pdf(None, xmp=df.xmp_packet(creators=("Odalys Brandtmoor", "Teodor Vashenko"))))
    assert out["parsed"] is True and out["sources"] == ["xmp"]
    assert out["fields"] == {**EMPTY, "title": "Annual report 2021", "author": "Odalys Brandtmoor; Teodor Vashenko",
                             "creator_software": "Quillwriter 7.2", "producer": "Tidewater PDF Library 3.1",
                             "created": "2021-02-27T10:00:00+01:00", "modified": "2021-03-01T08:30:00Z"}


def test_info_wins_and_xmp_fills_the_gaps():
    out = dp.parse_document(df.pdf(b"<< /Author (Teodor Vashenko) >>", xmp=df.xmp_packet()))
    assert out["sources"] == ["info", "xmp"] and out["fields"]["author"] == "Teodor Vashenko"
    assert out["fields"]["title"] == "Annual report 2021"


def test_an_embedded_pictures_xmp_is_not_the_documents():
    picture = df.xmp_packet(title="IMG_4410", creators=("Camera Owner",), tool="Photo Studio", pdf_schema=False)
    stream = b"<< /Type /Metadata /Subtype /XML /Length %d >>\nstream\n" % len(picture) + picture + b"\nendstream"
    # the catalog names object 5; the picture's packet sits in object 6
    both = dp.parse_document(df.pdf(None, xmp=df.xmp_packet(), extra_objects=(stream,)))
    assert both["fields"]["title"] == "Annual report 2021" and "Camera Owner" not in json.dumps(both)
    # the catalog names no metadata at all: the picture's packet is left alone
    alone = dp.parse_document(df.pdf(None, extra_objects=(stream,)))
    assert alone["parsed"] is True and alone["fields"] == EMPTY


def test_hostile_xmp_is_dropped_and_the_info_dictionary_still_counts():
    inside = df.xmp_packet().replace(b"<rdf:RDF", b'<!DOCTYPE x [<!ENTITY a "aaaa">]><rdf:RDF').replace(b"Annual report 2021", b"&a;")
    broken = df.xmp_packet().replace(b"</rdf:RDF>", b"")
    for xmp in (inside, broken):
        out = dp.parse_document(df.pdf(b"<< /Author (Teodor Vashenko) >>", xmp=xmp))
        assert out["sources"] == ["info"] and out["fields"]["title"] == "" and "aaaa" not in json.dumps(out)
    # a declaration in front of the packet is outside it: only the packet itself is parsed
    before = df.xmp_packet().replace(b"<x:xmpmeta", b'<!DOCTYPE x [<!ENTITY a "aaaa">]><x:xmpmeta')
    assert dp.parse_document(df.pdf(None, xmp=before))["fields"]["title"] == "Annual report 2021"


def test_a_pdf_that_declares_nothing_is_read_and_empty():
    for data in (df.pdf(None), df.pdf(b"<< >>"), df.pdf(b"<< /Trapped /False >>")):
        out = dp.parse_document(data)
        assert out["parsed"] is True and out["reason"] == "" and out["fields"] == EMPTY


def test_an_info_dictionary_inside_an_object_stream_is_read():
    out = dp.parse_document(df.pdf(info_in_file=False, extra_objects=(df.object_stream(),)))
    assert out["parsed"] is True and out["sources"] == ["info"] and out["fields"]["author"] == "Odalys Brandtmoor"
    assert out["fields"]["created"] == "2021-02-27T10:00:00+01:00"
    # the last object stream that lists the object wins, as with objects in the file itself
    later = df.object_stream(b"<< /Author (Teodor Vashenko) >>")
    out = dp.parse_document(df.pdf(info_in_file=False, extra_objects=(df.object_stream(), later)))
    assert out["fields"]["author"] == "Teodor Vashenko"
    # a stream that holds other objects only is not the answer
    other = df.pdf(info_in_file=False, extra_objects=(df.object_stream(b"<< /Author (decoy) >>", number=9),))
    assert dp.parse_document(other)["reason"] == "compressed"


def test_an_object_stream_bomb_is_not_unpacked(monkeypatch):
    bomb = df.object_stream(df.INFO + b" " * 30_000_000)
    assert len(bomb) < 100_000
    out = dp.parse_document(df.pdf(info_in_file=False, extra_objects=(bomb,)))
    assert out["parsed"] is False and out["reason"] == "compressed"
    # many streams: the file's budget runs out before the last one, which holds the object
    monkeypatch.setattr(dp, "INFLATE_BUDGET", 3000)
    filler = df.object_stream(b"<< /X (" + b"y" * 2000 + b") >>", number=9)
    out = dp.parse_document(df.pdf(info_in_file=False, extra_objects=(filler, filler, df.object_stream())))
    assert out["parsed"] is False and out["reason"] == "compressed"


@pytest.mark.parametrize("stream", [
    df.object_stream(parms=df.PREDICTOR),
    df.object_stream(filter_name=b"/LZWDecode"),
    df.object_stream(filter_name=b"[/ASCIIHexDecode /FlateDecode]"),
    df.object_stream().replace(b"/First 4", b"/First 400000"),
    df.object_stream().replace(b"/N 1", b"/N 99999999"),
    df.object_stream()[:-40] + b"\x00" * 29 + b"\nendstream",
    df.object_stream(b"(not a dictionary)"),
])
def test_metadata_in_a_compressed_part_that_is_not_unpacked_is_not_guessed(stream):
    out = dp.parse_document(df.pdf(info_in_file=False, extra_objects=(stream,)))
    assert out["parsed"] is False and out["reason"] in ("compressed", "bad_pdf") and out["fields"] == EMPTY


def test_other_compressed_metadata_is_not_guessed():
    # no /Info reference at all, and the catalog itself is inside the object stream
    hidden = df.pdf(None, extra_objects=(df.object_stream(),)).replace(b"/Type /Catalog", b"/Type /Hidden ")
    assert dp.parse_document(hidden)["reason"] == "compressed"
    # the catalog names an XMP stream that is not in the file as text
    packed = df.pdf(None, xmp=df.xmp_packet()).replace(b"<x:xmpmeta", b"<x:zzzmeta")
    assert dp.parse_document(packed)["reason"] == "compressed"


def test_an_encrypted_pdf_is_not_read():
    for extra in (b" /Encrypt 9 0 R", b" /Encrypt << /Filter /Standard >>"):
        out = dp.parse_document(df.pdf(trailer_extra=extra))
        assert out["parsed"] is False and out["reason"] == "encrypted" and out["fields"] == EMPTY


def test_a_truncated_pdf_is_not_read():
    whole = df.pdf()
    for cut in (whole.index(b"4 0 obj"), whole.index(b"/Author") + 12, 30):
        out = dp.parse_document(whole[:cut])
        assert out["parsed"] is False and out["reason"] in ("truncated", "bad_pdf") and out["fields"] == EMPTY
    assert dp.parse_document(whole[: whole.index(b"4 0 obj")])["reason"] == "truncated"


@pytest.mark.parametrize("info", [
    b"<< /Author (never closed", b"<< /Author <zz> >>", b"<< /Author (" + b"a" * 5000 + b") >>",
    b"<< " + b"/K [" * 40 + b"]" * 40 + b" >>", b"<< /Author", b"(a string, not a dictionary)", b"<< (no name) (x) >>",
    b"<< /A " + b"<< " * 30 + b">> " * 30 + b"/Author (deep) >>",
])
def test_a_damaged_info_dictionary_never_raises(info):
    out = dp.parse_document(df.pdf(info))
    assert out["type"] == "pdf" and (out["parsed"] is False or out["fields"]["author"] in ("", "deep"))


def test_random_bytes_after_a_pdf_header_never_raise():
    import random
    rnd = random.Random(7)
    for _ in range(40):
        junk = bytes(rnd.choice(b"<>()[]/\\% \n0123456789RobjInfoendstream") for _ in range(rnd.randrange(10, 3000)))
        out = dp.parse_document(b"%PDF-1.4\n" + junk + b"\ntrailer << /Info 1 0 R >>\n1 0 obj\n" + junk + b"\n%%EOF")
        assert out["type"] == "pdf" and isinstance(out["parsed"], bool)


@pytest.mark.parametrize("filler", [
    b"<x:xmpmeta ", b"<x:xmpmeta></x:xmpmeta>", b"/Type /Catalog ", b"1 0 obj << /Type /Catalog /Metadata 5 0 R >> ",
    b"7 0 obj << /Type /ObjStm /N 1 /First 4 /Filter /FlateDecode /Length 9 >> stream\nxxxxxxxxx endstream ",
    b"/Info 4 0 R ", b"4 0 obj ", b"4 0 obj << /Author (", b"((((((((", b"<< << << << ", b"\\(\\(\\(",
])
def test_a_file_stuffed_with_markers_is_read_in_bounded_time(filler):
    import time
    body = b"%PDF-1.7\n" + filler * (6_000_000 // len(filler)) + b"\ntrailer << /Root 1 0 R /Info 4 0 R >>\n%%EOF\n"
    began = time.monotonic()
    out = dp.parse_document(body)
    assert time.monotonic() - began < 10 and out["type"] == "pdf" and out["fields"] == EMPTY


@pytest.mark.parametrize("raw, iso", [
    ("D:20210227100000+01'00'", "2021-02-27T10:00:00+01:00"), ("D:20210227100000Z", "2021-02-27T10:00:00Z"),
    ("D:20210227100000-08'00", "2021-02-27T10:00:00-08:00"), ("20210227", "2021-02-27"), ("D:202102", "2021-02"),
    ("D:2021", "2021"), ("D:20210227100000", "2021-02-27T10:00:00"), ("D:20211399", ""), ("yesterday", ""), ("", ""),
])
def test_pdf_dates(raw, iso):
    assert dp.pdf_date(raw) == iso


@pytest.mark.parametrize("raw, iso", [
    ("2024-03-04T09:15:00Z", "2024-03-04T09:15:00Z"), ("2024-03-04T09:15:00.123+02:00", "2024-03-04T09:15:00+02:00"),
    ("2024-03-04", "2024-03-04"), ("2024", "2024"), ("2024-13-04", ""), ("04/03/2024", ""), ("<script>", ""),
])
def test_iso_dates(raw, iso):
    assert dp.iso_date(raw) == iso


# --------------------------------------------------------------------------------------
# The archive's list
# --------------------------------------------------------------------------------------
def test_candidates_are_on_the_domain_newest_first_and_https():
    rows, listed, large = dm.pick_candidates(json.loads(CDX_OK), DOMAIN)
    assert listed == 5 and large == 0
    assert rows == [
        {"url": f"https://www.{DOMAIN}/press/Launch.DOCX", "type": "docx", "last_archived": "2026-03-01T00:00:00Z"},
        {"url": f"https://www.{DOMAIN}/files/price-list.xlsx", "type": "xlsx", "last_archived": "2026-01-15T07:00:00Z"},
        {"url": f"https://{DOMAIN}/files/annual-report-2021.pdf", "type": "pdf", "last_archived": "2025-10-02T12:00:00Z"},
        {"url": f"https://files.{DOMAIN}/deck.pptx", "type": "pptx", "last_archived": "2024-02-02T00:00:00Z"},
        {"url": f"https://www.{DOMAIN}/old/brochure.pdf", "type": "pdf", "last_archived": "2015-01-01T00:00:00Z"},
    ]


def test_candidates_are_capped_and_other_shapes_are_refused():
    urls = [f"https://{DOMAIN}/d/{n}.pdf" for n in range(30)]
    rows, listed, _large = dm.pick_candidates(json.loads(cdx(*urls)), DOMAIN)
    assert len(rows) == dm.MAX_DOCS == 8 and listed == 30 and rows[0]["url"].endswith("/29.pdf")
    assert dm.pick_candidates([], DOMAIN) == ([], 0, 0)
    for bad in ({"a": 1}, "text", None, [["timestamp"], ["x"]], ["original"]):
        assert dm.pick_candidates(bad, DOMAIN) is None


def test_documents_the_archive_stored_as_over_the_cap_go_last():
    data = json.loads(cdx(*[f"https://{DOMAIN}/d/{n}.pdf" for n in range(10)]))
    for row in data[6:]:                                  # the five newest are huge
        row[4] = str(dm.MAX_DOC_BYTES + 1)
    data[3][4] = "not a number"
    rows, listed, large = dm.pick_candidates(data, DOMAIN)
    assert listed == 10 and large == 5
    assert [r["url"].rsplit("/", 1)[1] for r in rows] == ["4.pdf", "3.pdf", "2.pdf", "1.pdf", "0.pdf", "9.pdf", "8.pdf", "7.pdf"]
    assert set(rows[0]) == {"url", "type", "last_archived"}


@pytest.mark.parametrize("host, ok", [
    (DOMAIN, True), (f"www.{DOMAIN}", True), (f"www2.{DOMAIN}", True), (f"files.{DOMAIN}", True),
    (f"{DOMAIN}.evil.example", False), (f"not{DOMAIN}", False), ("example", False), ("", False),
])
def test_on_target(host, ok):
    assert dm.on_target(host, DOMAIN) is ok and dm.on_target(host, f"www.{DOMAIN}") is ok


# --------------------------------------------------------------------------------------
# A whole run
# --------------------------------------------------------------------------------------
FILES = {
    "/press/Launch.DOCX": df.office("docx"),
    "/files/price-list.xlsx": df.office("xlsx", core=df.core_xml(author="teodor vashenko", modified_by="Odalys Brandtmoor"),
                                        app=df.app_xml("Microsoft Excel", "16.0300")),
    "/files/annual-report-2021.pdf": df.pdf(),
    "/deck.pptx": df.office("pptx", core=None, app=None),
    "/old/brochure.pdf": df.pdf(info_in_file=False, extra_objects=(df.object_stream(parms=df.PREDICTOR),)),
}


def test_ok_run_one_list_request_then_only_the_listed_documents(monkeypatch):
    calls = []
    serve(monkeypatch, (200, CDX_OK), FILES, calls)
    out = run()
    assert out["state"] == "ok" and out["requests_target"] is True and out["cached"] is False
    assert out["listed"] == 5 and out["listed_too_large"] == 0 and out["listing_truncated"] is False
    assert out["note"] == "" and "error" not in out
    assert [d["state"] for d in out["documents"]] == ["ok", "ok", "ok", "none", "unparsed"]
    assert out["counts"] == {"ok": 3, "none": 1, "unparsed": 1}

    archive = [r for r in calls if r.headers["host"] == ARCHIVE]
    assert len(archive) == 1 and archive[0].url.path == "/cdx/search/cdx" and archive[0].url.scheme == "https"
    assert parse_qs(urlsplit(str(archive[0].url)).query) == {
        "url": [f"{DOMAIN}/*"], "output": ["json"], "fl": ["original,timestamp,endtimestamp,mimetype,length"],
        "filter": ["statuscode:200", r"original:(?i).*\.(pdf|docx|xlsx|pptx)$"], "collapse": ["urlkey"],
        "showSkipCount": ["true"], "lastSkipTimestamp": ["true"], "limit": ["1500"],
    }
    site = [r for r in calls if r.headers["host"] != ARCHIVE]
    assert sorted((r.headers["host"], r.url.path) for r in site) == sorted([
        (f"www.{DOMAIN}", "/press/Launch.DOCX"), (f"www.{DOMAIN}", "/files/price-list.xlsx"),
        (DOMAIN, "/files/annual-report-2021.pdf"), (f"files.{DOMAIN}", "/deck.pptx"), (f"www.{DOMAIN}", "/old/brochure.pdf"),
    ])
    assert all(r.method == "GET" and r.url.scheme == "https" and r.url.host == PUBLIC_IP for r in site)


def test_document_rows(monkeypatch):
    serve(monkeypatch, (200, CDX_OK), FILES)
    docs = run()["documents"]
    assert docs[0] == {
        "url": f"https://www.{DOMAIN}/press/Launch.DOCX", "type": "docx", "state": "ok", "size": len(FILES["/press/Launch.DOCX"]),
        "last_archived": "2026-03-01T00:00:00Z", "parsed": True, "reason": "", "reason_text": "", "sources": ["core", "app"],
        "title": "Spring price list", "author": "Odalys Brandtmoor", "last_modified_by": "Teodor Vashenko",
        "creator_software": "Microsoft Office Word 16.0000", "producer": "", "company": "Larkspur Tide Supply Ltd",
        "created": "2024-03-04T09:15:00Z", "modified": "2025-11-20T16:42:10Z",
    }
    assert docs[2]["type"] == "pdf" and docs[2]["sources"] == ["info"] and docs[2]["producer"] == "Tidewater PDF Library 3.1"
    assert docs[3]["state"] == "none" and docs[3]["parsed"] is True and docs[3]["author"] == ""
    assert docs[4]["state"] == "unparsed" and docs[4]["parsed"] is False and docs[4]["reason"] == "compressed"
    assert "compressed part" in docs[4]["reason_text"] and docs[4]["size"] > 0
    keys = set(docs[0])
    assert all(set(d) == keys for d in docs)


def test_summary_findings_and_guard(monkeypatch):
    serve(monkeypatch, (200, CDX_OK), FILES)
    out = run()
    s = out["summary"]
    assert s["authors"] == [
        {"name": "Odalys Brandtmoor", "roles": ["author", "last_modified_by"], "documents": 3, "self_declared": True},
        {"name": "Teodor Vashenko", "roles": ["last_modified_by", "author"], "documents": 2, "self_declared": True},
    ]
    assert {x["name"]: x["documents"] for x in s["software"]} == {
        "Microsoft Office Word 16.0000": 1, "Microsoft Excel 16.0300": 1, "Quillwriter 7.2": 1, "Tidewater PDF Library 3.1": 1}
    assert s["companies"] == [{"name": "Larkspur Tide Supply Ltd", "documents": 3, "self_declared": True}]
    assert "Nothing verifies it" in s["note"]
    assert {f["level"] for f in out["findings"]} == {"info"} and len(out["findings"]) == 3
    assert out["findings"][0]["title"] == "2 self-declared author names in 3 public documents"
    assert out["guard"] == {"text": "Odalys Brandtmoor\nTeodor Vashenko\nLarkspur Tide Supply Ltd\nSpring price list\nAnnual report (2021)"}


# --------------------------------------------------------------------------------------
# Document states
# --------------------------------------------------------------------------------------
def test_none_when_every_document_declares_nothing(monkeypatch):
    out = one(monkeypatch, df.pdf(None))
    assert out["state"] == "none" and out["documents"][0]["state"] == "none" and out["summary"]["authors"] == []
    assert out["guard"] == {} and out["findings"] == [] and out["summary"]["note"] == ""


@pytest.mark.parametrize("status", [401, 403, 451])
def test_blocked(monkeypatch, status):
    out = one(monkeypatch, file(b"denied", status))
    assert out["state"] == "blocked" and out["documents"][0]["state"] == "blocked" and out["documents"][0]["error_code"] == "blocked"
    assert out["counts"] == {"blocked": 1}


def test_a_challenge_is_blocked(monkeypatch):
    assert one(monkeypatch, file(df.pdf(), 200, **{"cf-mitigated": "challenge"}))["state"] == "blocked"


def test_rate_limited_and_the_rest_are_not_asked(monkeypatch):
    calls = []
    urls = [f"https://{DOMAIN}/d/{n}.pdf" for n in range(8)]
    serve(monkeypatch, (200, cdx(*urls)), {f"/d/{n}.pdf": file(b"slow down", 429) for n in range(8)}, calls)
    out = run()
    assert out["state"] == "rate_limited" and out["counts"] == {"rate_limited": 8}
    assert all(d["error_code"] == "rate_limited" for d in out["documents"])
    assert len([r for r in calls if r.headers["host"] != ARCHIVE]) <= dm.CONCURRENCY


@pytest.mark.parametrize("answer, code", [
    (None, "not_found"),
    (file(b"gone", 410), "not_found"),
    (file(b"oops", 500), "upstream"),
    (httpx.ReadTimeout("t"), "timeout"),
    (httpx.ConnectError("refused"), "unreachable"),
    (b"<!doctype html><html><body>Page not found</body></html>", "not_document"),
    (httpx.Response(200, stream=httpx.ByteStream(b"xx"), headers={"content-encoding": "br"}), "bad_response"),
])
def test_failed(monkeypatch, answer, code):
    serve(monkeypatch, (200, cdx(f"https://{DOMAIN}/a.pdf")), {"/a.pdf": answer} if answer is not None else {})
    out = run()
    doc = out["documents"][0]
    assert out["state"] == "failed" and doc["state"] == "failed" and doc["error_code"] == code and doc["error"]
    assert DOMAIN not in doc["error_detail"] and doc["author"] == ""


def test_a_document_that_takes_too_long_is_failed(monkeypatch):
    async def slow(*a, **k):
        await asyncio.sleep(5)
    monkeypatch.setattr(dm, "DOC_DEADLINE", 0.05)
    monkeypatch.setattr(dm, "_fetch", slow)
    out = one(monkeypatch, df.pdf())
    assert out["documents"][0]["state"] == "failed" and out["documents"][0]["error_code"] == "timeout"


def test_too_large_by_its_declared_length_is_refused_before_the_body(monkeypatch):
    out = one(monkeypatch, httpx.Response(200, stream=httpx.ByteStream(b"%PDF-1.4"), headers={"content-length": str(dm.MAX_DOC_BYTES + 1)}))
    doc = out["documents"][0]
    assert out["state"] == "too_large" and doc["state"] == "too_large" and doc["size"] == dm.MAX_DOC_BYTES + 1
    assert doc["error_code"] == "too_large" and doc["parsed"] is False


class Endless(httpx.AsyncByteStream):
    """A body with no declared length that never stops by itself."""
    sent = 0

    async def __aiter__(self):
        yield b"%PDF-1.4\n"
        while True:
            Endless.sent += 65536
            assert Endless.sent < dm.MAX_DOC_BYTES * 2, "the download was not stopped at the cap"
            yield b"\x00" * 65536


def test_too_large_without_a_declared_length_is_stopped_at_the_cap(monkeypatch):
    Endless.sent = 0
    out = one(monkeypatch, lambda r: httpx.Response(200, stream=Endless()))
    doc = out["documents"][0]
    assert doc["state"] == "too_large" and doc["size"] is None and dm.MAX_DOC_BYTES <= Endless.sent < dm.MAX_DOC_BYTES * 2


@pytest.mark.parametrize("body, reason", [
    (df.pdf(info_in_file=False, extra_objects=(df.object_stream(parms=df.PREDICTOR),)), "compressed"),
    (df.pdf(trailer_extra=b" /Encrypt 9 0 R"), "encrypted"),
    (df.pdf()[:260], "truncated"),
    (df.office(core=BILLION_LAUGHS), "xml_entities"),
    (df.office(core=b"<a>" + b" " * 5_000_000 + b"</a>"), "zip_bomb"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 600, "legacy_office"),
    (b"\x89PNG\r\n\x1a\n" + b"\x00" * 64, "unknown_format"),
])
def test_unparsed(monkeypatch, body, reason):
    out = one(monkeypatch, body)
    doc = out["documents"][0]
    assert out["state"] == "unparsed" and doc["state"] == "unparsed" and doc["parsed"] is False
    assert doc["reason"] == reason and doc["reason_text"] == dp.REASONS[reason] and doc["size"] == len(body)
    assert all(doc[k] == "" for k in dp.FIELDS)


# --------------------------------------------------------------------------------------
# Redirects and the guard
# --------------------------------------------------------------------------------------
def test_a_redirect_inside_the_domain_is_followed_and_checked_again(monkeypatch):
    calls, asked = [], []
    serve(monkeypatch, (200, cdx(f"https://{DOMAIN}/a.pdf")),
          {"/a.pdf": httpx.Response(302, headers={"location": f"https://files.{DOMAIN}/store/a.pdf"}), "/store/a.pdf": df.pdf()}, calls)
    real = ng.resolve_public

    async def resolve(host, port=443):
        asked.append(host)
        return await real(host, port)
    monkeypatch.setattr(ng, "resolve_public", resolve)
    out = run()
    assert out["documents"][0]["state"] == "ok" and out["documents"][0]["url"] == f"https://{DOMAIN}/a.pdf"
    assert asked == [ARCHIVE, DOMAIN, f"files.{DOMAIN}"]


def test_a_redirect_to_another_site_is_not_followed(monkeypatch):
    calls = []
    serve(monkeypatch, (200, cdx(f"https://{DOMAIN}/a.pdf")),
          {"/a.pdf": httpx.Response(302, headers={"location": "https://cdn.quillmoor-hosting.example/a.pdf"})}, calls)
    out = run()
    doc = out["documents"][0]
    assert doc["state"] == "failed" and doc["error_code"] == "off_site" and "another site" in doc["error"]
    assert [r.headers["host"] for r in calls] == [ARCHIVE, DOMAIN]


def test_a_redirect_to_a_private_host_on_the_domain_is_refused(monkeypatch):
    calls = []
    serve(monkeypatch, (200, cdx(f"https://{DOMAIN}/a.pdf")),
          {"/a.pdf": httpx.Response(302, headers={"location": f"https://intranet.{DOMAIN}/a.pdf"})}, calls,
          private=(f"intranet.{DOMAIN}",))
    doc = run()["documents"][0]
    assert doc["state"] == "failed" and doc["error_code"] == "blocked_target"
    assert [r.headers["host"] for r in calls] == [ARCHIVE, DOMAIN]


def test_endless_redirects_stop(monkeypatch):
    calls = []
    serve(monkeypatch, (200, cdx(f"https://{DOMAIN}/a.pdf")), {"/a.pdf": httpx.Response(302, headers={"location": "/a.pdf"})}, calls)
    doc = run()["documents"][0]
    assert doc["state"] == "failed" and len(calls) == 1 + dm.MAX_REDIRECTS + 1


def test_a_domain_that_resolves_to_a_private_address_gets_no_document_request(monkeypatch):
    calls = []
    serve(monkeypatch, (200, cdx(f"https://{DOMAIN}/a.pdf")), {"/a.pdf": df.pdf()}, calls, private=(DOMAIN,))
    doc = run()["documents"][0]
    assert doc["state"] == "failed" and doc["error_code"] == "blocked_target" and len(calls) == 1


# --------------------------------------------------------------------------------------
# Overall states
# --------------------------------------------------------------------------------------
def test_none_when_the_archive_lists_nothing(monkeypatch):
    calls = []
    serve(monkeypatch, (200, CDX_NONE), {}, calls)
    out = run()
    assert out["state"] == "none" and out["documents"] == [] and out["listed"] == 0 and "not proof" in out["note"]
    assert len(calls) == 1 and "error" not in out


def test_none_when_the_list_holds_only_other_hosts(monkeypatch):
    serve(monkeypatch, (200, cdx("https://other-site.example/a.pdf")))
    assert run()["state"] == "none"


@pytest.mark.parametrize("listing, state, code", [
    ((429, ""), "rate_limited", "rate_limited"),
    ((403, ""), "rate_limited", "rate_limited"),
    ((500, ""), "failed", "upstream"),
    ((400, ""), "failed", "upstream"),
    ((200, "<html>busy</html>"), "failed", "bad_response"),
    ((200, '{"error": "x"}'), "failed", "bad_response"),
    ((200, "[" * 100000), "failed", "bad_response"),
    ((200, "[[" + "1" * (dm.MAX_LIST_BYTES + 10) + "]]"), "failed", "bad_response"),
    (httpx.ReadTimeout("t"), "failed", "timeout"),
    (httpx.ConnectError("x"), "failed", "unreachable"),
])
def test_the_archive_failing_is_not_none(monkeypatch, listing, state, code):
    calls = []
    serve(monkeypatch, listing, FILES, calls)
    out = run()
    assert out["state"] == state and out["error_code"] == code and out["error"] and out["documents"] == []
    assert len(calls) == 1 and DOMAIN not in out["error_detail"]


def test_overall_state_rules():
    docs = lambda *states: [{"state": s} for s in states]
    assert dm.overall_state(docs("failed", "ok", "blocked")) == "ok"
    assert dm.overall_state(docs("none", "none")) == "none"
    assert dm.overall_state(docs("none", "unparsed")) == "unparsed"          # one unread file: not "none"
    assert dm.overall_state(docs("failed", "blocked", "blocked")) == "blocked"
    assert dm.overall_state(docs("too_large", "too_large", "failed")) == "too_large"
    assert dm.overall_state(docs("unparsed", "blocked")) == "blocked"        # a tie goes by the fixed order
    assert dm.overall_state(docs("too_large", "unparsed")) == "too_large"


def test_an_adult_or_dating_site_is_refused_before_any_request(monkeypatch):
    calls = []
    serve(monkeypatch, (200, CDX_OK), FILES, calls)
    host = sorted(adult_sites.HOSTS)[0]
    out = run(host)
    assert out["state"] == "refused" and out["reason"] == "adult_site" and out["requests_target"] is False
    assert out["documents"] == [] and calls == []


# --------------------------------------------------------------------------------------
# Cache, log, copy, endpoint
# --------------------------------------------------------------------------------------
def test_answers_are_cached_and_a_cached_answer_is_a_copy(monkeypatch):
    calls = []
    serve(monkeypatch, (200, CDX_OK), FILES, calls)
    first = run()
    first["documents"].clear()
    first["summary"]["authors"].clear()
    n = len(calls)
    second = run()
    assert second["cached"] is True and len(calls) == n and len(second["documents"]) == 5 and len(second["summary"]["authors"]) == 2


def test_a_failure_is_cached_only_briefly(monkeypatch):
    serve(monkeypatch, (500, ""))
    assert run()["state"] == "failed"
    monkeypatch.setattr(dm.time, "time", lambda: 10 ** 10)
    serve(monkeypatch, (200, CDX_NONE))
    assert run()["state"] == "none"


def test_nothing_about_the_target_is_logged(monkeypatch, caplog):
    serve(monkeypatch, (200, CDX_OK), FILES)
    with caplog.at_level("DEBUG"):
        run()
    text = " ".join(f"{r.getMessage()} {r.__dict__}" for r in caplog.records if r.name.startswith("modules.doc_"))
    assert "doc metadata" in text
    for secret in (DOMAIN, "Brandtmoor", "Vashenko", "Larkspur", "price-list"):
        assert secret not in text


def test_no_em_dashes_in_any_copy():
    text = " ".join([dm.NAMES_NOTE, dm.NO_LISTING_NOTE, dm.ADULT_NOTE, *dp.REASONS.values()])
    assert "—" not in text and "–" not in text


def test_endpoint_and_rate_limit(monkeypatch, c):
    serve(monkeypatch, (200, CDX_OK), FILES)
    assert rl.RATE_LIMITS["/api/recon/doc-metadata"] == (2, 60)
    r = c.post("/api/recon/doc-metadata", json={"domain": f"https://{DOMAIN}/about"})
    body = r.json()
    assert r.status_code == 200 and body["state"] == "ok" and body["domain"] == DOMAIN and body["requests_target"] is True
    assert match_limit("/api/recon/doc-metadata")[0] == "/api/recon/doc-metadata"


@pytest.mark.parametrize("bad", ["", "not a domain", "8.8.8.8", "a" * 400, "exa mple.com/*", "x.example/*?a=b"])
def test_endpoint_refuses_what_is_not_a_domain(monkeypatch, c, bad):
    calls = []
    monkeypatch.setitem(rl.RATE_LIMITS, "/api/recon/doc-metadata", (1000, 60))
    serve(monkeypatch, (200, CDX_OK), FILES, calls)
    r = c.post("/api/recon/doc-metadata", json={"domain": bad})
    if r.status_code == 200:                     # a path after a valid host is cut off by the validator
        assert r.json()["domain"] == "x.example"
    else:
        assert r.status_code in (400, 422) and calls == []
