"""
Read the metadata inside a PDF or an Office file. Pure: bytes in, a dict out, no network,
standard library only. The bytes come from a site an investigator typed, so they are hostile.

Office files (docx, xlsx, pptx) are zip archives. Two members hold the metadata:
`docProps/core.xml` (title, author, last modified by, dates) and `docProps/app.xml`
(application, version, company). Guards:

  * only those two members are ever read; nothing is extracted to disk;
  * a member that declares more than MAX_MEMBER bytes is refused, and the read itself stops
    at MAX_MEMBER whatever the header declared (a zip bomb lies in its header);
  * an archive with more than MAX_ENTRIES entries, or an encrypted member, is refused;
  * XML with a DOCTYPE or an ENTITY declaration is refused before it reaches the parser, so
    there is no entity to expand and no external entity to resolve. The parser is told the
    bytes are UTF-8, so a declared encoding cannot hide a DOCTYPE from that check.

PDFs are read by hand, and only what sits in the file uncompressed:

  * the Info dictionary: the last `/Info n g R` in a trailer or cross-reference stream
    dictionary (both are stored uncompressed), then the last `n g obj` it points at;
  * the XMP packet the catalog's /Metadata entry points at. When the catalog itself is
    compressed, a single packet is accepted only if it uses the PDF schema, which image
    metadata never does; otherwise it is left alone (it may describe an embedded picture).

When the Info dictionary is not in the file as text, PDF 1.5 object streams are inflated to
look for it: plain FlateDecode streams only (no predictor, no other filter), at most
MAX_INFLATE bytes each and INFLATE_BUDGET bytes per file, and nothing else is ever inflated.
When the metadata still cannot be reached (another filter, a compressed XMP stream, an
encrypted or cut-short file) the answer is `parsed: false` with a `reason`, never a guess.

Every text value is self-declared: it is whatever the author's software wrote, or whatever
somebody typed over it. Nothing here verifies it.

Answer: {type, parsed, reason, sources, fields}
  type     "pdf" | "docx" | "xlsx" | "pptx" | ""
  parsed   True when the file's metadata could be read (even if it turned out empty)
  reason   "" or one of REASONS
  sources  where the fields came from: "info", "xmp", "core", "app"
  fields   {title, author, last_modified_by, creator_software, producer, company, created,
            modified}: strings, "" when absent. Dates are ISO 8601 or "".
"""

import io
import re
import xml.etree.ElementTree as ET
import zipfile
import zlib

FIELDS = ("title", "author", "last_modified_by", "creator_software", "producer", "company", "created", "modified")
REASONS = {
    "not_pdf": "The file does not start like a PDF.",
    "encrypted": "The file is encrypted, so its metadata cannot be read.",
    "truncated": "The file is cut short, so its metadata could not be found.",
    "compressed": "The metadata sits in a compressed part of the file, which CrawlR does not unpack.",
    "bad_pdf": "The file's metadata is damaged or written in a way CrawlR does not read.",
    "bad_zip": "The file is not a readable Office archive.",
    "zip_bomb": "The archive's metadata is larger than any real document's, so it was not unpacked.",
    "xml_entities": "The metadata declares XML entities, so it was not parsed.",
    "bad_xml": "The metadata inside the file is not readable XML.",
    "legacy_office": "This is an older or password-protected Office file, which CrawlR does not read.",
    "unknown_format": "The file is not a PDF or an Office document.",
}

TEXT_MAX = 300
MAX_MEMBER = 512_000          # bytes of one metadata member, unpacked
MAX_ENTRIES = 20_000
MAX_XMP = 512_000
MAX_STRING = 4096             # bytes of one PDF string
MAX_DICT_SPAN = 65_536        # bytes of one PDF dictionary
MAX_DEPTH = 8
MAX_INFLATE = 4_000_000       # bytes one object stream may inflate to
INFLATE_BUDGET = 24_000_000   # bytes inflated per file, all object streams together
MAX_STREAM_OBJECTS = 20_000   # objects listed in one object stream
MAX_MARKERS = 1000            # object streams, or catalogs, looked at in one file


class _Refused(Exception):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def _answer(kind: str, parsed: bool, reason: str = "", fields: dict | None = None, sources: list | None = None) -> dict:
    full = {k: "" for k in FIELDS}
    full.update({k: v for k, v in (fields or {}).items() if k in full and v})
    return {"type": kind, "parsed": parsed, "reason": reason, "sources": sources or [], "fields": full}


def clean(value, cap: int = TEXT_MAX) -> str:
    """One line of printable text, capped."""
    if not isinstance(value, str):
        return ""
    text = "".join(ch if ch.isprintable() else " " for ch in value)
    return " ".join(text.split())[:cap].strip()


_ISO = re.compile(r"^(\d{4})(?:-(\d{2})(?:-(\d{2})(?:T(\d{2}):(\d{2})(?::(\d{2})(?:\.\d+)?)?(Z|[+-]\d{2}:\d{2})?)?)?)?$")
_PDF_DATE = re.compile(r"^(?:D:)?(\d{4})(\d{2})?(\d{2})?(\d{2})?(\d{2})?(\d{2})?\s*(?:(Z)|([+-])(\d{2})'?(\d{2})?'?)?")


def _valid(month, day, hour, minute, second) -> bool:
    return (1 <= int(month or 1) <= 12 and 1 <= int(day or 1) <= 31 and int(hour or 0) <= 23
            and int(minute or 0) <= 59 and int(second or 0) <= 59)


def iso_date(value: str) -> str:
    """An ISO 8601 date as XMP and Office write it, checked, without fractions. "" if it is not one."""
    m = _ISO.fullmatch((value or "").strip())
    if not m or not _valid(*m.groups()[1:6]):
        return ""
    y, mo, d, h, mi, s, tz = m.groups()
    out = y + (f"-{mo}" if mo else "") + (f"-{d}" if d else "")
    if h:
        out += f"T{h}:{mi}:{s or '00'}{tz or ''}"
    return out


def pdf_date(value: str) -> str:
    """A PDF date (D:YYYYMMDDHHmmSS+HH'mm') as ISO 8601. "" if it is not one."""
    m = _PDF_DATE.match((value or "").strip())
    if not m or not _valid(*m.groups()[1:6]):
        return ""
    y, mo, d, h, mi, s, z, sign, th, tm = m.groups()
    out = y + (f"-{mo}" if mo else "") + (f"-{d}" if mo and d else "")
    if mo and d and h:
        out += f"T{h}:{mi or '00'}:{s or '00'}"
        if z:
            out += "Z"
        elif sign and int(th) <= 14 and int(tm or 0) <= 59:
            out += f"{sign}{th}:{tm or '00'}"
    return out


def sniff(data: bytes) -> str:
    """"pdf", "zip", "ole", "html" or "": what the first bytes say the file is."""
    if b"%PDF-" in data[:1024]:
        return "pdf"
    if data[:4] == b"PK\x03\x04":
        return "zip"
    if data[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        return "ole"
    if data[:512].lstrip(b"\xef\xbb\xbf \t\r\n").startswith(b"<"):
        return "html"
    return ""


# --------------------------------------------------------------------------------------
# XML
# --------------------------------------------------------------------------------------
def safe_xml(data: bytes) -> ET.Element:
    """Parse XML that may not declare anything. Raises _Refused."""
    low = data.lower()
    if b"\x00" in data:
        raise _Refused("bad_xml")              # UTF-16 or binary: not read
    if b"<!doctype" in low or b"<!entity" in low:
        raise _Refused("xml_entities")
    try:
        # The encoding is fixed, so the document's own declaration cannot change how it is read.
        return ET.fromstring(data, parser=ET.XMLParser(encoding="utf-8"))
    except (ET.ParseError, ValueError, LookupError, RecursionError):
        raise _Refused("bad_xml") from None


def _local(tag) -> str:
    return tag.rsplit("}", 1)[-1] if isinstance(tag, str) else ""


# --------------------------------------------------------------------------------------
# Office
# --------------------------------------------------------------------------------------
_OFFICE_DIRS = (("word/", "docx"), ("xl/", "xlsx"), ("ppt/", "pptx"))


def _member(zf: zipfile.ZipFile, info: zipfile.ZipInfo) -> bytes:
    if info.flag_bits & 0x1:
        raise _Refused("encrypted")
    if info.file_size > MAX_MEMBER:
        raise _Refused("zip_bomb")
    try:
        with zf.open(info) as f:
            data = f.read(MAX_MEMBER + 1)      # the read is bounded whatever the header declared
    except (zipfile.BadZipFile, zlib.error, EOFError, NotImplementedError, RuntimeError, OSError, ValueError):
        raise _Refused("bad_zip") from None
    if len(data) > MAX_MEMBER:
        raise _Refused("zip_bomb")
    return data


def parse_office(data: bytes, hint: str = "") -> dict:
    """Metadata of a docx, xlsx or pptx. `hint` is the type the URL suggested."""
    kind = hint if hint in ("docx", "xlsx", "pptx") else ""
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except (zipfile.BadZipFile, zlib.error, EOFError, NotImplementedError, OSError, ValueError):
        return _answer(kind, False, "bad_zip")
    with zf:
        infos = zf.infolist()
        if len(infos) > MAX_ENTRIES:
            return _answer(kind, False, "zip_bomb")
        by_name = {}
        for info in infos:
            by_name.setdefault(info.filename, info)
        for prefix, name in _OFFICE_DIRS:
            if any(n.startswith(prefix) for n in by_name):
                kind = name
                break
        else:
            if "[Content_Types].xml" not in by_name:
                return _answer(kind, False, "unknown_format")
        fields: dict[str, str] = {}
        sources: list[str] = []
        try:
            core = by_name.get("docProps/core.xml")
            if core is not None:
                root = safe_xml(_member(zf, core))
                got = {_local(el.tag): clean(el.text or "") for el in root}
                fields.update({
                    "title": got.get("title", ""), "author": got.get("creator", ""),
                    "last_modified_by": got.get("lastModifiedBy", ""),
                    "created": iso_date(got.get("created", "")), "modified": iso_date(got.get("modified", "")),
                })
                sources.append("core")
            app = by_name.get("docProps/app.xml")
            if app is not None:
                root = safe_xml(_member(zf, app))
                got = {_local(el.tag): clean(el.text or "") for el in root}
                name, version = got.get("Application", ""), got.get("AppVersion", "")
                fields["creator_software"] = clean(f"{name} {version}") if name else ""
                fields["company"] = got.get("Company", "")
                sources.append("app")
        except _Refused as e:
            return _answer(kind, False, e.reason)
    return _answer(kind, True, "", fields, sources)


# --------------------------------------------------------------------------------------
# PDF: a small reader for one dictionary
# --------------------------------------------------------------------------------------
_WS = b"\x00\t\n\x0c\r "
_DELIM = b"()<>[]{}/%"
_ESC = {ord("n"): b"\n", ord("r"): b"\r", ord("t"): b"\t", ord("b"): b"\b", ord("f"): b"\f",
        ord("("): b"(", ord(")"): b")", ord("\\"): b"\\"}


class _Bad(Exception):
    pass


def _literal(data: bytes, p: int, end: int) -> tuple[bytes, int]:
    """A literal string starting at the '(' at p. Returns (bytes, position after it)."""
    out = bytearray()
    depth = 1
    p += 1
    while p < end:
        c = data[p]
        if c == 0x5C:                                   # backslash
            p += 1
            if p >= end:
                break
            c = data[p]
            if c in _ESC:
                out += _ESC[c]
            elif 0x30 <= c <= 0x37:                     # up to three octal digits
                digits = bytes([c])
                while len(digits) < 3 and p + 1 < end and 0x30 <= data[p + 1] <= 0x37:
                    p += 1
                    digits += bytes([data[p]])
                out.append(int(digits, 8) & 0xFF)
            elif c == 0x0D:                             # line continuation
                if p + 1 < end and data[p + 1] == 0x0A:
                    p += 1
            elif c != 0x0A:
                out.append(c)
        elif c == 0x28:
            depth += 1
            out.append(c)
        elif c == 0x29:
            depth -= 1
            if depth == 0:
                return bytes(out), p + 1
            out.append(c)
        else:
            out.append(c)
        if len(out) > MAX_STRING:
            raise _Bad("string too long")
        p += 1
    raise _Bad("string not closed")


def _token(data: bytes, p: int, end: int):
    """(kind, value, next position). kind: eof, dict_open, dict_close, arr_open, arr_close,
    str, name, word."""
    while p < end:
        c = data[p]
        if c in _WS:
            p += 1
        elif c == 0x25:                                 # a comment runs to the end of the line
            while p < end and data[p] not in b"\r\n":
                p += 1
        else:
            break
    if p >= end:
        return "eof", None, p
    two = data[p:p + 2]
    if two == b"<<":
        return "dict_open", None, p + 2
    if two == b">>":
        return "dict_close", None, p + 2
    c = data[p]
    if c == 0x28:
        value, q = _literal(data, p, end)
        return "str", value, q
    if c == 0x3C:                                       # a hex string
        q = data.find(b">", p, min(end, p + 2 * MAX_STRING + 2))
        if q < 0:
            raise _Bad("hex string not closed")
        digits = bytes(b for b in data[p + 1:q] if b not in _WS)
        if len(digits) % 2:
            digits += b"0"
        try:
            return "str", bytes.fromhex(digits.decode("ascii")), q + 1
        except (ValueError, UnicodeDecodeError):
            raise _Bad("bad hex string") from None
    if c == 0x5B:
        return "arr_open", None, p + 1
    if c == 0x5D:
        return "arr_close", None, p + 1
    if c == 0x2F:
        q = p + 1
        while q < end and data[q] not in _WS and data[q] not in _DELIM:
            q += 1
        return "name", data[p + 1:q].decode("latin-1"), q
    q = p
    while q < end and data[q] not in _WS and data[q] not in _DELIM:
        q += 1
    if q == p:
        raise _Bad("unexpected byte")
    return "word", data[p:q], q


def _skip_value(data: bytes, p: int, end: int, kind: str, depth: int) -> int:
    """Move past a dictionary or an array whose opening token was just read."""
    if depth > MAX_DEPTH:
        raise _Bad("too deep")
    close = "dict_close" if kind == "dict_open" else "arr_close"
    while True:
        k, _v, p = _token(data, p, end)
        if k == "eof":
            raise _Bad("not closed")
        if k == close:
            return p
        if k in ("dict_open", "arr_open"):
            p = _skip_value(data, p, end, k, depth + 1)


def _read_dict(data: bytes, p: int) -> tuple[dict, int]:
    """(the top-level entries of the dictionary that opens at p, the position after it).
    Entries: {name: ("str", bytes) | ("ref", n, g) | ("int", n) | ("name", str) | ("other",)}.
    Raises _Bad."""
    end = min(len(data), p + MAX_DICT_SPAN)
    kind, _v, p = _token(data, p, end)
    if kind != "dict_open":
        raise _Bad("not a dictionary")
    out: dict = {}
    while True:
        kind, key, p = _token(data, p, end)
        if kind == "dict_close":
            return out, p
        if kind != "name":
            raise _Bad("expected a name")
        kind, value, p = _token(data, p, end)
        if kind == "str":
            out[key] = ("str", value)
        elif kind in ("dict_open", "arr_open"):
            p = _skip_value(data, p, end, kind, 1)
            out[key] = ("other",)
        elif kind == "word" and value.isdigit():
            k2, v2, p2 = _token(data, p, end)
            k3, v3, p3 = _token(data, p2, end) if k2 == "word" and v2.isdigit() else ("", None, p2)
            if k3 == "word" and v3 == b"R":
                out[key] = ("ref", int(value), int(v2))
                p = p3
            else:
                out[key] = ("int", int(value))
        elif kind == "name":
            out[key] = ("name", value)
        elif kind == "word":
            out[key] = ("other",)
        else:
            raise _Bad("unexpected token")


def _find_object(data: bytes, num: int, gen: int) -> int:
    """Position just after the last `num gen obj`, or -1. The last one wins: an edited PDF
    appends new versions of its objects."""
    last = -1
    for m in re.finditer(rb"(?<![0-9])%d[\x00\t\n\x0c\r ]+%d[\x00\t\n\x0c\r ]+obj(?![A-Za-z])" % (num, gen), data):
        last = m.end()
    return last


def _text(raw: bytes) -> str:
    """A PDF text string: UTF-16 or UTF-8 when it says so, otherwise one byte per character."""
    if raw[:2] == b"\xfe\xff":
        return clean(raw[2:].decode("utf-16-be", errors="replace"))
    if raw[:2] == b"\xff\xfe":
        return clean(raw[2:].decode("utf-16-le", errors="replace"))
    if raw[:3] == b"\xef\xbb\xbf":
        return clean(raw[3:].decode("utf-8", errors="replace"))
    return clean(raw.decode("latin-1"))


_INFO_KEYS = {"Title": "title", "Author": "author", "Creator": "creator_software", "Producer": "producer",
              "Company": "company", "CreationDate": "created", "ModDate": "modified"}
_INFO_REF = re.compile(rb"/Info[\x00\t\n\x0c\r ]+(\d{1,10})[\x00\t\n\x0c\r ]+(\d{1,5})[\x00\t\n\x0c\r ]+R(?![A-Za-z0-9])")


_OBJSTM = re.compile(rb"/Type[\x00\t\n\x0c\r ]*/ObjStm(?![A-Za-z])")
_STREAM = re.compile(rb"[\x00\t\n\x0c\r ]*stream(?:\r\n|\n|\r)")


def _in_object_stream(data: bytes, num: int) -> tuple[bytes, int] | None:
    """(inflated object stream, position of object `num` in it) when a plain FlateDecode
    object stream holds that object, else None. The last stream that lists it wins. Bounded:
    see MAX_INFLATE and INFLATE_BUDGET."""
    budget = INFLATE_BUDGET
    found = None
    # Only the last MAX_MARKERS are looked at: a real file has far fewer, and the last wins.
    for m in list(_OBJSTM.finditer(data))[-MAX_MARKERS:]:
        head = None
        for head in _OBJ_HEAD.finditer(data, max(0, m.start() - 2048), m.start()):
            pass
        if head is None:
            continue
        try:
            entries, after = _read_dict(data, head.end())
        except _Bad:
            continue
        first, count, length = entries.get("First"), entries.get("N"), entries.get("Length")
        if entries.get("Filter") != ("name", "FlateDecode") or "DecodeParms" in entries:
            continue                                    # another filter or a predictor: not unpacked
        if not (first and first[0] == "int" and count and count[0] == "int" and 0 < count[1] <= MAX_STREAM_OBJECTS):
            continue
        start = _STREAM.match(data, after)
        if not start:
            continue
        if length and length[0] == "int" and 0 < length[1] <= len(data) - start.end():
            raw = data[start.end():start.end() + length[1]]
        else:
            stop = data.find(b"endstream", start.end())
            raw = data[start.end():stop] if stop > 0 else b""
        if not raw or budget <= 0:
            continue
        try:
            inflater = zlib.decompressobj()
            plain = inflater.decompress(raw, min(MAX_INFLATE, budget) + 1)
        except zlib.error:
            continue
        budget -= len(plain)
        if len(plain) > MAX_INFLATE or inflater.unconsumed_tail or first[1] > len(plain):
            continue
        numbers = plain[:first[1]].split()
        if len(numbers) < 2 * count[1] or not all(n.isdigit() for n in numbers[:2 * count[1]]):
            continue
        for i in range(count[1]):
            if int(numbers[2 * i]) == num and first[1] + int(numbers[2 * i + 1]) < len(plain):
                found = (plain, first[1] + int(numbers[2 * i + 1]))
    return found


def _info(data: bytes) -> tuple[dict, str]:
    """(fields, status). status: "read", "absent" (no /Info reference), "hidden" (the
    reference points at an object that is neither in the file as text nor in an object stream
    this module unpacks) or "bad"."""
    refs = _INFO_REF.findall(data)
    if not refs:
        return {}, "absent"
    num, gen = int(refs[-1][0]), int(refs[-1][1])
    at = _find_object(data, num, gen)
    packed = _in_object_stream(data, num) if at < 0 else None
    if at < 0 and packed is None:
        return {}, "hidden"
    try:
        entries, _end = _read_dict(*packed) if packed else _read_dict(data, at)
    except _Bad:
        return {}, "bad"
    fields = {}
    for key, name in _INFO_KEYS.items():
        value = entries.get(key)
        if value and value[0] == "ref":                 # the string is its own object
            pos = _find_object(data, value[1], value[2])
            try:
                kind, raw, _p = _token(data, pos, min(len(data), pos + MAX_STRING * 2 + 16)) if pos >= 0 else ("", None, 0)
            except _Bad:
                kind, raw = "", None
            value = ("str", raw) if kind == "str" else None
        if value and value[0] == "str":
            text = _text(value[1])
            fields[name] = pdf_date(text) if name in ("created", "modified") else text
    return fields, "read"


# --------------------------------------------------------------------------------------
# PDF: XMP
# --------------------------------------------------------------------------------------
_XMP_OPEN, _XMP_CLOSE = b"<x:xmpmeta", b"</x:xmpmeta>"
_OBJ_HEAD = re.compile(rb"(?<![0-9])(\d{1,10})[\x00\t\n\x0c\r ]+(\d{1,5})[\x00\t\n\x0c\r ]+obj(?![A-Za-z])")
_CATALOG = re.compile(rb"/Type[\x00\t\n\x0c\r ]*/Catalog(?![A-Za-z])")
_META_REF = re.compile(rb"/Metadata[\x00\t\n\x0c\r ]+(\d{1,10})[\x00\t\n\x0c\r ]+(\d{1,5})[\x00\t\n\x0c\r ]+R(?![A-Za-z0-9])")
_NS_DC = "{http://purl.org/dc/elements/1.1/}"
_NS_XMP = "{http://ns.adobe.com/xap/1.0/}"
_NS_PDF = "{http://ns.adobe.com/pdf/1.3/}"
_NS_RDF = "{http://www.w3.org/1999/02/22-rdf-syntax-ns#}"
_PDF_SCHEMA = b"http://ns.adobe.com/pdf/1.3/"
MAX_PACKETS = 40


def _owner(data: bytes, at: int) -> int:
    """The number of the object a position sits in, or -1."""
    last = -1
    for m in _OBJ_HEAD.finditer(data, max(0, at - 4096), at):
        last = int(m.group(1))
    return last


def _catalog_metadata(data: bytes) -> tuple[bool, int]:
    """(a catalog is readable, the object number its /Metadata points at or -1). The last
    catalog wins."""
    seen, target = False, -1
    for m in list(_CATALOG.finditer(data))[-MAX_MARKERS:]:
        start = data.rfind(b"obj", max(0, m.start() - MAX_DICT_SPAN), m.start())
        stop = data.find(b"endobj", m.end(), m.end() + MAX_DICT_SPAN)
        if start < 0:
            continue
        seen = True
        ref = _META_REF.search(data, start, stop if stop > 0 else m.end() + MAX_DICT_SPAN)
        target = int(ref.group(1)) if ref else -1
    return seen, target


def _xmp_packet(data: bytes) -> tuple[bytes | None, str]:
    """(the document's own XMP packet or None, status). status: "found"; "none" (the catalog is
    readable and names no metadata); "hidden" (it names a stream that is not readable here);
    "unknown" (no catalog is readable, and no single packet is clearly the document's)."""
    # Walk the closing tags and look back for each one's opening tag, never past the previous
    # packet: the work stays proportional to the file however many tags it holds.
    packets = []
    floor = at = 0
    while len(packets) < MAX_PACKETS:
        close = data.find(_XMP_CLOSE, at)
        if close < 0:
            break
        at = close + len(_XMP_CLOSE)
        start = data.rfind(_XMP_OPEN, max(floor, close - MAX_XMP), close)
        floor = at
        if start >= 0 and data[start + len(_XMP_OPEN):start + len(_XMP_OPEN) + 1] in (b" ", b">", b"\n", b"\r", b"\t"):
            packets.append((start, data[start:at]))
    seen, target = _catalog_metadata(data)
    if seen:
        if target < 0:
            return None, "none"
        for at, packet in packets:
            if _owner(data, at) == target:
                return packet, "found"
        return None, "hidden"
    own = [packet for _at, packet in packets if _PDF_SCHEMA in packet]
    if len(own) == 1:
        return own[0], "found"
    return None, "unknown"


def _rdf_text(el: ET.Element) -> list[str]:
    """The values of an XMP property: its text, or the items of its rdf list (x-default first)."""
    items = [li for li in el.iter(_NS_RDF + "li")]
    if not items:
        return [t for t in [clean(el.text or "")] if t]
    items.sort(key=lambda li: li.get("{http://www.w3.org/XML/1998/namespace}lang") != "x-default")
    return [t for t in (clean(li.text or "") for li in items[:20]) if t]


def _xmp_fields(packet: bytes) -> dict:
    root = safe_xml(packet)
    fields: dict[str, str] = {}

    def put(name: str, values: list[str], joined: bool = False) -> None:
        if values and not fields.get(name):
            fields[name] = clean("; ".join(values)) if joined else values[0]

    for desc in root.iter(_NS_RDF + "Description"):
        simple = {_NS_XMP + "CreatorTool": "creator_software", _NS_PDF + "Producer": "producer",
                  _NS_XMP + "CreateDate": "created", _NS_XMP + "ModifyDate": "modified"}
        for attr, name in simple.items():
            if desc.get(attr):
                put(name, [clean(desc.get(attr))])
        for child in desc:
            if child.tag in simple:
                put(simple[child.tag], _rdf_text(child))
            elif child.tag == _NS_DC + "title":
                put("title", _rdf_text(child))
            elif child.tag == _NS_DC + "creator":
                put("author", _rdf_text(child), joined=True)
    for name in ("created", "modified"):
        if name in fields:
            fields[name] = iso_date(fields[name])
    return fields


def parse_pdf(data: bytes) -> dict:
    if b"%PDF-" not in data[:1024]:
        return _answer("pdf", False, "not_pdf")
    complete = b"%%EOF" in data[-2048:]
    encrypted = re.search(rb"/Encrypt[\x00\t\n\x0c\r ]*(?:\d{1,10}[\x00\t\n\x0c\r ]+\d{1,5}[\x00\t\n\x0c\r ]+R|<<)", data) is not None
    object_streams = re.search(rb"/Type[\x00\t\n\x0c\r ]*/ObjStm", data) is not None

    fields: dict[str, str] = {}
    sources: list[str] = []
    info, info_status = ({}, "encrypted") if encrypted else _info(data)   # an encrypted file's strings are ciphertext
    if any(info.values()):
        fields.update({k: v for k, v in info.items() if v})
        sources.append("info")
    packet, xmp_status = _xmp_packet(data)
    if packet is not None:
        try:
            extra = _xmp_fields(packet)
        except _Refused:
            extra = {}
        added = {k: v for k, v in extra.items() if v and not fields.get(k)}
        if added:
            fields.update(added)
            sources.append("xmp")
    if fields:
        return _answer("pdf", True, "", fields, sources)
    if encrypted:
        return _answer("pdf", False, "encrypted")
    if not complete:
        return _answer("pdf", False, "truncated")
    if info_status == "hidden" or xmp_status == "hidden" or (object_streams and info_status == "absent" and xmp_status == "unknown"):
        return _answer("pdf", False, "compressed")
    if info_status == "bad":
        return _answer("pdf", False, "bad_pdf")
    return _answer("pdf", True, "")                     # read, and it declares nothing


def parse_document(data: bytes, hint: str = "") -> dict:
    """Metadata of a fetched file. `hint` is the type the URL's extension suggested."""
    kind = sniff(data)
    if kind == "pdf":
        return parse_pdf(data)
    if kind == "zip":
        return parse_office(data, hint)
    if kind == "ole":
        return _answer(hint if hint != "pdf" else "", False, "legacy_office")
    return _answer("", False, "unknown_format")
