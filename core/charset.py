"""
Turning a fetched page's bytes into text, whatever charset the page claims.

The charset label of a page is outside data: it comes from a Content-Type header or a meta tag
that the remote side wrote. Python's codec registry holds far more than page charsets (codecs
that are not text at all, and text codecs that are slow on a large input), so a label is never
handed to `bytes.decode` as it came. `pick` maps a label to one of a short, fixed list of
charsets that real pages use and that decode in one linear pass; any other label is read as
UTF-8. Undecodable bytes become U+FFFD. `decode` never raises.

A one-byte charset is decoded through a table of its 256 characters, made once, so a byte the
charset does not define costs the same as one it does. A body that starts with a UTF-16 byte
order mark is UTF-16 whatever its label says, as browsers read it. UTF-16 without the mark is
not guessed: read as UTF-8 it comes out full of NUL characters, and `not_text` says so, so a
caller can answer "could not be read" instead of reading nothing out of it.

Callers with a large body run `decode` on the parse pool (core.parsepool) together with the
parsing that follows it.
"""

import codecs
import re

DEFAULT = "utf-8"

# label (lower case, "_" as "-") -> the Python codec that reads it.
_LABELS: dict[str, str] = {
    "utf-8": "utf-8", "utf8": "utf-8", "unicode-1-1-utf-8": "utf-8",
    # As browsers do, ASCII and Latin-1 are read as windows-1252, which is a superset in print.
    "ascii": "cp1252", "us-ascii": "cp1252", "latin1": "cp1252", "latin-1": "cp1252", "l1": "cp1252",
    "iso-8859-1": "cp1252", "iso8859-1": "cp1252",
    "shift-jis": "cp932", "shiftjis": "cp932", "sjis": "cp932", "x-sjis": "cp932", "ms-kanji": "cp932",
    "windows-31j": "cp932", "cp932": "cp932",
    "euc-jp": "euc_jp", "eucjp": "euc_jp", "x-euc-jp": "euc_jp",
    "iso-2022-jp": "iso2022_jp",
    "gb2312": "gb18030", "gbk": "gb18030", "gb18030": "gb18030", "x-gbk": "gb18030", "cp936": "gb18030",
    "big5": "big5hkscs", "big5-hkscs": "big5hkscs", "x-x-big5": "big5hkscs", "cp950": "cp950",
    "euc-kr": "cp949", "euckr": "cp949", "ks-c-5601-1987": "cp949", "cp949": "cp949", "windows-949": "cp949",
    "koi8-r": "koi8_r", "koi8-u": "koi8_u",
    "macintosh": "mac_roman", "x-mac-roman": "mac_roman",
}
for _n in (2, 3, 4, 5, 6, 7, 8, 9, 10, 13, 14, 15, 16):
    _LABELS[f"iso-8859-{_n}"] = _LABELS[f"iso8859-{_n}"] = f"iso8859_{_n}"
for _n in range(1250, 1259):
    _LABELS[f"windows-{_n}"] = _LABELS[f"cp{_n}"] = _LABELS[f"x-cp{_n}"] = f"cp{_n}"

ALLOWED = frozenset(_LABELS.values())


def _table(codec: str) -> str | None:
    """The 256 characters of a one-byte charset, U+FFFD where it defines none; None for a
    charset that is not one byte per character."""
    try:
        chars = [bytes([n]).decode(codec, "replace") for n in range(256)]
    except Exception:  # noqa: BLE001 - a codec that cannot take one byte alone is not one-byte
        return None
    return "".join(chars) if all(len(c) == 1 for c in chars) and chars[0x41] == "A" else None


# Only the families that are one byte per character by definition are given a table.
_TABLES: dict[str, str] = {
    codec: table for codec in sorted(ALLOWED) if codec.startswith(("cp125", "iso8859_", "koi8_", "mac_"))
    and (table := _table(codec))
}
_BOMS = ((b"\xff\xfe", "utf-16-le"), (b"\xfe\xff", "utf-16-be"))

_HEADER_CHARSET = re.compile(r"charset\s*=\s*[\"']?([A-Za-z0-9._:-]{2,40})", re.I)
_META_CHARSET = re.compile(rb"<meta[^>]{0,200}?charset\s*=\s*[\"']?\s*([A-Za-z0-9._:-]{2,40})", re.I)
META_WINDOW = 4096            # bytes at the start of a page that are searched for a meta charset


def pick(label) -> str:
    """The codec for a charset label, always a member of ALLOWED. An unknown label is UTF-8."""
    if not isinstance(label, str):
        return DEFAULT
    return _LABELS.get(label.strip().lower().replace("_", "-"), DEFAULT)


def labels(body: bytes, content_type: str = "") -> list[str]:
    """The charset labels a page states, most trusted first: the header's, then a meta tag's."""
    found = []
    m = _HEADER_CHARSET.search(content_type or "")
    if m:
        found.append(m.group(1))
    m = _META_CHARSET.search(body[:META_WINDOW])
    if m:
        found.append(m.group(1).decode("ascii", "replace"))
    return found


def choose(body: bytes, content_type: str = "") -> str:
    """The codec `decode` will use: the first stated label that names a known charset."""
    for label in labels(body, content_type):
        if label.strip().lower().replace("_", "-") in _LABELS:
            return pick(label)
    return DEFAULT


def decode(body: bytes, content_type: str = "") -> str:
    """`body` as text. Never raises, and never uses a codec outside ALLOWED (or UTF-16, for a
    body that opens with its byte order mark)."""
    for mark, codec in _BOMS:
        if body.startswith(mark):
            # An odd last byte is half a character: dropped, like any other undecodable tail.
            return body[2:].decode(codec, "replace")
    codec = choose(body, content_type)
    try:
        table = _TABLES.get(codec)
        if table is not None:
            return codecs.charmap_decode(body, "replace", table)[0]
        return body.decode(codec, "replace")
    except Exception:  # noqa: BLE001 - a codec that gives up on the bytes falls back to the default
        return body.decode(DEFAULT, "replace")


def not_text(text: str) -> bool:
    """Is this decoded body something other than text in the charset it was read in? One
    character in a hundred being NUL says so: a page in UTF-16 or UTF-32 that carries no byte
    order mark reads that way, and so does a binary file. A stray NUL in a real page does not."""
    return bool(text) and text.count("\x00") * 100 >= len(text)
