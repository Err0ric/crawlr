"""
Input validation shared by the routers.

Usernames and emails are passed to command-line tools (sherlock, maigret,
holehe) and used in upstream URLs, so they are checked against a strict
allow-list before anything else touches them. Hostnames are normalized once
here so every module sees the same value.
"""

import ipaddress
import re
import unicodedata
from urllib.parse import urlsplit

from fastapi import HTTPException

USERNAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\.[A-Za-z]{2,63}$")
HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)(?:[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$")

# Second-level public suffixes that are common enough to matter for "same site" checks.
# This is deliberately small; it only has to stop a.co.uk and b.co.uk from looking related.
_TWO_LEVEL_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "ltd.uk", "plc.uk", "net.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "co.nz", "org.nz", "net.nz",
    "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp", "co.kr", "or.kr", "co.in", "net.in", "org.in",
    "com.br", "net.br", "org.br", "com.mx", "com.ar", "com.co", "com.tr", "com.cn", "net.cn", "org.cn",
    "com.hk", "com.sg", "com.tw", "com.my", "com.ph", "co.za", "co.il", "co.id", "co.th", "com.vn",
    "com.ua", "com.pl", "com.ru", "com.eg", "com.ng", "co.ke", "com.pk", "com.bd", "com.sa", "com.es",
}


def _bad(detail: str) -> HTTPException:
    return HTTPException(status_code=400, detail=detail)


def username(value: str) -> str:
    v = (value or "").strip().lstrip("@")
    if not USERNAME_RE.fullmatch(v) or v.startswith("-"):
        raise _bad("Enter a username of 1 to 64 letters, digits, dots, dashes or underscores.")
    return v


def email(value: str) -> str:
    v = (value or "").strip()
    if len(v) > 254 or not EMAIL_RE.fullmatch(v) or v.startswith("-") or ".." in v:
        raise _bad("Enter a valid email address.")
    return v


# "example.com" and "first.last" are made of name characters but are not names.
_DOTTED_RE = re.compile(r"\w{2,}\.\w{2,}")
_NAME_PUNCT = "-'.\u00b7"          # hyphen, apostrophe, period, middle dot (Gil·les)
PERSON_NAME_MAX = 80
PERSON_NAME_MAX_MARKS = 4          # combining marks on one base letter; real names use fewer
PERSON_NAME_MSG = ("Enter a person's name: 2 to 80 characters, letters from any script, with spaces, hyphens, "
                   "apostrophes, periods or a middle dot. Digits, commas, quotes, @, slashes and web addresses "
                   "are not accepted.")
_ZW_JOINERS = "\u200c\u200d"
# Scripts whose spelling uses the zero width joiner or non-joiner inside a word.
_JOINER_SCRIPTS = ("ARABIC", "SYRIAC", "DEVANAGARI", "BENGALI", "GURMUKHI", "GUJARATI", "ORIYA", "TAMIL", "TELUGU",
                   "KANNADA", "MALAYALAM", "SINHALA")


def _joiner_script(ch: str) -> bool:
    return unicodedata.name(ch, "").startswith(_JOINER_SCRIPTS)


def _strip_joiners(v: str) -> str:
    """Keeps a zero width joiner or non-joiner only between two letters or marks of a script
    that spells with them. Anywhere else it is invisible padding and is dropped."""
    out = []
    for i, ch in enumerate(v):
        if ch in _ZW_JOINERS and not (0 < i < len(v) - 1 and _joiner_script(v[i - 1]) and _joiner_script(v[i + 1])):
            continue
        out.append(ch)
    return "".join(out)


def person_name(value: str) -> str:
    """A person's name as typed: letters from any script, spaces, hyphens, apostrophes,
    periods and the middle dot. Returned NFC-normalized, trimmed, with runs of spaces collapsed.
    Anything that looks like a URL, an email address, a handle or a number is refused. A word
    that is a search operator in capitals (OR, AND, NOT) is a real name for some people, so it is
    accepted here and made harmless where a query is built (modules/name_search.py)."""
    msg = PERSON_NAME_MSG
    # Trim first: a tab or line break pasted after the name is not part of it. Inside it is refused.
    v = unicodedata.normalize("NFC", (value or "").strip())
    v = v.replace("\u2019", "'").replace("\u02bc", "'")
    if any(unicodedata.category(ch) == "Cc" for ch in v):
        raise _bad(msg)
    v = _strip_joiners(v)
    v = " ".join("".join(" " if unicodedata.category(ch) == "Zs" else ch for ch in v).split())
    if not 2 <= len(v) <= PERSON_NAME_MAX:
        raise _bad(msg)
    # Marks are counted on the decomposed form, so stacking them on a letter that also has a
    # composed spelling does not get one free.
    marks = 0
    for ch in unicodedata.normalize("NFD", v):
        marks = marks + 1 if unicodedata.category(ch) in ("Mn", "Mc") else 0
        if marks > PERSON_NAME_MAX_MARKS:
            raise _bad(msg)
    for ch in v:
        # Combining marks are part of the letters in many scripts (Devanagari, Thai, Arabic).
        mark = unicodedata.category(ch) in ("Mn", "Mc")
        if not (ch == " " or ch in _NAME_PUNCT or ch in _ZW_JOINERS or ch.isalpha() or mark):
            raise _bad(msg)
    if sum(ch.isalpha() for ch in v) < 2:
        raise _bad(msg)
    for token in v.split(" "):
        if token.startswith("-") or not any(ch.isalpha() for ch in token) or _DOTTED_RE.search(token):
            raise _bad(msg)
    return v


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def host(value: str, *, allow_ip: bool = True) -> str:
    """Normalize a domain or IP typed by a user: strips scheme, path, port and a trailing dot."""
    v = (value or "").strip().lower()
    if "://" in v:
        v = urlsplit(v).hostname or ""
    v = v.split("/")[0].split("?")[0].rstrip(".")
    if v.count(":") == 1:          # host:port (bare IPv6 has more than one colon)
        v = v.split(":")[0]
    v = v.strip("[]")
    if is_ip(v):
        if not allow_ip:
            raise _bad("Enter a domain name, not an IP address.")
        return v
    if not HOSTNAME_RE.fullmatch(v):
        raise _bad("Enter a valid domain name or IP address." if allow_ip else "Enter a valid domain name.")
    return v


def http_url(value: str) -> str:
    """A URL or bare host for the redirect tracer. Returns an absolute http(s) URL."""
    v = (value or "").strip()
    if not re.match(r"^https?://", v, re.I):
        v = "https://" + v
    parts = urlsplit(v)
    if parts.username or parts.password:
        raise _bad("URLs with credentials are not supported.")
    host(parts.hostname or "")
    return v


def registrable_domain(hostname: str) -> str:
    """Best-effort eTLD+1: 'a.b.example.co.uk' -> 'example.co.uk'. IPs are returned unchanged."""
    h = (hostname or "").strip().lower().rstrip(".")
    if not h or is_ip(h):
        return h
    labels = h.split(".")
    if len(labels) <= 2:
        return h
    if ".".join(labels[-2:]) in _TWO_LEVEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def same_site(a: str, b: str) -> bool:
    ra, rb = registrable_domain(a), registrable_domain(b)
    return bool(ra) and ra == rb


# A phone number as people write it: digits with spaces, dashes, dots, slashes and parentheses,
# an optional leading +, an extension ("ext. 22", "x22", ";ext=22", "#22") and letters for a
# vanity number (1-800-FLOWERS). It must start like a number and carry at least two digits.
PHONE_MAX = 40
PHONE_MSG = ("Enter a phone number: digits with an optional + and country code, for example +1 202 456 1111. "
             "Spaces, dashes, dots, parentheses, an extension and vanity letters are accepted.")
_PHONE_RE = re.compile(r"^[+(]?[0-9(][0-9A-Za-z()\-. /,;=#*]*$")
_REGION_RE = re.compile(r"^[A-Za-z]{2}$")


def phone_text(value: str) -> str:
    """A pasted phone number as plain text. Phones and contact apps wrap a number in invisible
    direction marks and write it with non-breaking spaces and typographic dashes. Format
    characters (Unicode category Cf) are dropped, every Unicode dash becomes "-", every Unicode
    space becomes " ", and runs of whitespace collapse. normalizePhoneText in
    static/v2/js/core.js does the same; tests/fixtures/phone_text.json holds the pairs both
    suites assert."""
    out = []
    for ch in unicodedata.normalize("NFKC", value or ""):
        cat = unicodedata.category(ch)
        if cat == "Cf":
            continue
        out.append("-" if cat == "Pd" or ch == "\u2212" else " " if cat == "Zs" else ch)
    return " ".join("".join(out).split())


def phone(value: str) -> str:
    """The number as typed, cleaned by phone_text. Refuses text that is not written like a
    phone number. Whether it is a possible or a valid number is decided later, by
    modules/phone_plan.py."""
    v = phone_text(value)
    if not v or len(v) > PHONE_MAX or not _PHONE_RE.fullmatch(v) or sum(ch.isdigit() for ch in v) < 2:
        raise _bad(PHONE_MSG)
    return v


def phone_region(value: str | None, default: str = "US") -> str:
    """The two-letter country a number written without a country code is read as."""
    v = (value or "").strip().upper()
    if not v:
        return default
    if not _REGION_RE.fullmatch(v):
        raise _bad("The region must be a two-letter country code, for example US or GB.")
    return v
