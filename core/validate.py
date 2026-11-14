"""
Input validation shared by the routers.

Usernames and emails are passed to command-line tools (sherlock, maigret,
holehe) and used in upstream URLs, so they are checked against a strict
allow-list before anything else touches them. Hostnames are normalized once
here so every module sees the same value.
"""

import ipaddress
import re
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
