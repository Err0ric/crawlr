"""
OpenPGP keys published for an email address on keys.openpgp.org.

One request: GET https://keys.openpgp.org/vks/v1/by-email/{address}. The answer is an ASCII
armored key (200, application/pgp-keys) or a short text with 404. No key is needed.

keys.openpgp.org only hands out a user ID after the owner of that address confirmed it by
mail, so a name next to the address was put there by someone who reads that mailbox. The name
itself is still whatever they typed.

The key is read here without a dependency: the armor is decoded, the packets are walked, and
only the facts are returned (fingerprint, creation time, algorithm, user IDs). Key material is
never returned. A version 4 fingerprint is the SHA-1 of 0x99, the two length bytes and the
public key packet body (RFC 4880, 12.2). Keys of another version (3, 5, 6) are reported as
unparsed with their version, never guessed at.

States: `ok` (a key came back), `none` (404: no key for the address), `rate_limited` (429),
`failed` (anything else, including an answer that holds no readable key).
"""

import base64
import binascii
import hashlib
import re
import unicodedata
from datetime import datetime, timezone
from urllib.parse import quote

import httpx

from core.errors import classify, error_fields
from core.logging import get_logger

log = get_logger(__name__)

HOST = "keys.openpgp.org"
TIMEOUT = 8.0
USER_AGENT = "CrawlR/1.0 (+https://crawlr.lol)"
MAX_BYTES = 512_000        # a key with many signatures is tens of kilobytes; this is a hard stop
MAX_KEYS = 5
MAX_USER_IDS = 20
MAX_PACKETS = 5000

ALGORITHMS = {
    1: "RSA", 2: "RSA (encrypt only)", 3: "RSA (sign only)", 16: "ElGamal", 17: "DSA", 18: "ECDH",
    19: "ECDSA", 22: "EdDSA", 25: "X25519", 26: "X448", 27: "Ed25519", 28: "Ed448",
}
CURVES = {
    "2b06010401da470f01": "Ed25519", "2b060104019755010501": "Curve25519", "2a8648ce3d030107": "NIST P-256",
    "2b81040022": "NIST P-384", "2b81040023": "NIST P-521", "2b8104000a": "secp256k1",
    "2b2403030208010107": "brainpoolP256r1", "2b240303020801010b": "brainpoolP384r1",
    "2b240303020801010d": "brainpoolP512r1",
}
_UID_RE = re.compile(r"^(?P<name>[^<(]*?)\s*(?:\((?P<comment>[^)]*)\))?\s*(?:<(?P<email>[^<>\s]+)>)?\s*$")
_BARE_EMAIL_RE = re.compile(r"^[^@\s<>]+@[^@\s<>]+\.[^@\s<>]+$")


class _Unreadable(Exception):
    pass


def _text(value: str, cap: int) -> str:
    """One line of plain text: control and format characters out, capped."""
    s = "".join(" " if unicodedata.category(ch) in ("Cc", "Cf", "Zl", "Zp", "Cs", "Co") else ch for ch in value)
    return " ".join(s.split())[:cap].strip()


def dearmor(text: str) -> bytes:
    """The binary inside the first PGP PUBLIC KEY BLOCK. Raises _Unreadable when there is none."""
    lines = (text or "").replace("\r\n", "\n").replace("\r", "\n").split("\n")
    try:
        start = next(i for i, line in enumerate(lines) if line.strip() == "-----BEGIN PGP PUBLIC KEY BLOCK-----")
    except StopIteration:
        raise _Unreadable("no armor header") from None
    body: list[str] = []
    in_headers = True
    for line in lines[start + 1:]:
        line = line.strip()
        if line.startswith("-----END PGP"):
            break
        if in_headers:
            # Armor headers ("Comment: ...") run up to the first blank line.
            if not line:
                in_headers = False
            elif ":" not in line:
                in_headers = False
                body.append(line)
            continue
        if line.startswith("="):       # the optional CRC-24 line ends the data
            break
        if line:
            body.append(line)
    try:
        data = base64.b64decode("".join(body), validate=True)
    except (binascii.Error, ValueError):
        raise _Unreadable("bad base64") from None
    if not data:
        raise _Unreadable("empty armor")
    return data


def packets(data: bytes):
    """Yields (tag, body) for each packet. Raises _Unreadable on a malformed stream."""
    i, n, seen = 0, len(data), 0
    while i < n:
        seen += 1
        if seen > MAX_PACKETS:
            raise _Unreadable("too many packets")
        first = data[i]
        i += 1
        if not first & 0x80:
            raise _Unreadable("not a packet header")
        if first & 0x40:                       # new format
            tag = first & 0x3F
            if i >= n:
                raise _Unreadable("truncated")
            o = data[i]
            i += 1
            if o < 192:
                length = o
            elif o < 224:
                if i >= n:
                    raise _Unreadable("truncated")
                length = ((o - 192) << 8) + data[i] + 192
                i += 1
            elif o == 255:
                if i + 4 > n:
                    raise _Unreadable("truncated")
                length = int.from_bytes(data[i:i + 4], "big")
                i += 4
            else:
                # Partial body lengths are for streamed data packets, never for keys.
                raise _Unreadable("partial length")
        else:                                  # old format
            tag = (first >> 2) & 0x0F
            kind = first & 0x03
            if kind == 3:
                length = n - i
            else:
                size = (1, 2, 4)[kind]
                if i + size > n:
                    raise _Unreadable("truncated")
                length = int.from_bytes(data[i:i + size], "big")
                i += size
        if i + length > n:
            raise _Unreadable("truncated")
        yield tag, data[i:i + length]
        i += length


def split_user_id(raw: bytes) -> dict | None:
    """`Name (comment) <address>` into its parts. The text is the key owner's own."""
    text = _text(raw.decode("utf-8", errors="replace"), 400)
    if not text:
        return None
    if _BARE_EMAIL_RE.fullmatch(text):
        return {"name": "", "email": text[:254], "comment": ""}
    m = _UID_RE.match(text)
    if not m:
        return {"name": text[:120], "email": "", "comment": ""}
    return {
        "name": (m.group("name") or "").strip()[:120],
        "email": (m.group("email") or "")[:254],
        "comment": (m.group("comment") or "").strip()[:120],
    }


def _key_facts(body: bytes) -> dict:
    """A public key packet body into the facts shown. Never the key material."""
    version = body[0] if body else 0
    if version != 4 or len(body) < 6:
        # v3 fingerprints are MD5 over the key numbers, v5 and v6 use SHA-256 with their own
        # framing. None of them is worked out here.
        return {"parsed": False, "version": version, "reason": f"Version {version} key: not read."}
    if len(body) > 0xFFFF:
        # The version 4 fingerprint frames the body with a two byte length, so a longer body
        # has no fingerprint. Reported as unread, never guessed at.
        return {"parsed": False, "version": 4, "reason": "Version 4 key packet too large to have a fingerprint: not read."}
    fingerprint = hashlib.sha1(b"\x99" + len(body).to_bytes(2, "big") + body).hexdigest().upper()
    created = int.from_bytes(body[1:5], "big")
    algo = body[5]
    out = {
        "parsed": True,
        "version": 4,
        "fingerprint": fingerprint,
        "key_id": fingerprint[-16:],
        "created": datetime.fromtimestamp(created, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "algorithm": ALGORITHMS.get(algo, f"algorithm {algo}"),
        "bits": None,
        "curve": "",
        "url": f"https://{HOST}/vks/v1/by-fingerprint/{fingerprint}",
    }
    rest = body[6:]
    if algo in (1, 2, 3, 16, 17) and len(rest) >= 2:
        out["bits"] = int.from_bytes(rest[:2], "big")          # the bit count of the first number
    elif algo in (18, 19, 22) and rest and 0 < rest[0] < 0xFF and len(rest) > rest[0]:
        out["curve"] = CURVES.get(rest[1:1 + rest[0]].hex(), "")
    return out


def _is_key_revocation(body: bytes) -> bool:
    if len(body) >= 2 and body[0] in (4, 5, 6):
        return body[1] == 0x20
    if len(body) >= 3 and body[0] == 3:
        return body[2] == 0x20
    return False


def parse_keys(armored: str) -> list[dict]:
    """Every key in an armored block. Raises _Unreadable when nothing in it is a key."""
    keys: list[dict] = []
    current: dict | None = None
    direct = False          # still between the primary key and its first user ID or subkey
    for tag, body in packets(dearmor(armored)):
        if tag == 6:
            if len(keys) >= MAX_KEYS:
                break
            current = {**_key_facts(body), "user_ids": [], "subkeys": 0, "revoked": False}
            keys.append(current)
            direct = True
        elif current is None:
            continue
        elif tag == 2:
            if direct and _is_key_revocation(body):
                current["revoked"] = True
        elif tag == 13:
            direct = False
            uid = split_user_id(body)
            if uid and len(current["user_ids"]) < MAX_USER_IDS and uid not in current["user_ids"]:
                current["user_ids"].append(uid)
        elif tag == 14:
            direct = False
            current["subkeys"] += 1
        elif tag == 17:        # a photo. Never read, never returned.
            direct = False
    if not keys:
        raise _Unreadable("no public key packet")
    return keys


async def lookup(client: httpx.AsyncClient, email: str) -> dict:
    """{state, keys} plus the error fields when the keyserver did not answer. Never raises:
    anything unexpected, in the request or in reading the key, is `failed`."""
    try:
        return await _lookup(client, email)
    except Exception as e:  # noqa: BLE001
        # The class name only: the request URL carries the address.
        fields = error_fields(code=classify(e), detail=type(e).__name__)
        log.warning("openpgp lookup did not answer", extra={"error_code": fields["error_code"]})
        return {"state": "failed", "keys": [], **fields}


async def _lookup(client: httpx.AsyncClient, email: str) -> dict:
    url = f"https://{HOST}/vks/v1/by-email/{quote(email, safe='')}"
    try:
        async with client.stream("GET", url, headers={"User-Agent": USER_AGENT, "Accept-Encoding": "identity"},
                                 follow_redirects=False) as resp:
            status = resp.status_code
            retry = resp.headers.get("retry-after", "")
            buf = bytearray()
            if status == 200:
                async for chunk in resp.aiter_bytes():
                    buf += chunk
                    if len(buf) > MAX_BYTES:
                        break
    except Exception as e:
        # The class name only: the request URL carries the address.
        fields = error_fields(code=classify(e), detail=type(e).__name__)
        log.warning("openpgp lookup did not answer", extra={"error_code": fields["error_code"]})
        return {"state": "failed", "keys": [], **fields}

    if status == 404:
        return {"state": "none", "keys": []}
    if status == 429:
        log.warning("openpgp lookup rate limited")
        out = {"state": "rate_limited", "keys": [],
               **error_fields(code="rate_limited", detail=f"HTTP 429 from {HOST}")}
        if retry.isdigit():
            out["retry_after"] = max(1, int(retry))
        return out
    if status != 200:
        log.warning("openpgp lookup did not answer", extra={"status": status})
        return {"state": "failed", "keys": [], **error_fields(code="upstream", detail=f"HTTP {status} from {HOST}")}
    if len(buf) > MAX_BYTES:
        return {"state": "failed", "keys": [],
                **error_fields(code="bad_response", detail=f"Key larger than {MAX_BYTES} bytes from {HOST}")}
    try:
        keys = parse_keys(bytes(buf).decode("ascii", errors="replace"))
    except _Unreadable as e:
        log.warning("openpgp key unreadable", extra={"reason": str(e)})
        return {"state": "failed", "keys": [],
                **error_fields(code="bad_response", detail=f"Unreadable key from {HOST}")}
    except Exception as e:  # noqa: BLE001  (a key built to break the reader is an unreadable key)
        log.warning("openpgp key unreadable", extra={"reason": type(e).__name__})
        return {"state": "failed", "keys": [],
                **error_fields(code="bad_response", detail=f"Unreadable key from {HOST}")}
    return {"state": "ok", "keys": keys}
