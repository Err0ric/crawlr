"""
Perceptual hashes for profile pictures.

Two accounts that use the same picture are a strong link between them, and a visual match
survives the resizing and recompression every platform applies. Each image is fetched once,
reduced to a 64-bit difference hash (dHash) and thrown away: nothing but the hash is kept.

Placeholders are marked `default: true` so the default avatar a platform gives every new
account is never read as a match.

Avatar URLs come from third-party pages, so every fetch goes through core.netguard.safe_fetch
and is capped in size, time and pixel count.
"""

import asyncio
import io
import re
import threading
import time
from collections import OrderedDict

import httpx
from PIL import Image

from core.errors import classify_status, error_fields
from core.netguard import safe_fetch

MAX_IMAGES = 30
MAX_BYTES = 2 * 1024 * 1024
FETCH_TIMEOUT = 8
CONCURRENCY = 6
MAX_REDIRECTS = 4
HASH_CONCURRENCY = 2                # decodes at once, across all requests
MAX_PIXELS = 4_000_000              # decoded size cap: a 4 MP RGBA image is about 16 MB in memory
WORK_SIDE = 128                     # everything after decoding works on a thumbnail this size
ALLOWED_FORMATS = ["PNG", "JPEG", "GIF", "WEBP"]
MIN_SIDE = 16
MIN_GRAY_LEVELS = 8
UA = "Mozilla/5.0 (compatible; CrawlR/1.0; +https://crawlr.lol)"

# Pillow's own bomb guard, as a backstop. Oversized images are rejected below from the header
# alone, before any pixel is decoded.
Image.MAX_IMAGE_PIXELS = 20_000_000

# A small file can still decode to tens of megabytes, so only a couple are decoded at a time.
_decode_slots = threading.BoundedSemaphore(HASH_CONCURRENCY)

CACHE_TTL = 86400
CACHE_MAX = 5000
_cache: "OrderedDict[str, tuple[float, dict]]" = OrderedDict()

# URL shapes of the picture a platform shows when the account never uploaded one.
# Gravatar's d= parameter is not in this list: it only names the fallback, and the URL still
# returns the real picture when there is one. Generated identicons are caught by the image test.
DEFAULT_URL_PATTERNS = [re.compile(p, re.I) for p in (
    r"twimg\.com/sticky/default_profile",
    r"default_profile(_images)?",
    r"gravatar\.com/avatar/(0{32})?(\?|$)",
    r"default[-_]?avatar",
    r"avatar[-_/]default",
    r"default[-_]?(user|profile|pic|picture|photo|image|icon)",
    r"/default\.(png|jpe?g|gif|webp)",
    r"pastebin\.com/.*guest\.png",
    r"no[-_]?avatar",
    r"no[-_]?(photo|image|picture|profile)\b",
    r"/identicons?/",
    r"avatar_default_",
    r"user-default-pictures",
    r"cdn\.discordapp\.com/embed/avatars/",
    r"fef49e7fa7e1997310d705b2a6158ff8dc1cdfeb",      # Steam's question mark
    r"blank[-_]?(avatar|profile|user)",
    r"(avatar|profile|user)[-_]?(placeholder|blank|anonymous)",
    r"placeholder[-_]?(avatar|profile|user)",
    r"mystery[-_]?man",
    r"silhouette",
    r"anonymous[-_]?(user|avatar)",
    r"ghost[-_]?(user|avatar)?\.(png|jpe?g|gif|svg)",
)]


class _Rejected(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def clear_cache_for_tests() -> None:
    _cache.clear()


def _cache_get(url: str) -> dict | None:
    hit = _cache.get(url)
    if not hit:
        return None
    ts, val = hit
    if time.time() - ts > CACHE_TTL:
        _cache.pop(url, None)
        return None
    _cache.move_to_end(url)
    return val


def _cache_put(url: str, val: dict) -> None:
    _cache[url] = (time.time(), val)
    _cache.move_to_end(url)
    while len(_cache) > CACHE_MAX:
        _cache.popitem(last=False)


def is_default_url(url: str) -> bool:
    return any(p.search(url or "") for p in DEFAULT_URL_PATTERNS)


# ---- fetching ----------------------------------------------------------------------

class _CappedStream(httpx.AsyncByteStream):
    """Stops a download as soon as it passes the size cap, whatever Content-Length claimed."""

    def __init__(self, inner):
        self._inner = inner

    async def __aiter__(self):
        seen = 0
        async for chunk in self._inner:
            seen += len(chunk)
            if seen > MAX_BYTES:
                raise _Rejected("too_large", "The image is larger than 2 MB.")
            yield chunk

    async def aclose(self):
        await self._inner.aclose()


class _CappedTransport(httpx.AsyncBaseTransport):
    def __init__(self, inner: httpx.AsyncBaseTransport):
        self._inner = inner

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        resp = await self._inner.handle_async_request(request)
        try:
            declared = int(resp.headers.get("content-length") or 0)
        except ValueError:
            declared = 0
        encoding = (resp.headers.get("content-encoding") or "identity").strip().lower()
        if declared > MAX_BYTES or encoding not in ("", "identity"):
            # A compressed body could expand past the cap after it is counted, so it is refused.
            await resp.aclose()
            if declared > MAX_BYTES:
                raise _Rejected("too_large", "The image is larger than 2 MB.")
            raise _Rejected("bad_response", "The image host sent a compressed response CrawlR does not accept.")
        return httpx.Response(
            resp.status_code, headers=resp.headers, stream=_CappedStream(resp.stream),
            extensions=resp.extensions, request=request,
        )

    async def aclose(self):
        await self._inner.aclose()


def _inner_transport() -> httpx.AsyncBaseTransport:
    """The real network transport. Tests replace this with a mock."""
    return httpx.AsyncHTTPTransport(retries=0)


def _client() -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=_CappedTransport(_inner_transport()), timeout=FETCH_TIMEOUT)


async def _fetch(client: httpx.AsyncClient, url: str) -> bytes:
    got = await safe_fetch(
        client, url, max_redirects=MAX_REDIRECTS,
        headers={"User-Agent": UA, "Accept": "image/*", "Accept-Encoding": "identity"},
    )
    resp = got.response
    if resp.status_code != 200:
        code = classify_status(resp.status_code)
        raise _Rejected(code, error_fields(code=code)["error"])
    ctype = (resp.headers.get("content-type") or "").split(";")[0].strip().lower()
    if not ctype.startswith("image/"):
        raise _Rejected("not_image", "This URL does not serve an image.")
    if ctype == "image/svg+xml":
        raise _Rejected("not_image", "Vector images cannot be compared.")
    body = resp.content
    if len(body) > MAX_BYTES:
        raise _Rejected("too_large", "The image is larger than 2 MB.")
    return body


# ---- hashing -----------------------------------------------------------------------

def _open_gray(data: bytes) -> tuple[Image.Image, tuple[int, int]]:
    """Decode to a small grayscale thumbnail. Returns (thumbnail, original size)."""
    try:
        # Only the formats avatars come in. EPS, PSD, FLI and the rest are refused whatever
        # the Content-Type header claimed.
        img = Image.open(io.BytesIO(data), formats=ALLOWED_FORMATS)
        size = img.size
        if size[0] * size[1] > MAX_PIXELS:
            raise _Rejected("too_large", "The image has too many pixels to compare.")
        if getattr(img, "is_animated", False):
            img.seek(0)
        img.draft("L", (WORK_SIDE, WORK_SIDE))      # JPEG: decode at reduced size
        # Shrink first, so the transparency flatten below never holds a full-size RGBA copy.
        img.thumbnail((WORK_SIDE, WORK_SIDE), Image.Resampling.BOX)
        if img.mode in ("RGBA", "LA", "PA") or (img.mode == "P" and "transparency" in img.info):
            # Flatten transparency onto white so the same picture hashes alike as PNG and JPEG.
            rgba = img.convert("RGBA")
            flat = Image.new("RGBA", rgba.size, (255, 255, 255, 255))
            flat.alpha_composite(rgba)
            img = flat
        return img.convert("L"), size
    except _Rejected:
        raise
    except (Image.DecompressionBombError, Image.DecompressionBombWarning):
        raise _Rejected("too_large", "The image has too many pixels to compare.") from None
    except Exception:
        raise _Rejected("bad_response", "The image could not be read.") from None


def dhash(gray: Image.Image) -> str:
    """
    64-bit difference hash as 16 hex chars: 32 bits of row gradient (9x4, each pixel against its
    right neighbor) followed by 32 bits of column gradient (4x9, each pixel against the one below).
    Using both directions keeps images that only vary along one axis from all hashing alike.
    """
    bits = 0
    rows = gray.resize((9, 4), Image.Resampling.LANCZOS).tobytes()
    for row in range(4):
        for col in range(8):
            bits = (bits << 1) | (1 if rows[row * 9 + col] > rows[row * 9 + col + 1] else 0)
    cols = gray.resize((4, 9), Image.Resampling.LANCZOS).tobytes()
    for row in range(8):
        for col in range(4):
            bits = (bits << 1) | (1 if cols[row * 4 + col] > cols[(row + 1) * 4 + col] else 0)
    return f"{bits:016x}"


def low_information(hash_hex: str) -> bool:
    """
    A hash that is nearly all ones or all zeros, overall or in either half, describes a plain
    gradient or a blank image. Many unrelated pictures share it, so it must not count as a match.
    """
    value = int(hash_hex, 16)
    total = bin(value).count("1")
    row_bits, col_bits = bin(value >> 32).count("1"), bin(value & 0xFFFFFFFF).count("1")
    return total < 8 or total > 56 or any(n < 2 or n > 30 for n in (row_bits, col_bits))


def looks_default(gray: Image.Image, size: tuple[int, int] | None = None) -> bool:
    """Tiny, single-color or flat few-tone images (identicons, initials, silhouettes) are placeholders."""
    w, h = size or gray.size
    if min(w, h) < MIN_SIDE:
        return True
    small = gray.resize((32, 32), Image.Resampling.BOX)
    counts: dict[int, int] = {}
    for v in small.tobytes():
        counts[v >> 3] = counts.get(v >> 3, 0) + 1
    # Count the gray bands that cover a real share of the picture, so the thin blended edge
    # between two flat colors does not make an identicon look like a photograph.
    return sum(1 for n in counts.values() if n >= 10) < MIN_GRAY_LEVELS


def hash_image(data: bytes) -> dict:
    """Bytes -> {hash, default}. Raises _Rejected for anything that is not a readable image."""
    with _decode_slots:
        gray, size = _open_gray(data)
        value = dhash(gray)
        return {"hash": value, "default": looks_default(gray, size) or low_information(value)}


def hamming(a: str, b: str) -> int:
    return bin(int(a, 16) ^ int(b, 16)).count("1")


# ---- entry point -------------------------------------------------------------------

async def _one(client: httpx.AsyncClient, sem: asyncio.Semaphore, url: str) -> dict:
    cached = _cache_get(url)
    if cached is not None:
        return cached
    try:
        async with sem:      # fetch slots only; decoding has its own, smaller limit
            data = await asyncio.wait_for(_fetch(client, url), FETCH_TIMEOUT)
        result = await asyncio.to_thread(hash_image, data)
    except _Rejected as e:
        return error_fields(code=e.code, message=e.message, detail=e.code)
    except Exception as e:
        # error_detail carries the exception type only: the text can hold the image URL.
        return error_fields(e, detail=type(e).__name__)
    result["default"] = bool(result["default"] or is_default_url(url))
    _cache_put(url, result)
    return result


async def run_avatar_hash(images: list[dict]) -> dict:
    """images: [{id, url}] -> {"results": [{id, hash, default} | {id, error, error_code, error_detail}]}"""
    items = [(str(i.get("id") or ""), str(i.get("url") or "").strip()) for i in (images or [])[:MAX_IMAGES]]
    urls = list(dict.fromkeys(url for _id, url in items))
    sem = asyncio.Semaphore(CONCURRENCY)
    async with _client() as client:
        fetched = await asyncio.gather(*(_one(client, sem, url) for url in urls))
    by_url = dict(zip(urls, fetched))
    return {"results": [{"id": id_, **by_url[url]} for id_, url in items]}
