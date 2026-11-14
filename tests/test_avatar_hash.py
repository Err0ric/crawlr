"""Avatar hashing. Images are generated here and served by a mock transport: no network."""

import asyncio
import io
import random

import httpx
import pytest
from fastapi.testclient import TestClient
from PIL import Image, ImageDraw

from core import netguard as ng
from main import app
from modules import avatar_hash as ah

HOST = "https://93.184.216.34"      # a public literal, so the guard needs no DNS


@pytest.fixture(autouse=True)
def _clean():
    ah.clear_cache_for_tests()
    yield
    ah.clear_cache_for_tests()


def picture(seed: int, size: int = 256) -> Image.Image:
    """A deterministic photo-like image: a smooth gradient with soft blobs on top."""
    rnd = random.Random(seed)
    base = 512
    img = Image.new("RGB", (base, base))
    px = img.load()
    ax, ay = rnd.uniform(0.2, 0.5), rnd.uniform(0.2, 0.5)
    for y in range(base):
        for x in range(base):
            v = int(x * ax + y * ay) % 256
            px[x, y] = (v, (v + 60) % 256, 255 - v)
    draw = ImageDraw.Draw(img)
    for _ in range(14):
        x, y, r = rnd.randrange(base), rnd.randrange(base), rnd.randrange(40, 150)
        draw.ellipse((x - r, y - r, x + r, y + r), fill=tuple(rnd.randrange(256) for _ in range(3)))
    return img.resize((size, size), Image.Resampling.LANCZOS)


def encode(img: Image.Image, fmt: str = "PNG", **kw) -> bytes:
    buf = io.BytesIO()
    img.save(buf, fmt, **kw)
    return buf.getvalue()


def identicon() -> Image.Image:
    img = Image.new("RGB", (420, 420), (240, 240, 240))
    draw = ImageDraw.Draw(img)
    for cx, cy in [(1, 0), (3, 0), (2, 1), (0, 2), (4, 2), (2, 3), (1, 4), (3, 4)]:
        draw.rectangle((35 + cx * 70, 35 + cy * 70, 104 + cx * 70, 104 + cy * 70), fill=(110, 170, 90))
    return img


def serve(monkeypatch, routes: dict, calls: list | None = None):
    """routes: path -> (content_type, bytes) | httpx.Response | callable(request)."""

    def handler(request: httpx.Request):
        if calls is not None:
            calls.append(request)
        hit = routes.get(request.url.path)
        if hit is None:
            return httpx.Response(404, text="nope")
        if callable(hit):
            return hit(request)
        if isinstance(hit, httpx.Response):
            return hit
        ctype, body = hit
        return httpx.Response(200, content=body, headers={"content-type": ctype})

    monkeypatch.setattr(ah, "_inner_transport", lambda: httpx.MockTransport(handler))


def run(images):
    return asyncio.run(ah.run_avatar_hash(images))["results"]


# ---- the hash ----------------------------------------------------------------------

def test_hash_is_deterministic_and_16_hex_chars():
    data = encode(picture(1))
    a, b = ah.hash_image(data), ah.hash_image(data)
    assert a == b and a["default"] is False
    assert len(a["hash"]) == 16 and int(a["hash"], 16) >= 0


def test_resized_and_recompressed_copies_match_and_a_different_picture_does_not():
    big = ah.hash_image(encode(picture(1, 400)))["hash"]
    small = ah.hash_image(encode(picture(1, 96)))["hash"]
    jpeg = ah.hash_image(encode(picture(1, 200), "JPEG", quality=70))["hash"]
    other = ah.hash_image(encode(picture(2, 400)))["hash"]
    assert ah.hamming(big, small) <= 4
    assert ah.hamming(big, jpeg) <= 4
    assert ah.hamming(big, other) > 10


def test_transparent_png_hashes_like_the_same_picture_on_white():
    rgba = Image.new("RGBA", (128, 128), (0, 0, 0, 0))
    ImageDraw.Draw(rgba).ellipse((20, 30, 90, 110), fill=(200, 30, 30, 255))
    flat = Image.new("RGB", (128, 128), (255, 255, 255))
    ImageDraw.Draw(flat).ellipse((20, 30, 90, 110), fill=(200, 30, 30))
    assert ah.hamming(ah.hash_image(encode(rgba))["hash"], ah.hash_image(encode(flat))["hash"]) <= 2


# ---- placeholders ------------------------------------------------------------------

def test_flat_tiny_and_identicon_images_are_default():
    assert ah.hash_image(encode(Image.new("RGB", (200, 200), (204, 214, 221))))["default"] is True   # one color
    assert ah.hash_image(encode(picture(3, 12)))["default"] is True                                  # under 16 px
    assert ah.hash_image(encode(identicon()))["default"] is True                                     # two flat tones
    assert ah.hash_image(encode(identicon(), "JPEG", quality=60))["default"] is True                 # with JPEG noise
    assert ah.hash_image(encode(picture(3)))["default"] is False


@pytest.mark.parametrize("url", [
    "https://abs.twimg.com/sticky/default_profile_images/default_profile_normal.png",
    "https://assets.leetcode.com/users/default_avatar.jpg",
    "https://simg-ssl.duolingo.com/avatar/default_2/large",
    "https://pastebin.com/themes/pastebin/img/guest.png",
    "https://a.disquscdn.com/1699999999/images/noavatar92.png",
    "https://www.gravatar.com/avatar/00000000000000000000000000000000?d=mp",
    "https://www.gravatar.com/avatar/?d=identicon",
    "https://github.com/identicons/someone.png",
    "https://www.redditstatic.com/avatars/defaults/v2/avatar_default_3.png",
    "https://cdn.discordapp.com/embed/avatars/2.png",
    "https://static-cdn.jtvnw.net/user-default-pictures-uv/abc-profile_image-300x300.png",
    "https://example.org/static/img/no-avatar.png",
])
def test_known_default_avatar_urls(url):
    assert ah.is_default_url(url) is True


@pytest.mark.parametrize("url", [
    "https://avatars.githubusercontent.com/u/1024025?v=4",
    "https://pbs.twimg.com/profile_images/123/abc_400x400.jpg",
    # d= only names the fallback: this URL still serves the real picture when one exists
    "https://www.gravatar.com/avatar/fb2e5c7f1b2ad9a2bb1c3f0f0f6d2a11?d=identicon",
])
def test_real_avatar_urls_are_not_default(url):
    assert ah.is_default_url(url) is False


def test_default_url_marks_the_result_even_when_the_image_looks_real(monkeypatch):
    serve(monkeypatch, {"/img/default_avatar.jpg": ("image/png", encode(picture(4))),
                        "/u/1.png": ("image/png", encode(picture(4)))})
    out = run([{"id": "a", "url": f"{HOST}/img/default_avatar.jpg"}, {"id": "b", "url": f"{HOST}/u/1.png"}])
    assert out[0]["default"] is True and out[1]["default"] is False and out[0]["hash"] == out[1]["hash"]


# ---- fetching ----------------------------------------------------------------------

def test_results_keep_request_order_and_ids(monkeypatch):
    serve(monkeypatch, {"/a.png": ("image/png", encode(picture(1))), "/b.jpg": ("image/jpeg; charset=binary", encode(picture(2), "JPEG"))})
    out = run([{"id": "acct:github", "url": f"{HOST}/a.png"}, {"id": "acct:gitlab", "url": f"{HOST}/b.jpg"}, {"id": "acct:missing", "url": f"{HOST}/gone.png"}])
    assert [r["id"] for r in out] == ["acct:github", "acct:gitlab", "acct:missing"]
    assert set(out[0]) == {"id", "hash", "default"} and out[0]["hash"] != out[1]["hash"]
    assert out[2]["error_code"] == "not_found" and "hash" not in out[2]


def test_non_image_responses_are_rejected(monkeypatch):
    serve(monkeypatch, {
        "/page": ("text/html; charset=utf-8", b"<html>login</html>"),
        "/logo.svg": ("image/svg+xml", b"<svg xmlns='http://www.w3.org/2000/svg'/>"),
        "/liar.png": ("image/png", b"this is not a png"),
        "/untyped": httpx.Response(200, content=encode(picture(1))),
    })
    out = run([{"id": k, "url": f"{HOST}/{k}"} for k in ("page", "logo.svg", "liar.png", "untyped")])
    assert [r["error_code"] for r in out] == ["not_image", "not_image", "bad_response", "not_image"]
    assert all("hash" not in r and r["error"] for r in out)


def test_oversize_images_are_rejected(monkeypatch):
    big = b"\x89PNG" + b"\0" * (ah.MAX_BYTES + 10)

    async def chunks():
        for i in range(0, len(big), 65536):
            yield big[i:i + 65536]

    serve(monkeypatch, {
        "/declared.png": ("image/png", big),                                             # Content-Length says so
        "/streamed.png": lambda r: httpx.Response(200, content=chunks(), headers={"content-type": "image/png"}),
        "/gzip.png": httpx.Response(200, content=b"x", headers={"content-type": "image/png", "content-encoding": "gzip"}),
    })
    out = run([{"id": "d", "url": f"{HOST}/declared.png"}, {"id": "s", "url": f"{HOST}/streamed.png"}, {"id": "g", "url": f"{HOST}/gzip.png"}])
    assert out[0]["error_code"] == "too_large" and out[1]["error_code"] == "too_large"
    assert out[2]["error_code"] == "bad_response"


def test_small_file_with_huge_dimensions_is_refused_before_decoding(monkeypatch):
    # 20 megapixels of transparent RGBA compress to a few KB and would decode to about 80 MB.
    bomb = encode(Image.new("RGBA", (4472, 4472), (0, 0, 0, 0)))
    assert len(bomb) < 200_000 < ah.MAX_BYTES
    loaded = []
    real_load = Image.Image.load
    monkeypatch.setattr(Image.Image, "load", lambda self, *a, **k: (loaded.append(self.size), real_load(self, *a, **k))[1])
    with pytest.raises(ah._Rejected) as e:
        ah.hash_image(bomb)
    assert e.value.code == "too_large" and (4472, 4472) not in loaded      # rejected from the header alone

    serve(monkeypatch, {"/bomb.png": ("image/png", bomb)})
    out = run([{"id": "x", "url": f"{HOST}/bomb.png"}])
    assert out[0]["error_code"] == "too_large" and "hash" not in out[0]
    assert ah.MAX_PIXELS <= 4_000_000 and Image.MAX_IMAGE_PIXELS is not None


def test_images_up_to_the_pixel_cap_still_hash_and_work_on_a_thumbnail():
    big = picture(1, 512).resize((2000, 2000), Image.Resampling.BILINEAR)       # exactly 4 MP
    gray, size = ah._open_gray(encode(big, "JPEG", quality=80))
    assert size == (2000, 2000) and max(gray.size) <= ah.WORK_SIDE and gray.mode == "L"
    rgba, _ = ah._open_gray(encode(big.convert("RGBA").resize((1500, 1500))))
    assert max(rgba.size) <= ah.WORK_SIDE
    assert ah.hamming(ah.dhash(gray), ah.hash_image(encode(picture(1, 96)))["hash"]) <= 4


@pytest.mark.parametrize("fmt", ["TIFF", "BMP", "PPM", "ICO", "EPS"])
def test_formats_outside_the_allow_list_are_refused_whatever_the_content_type(monkeypatch, fmt):
    data = encode(picture(1, 64).convert("RGB"), fmt)
    assert Image.open(io.BytesIO(data)).format == fmt       # Pillow could read it if allowed to
    with pytest.raises(ah._Rejected) as e:
        ah.hash_image(data)
    assert e.value.code == "bad_response"
    serve(monkeypatch, {"/a.png": ("image/png", data)})
    assert run([{"id": "x", "url": f"{HOST}/a.png"}])[0]["error_code"] == "bad_response"


def test_decoding_is_limited_to_two_at_a_time_while_fetches_run_six_wide(monkeypatch):
    import threading
    import time as _time
    lock = threading.Lock()
    state = {"decoding": 0, "peak_decode": 0, "fetching": 0, "peak_fetch": 0}
    real_open = ah._open_gray

    def slow_open(data):
        with lock:
            state["decoding"] += 1
            state["peak_decode"] = max(state["peak_decode"], state["decoding"])
        _time.sleep(0.03)
        try:
            return real_open(data)
        finally:
            with lock:
                state["decoding"] -= 1

    real_fetch = ah._fetch

    async def slow_fetch(client, url):
        state["fetching"] += 1
        state["peak_fetch"] = max(state["peak_fetch"], state["fetching"])
        await asyncio.sleep(0.02)
        try:
            return await real_fetch(client, url)
        finally:
            state["fetching"] -= 1

    monkeypatch.setattr(ah, "_open_gray", slow_open)
    monkeypatch.setattr(ah, "_fetch", slow_fetch)
    serve(monkeypatch, {f"/{i}.png": ("image/png", encode(picture(1, 32))) for i in range(12)})
    out = run([{"id": str(i), "url": f"{HOST}/{i}.png"} for i in range(12)])
    assert all("hash" in r for r in out)
    assert state["peak_decode"] == ah.HASH_CONCURRENCY == 2
    assert 2 < state["peak_fetch"] <= ah.CONCURRENCY == 6


# ---- low-information hashes ----------------------------------------------------------

def gradient(horizontal: bool, start: tuple, end: tuple, size: int = 256) -> Image.Image:
    img = Image.new("RGB", (size, size))
    px = img.load()
    for y in range(size):
        for x in range(size):
            t = (x if horizontal else y) / (size - 1)
            px[x, y] = tuple(int(a + (b - a) * t) for a, b in zip(start, end))
    return img


def test_plain_gradients_are_marked_default_so_they_cannot_match_each_other():
    a = ah.hash_image(encode(gradient(True, (255, 255, 255), (0, 0, 0))))
    b = ah.hash_image(encode(gradient(True, (250, 200, 40), (20, 30, 90))))
    c = ah.hash_image(encode(gradient(False, (255, 255, 255), (0, 0, 0))))
    d = ah.hash_image(encode(gradient(False, (0, 0, 0), (255, 255, 255))))
    # two unrelated gradients share a hash, which is exactly why neither may count as evidence
    assert a["hash"] == b["hash"]
    assert all(r["default"] is True for r in (a, b, c, d))
    # row and column gradients no longer collapse into one value
    assert a["hash"] != c["hash"] and c["hash"] != d["hash"]


@pytest.mark.parametrize("value,expected", [
    ("ffffffffffffffff", True), ("0000000000000000", True), ("ffffffff00000000", True), ("00000000ffffffff", True),
    ("fffffffffffffff0", True),          # 60 bits set
    ("0000000100000100", True),          # 2 bits set
    ("a5a5a5a55a5a5a5a", False), ("3c7e1f80f00ff1e2", False),
])
def test_low_information_rule(value, expected):
    assert ah.low_information(value) is expected


def test_real_pictures_are_not_caught_by_the_low_information_rule():
    for seed in range(1, 9):
        out = ah.hash_image(encode(picture(seed)))
        assert out["default"] is False and not ah.low_information(out["hash"]), seed


@pytest.mark.parametrize("url", [
    "http://127.0.0.1/avatar.png", "http://localhost:8000/a.png", "http://10.0.0.5/a.png", "http://169.254.169.254/latest/meta-data",
    "http://[::1]/a.png", "http://db.railway.internal/a.png", "file:///etc/passwd", "ftp://example.org/a.png",
    "https://user:pw@93.184.216.34/a.png", "not a url",
])
def test_private_and_non_http_urls_are_refused_by_the_guard(monkeypatch, url):
    calls = []
    serve(monkeypatch, {}, calls)
    out = run([{"id": "x", "url": url}])
    assert out == [{"id": "x", **out[0]}] and out[0]["error_code"] == "blocked_target"
    assert calls == []                                    # nothing was requested
    assert "127.0.0.1" not in out[0]["error"] and url not in out[0]["error_detail"]


def test_public_name_resolving_to_loopback_is_refused(monkeypatch):
    monkeypatch.setattr(ng, "_public_dns_blocking", lambda host: [])

    async def getaddrinfo(self, host, port, **kw):
        return [(2, 1, 6, "", ("127.0.0.1", port))]

    monkeypatch.setattr(asyncio.BaseEventLoop, "getaddrinfo", getaddrinfo)
    calls = []
    serve(monkeypatch, {}, calls)
    assert run([{"id": "x", "url": "https://avatars.example.com/a.png"}])[0]["error_code"] == "blocked_target"
    assert calls == []


def test_redirect_to_a_private_address_is_refused(monkeypatch):
    calls = []
    serve(monkeypatch, {"/a.png": httpx.Response(302, headers={"location": "http://169.254.169.254/latest/meta-data"})}, calls)
    assert run([{"id": "x", "url": f"{HOST}/a.png"}])[0]["error_code"] == "blocked_target"
    assert len(calls) == 1


def test_redirect_to_a_public_image_is_followed(monkeypatch):
    serve(monkeypatch, {"/a": httpx.Response(302, headers={"location": "/real.png"}), "/real.png": ("image/png", encode(picture(5)))})
    assert run([{"id": "x", "url": f"{HOST}/a"}])[0]["hash"] == ah.hash_image(encode(picture(5)))["hash"]


def test_timeouts_are_reported_as_errors(monkeypatch):
    def slow(request):
        raise httpx.ReadTimeout("timed out")
    serve(monkeypatch, {"/a.png": slow})
    assert run([{"id": "x", "url": f"{HOST}/a.png"}])[0]["error_code"] == "timeout"


# ---- cache and limits --------------------------------------------------------------

def test_each_url_is_fetched_once_and_then_served_from_cache(monkeypatch):
    calls = []
    serve(monkeypatch, {"/a.png": ("image/png", encode(picture(1)))}, calls)
    first = run([{"id": "one", "url": f"{HOST}/a.png"}, {"id": "two", "url": f"{HOST}/a.png"}])
    assert len(calls) == 1 and first[0]["hash"] == first[1]["hash"] and [r["id"] for r in first] == ["one", "two"]
    again = run([{"id": "three", "url": f"{HOST}/a.png"}])
    assert len(calls) == 1 and again[0] == {"id": "three", "hash": first[0]["hash"], "default": False}


def test_failures_are_not_cached(monkeypatch):
    serve(monkeypatch, {"/a.png": httpx.Response(503, text="busy")})
    assert run([{"id": "x", "url": f"{HOST}/a.png"}])[0]["error_code"] == "upstream"
    serve(monkeypatch, {"/a.png": ("image/png", encode(picture(1)))})
    assert "hash" in run([{"id": "x", "url": f"{HOST}/a.png"}])[0]


def test_cache_is_bounded(monkeypatch):
    monkeypatch.setattr(ah, "CACHE_MAX", 3)
    for i in range(6):
        ah._cache_put(f"u{i}", {"hash": "0" * 16, "default": False})
    assert list(ah._cache) == ["u3", "u4", "u5"]


def test_at_most_30_images_per_call(monkeypatch):
    calls = []
    serve(monkeypatch, {f"/{i}.png": ("image/png", encode(picture(1, 32))) for i in range(40)}, calls)
    out = run([{"id": str(i), "url": f"{HOST}/{i}.png"} for i in range(40)])
    assert len(out) == 30 and len(calls) == 30


def test_route_validates_the_request(monkeypatch):
    serve(monkeypatch, {"/a.png": ("image/png", encode(picture(1)))})
    with TestClient(app) as c:
        ok = c.post("/api/recon/avatar-hash", json={"images": [{"id": "acct:github", "url": f"{HOST}/a.png"}]})
        assert ok.status_code == 200 and len(ok.json()["results"][0]["hash"]) == 16
        assert c.post("/api/recon/avatar-hash", json={"images": []}).json() == {"results": []}
        too_many = [{"id": str(i), "url": f"{HOST}/a.png"} for i in range(31)]
        assert c.post("/api/recon/avatar-hash", json={"images": too_many}).status_code == 422
        assert c.post("/api/recon/avatar-hash", json={"images": [{"id": "x" * 81, "url": f"{HOST}/a.png"}]}).status_code == 422
        assert c.post("/api/recon/avatar-hash", json={"images": [{"id": "x", "url": HOST + "/" + "a" * 600}]}).status_code == 422
        assert c.post("/api/recon/avatar-hash", json={"images": [{"url": f"{HOST}/a.png"}]}).status_code == 422
        assert c.post("/api/recon/avatar-hash", json={}).status_code == 422


def test_pictures_on_adult_or_dating_hosts_are_never_fetched(monkeypatch):
    calls = []
    serve(monkeypatch, {}, calls)
    out = run([{"id": "a", "url": "https://cdn.fansly.com/someone/avatar.jpg"}, {"id": "b", "url": "https://www.pornhub.com/x.png"}])
    assert [r.get("error_code") for r in out] == ["adult_site", "adult_site"]
    assert calls == []
