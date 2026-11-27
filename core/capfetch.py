"""
A size cap for bodies fetched from a host the user typed, and the one bounded reader every
capped fetch in the server uses.

`core.netguard.safe_fetch` decides where a request may go. It reads the whole body, so a
target could answer with gigabytes, or with a few kilobytes of gzip that inflate to gigabytes.
`CappedTransport` sits under the client that `safe_fetch` drives and bounds both:

  * a declared Content-Length over the cap is refused before a byte of the body is read;
  * the body is read by `read_body`, below;
  * any other content coding (br, zstd) is refused: nothing here can bound it.

`read_body` reads a body as a stream of the bytes on the wire and holds no more than
`max_bytes` of it (core.pinned and modules.profile_archive read through it too):

  * gzip and deflate are inflated here, chunk by chunk, each call told how many bytes are
    still wanted, so the cap is on the bytes the caller will hold, not on the bytes on the wire;
  * the bytes on the wire are capped as well (`raw_allowance`): a compressed body that takes
    more of them than its cap could ever need is not a body, it is an error;
  * reading stops where the compressed body ends. Bytes that follow it are never fed to the
    inflater and never kept; the body is then marked as cut ("trailing"), like one cut at the cap;
  * a compressed body that stops before its end is an error, never a short body.

Two modes. `truncate=False` raises `TooLarge` (a document cut short is not a document) and
`BadEncoding` for a body with bytes after its end. `truncate=True` keeps what was read and
marks the response (`was_capped`): the start of an HTML page is still worth reading.

The cap is on size only. Callers bound time with `asyncio.wait_for` or `asyncio.timeout`.
A caller that fetched a large body calls `release` on the response, so the body is freed as
soon as it is done with it and not whenever the cycle collector next runs.
"""

import zlib

import httpx


class TooLarge(Exception):
    """The body is larger than the cap. `declared` is the Content-Length, or 0 if none was sent."""

    def __init__(self, declared: int = 0):
        super().__init__("body larger than the cap")
        self.declared = declared


class BadEncoding(Exception):
    """The body came in a content coding that cannot be bounded here, or would not inflate."""


_INFLATE = ("gzip", "x-gzip", "deflate")
_DROP = {"content-encoding", "content-length", "transfer-encoding"}
_CAPPED = "crawlr_capped"
_PEEKS = 4                    # reads made after a compressed body ended, to see whether more follows


def was_capped(resp: httpx.Response) -> bool:
    """True when the body is only the first part of what the server sent."""
    return bool(resp.extensions.get(_CAPPED))


def release(resp: httpx.Response) -> httpx.Response:
    """Let a response that has been read be freed the moment its last user lets go of it.
    The HTTP client leaves every response pointing at a stream wrapper that points back at
    the response, so without this a body of megabytes stays in memory until the interpreter's
    cycle collector happens to run. The body itself (`resp.content`) is untouched."""
    resp.stream = httpx.ByteStream(b"")
    return resp


def coding_of(headers) -> str:
    """The content coding a response states, lower case; "identity" when it states none."""
    return (headers.get("content-encoding") or "identity").strip().lower() or "identity"


def raw_allowance(max_bytes: int) -> int:
    """The most bytes on the wire a compressed body of at most `max_bytes` is given. Deflate
    never needs more than the plain size and a little framing, so this is generous."""
    return max_bytes + max(65_536, max_bytes // 8)


async def read_body(chunks, coding: str, max_bytes: int) -> tuple[bytes, str]:
    """(the body, at most `max_bytes` of it, how it was cut) from the chunks of a response as
    they came off the wire. The second value is "" for a whole body, "size" when the body is
    longer than the cap, and "trailing" when a compressed body ended and more bytes followed.
    Raises BadEncoding for a coding that cannot be bounded, a body that does not inflate, one
    that stops before its end, and one that spends its wire allowance without filling the cap."""
    coding = (coding or "identity").strip().lower()
    if coding not in ("", "identity", *_INFLATE):
        raise BadEncoding(coding[:40])
    # wbits 47: zlib or gzip framing, found from the header
    inflater = zlib.decompressobj(47) if coding in _INFLATE else None
    allowance = raw_allowance(max_bytes)
    body = bytearray()
    raw = 0
    cut = ""
    stream = chunks.__aiter__()
    async for chunk in stream:
        if inflater is None:
            body += chunk
            if len(body) > max_bytes:
                cut = "size"
                break
            continue
        raw += len(chunk)
        if raw > allowance:
            raise BadEncoding(coding)
        try:
            body += inflater.decompress(chunk, max_bytes + 1 - len(body))
        except zlib.error as e:
            raise BadEncoding(coding) from e
        if len(body) > max_bytes or inflater.unconsumed_tail:
            cut = "size"
            break
        if inflater.eof:
            # The body is complete. Nothing after it is inflated or kept; a few reads tell
            # whether anything was sent after it.
            more = bool(inflater.unused_data)
            for _ in range(_PEEKS):
                if more:
                    break
                try:
                    more = bool(await stream.__anext__())
                except StopAsyncIteration:
                    break
            cut = "trailing" if more else ""
            break
    else:
        if inflater is not None and raw and not inflater.eof:
            raise BadEncoding(coding)
    del body[max_bytes:]
    return bytes(body), cut


class CappedTransport(httpx.AsyncBaseTransport):
    def __init__(self, inner: httpx.AsyncBaseTransport, max_bytes: int, *, truncate: bool = False):
        self._inner = inner
        self._max = max_bytes
        self._truncate = truncate

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        resp = await self._inner.handle_async_request(request)
        try:
            try:
                declared = int(resp.headers.get("content-length") or 0)
            except ValueError:
                declared = 0
            coding = coding_of(resp.headers)
            if declared > self._max and not self._truncate and coding == "identity":
                raise TooLarge(declared)
            body, cut = await read_body(resp.stream, coding, self._max)
            if cut and not self._truncate:
                if cut == "trailing":
                    raise BadEncoding(coding)
                raise TooLarge(declared)
        finally:
            await resp.aclose()
        headers = [(k, v) for k, v in resp.headers.raw if k.decode("latin-1").lower() not in _DROP]
        return httpx.Response(
            resp.status_code, headers=headers, content=body,
            extensions={**resp.extensions, _CAPPED: bool(cut)}, request=request,
        )

    async def aclose(self) -> None:
        await self._inner.aclose()
