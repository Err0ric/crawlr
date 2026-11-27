"""
A size cap for bodies fetched from a host the user typed.

`core.netguard.safe_fetch` decides where a request may go. It reads the whole body, so a
target could answer with gigabytes, or with a few kilobytes of gzip that inflate to gigabytes.
`CappedTransport` sits under the client that `safe_fetch` drives and bounds both:

  * a declared Content-Length over the cap is refused before a byte of the body is read;
  * the body is read as a stream and the stream is dropped the moment it passes the cap;
  * gzip and deflate are inflated here, chunk by chunk, against the same cap, so the cap is
    on the bytes the caller will hold, not on the bytes on the wire;
  * any other content coding (br, zstd) is refused: nothing here can bound it.

Two modes. `truncate=False` raises `TooLarge` (a document cut short is not a document).
`truncate=True` keeps the first `max_bytes` and marks the response (`was_capped`): the start
of an HTML page is still worth reading.

The cap is on size only. Callers bound time with `asyncio.wait_for`.
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


def was_capped(resp: httpx.Response) -> bool:
    """True when the body is only the first `max_bytes` of what the server sent."""
    return bool(resp.extensions.get(_CAPPED))


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
            coding = (resp.headers.get("content-encoding") or "identity").strip().lower()
            if coding not in ("", "identity", *_INFLATE):
                raise BadEncoding(coding[:40])
            if declared > self._max and not self._truncate and coding in ("", "identity"):
                raise TooLarge(declared)
            # wbits 47: zlib or gzip framing, found from the header
            inflater = zlib.decompressobj(47) if coding in _INFLATE else None
            body = bytearray()
            capped = False
            async for chunk in resp.stream:
                if inflater is not None:
                    try:
                        chunk = inflater.decompress(chunk, self._max + 1 - len(body))
                    except zlib.error as e:
                        raise BadEncoding(coding) from e
                    if inflater.unconsumed_tail:
                        capped = True
                body += chunk
                if len(body) > self._max:
                    capped = True
                if capped:
                    break
            if capped and not self._truncate:
                raise TooLarge(declared)
        finally:
            await resp.aclose()
        headers = [(k, v) for k, v in resp.headers.raw if k.decode("latin-1").lower() not in _DROP]
        return httpx.Response(
            resp.status_code, headers=headers, content=bytes(body[: self._max]),
            extensions={**resp.extensions, _CAPPED: capped}, request=request,
        )

    async def aclose(self) -> None:
        await self._inner.aclose()
