"""
The one path every AI endpoint takes.

Order of operations for a request:

  1. Pick the key (the caller's own, or the house key). No quota touched yet.
  2. Look in the response cache. A hit is returned as-is and costs nothing.
  3. For the house key only: check the caller's free allowance, then spend one call.
  4. Call the provider. If it fails, the free call is refunded.

Provider failures surface as AIError, which main.py turns into a JSON body of
{"detail": "<message>", "code": "<ai_...>"} with a matching status, so the
frontend never sees a bare 500.
"""

from dataclasses import dataclass

from fastapi import Request

from core import house_key as hk
from middleware.observability import client_ip
from modules import ai_provider


@dataclass
class AIResult:
    text: str
    model: str
    tokens: int
    cached: bool
    source: str               # "user" | "house"
    free_remaining: int | None

    def meta(self) -> dict:
        """Fields every AI endpoint includes in its response."""
        return {
            "model": self.model,
            "tokens": self.tokens,
            "cached": self.cached,
            "ai_source": self.source,
            "free_remaining": self.free_remaining,
        }


async def run_ai(
    request: Request,
    x_api_key: str | None,
    x_ai_provider: str | None,
    bucket: str,
    messages: list[dict],
    max_tokens: int,
) -> AIResult:
    key = hk.pick_key(x_api_key, x_ai_provider)
    ip = client_ip(request)
    house = key.source == "house"
    scope = ai_provider.key_scope(key.api_key, key.source)

    def result(resp: dict) -> AIResult:
        return AIResult(
            text=resp["text"],
            model=resp["model"],
            tokens=int(resp.get("input_tokens") or 0) + int(resp.get("output_tokens") or 0),
            cached=bool(resp.get("cached")),
            source=key.source,
            free_remaining=hk.remaining(ip, bucket) if house else None,
        )

    hit = ai_provider.cache_get(ai_provider.cache_key(scope, key.provider, key.model, messages, max_tokens))
    if hit is not None:
        return result({**hit, "cached": True})

    if house:
        hk.check_quota(ip, bucket)
        hk.consume(ip, bucket)
    try:
        resp = await ai_provider.call_ai(
            api_key=key.api_key, provider=key.provider, model=key.model,
            max_tokens=max_tokens, messages=messages, scope=scope,
        )
    except Exception:
        if house:
            hk.refund(ip, bucket)
        raise
    return result(resp)
