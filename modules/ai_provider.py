"""Unified AI provider abstraction for Anthropic Claude and Google Gemini."""

import hashlib
import json
import os
import time
from collections import OrderedDict

import anthropic
import httpx

from core.ai_text import strip_fences
from core.logging import get_logger

log = get_logger(__name__)

# Default Claude model for people who bring their own Anthropic key. Override with
# ANTHROPIC_MODEL (any current model ID) without a code change.
DEFAULT_ANTHROPIC_MODEL = "claude-sonnet-5-5"
# Current Claude models always think before answering, and thinking tokens count against
# max_tokens. This headroom keeps the written report from being cut short.
ANTHROPIC_THINKING_HEADROOM = int(os.getenv("ANTHROPIC_THINKING_HEADROOM", "6000"))
ANTHROPIC_EFFORT = os.getenv("ANTHROPIC_EFFORT", "medium")
ANTHROPIC_TIMEOUT = float(os.getenv("ANTHROPIC_TIMEOUT", "180"))

GEMINI_THINKING_BUDGET = int(os.getenv("GEMINI_THINKING_BUDGET", "1024"))
AI_CACHE_TTL = int(os.getenv("AI_CACHE_TTL", str(24 * 3600)))
AI_CACHE_MAX = int(os.getenv("AI_CACHE_MAX", "500"))


def anthropic_model() -> str:
    return os.getenv("ANTHROPIC_MODEL") or DEFAULT_ANTHROPIC_MODEL


class AIError(Exception):
    """A provider failure with a message that is safe to show the user.

    code     stable identifier the frontend can branch on
    status   HTTP status the endpoint should answer with
    """

    def __init__(self, code: str, message: str, status: int = 502, retry_after: int | None = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status
        self.retry_after = retry_after


# ---- result cache ---------------------------------------------------------
# The same target run twice in a day produces the same prompt, so the answer is reused
# instead of re-billed. The key covers (scope, provider, model, messages, max_tokens).
# `scope` is "house" for the free tier and a hash of the caller's own key otherwise, so
# an answer paid for with one person's key is never served to someone else, and a request
# with a wrong key cannot read from the cache.
_cache: "OrderedDict[str, tuple[float, dict]]" = OrderedDict()


def key_scope(api_key: str, source: str = "user") -> str:
    if source == "house":
        return "house"
    return "user:" + hashlib.sha256(api_key.encode()).hexdigest()[:24]


def cache_key(scope: str, provider: str, model: str | None, messages: list[dict], max_tokens: int) -> str:
    raw = json.dumps({"s": scope, "p": provider, "m": model, "msgs": messages, "t": max_tokens}, sort_keys=True)
    return hashlib.sha256(raw.encode()).hexdigest()


def cache_get(k: str) -> dict | None:
    hit = _cache.get(k)
    if not hit:
        return None
    ts, val = hit
    if time.time() - ts > AI_CACHE_TTL:
        _cache.pop(k, None)
        return None
    _cache.move_to_end(k)
    return val


def cache_put(k: str, val: dict) -> None:
    _cache[k] = (time.time(), val)
    _cache.move_to_end(k)
    while len(_cache) > AI_CACHE_MAX:
        _cache.popitem(last=False)


def clear_cache_for_tests() -> None:
    _cache.clear()


async def call_ai(api_key: str, provider: str, messages: list[dict], max_tokens: int = 2048, model: str | None = None, scope: str | None = None) -> dict:
    """
    Call an AI provider and return {text, model, input_tokens, output_tokens, cached}.
    Raises AIError on any provider failure.

    scope: cache partition (see key_scope). Defaults to the caller's own key.
    """
    k = cache_key(scope or key_scope(api_key), provider, model, messages, max_tokens)
    cached = cache_get(k)
    if cached is not None:
        log.info("ai cache hit", extra={"provider": provider, "model": cached.get("model")})
        return {**cached, "cached": True}

    t0 = time.monotonic()
    if provider == "gemini":
        result = await _call_gemini(api_key, messages, max_tokens, model)
    else:
        result = await _call_anthropic(api_key, messages, max_tokens, model)
    log.info(
        "ai call",
        extra={
            "provider": provider,
            "model": result.get("model"),
            "input_tokens": result.get("input_tokens"),
            "output_tokens": result.get("output_tokens"),
            "ms": int((time.monotonic() - t0) * 1000),
        },
    )
    cache_put(k, result)
    return {**result, "cached": False}


async def _call_anthropic(api_key: str, messages: list[dict], max_tokens: int, model: str | None) -> dict:
    model = model or anthropic_model()
    try:
        # AsyncAnthropic keeps the event loop free; the sync client froze every other request
        # for the length of the call. max_retries=1 so a failing key answers quickly.
        async with anthropic.AsyncAnthropic(api_key=api_key, timeout=ANTHROPIC_TIMEOUT, max_retries=1) as client:
            message = await client.messages.create(
                model=model,
                max_tokens=max_tokens + ANTHROPIC_THINKING_HEADROOM,
                output_config={"effort": ANTHROPIC_EFFORT},
                messages=messages,
            )
    except anthropic.AuthenticationError:
        raise AIError("ai_invalid_key", "Anthropic rejected that API key. Check it in Settings.", 401)
    except anthropic.PermissionDeniedError:
        raise AIError("ai_invalid_key", "That Anthropic key is not allowed to use this model. Check it in Settings.", 403)
    except anthropic.NotFoundError:
        raise AIError("ai_bad_model", f"Anthropic does not recognize the model \"{model}\".", 502)
    except anthropic.RateLimitError as e:
        retry = e.response.headers.get("retry-after") if e.response is not None else None
        raise AIError("ai_rate_limited", "Anthropic is rate limiting this key. Try again in a minute.", 429, int(retry) if retry and retry.isdigit() else None)
    except anthropic.BadRequestError as e:
        log.warning("anthropic bad request", extra={"detail": str(e.message)[:300], "model": model})
        raise AIError("ai_bad_request", "Anthropic rejected the request. The collected data may be too large, or the account may be out of credit.", 502)
    except anthropic.APITimeoutError:
        raise AIError("ai_timeout", "Anthropic took too long to answer. Try again.", 504)
    except anthropic.APIConnectionError:
        raise AIError("ai_unreachable", "Could not reach Anthropic. Try again in a moment.", 502)
    except anthropic.APIStatusError as e:
        log.warning("anthropic error", extra={"status": e.status_code, "model": model})
        raise AIError("ai_upstream", f"Anthropic returned an error ({e.status_code}). Try again in a moment.", 502)

    if message.stop_reason == "refusal":
        raise AIError("ai_refused", "Claude declined to analyze this data.", 422)
    # Responses carry thinking blocks before the answer; keep only the text.
    text = "".join(block.text for block in message.content if block.type == "text").strip()
    if not text:
        raise AIError("ai_empty", "Claude returned an empty answer. Try again.", 502)
    return {
        "text": text,
        "model": message.model,
        "input_tokens": message.usage.input_tokens,
        "output_tokens": message.usage.output_tokens,
    }


async def _call_gemini(api_key: str, messages: list[dict], max_tokens: int, model: str | None) -> dict:
    model = model or "gemini-2.5-flash"
    # Key goes in the x-goog-api-key header, not ?key=. New AI Studio keys ("AQ." prefix)
    # are rejected as a query parameter; the header works for both AQ. and legacy AIza keys,
    # and keeps the key out of URLs (and any proxy/access logs that record them).
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"

    contents = [
        {"role": "user" if msg["role"] == "user" else "model", "parts": [{"text": msg["content"]}]}
        for msg in messages
    ]
    payload = {
        "contents": contents,
        "generationConfig": {
            # Gemini 2.5 "thinking" tokens count against maxOutputTokens. Without headroom the
            # model spends the budget reasoning and the written answer comes back short.
            "maxOutputTokens": max_tokens + (GEMINI_THINKING_BUDGET if "2.5" in model else 0),
            "temperature": 0.4,
            **({"thinkingConfig": {"thinkingBudget": GEMINI_THINKING_BUDGET}} if "2.5" in model else {}),
        },
    }

    try:
        async with httpx.AsyncClient(timeout=120) as client:
            resp = await client.post(url, json=payload, headers={"x-goog-api-key": api_key})
    except httpx.TimeoutException:
        raise AIError("ai_timeout", "Gemini took too long to answer. Try again.", 504)
    except httpx.HTTPError:
        raise AIError("ai_unreachable", "Could not reach Gemini. Try again in a moment.", 502)

    if resp.status_code != 200:
        detail = resp.text[:300]
        # Never log any part of the key, not even a prefix.
        log.warning("gemini error", extra={"status": resp.status_code, "detail": detail})
        if resp.status_code == 429:
            raise AIError("ai_rate_limited", "Gemini is rate limiting this key. Try again in a minute.", 429)
        if resp.status_code in (401, 403) or "API key not valid" in detail or "API_KEY_INVALID" in detail:
            raise AIError("ai_invalid_key", "Gemini rejected that API key. Check it in Settings.", 401)
        if resp.status_code == 404:
            raise AIError("ai_bad_model", f"Gemini does not recognize the model \"{model}\".", 502)
        raise AIError("ai_upstream", f"Gemini returned an error ({resp.status_code}). Try again in a moment.", 502)

    try:
        data = resp.json()
    except ValueError:
        raise AIError("ai_upstream", "Gemini sent a response CrawlR could not read.", 502)

    candidates = data.get("candidates", [])
    if not candidates:
        raise AIError("ai_refused", "Gemini returned no answer for this data (it may have been filtered).", 422)

    parts = candidates[0].get("content", {}).get("parts") or [{}]
    text = strip_fences("".join(p.get("text", "") for p in parts if not p.get("thought")))
    if not text:
        raise AIError("ai_empty", "Gemini returned an empty answer. Try again.", 502)

    usage = data.get("usageMetadata", {})
    return {
        "text": text,
        "model": model,
        "input_tokens": usage.get("promptTokenCount", 0),
        "output_tokens": usage.get("candidatesTokenCount", 0),
    }
