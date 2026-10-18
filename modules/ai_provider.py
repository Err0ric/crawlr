"""Unified AI provider abstraction for Anthropic Claude and Google Gemini."""

import anthropic
import hashlib
import httpx
import json
import os
import time
from collections import OrderedDict

from core.logging import get_logger

log = get_logger(__name__)

# ---- result cache ---------------------------------------------------------
# The same target run twice in a day produces the same recon data and the same
# prompt, so the AI answer is reused instead of re-billed. Keyed on a hash of
# (provider, model, messages, max_tokens); the API key is deliberately NOT part
# of the key so house-key and BYOK users share hits. Bounded LRU, 24h TTL.
AI_CACHE_TTL = int(os.getenv("AI_CACHE_TTL", str(24 * 3600)))
AI_CACHE_MAX = int(os.getenv("AI_CACHE_MAX", "500"))
_cache: "OrderedDict[str, tuple[float, dict]]" = OrderedDict()


def _cache_key(provider: str, model: str | None, messages: list[dict], max_tokens: int) -> str:
    raw = json.dumps({"p": provider, "m": model, "msgs": messages, "t": max_tokens}, sort_keys=True)
    return hashlib.sha256(raw.encode()).hexdigest()


def _cache_get(k: str) -> dict | None:
    hit = _cache.get(k)
    if not hit:
        return None
    ts, val = hit
    if time.time() - ts > AI_CACHE_TTL:
        _cache.pop(k, None)
        return None
    _cache.move_to_end(k)
    return val


def _cache_put(k: str, val: dict) -> None:
    _cache[k] = (time.time(), val)
    _cache.move_to_end(k)
    while len(_cache) > AI_CACHE_MAX:
        _cache.popitem(last=False)


def clear_cache_for_tests() -> None:
    _cache.clear()


async def call_ai(api_key: str, provider: str, messages: list[dict], max_tokens: int = 2048, model: str | None = None) -> dict:
    """
    Call an AI provider and return a standardized response.

    Args:
        api_key: The API key for the chosen provider.
        provider: 'anthropic' or 'gemini'.
        messages: List of message dicts with 'role' and 'content' keys.
        max_tokens: Max output tokens.
        model: Override model name. If None, uses a sensible default per provider.

    Returns:
        dict with keys: text, model, input_tokens, output_tokens
    """
    k = _cache_key(provider, model, messages, max_tokens)
    cached = _cache_get(k)
    if cached is not None:
        log.info("ai cache hit", extra={"provider": provider, "model": cached.get("model")})
        return {**cached, "cached": True}

    t0 = time.monotonic()
    if provider == "gemini":
        result = await _call_gemini(api_key, messages, max_tokens, model)
    else:
        result = _call_anthropic(api_key, messages, max_tokens, model)
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
    _cache_put(k, result)
    return {**result, "cached": False}


def _call_anthropic(api_key: str, messages: list[dict], max_tokens: int, model: str | None) -> dict:
    model = model or "claude-sonnet-4-20250514"
    client = anthropic.Anthropic(api_key=api_key)
    message = client.messages.create(
        model=model,
        max_tokens=max_tokens,
        messages=messages,
    )
    return {
        "text": message.content[0].text,
        "model": message.model,
        "input_tokens": message.usage.input_tokens,
        "output_tokens": message.usage.output_tokens,
    }


async def _call_gemini(api_key: str, messages: list[dict], max_tokens: int, model: str | None) -> dict:
    model = model or "gemini-2.5-flash"
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"

    # Convert Anthropic-style messages to Gemini format
    contents = []
    for msg in messages:
        role = "user" if msg["role"] == "user" else "model"
        contents.append({
            "role": role,
            "parts": [{"text": msg["content"]}],
        })

    payload = {
        "contents": contents,
        "generationConfig": {
            "maxOutputTokens": max_tokens,
            "temperature": 0.7,
        },
    }

    async with httpx.AsyncClient(timeout=120) as client:
        resp = await client.post(url, json=payload)
        if resp.status_code != 200:
            error_detail = resp.text[:500]
            raise Exception(f"Gemini API error ({resp.status_code}): {error_detail}")
        data = resp.json()

    # Extract text from Gemini response
    candidates = data.get("candidates", [])
    if not candidates:
        raise Exception("Gemini returned no candidates")

    text = candidates[0].get("content", {}).get("parts", [{}])[0].get("text", "")

    # Strip markdown code fences that Gemini often wraps around JSON
    text = text.strip()
    if text.startswith("```"):
        text = text.split("\n", 1)[-1]
    if text.endswith("```"):
        text = text.rsplit("```", 1)[0]
    text = text.strip()

    # Token usage from usageMetadata
    usage = data.get("usageMetadata", {})
    input_tokens = usage.get("promptTokenCount", 0)
    output_tokens = usage.get("candidatesTokenCount", 0)

    return {
        "text": text,
        "model": model,
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
    }
