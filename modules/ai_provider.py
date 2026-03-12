"""Unified AI provider abstraction for Anthropic Claude and Google Gemini."""

import anthropic
import httpx
import json


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
    if provider == "gemini":
        return await _call_gemini(api_key, messages, max_tokens, model)
    else:
        return _call_anthropic(api_key, messages, max_tokens, model)


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
