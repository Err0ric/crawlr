"""
One place for cleaning up model output.

Models wrap JSON in ```json fences, add a sentence before it, or return prose when
asked for JSON. Five endpoints used to carry their own copy of the fence-stripping
and fallback code; they all call these helpers now.
"""

import json
import re

_FENCE_RE = re.compile(r"^\s*```[A-Za-z0-9_-]*[ \t]*\n?(.*?)\n?```\s*$", re.S)


def strip_fences(text: str) -> str:
    """Remove one surrounding markdown code fence (with or without a language tag)."""
    t = (text or "").strip()
    m = _FENCE_RE.match(t)
    if m:
        return m.group(1).strip()
    # An opening fence with no closing one: the reply was cut off mid-block.
    if t.startswith("```"):
        t = t.split("\n", 1)[1] if "\n" in t else ""
    return t.strip()


def parse_json_object(text: str) -> dict | None:
    """Return the JSON object in a model reply, or None when there isn't a valid one.
    Accepts fenced JSON and JSON with prose around it."""
    t = strip_fences(text)
    candidates = [t]
    start, end = t.find("{"), t.rfind("}")
    if 0 <= start < end:
        candidates.append(t[start:end + 1])
    for c in candidates:
        try:
            val = json.loads(c)
        except (json.JSONDecodeError, TypeError):
            continue
        if isinstance(val, dict):
            return val
    return None


_JSON_NOISE = {"{", "}", "[", "]", '",', "```", "```json"}


def fallback_bullets(text: str, limit: int = 4) -> list[str]:
    """Best-effort summary bullets from a reply that was meant to be JSON but isn't."""
    out = []
    for line in strip_fences(text).splitlines():
        l = line.strip()
        if not l or l in _JSON_NOISE or l.startswith(("#", "|", '"short_summary"', '"full_report"')):
            continue
        l = l.lstrip("-•*→ ").strip().strip('"').strip(",").strip('"').strip()
        if len(l) > 3:
            out.append(l)
    return out[:limit]


def summary_and_report(text: str) -> tuple[list[str], str]:
    """For replies shaped {"short_summary": [...], "full_report": "..."}: returns
    (bullets, report markdown), falling back to the raw text when the JSON is broken."""
    parsed = parse_json_object(text)
    if parsed is not None and ("short_summary" in parsed or "full_report" in parsed):
        bullets = parsed.get("short_summary") or []
        if not isinstance(bullets, list):
            bullets = [str(bullets)]
        return [str(b) for b in bullets][:6], str(parsed.get("full_report") or strip_fences(text))
    cleaned = strip_fences(text)
    return fallback_bullets(cleaned), cleaned
