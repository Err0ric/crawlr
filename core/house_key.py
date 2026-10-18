"""
House-key resolution and quotas for the AI endpoints.

Order of precedence for every AI call:

  1. The user sent their own key (X-Api-Key). Use it, with whatever provider
     they chose (X-Ai-Provider). No quota.
  2. No user key, but a house key is configured and enabled. Use it, counted
     against a per-IP daily quota and a global daily quota.
  3. Nothing available. Raise 401 with the same message as before.

Environment variables (all optional; without GEMINI_API_KEY this module is inert):

  GEMINI_API_KEY            house key for Google AI Studio (Gemini free tier)
  HOUSE_KEY_ENABLED         "true"/"false" kill switch, default true when a key is set
  HOUSE_MODEL               default "gemini-2.5-flash"
  HOUSE_QUOTA_ANALYSIS      per-IP per-day for summarize/correlate/headers/recon, default 5
  HOUSE_QUOTA_DEEPDIVE      per-IP per-day for deep-dive and deep analysis, default 1
  HOUSE_QUOTA_GLOBAL        all house-key calls per day across all IPs, default 300

Counters are in memory and reset at UTC midnight. That is fine for a single
Railway instance; if this ever scales out, move them to Redis.
"""

import os
import time
from collections import defaultdict
from dataclasses import dataclass

from fastapi import HTTPException

from core.logging import get_logger

log = get_logger(__name__)

# ---- config -------------------------------------------------------------

def _env_bool(name: str, default: bool) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return v.strip().lower() in ("1", "true", "yes", "on")


def house_key() -> str | None:
    return os.getenv("GEMINI_API_KEY") or None


def house_enabled() -> bool:
    return bool(house_key()) and _env_bool("HOUSE_KEY_ENABLED", True)


def house_model() -> str:
    return os.getenv("HOUSE_MODEL", "gemini-2.5-flash")


QUOTAS = {
    "analysis": lambda: int(os.getenv("HOUSE_QUOTA_ANALYSIS", "5")),
    "deepdive": lambda: int(os.getenv("HOUSE_QUOTA_DEEPDIVE", "1")),
}


def global_quota() -> int:
    return int(os.getenv("HOUSE_QUOTA_GLOBAL", "300"))


# ---- counters -----------------------------------------------------------

def _day() -> int:
    return int(time.time() // 86400)


class _Counters:
    def __init__(self):
        self.day = _day()
        self.per_ip: dict[tuple[str, str], int] = defaultdict(int)
        self.global_count = 0

    def roll(self):
        d = _day()
        if d != self.day:
            self.day = d
            self.per_ip.clear()
            self.global_count = 0

    def used(self, ip: str, bucket: str) -> int:
        self.roll()
        return self.per_ip[(ip, bucket)]

    def consume(self, ip: str, bucket: str):
        self.roll()
        self.per_ip[(ip, bucket)] += 1
        self.global_count += 1

    def seconds_until_reset(self) -> int:
        return int(86400 - (time.time() % 86400))


_counters = _Counters()


def reset_counters_for_tests():
    global _counters
    _counters = _Counters()


# ---- public API ---------------------------------------------------------

@dataclass
class ResolvedKey:
    api_key: str
    provider: str
    model: str | None
    source: str          # "user" | "house"
    remaining: int | None  # None for user keys


def resolve_ai_key(
    x_api_key: str | None,
    x_ai_provider: str | None,
    client_ip: str,
    bucket: str,
) -> ResolvedKey:
    """
    Decide which key an AI endpoint should use. Consumes one unit of house
    quota when the house key is chosen. Raises HTTPException(401) when
    nothing is available and HTTPException(429) when quota is exhausted.
    """
    if x_api_key:
        provider = x_ai_provider if x_ai_provider in ("anthropic", "gemini") else "anthropic"
        return ResolvedKey(api_key=x_api_key, provider=provider, model=None, source="user", remaining=None)

    if not house_enabled():
        raise HTTPException(
            status_code=401,
            detail="API key is required. Add your own key in Settings.",
        )

    limit = QUOTAS.get(bucket, QUOTAS["analysis"])()
    used = _counters.used(client_ip, bucket)
    if _counters.global_count >= global_quota():
        log.warning("house key global quota exhausted", extra={"bucket": bucket, "ip": client_ip})
        raise HTTPException(
            status_code=429,
            detail="Free AI analysis is at capacity for today. Add your own key in Settings for unlimited use.",
            headers={"Retry-After": str(_counters.seconds_until_reset())},
        )
    if used >= limit:
        raise HTTPException(
            status_code=429,
            detail=f"You've used your {limit} free {'Deep Dive' if bucket == 'deepdive' else 'AI analysis'} call{'s' if limit != 1 else ''} for today. Add your own key in Settings for unlimited use.",
            headers={"Retry-After": str(_counters.seconds_until_reset())},
        )

    _counters.consume(client_ip, bucket)
    remaining = limit - used - 1
    log.info("house key used", extra={"bucket": bucket, "ip": client_ip, "remaining": remaining, "global": _counters.global_count})
    return ResolvedKey(api_key=house_key(), provider="gemini", model=house_model(), source="house", remaining=remaining)


def quota_status(client_ip: str) -> dict:
    """What the frontend shows: is free AI on, and how much is left for this IP."""
    if not house_enabled():
        return {"house_ai": False}
    _counters.roll()
    return {
        "house_ai": True,
        "model": house_model(),
        "remaining": {
            bucket: max(0, QUOTAS[bucket]() - _counters.used(client_ip, bucket))
            for bucket in QUOTAS
        },
        "limits": {bucket: QUOTAS[bucket]() for bucket in QUOTAS},
        "resets_in": _counters.seconds_until_reset(),
    }
