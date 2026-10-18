"""
Concurrency guardrail for the external OSINT tools (sherlock, maigret,
holehe, theHarvester).

Each of those spawns a process that fans out hundreds of HTTP requests. The
per-call timeouts already exist in the module code; what was missing is a
cap on how many can run at once. Without it, a burst of requests pins the
container's CPU and every user's investigation crawls.

MAX_CONCURRENT_TOOLS (env, default 4) bounds total concurrent tool processes.
Callers that would exceed it wait in line rather than fail, up to
TOOL_QUEUE_TIMEOUT seconds (default 60), after which they get a 'busy'
result instead of hanging the request.
"""

import asyncio
import os
import time

from core.logging import get_logger

log = get_logger(__name__)

MAX_CONCURRENT_TOOLS = int(os.getenv("MAX_CONCURRENT_TOOLS", "4"))
TOOL_QUEUE_TIMEOUT = float(os.getenv("TOOL_QUEUE_TIMEOUT", "60"))

_semaphore: asyncio.Semaphore | None = None
_active = 0


def _get_semaphore() -> asyncio.Semaphore:
    # created lazily so it binds to the running event loop
    global _semaphore
    if _semaphore is None:
        _semaphore = asyncio.Semaphore(MAX_CONCURRENT_TOOLS)
    return _semaphore


class ToolBusy(Exception):
    """Raised when the tool queue is saturated for longer than TOOL_QUEUE_TIMEOUT."""


class tool_slot:
    """
    Async context manager that acquires one tool slot.

        async with tool_slot("maigret"):
            ... spawn the process ...
    """

    def __init__(self, tool: str):
        self.tool = tool
        self._t0 = 0.0

    async def __aenter__(self):
        global _active
        sem = _get_semaphore()
        t0 = time.monotonic()
        try:
            await asyncio.wait_for(sem.acquire(), timeout=TOOL_QUEUE_TIMEOUT)
        except asyncio.TimeoutError:
            log.warning("tool queue saturated", extra={"tool": self.tool, "active": _active, "waited_s": round(time.monotonic() - t0, 1)})
            raise ToolBusy(self.tool)
        _active += 1
        waited = time.monotonic() - t0
        if waited > 1:
            log.info("tool slot acquired after wait", extra={"tool": self.tool, "waited_s": round(waited, 1), "active": _active})
        self._t0 = time.monotonic()
        return self

    async def __aexit__(self, exc_type, exc, tb):
        global _active
        _active -= 1
        _get_semaphore().release()
        log.info("tool finished", extra={"tool": self.tool, "ms": int((time.monotonic() - self._t0) * 1000), "ok": exc is None, "active": _active})
        return False


def busy_result(**fields) -> dict:
    """Standard payload returned to the client when a tool slot could not be acquired."""
    return {**fields, "error": "busy", "message": "CrawlR is at capacity right now. Try again in a minute."}
