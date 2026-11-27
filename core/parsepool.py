"""
One small, bounded place for heavy parsing of outside data.

Reading a fetched page or document (decoding it, walking its markup, unpacking its metadata)
is pure Python. In a thread it still shares the interpreter with the event loop, so every
parse that runs at once slows every visitor, and on asyncio's default executor it also takes
the threads that name lookups, WHOIS and TLS checks need. Everything of that kind goes through
this pool instead:

  * its own executor with WORKERS threads (one), so at most one such parse runs at a time,
    whatever the number of requests, and the default executor is never used for it;
  * at most MAX_PENDING jobs are admitted (running and waiting together; PARSE_QUEUE in the
    environment changes it). One more raises `Busy` at once: nothing queues without limit. A
    caller answers `failed` with the `busy` code (core.errors) and does not keep that answer;
  * `Budget` gives a job a ceiling on its own CPU time. A parser checks `over()` between
    pieces of its input and stops with what it has, which it must then mark as cut short.

So the most parsing the whole process does is one thread's worth, the longest a job waits is
(MAX_PENDING - 1) jobs, and the most memory parsing holds is one job's working set plus the
inputs of the jobs that wait.
"""

import asyncio
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor

WORKERS = 1
MAX_PENDING = max(1, int(os.getenv("PARSE_QUEUE", "8")))      # jobs admitted at once, the running one included
JOB_SECONDS = 1.0                                              # CPU seconds one job may spend on one input
READ_SHARE = 0.7                                               # of which, at most this much on walking the markup

_pool = ThreadPoolExecutor(max_workers=WORKERS, thread_name_prefix="parse")
_lock = threading.Lock()
_admitted = 0


class Busy(Exception):
    """The pool already holds MAX_PENDING jobs. Nothing was started."""


def _clock() -> float:
    """CPU seconds this thread has used. Waiting for the interpreter or for I/O does not count."""
    return time.thread_time()


class Budget:
    """A ceiling on the CPU time of the thread that makes it. `over()` says whether it is
    spent; `over(share)` whether that share of it is, so a first stage can leave time for
    the one that turns what it read into an answer. `cut` is True once any of them said yes:
    the work stopped early, and the caller must say so."""

    def __init__(self, seconds: float = JOB_SECONDS):
        self._start = _clock()
        self._seconds = seconds
        self.cut = False

    def over(self, share: float = 1.0) -> bool:
        if _clock() >= self._start + self._seconds * share:
            self.cut = True
            return True
        return False


def pending() -> int:
    """Jobs admitted and not yet finished."""
    return _admitted


def _release(_future) -> None:
    global _admitted
    with _lock:
        _admitted -= 1


async def run(fn, *args):
    """Run `fn(*args)` on the parse pool and return its result. Raises `Busy`, without
    starting anything, when the pool is full. A caller that goes away does not free the slot
    early: it is freed when the job really ends (or is dropped before it started)."""
    global _admitted
    with _lock:
        if _admitted >= MAX_PENDING:
            raise Busy()
        _admitted += 1
    try:
        job = _pool.submit(fn, *args)
    except BaseException:
        _release(None)
        raise
    job.add_done_callback(_release)
    return await asyncio.wrap_future(job)
