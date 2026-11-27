"""
One piece of work per key at a time.

Several visitors can ask for the same uncached answer in the same moment. `shared` lets the
first one do the work and hands the others the same result, so a burst of identical requests
is one set of outbound requests, not one per visitor.

The work runs as its own task: a visitor who goes away does not cancel it for the others.
An entry is dropped the moment its work ends, whatever the outcome, so nothing is kept here
past the call: keeping answers is the caller's cache's job.
"""

import asyncio
from collections.abc import Awaitable, Callable, Hashable


async def shared(pending: dict, key: Hashable, work: Callable[[], Awaitable]):
    """Await `work()` for `key`, or the run of it that is already under way in `pending`."""
    task = pending.get(key)
    if task is None or task.done() or task.get_loop() is not asyncio.get_running_loop():
        task = asyncio.ensure_future(work())
        pending[key] = task

        def forget(done, key=key):
            if pending.get(key) is done:
                pending.pop(key, None)

        task.add_done_callback(forget)
    return await asyncio.shield(task)
