"""
A small, shared thread pool for bulk DNS work.

Several recon checks make dozens or hundreds of blocking DNS queries (lookalike domains,
DKIM selectors, the subdomain wordlist, takeover candidates). Run through asyncio's
default executor they crowd out everything else that needs a thread, including the
system resolver calls that every outbound HTTP request starts with, and a burst that
size is unfriendly to the upstream resolvers.

Everything bulk goes through this pool instead: one cap for the whole process, however
many checks are running. Override the size with DNS_POOL_SIZE.
"""

import asyncio
import os
from concurrent.futures import ThreadPoolExecutor

DNS_POOL_SIZE = int(os.getenv("DNS_POOL_SIZE", "16"))
_pool = ThreadPoolExecutor(max_workers=DNS_POOL_SIZE, thread_name_prefix="dns")


async def dns_thread(fn, *args):
    """Run a blocking DNS function on the shared pool."""
    return await asyncio.get_running_loop().run_in_executor(_pool, fn, *args)
