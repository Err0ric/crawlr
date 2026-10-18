import asyncio
import shutil
import json
import os
import tempfile
from core.subprocess_guard import tool_slot, ToolBusy, busy_result


async def _run_harvester_impl(domain: str, timeout: int = 300) -> dict:
    with tempfile.TemporaryDirectory() as tmpdir:
        if shutil.which("theHarvester") is None:
            return {"domain": domain, "error": "unavailable", "message": "theHarvester is not installed on this server", "hosts": [], "emails": []}
        proc = await asyncio.create_subprocess_exec(
            "theHarvester",
            "-d", domain,
            "-b", "crtsh",
            "-l", "200",
            "-f", "results",
            "-q",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=tmpdir,
        )
        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=timeout
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return {"domain": domain, "error": "timeout", "hosts": [], "emails": []}

        hosts = []
        emails = []
        json_path = os.path.join(tmpdir, "results.json")
        if os.path.exists(json_path):
            with open(json_path) as f:
                data = json.load(f)
            hosts = data.get("hosts", [])
            emails = data.get("emails", [])

        return {
            "domain": domain,
            "total_hosts": len(hosts),
            "total_emails": len(emails),
            "hosts": hosts,
            "emails": emails,
        }


async def run_harvester(domain: str, timeout: int = 300) -> dict:
    """Guarded entry point: bounded by the global tool concurrency limit."""
    try:
        async with tool_slot("harvester"):
            return await _run_harvester_impl(domain=domain, timeout=timeout)
    except ToolBusy:
        return busy_result(domain=domain, hosts=[], emails=[])
