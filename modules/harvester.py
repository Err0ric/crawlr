import asyncio
import json
import os
import tempfile


async def run_harvester(domain: str, timeout: int = 300) -> dict:
    with tempfile.TemporaryDirectory() as tmpdir:
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
