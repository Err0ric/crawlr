import asyncio
import json
import tempfile
import os


async def run_sherlock(username: str, timeout: int = 120) -> dict:
    with tempfile.TemporaryDirectory() as tmpdir:
        json_path = os.path.join(tmpdir, "results.json")
        proc = await asyncio.create_subprocess_exec(
            "sherlock", username,
            "--json", json_path,
            "--timeout", "15",
            "--no-color",
            "--print-found",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=timeout
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return {"username": username, "error": "timeout", "results": []}

        results = []
        if os.path.exists(json_path):
            with open(json_path) as f:
                data = json.load(f)
            for site, info in data.items():
                if info.get("status") == "Claimed":
                    results.append({
                        "site": site,
                        "url": info.get("url_user", ""),
                    })

        return {
            "username": username,
            "total": len(results),
            "results": results,
        }
