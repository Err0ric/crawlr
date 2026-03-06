import asyncio
import csv
import io
import tempfile
import os


async def run_sherlock(username: str, timeout: int = 300) -> dict:
    with tempfile.TemporaryDirectory() as tmpdir:
        proc = await asyncio.create_subprocess_exec(
            "sherlock", username,
            "--csv",
            "--timeout", "15",
            "--no-color",
            "--print-found",
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
            return {"username": username, "error": "timeout", "results": []}

        results = []
        csv_path = os.path.join(tmpdir, f"{username}.csv")
        if os.path.exists(csv_path):
            with open(csv_path, newline="") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    if row.get("exists") == "Claimed":
                        results.append({
                            "site": row.get("name", ""),
                            "url": row.get("url_user", ""),
                            "response_time": round(float(row.get("response_time_s", 0)), 2),
                        })

        return {
            "username": username,
            "total": len(results),
            "results": results,
        }
