import asyncio
import csv
import glob
import os
import tempfile


async def run_holehe(email: str, timeout: int = 300) -> dict:
    with tempfile.TemporaryDirectory() as tmpdir:
        proc = await asyncio.create_subprocess_exec(
            "holehe", email,
            "--csv",
            "--only-used",
            "--no-color",
            "--no-clear",
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
            return {"email": email, "error": "timeout", "results": []}

        results = []
        csv_files = glob.glob(os.path.join(tmpdir, "holehe_*_results.csv"))
        if csv_files:
            with open(csv_files[0], newline="") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    if row.get("exists") == "True":
                        results.append({
                            "site": row.get("name", ""),
                            "domain": row.get("domain", ""),
                            "method": row.get("method", ""),
                        })

        return {
            "email": email,
            "total": len(results),
            "results": results,
        }
