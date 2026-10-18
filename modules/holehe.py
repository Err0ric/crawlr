import asyncio
import csv
import glob
import os
import tempfile
from core.subprocess_guard import tool_slot, ToolBusy, busy_result, log_result, log_process


async def _run_holehe_impl(email: str, timeout: int = 300) -> dict:
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
        log_process("holehe", proc.returncode, stderr)

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


async def run_holehe(email: str, timeout: int = 300) -> dict:
    """Guarded entry point: bounded by the global tool concurrency limit."""
    try:
        async with tool_slot("holehe"):
            return log_result("holehe", await _run_holehe_impl(email=email, timeout=timeout))
    except ToolBusy:
        return busy_result(email=email, results=[])
