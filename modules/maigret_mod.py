import asyncio
import json
import os
import shutil
import tempfile

from modules.sherlock import _classify_site

MAIGRET_AVAILABLE = shutil.which("maigret") is not None


async def run_maigret(username: str, nsfw: bool = True, timeout: int = 180) -> dict:
    if not MAIGRET_AVAILABLE:
        return {"username": username, "error": "maigret not installed", "results": [], "total": 0, "confirmed": 0}

    with tempfile.TemporaryDirectory() as tmpdir:
        cmd = [
            "maigret", username,
            "-J", "simple",
            "--timeout", "10",
            "--no-color",
            "--no-progressbar",
            "--no-recursion",
            "--folderoutput", tmpdir,
        ]
        if not nsfw:
            cmd.extend(["--tags", "!nsfw"])

        proc = await asyncio.create_subprocess_exec(
            *cmd,
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
            return {"username": username, "error": "timeout", "results": [], "total": 0, "confirmed": 0}

        results = []

        # Find the JSON output file
        raw = None
        for fname in sorted(os.listdir(tmpdir)):
            if fname.endswith(".json"):
                fpath = os.path.join(tmpdir, fname)
                with open(fpath) as f:
                    try:
                        raw = json.load(f)
                        break
                    except json.JSONDecodeError:
                        continue

        if raw and isinstance(raw, dict):
            # maigret simple JSON format:
            # { "SiteName": { "status": { "status": "Claimed", "site_name": "...", "tags": [...] },
            #                  "url_user": "...", "site": { "tags": [...] } } }
            for site_key, info in raw.items():
                if not isinstance(info, dict):
                    continue
                status_obj = info.get("status", {})
                if not isinstance(status_obj, dict):
                    continue
                status_val = status_obj.get("status", "")
                if str(status_val).lower() != "claimed":
                    continue

                site_name = status_obj.get("site_name", site_key)
                url = info.get("url_user", status_obj.get("url", ""))

                # Tags from status or site metadata
                tags = status_obj.get("tags", [])
                if not tags:
                    site_meta = info.get("site", {})
                    if isinstance(site_meta, dict):
                        tags = site_meta.get("tags", [])
                if isinstance(tags, list):
                    category = ", ".join(tags) if tags else ""
                else:
                    category = str(tags) if tags else ""

                confidence = _classify_site(site_name)
                results.append({
                    "site": site_name,
                    "url": url,
                    "confidence": confidence,
                    "category": category,
                })

        order = {"high_confidence": 0, "normal": 1, "false_positive": 2}
        results.sort(key=lambda r: order.get(r["confidence"], 1))
        confirmed = sum(1 for r in results if r["confidence"] != "false_positive")

        return {
            "username": username,
            "total": len(results),
            "confirmed": confirmed,
            "results": results,
        }
