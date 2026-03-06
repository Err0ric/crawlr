import asyncio
import csv
import io
import tempfile
import os

# Sites known to return 200 for any username (false positives)
FALSE_POSITIVE_SITES = {
    "roblox", "chess", "chess.com", "nitrotype", "runescape",
    "scratch", "wikipedia", "geocaching", "periscope",
    "livejournal", "hudsonrock",
}

HIGH_CONFIDENCE_SITES = {
    "github", "reddit", "steam", "tiktok", "linkedin", "twitter",
    "x", "instagram", "facebook", "youtube", "twitch", "pinterest",
    "snapchat", "telegram", "discord", "spotify", "soundcloud",
    "medium", "deviantart", "flickr", "vimeo", "tumblr",
}


def _classify_site(site_name: str) -> str:
    """Return 'false_positive', 'high_confidence', or 'normal'."""
    name_lower = site_name.lower().strip()
    if any(fp in name_lower for fp in FALSE_POSITIVE_SITES):
        return "false_positive"
    if any(hc in name_lower for hc in HIGH_CONFIDENCE_SITES):
        return "high_confidence"
    return "normal"


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
                        site = row.get("name", "")
                        confidence = _classify_site(site)
                        results.append({
                            "site": site,
                            "url": row.get("url_user", ""),
                            "response_time": round(float(row.get("response_time_s", 0)), 2),
                            "confidence": confidence,
                        })

        # Sort: high_confidence first, then normal, then false_positive
        order = {"high_confidence": 0, "normal": 1, "false_positive": 2}
        results.sort(key=lambda r: order.get(r["confidence"], 1))
        confirmed = sum(1 for r in results if r["confidence"] != "false_positive")

        return {
            "username": username,
            "total": len(results),
            "confirmed": confirmed,
            "results": results,
        }
