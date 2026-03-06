import hashlib
import httpx


async def run_gravatar(email: str, timeout: int = 10) -> dict:
    email_hash = hashlib.md5(email.lower().strip().encode()).hexdigest()
    url = f"https://en.gravatar.com/{email_hash}.json"
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.get(url, headers={"User-Agent": "Crawlr/0.1"})
            if resp.status_code == 404:
                return {"email": email, "found": False}
            resp.raise_for_status()
            data = resp.json()
            entry = data.get("entry", [{}])[0]
            result = {
                "email": email,
                "found": True,
                "display_name": entry.get("displayName", ""),
                "name": "",
                "location": entry.get("currentLocation", ""),
                "profile_url": entry.get("profileUrl", ""),
                "avatar_url": f"https://www.gravatar.com/avatar/{email_hash}?s=200",
            }
            name_obj = entry.get("name", {})
            if name_obj:
                parts = [name_obj.get("givenName", ""), name_obj.get("familyName", "")]
                result["name"] = " ".join(p for p in parts if p)
            return result
    except Exception as e:
        return {"email": email, "found": False, "error": str(e)}
