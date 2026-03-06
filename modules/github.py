import httpx


async def run_github(username: str, timeout: int = 10) -> dict:
    url = f"https://api.github.com/users/{username}"
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.get(url, headers={
                "User-Agent": "Crawlr/0.1",
                "Accept": "application/vnd.github.v3+json",
            })
            if resp.status_code == 404:
                return {"username": username, "found": False}
            resp.raise_for_status()
            data = resp.json()
            return {
                "username": username,
                "found": True,
                "name": data.get("name") or "",
                "bio": data.get("bio") or "",
                "location": data.get("location") or "",
                "company": data.get("company") or "",
                "email": data.get("email") or "",
                "blog": data.get("blog") or "",
                "public_repos": data.get("public_repos", 0),
                "followers": data.get("followers", 0),
                "profile_url": data.get("html_url", ""),
                "avatar_url": data.get("avatar_url", ""),
                "created_at": data.get("created_at", ""),
            }
    except Exception as e:
        return {"username": username, "found": False, "error": str(e)}
