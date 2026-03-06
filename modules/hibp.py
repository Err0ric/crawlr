import httpx


async def run_hibp(email: str, timeout: int = 15) -> dict:
    url = f"https://api.xposedornot.com/v1/check-email/{email}"
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.get(url, headers={"User-Agent": "Crawlr/0.1"})
            if resp.status_code == 404:
                return {"email": email, "total": 0, "breaches": []}
            resp.raise_for_status()
            data = resp.json()
            breaches = data.get("breaches", [[]])[0]
            if isinstance(breaches, str):
                breaches = [breaches]
            return {
                "email": email,
                "total": len(breaches),
                "breaches": breaches,
            }
    except Exception as e:
        return {"email": email, "total": 0, "breaches": [], "error": str(e)}
