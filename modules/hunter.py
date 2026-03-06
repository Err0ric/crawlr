import httpx


async def run_hunter(domain: str, api_key: str, timeout: int = 15) -> dict:
    """Query Hunter.io for email addresses associated with a domain."""
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.get(
                "https://api.hunter.io/v2/domain-search",
                params={"domain": domain, "api_key": api_key},
            )
            if resp.status_code == 401:
                return {"domain": domain, "total": 0, "emails": [], "error": "Invalid API key"}
            if resp.status_code == 429:
                return {"domain": domain, "total": 0, "emails": [], "error": "Rate limit exceeded"}
            resp.raise_for_status()
            data = resp.json().get("data", {})
            emails = []
            for e in data.get("emails", []):
                emails.append({
                    "email": e.get("value", ""),
                    "type": e.get("type", ""),
                    "confidence": e.get("confidence", 0),
                    "first_name": e.get("first_name", ""),
                    "last_name": e.get("last_name", ""),
                    "position": e.get("position", ""),
                })
            return {
                "domain": domain,
                "total": len(emails),
                "org": data.get("organization", ""),
                "pattern": data.get("pattern", ""),
                "emails": emails,
            }
    except Exception as e:
        return {"domain": domain, "total": 0, "emails": [], "error": str(e)}
