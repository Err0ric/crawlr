import httpx


async def run_shodan(target: str, api_key: str, timeout: int = 15) -> dict:
    """Query Shodan for host information by IP or domain."""
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            # Try as IP first, fall back to DNS resolve
            resp = await client.get(
                f"https://api.shodan.io/shodan/host/{target}",
                params={"key": api_key},
            )
            if resp.status_code == 401:
                return {"target": target, "found": False, "error": "Invalid API key"}
            if resp.status_code == 404:
                return {"target": target, "found": False, "ports": [], "vulns": [], "services": []}
            resp.raise_for_status()
            data = resp.json()

            services = []
            for item in data.get("data", []):
                services.append({
                    "port": item.get("port", 0),
                    "transport": item.get("transport", "tcp"),
                    "product": item.get("product", ""),
                    "version": item.get("version", ""),
                    "banner": (item.get("data", "") or "")[:200],
                })

            return {
                "target": target,
                "found": True,
                "ip": data.get("ip_str", ""),
                "org": data.get("org", ""),
                "os": data.get("os", ""),
                "isp": data.get("isp", ""),
                "country": data.get("country_name", ""),
                "city": data.get("city", ""),
                "ports": data.get("ports", []),
                "vulns": list(data.get("vulns", []))[:20] if data.get("vulns") else [],
                "total_services": len(services),
                "services": services[:30],
            }
    except Exception as e:
        return {"target": target, "found": False, "error": str(e)}
