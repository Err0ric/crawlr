import httpx


async def run_redirect_chain(target: str) -> dict:
    """Follow all redirects for a URL/domain and capture each hop."""
    # Ensure URL has a protocol
    url = target.strip()
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    hops = []
    current_url = url

    try:
        async with httpx.AsyncClient(
            timeout=15,
            follow_redirects=False,
            verify=False,
        ) as client:
            for step in range(1, 21):  # Max 20 hops
                try:
                    resp = await client.get(current_url)
                except httpx.ConnectError:
                    # If https fails on first hop, try http
                    if step == 1 and current_url.startswith("https://"):
                        current_url = "http://" + current_url[8:]
                        resp = await client.get(current_url)
                    else:
                        raise

                hop = {
                    "step": step,
                    "url": str(resp.url),
                    "status_code": resp.status_code,
                    "server": resp.headers.get("server", ""),
                }
                hops.append(hop)

                if resp.is_redirect:
                    location = resp.headers.get("location", "")
                    if not location:
                        break
                    # Handle relative redirects
                    if location.startswith("/"):
                        from urllib.parse import urlparse
                        parsed = urlparse(str(resp.url))
                        location = f"{parsed.scheme}://{parsed.netloc}{location}"
                    current_url = location
                else:
                    break

    except Exception as e:
        if not hops:
            return {
                "target": target,
                "found": False,
                "error": str(e),
                "hops": [],
                "final_url": "",
                "hop_count": 0,
                "is_clean": False,
            }

    final_url = hops[-1]["url"] if hops else ""

    # Check if final destination matches expected domain
    from urllib.parse import urlparse
    expected_domain = target.replace("https://", "").replace("http://", "").split("/")[0].lower()
    final_domain = urlparse(final_url).netloc.lower() if final_url else ""
    is_clean = expected_domain in final_domain or final_domain in expected_domain

    return {
        "target": target,
        "found": True,
        "hops": hops,
        "final_url": final_url,
        "hop_count": len(hops),
        "is_clean": is_clean,
    }
