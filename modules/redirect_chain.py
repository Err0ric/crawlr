from urllib.parse import urlsplit

import httpx

from core.errors import error_fields
from core.netguard import safe_fetch
from core.validate import same_site


def is_clean_chain(start_url: str, final_url: str) -> bool:
    """A chain is clean when it ends on the same registrable domain it started on
    and does not drop from https to http. 'evila.com' is not the same site as 'a.com'."""
    start, final = urlsplit(start_url), urlsplit(final_url)
    if not final.hostname:
        return False
    if start.scheme == "https" and final.scheme != "https":
        return False
    return same_site(start.hostname or "", final.hostname)


async def run_redirect_chain(target: str) -> dict:
    """Follow all redirects for a URL/domain and capture each hop."""
    url = target.strip()
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    empty = {"target": target, "found": False, "hops": [], "final_url": "", "hop_count": 0, "is_clean": False}
    # verify=False is deliberate: the point is to trace where a link goes, even over a bad
    # certificate. safe_fetch vets and pins every hop, so the chain cannot reach internal hosts.
    async with httpx.AsyncClient(timeout=15, verify=False) as client:
        try:
            got = await safe_fetch(client, url, max_redirects=20)
        except httpx.ConnectError as e:
            # Nothing on 443: try plain http once.
            if not url.startswith("https://"):
                return {**empty, **error_fields(e)}
            url = "http://" + url[8:]
            try:
                got = await safe_fetch(client, url, max_redirects=20)
            except Exception as e2:
                return {**empty, **error_fields(e2)}
        except Exception as e:
            return {**empty, **error_fields(e)}

    hops = [{"step": i, "url": h["url"], "status_code": h["status_code"], "server": h["server"]} for i, h in enumerate(got.hops, 1)]
    return {
        "target": target,
        "found": True,
        "hops": hops,
        "final_url": got.url,
        "hop_count": len(hops),
        "is_clean": is_clean_chain(url if target.startswith("http") else "https://" + target.strip(), got.url),
    }
