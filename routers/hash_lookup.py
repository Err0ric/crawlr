from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
import httpx
import re

router = APIRouter()


class HashRequest(BaseModel):
    hash: str


def detect_hash_type(h: str) -> str | None:
    h = h.strip().lower()
    if not re.match(r'^[a-f0-9]+$', h):
        return None
    length = len(h)
    if length == 32:
        return "MD5"
    elif length == 40:
        return "SHA1"
    elif length == 64:
        return "SHA256"
    return None


@router.post("/hash")
async def hash_lookup(req: HashRequest):
    h = req.hash.strip().lower()
    hash_type = detect_hash_type(h)
    if not hash_type:
        raise HTTPException(status_code=400, detail="Invalid hash. Must be MD5 (32), SHA1 (40), or SHA256 (64) hex characters.")

    malware_bazaar = {"found": False}
    circl = {"found": False}

    async with httpx.AsyncClient(timeout=15) as client:
        # MalwareBazaar
        try:
            resp = await client.post(
                "https://mb-api.abuse.ch/api/v1/",
                data={"query": "get_info", "hash": h},
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get("query_status") == "hash_not_found":
                    malware_bazaar = {"found": False}
                elif data.get("query_status") == "ok" and data.get("data"):
                    entry = data["data"][0]
                    malware_bazaar = {
                        "found": True,
                        "malicious": True,
                        "file_name": entry.get("file_name"),
                        "file_type": entry.get("file_type"),
                        "file_size": entry.get("file_size"),
                        "signature": entry.get("signature"),
                        "tags": entry.get("tags"),
                        "first_seen": entry.get("first_seen"),
                        "last_seen": entry.get("last_seen"),
                        "reporter": entry.get("reporter"),
                    }
        except Exception:
            pass

        # CIRCL hashlookup
        try:
            url = f"https://hashlookup.circl.lu/lookup/{hash_type.lower()}/{h}"
            resp = await client.get(url, headers={"Accept": "application/json"})
            if resp.status_code == 200:
                data = resp.json()
                circl = {
                    "found": True,
                    "file_name": data.get("FileName"),
                    "file_size": data.get("FileSize"),
                    "known_malicious": bool(data.get("KnownMalicious")),
                }
            elif resp.status_code == 404:
                circl = {"found": False}
        except Exception:
            pass

    # Determine verdict
    if malware_bazaar.get("malicious"):
        verdict = "MALICIOUS"
    elif circl.get("known_malicious"):
        verdict = "MALICIOUS"
    elif circl.get("found") and not circl.get("known_malicious"):
        verdict = "CLEAN"
    else:
        verdict = "UNKNOWN"

    return {
        "hash": h,
        "hash_type": hash_type,
        "malware_bazaar": malware_bazaar,
        "circl": circl,
        "verdict": verdict,
    }
