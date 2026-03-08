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
    alienvault = {"found": False}
    threatfox = {"found": False}

    async with httpx.AsyncClient(timeout=15) as client:
        # MalwareBazaar (abuse.ch)
        try:
            resp = await client.post(
                "https://mb-api.abuse.ch/api/v1/",
                data={"query": "get_info", "hash": h},
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get("query_status") == "ok" and data.get("data"):
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
        except Exception:
            pass

        # AlienVault OTX
        try:
            resp = await client.get(
                f"https://otx.alienvault.com/api/v1/indicators/file/{h}/general",
                headers={"Accept": "application/json"},
            )
            if resp.status_code == 200:
                data = resp.json()
                pulses = data.get("pulse_info", {}).get("count", 0)
                malware_families = []
                for pulse in data.get("pulse_info", {}).get("pulses", [])[:5]:
                    if pulse.get("malware_families"):
                        for mf in pulse["malware_families"]:
                            name = mf.get("display_name") or mf.get("id", "")
                            if name and name not in malware_families:
                                malware_families.append(name)
                alienvault = {
                    "found": pulses > 0,
                    "pulse_count": pulses,
                    "malware_families": malware_families[:5],
                }
        except Exception:
            pass

        # ThreatFox (abuse.ch)
        try:
            resp = await client.post(
                "https://threatfox-api.abuse.ch/api/v1/",
                json={"query": "search_hash", "hash": h},
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get("query_status") == "ok" and data.get("data"):
                    entries = data["data"]
                    malware_names = []
                    ioc_types = []
                    for e in entries[:5]:
                        mname = e.get("malware_printable")
                        if mname and mname not in malware_names:
                            malware_names.append(mname)
                        itype = e.get("ioc_type")
                        if itype and itype not in ioc_types:
                            ioc_types.append(itype)
                    threatfox = {
                        "found": True,
                        "malware_names": malware_names,
                        "ioc_types": ioc_types,
                        "count": len(entries),
                    }
        except Exception:
            pass

    # Determine verdict
    is_malicious = (
        malware_bazaar.get("malicious")
        or circl.get("known_malicious")
        or threatfox.get("found")
        or (alienvault.get("found") and alienvault.get("pulse_count", 0) >= 3)
    )

    if is_malicious:
        verdict = "MALICIOUS"
    elif circl.get("found") and not circl.get("known_malicious"):
        verdict = "CLEAN"
    else:
        verdict = "UNKNOWN"

    # Collect all malware family names
    malware_families = []
    if malware_bazaar.get("signature"):
        malware_families.append(malware_bazaar["signature"])
    malware_families.extend(alienvault.get("malware_families", []))
    malware_families.extend(threatfox.get("malware_names", []))
    # Deduplicate
    seen = set()
    unique_families = []
    for f in malware_families:
        fl = f.lower()
        if fl not in seen:
            seen.add(fl)
            unique_families.append(f)

    return {
        "hash": h,
        "hash_type": hash_type,
        "malware_bazaar": malware_bazaar,
        "circl": circl,
        "alienvault": alienvault,
        "threatfox": threatfox,
        "virustotal_url": f"https://www.virustotal.com/gui/file/{h}",
        "malware_families": unique_families,
        "verdict": verdict,
    }
