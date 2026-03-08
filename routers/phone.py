from fastapi import APIRouter, HTTPException, Header
from pydantic import BaseModel
from typing import Optional
import httpx
import re

router = APIRouter()


class PhoneRequest(BaseModel):
    phone: str


def normalize_phone(raw: str) -> str:
    """Strip formatting and normalize to E.164-ish format."""
    digits = re.sub(r'[^\d+]', '', raw)
    # If it starts with +, keep it
    if digits.startswith('+'):
        return digits
    # US/CA numbers: 10 digits -> +1
    if len(digits) == 10:
        return '+1' + digits
    # 11 digits starting with 1 -> +1
    if len(digits) == 11 and digits.startswith('1'):
        return '+' + digits
    # Otherwise just prepend +
    return '+' + digits


@router.post("/lookup")
async def phone_lookup(req: PhoneRequest, x_numlookup_key: Optional[str] = Header(None)):
    raw = req.phone.strip()
    if not raw:
        raise HTTPException(status_code=400, detail="Phone number required")

    normalized = normalize_phone(raw)

    result = {
        "input": raw,
        "normalized": normalized,
        "valid": None,
        "country": None,
        "country_code": None,
        "location": None,
        "carrier": None,
        "line_type": None,
    }

    if x_numlookup_key:
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.get(
                    f"https://api.numlookupapi.com/v1/validate/{normalized}",
                    params={"apikey": x_numlookup_key},
                )
                if resp.status_code == 200:
                    data = resp.json()
                    result["valid"] = data.get("valid")
                    result["country"] = data.get("country_name")
                    result["country_code"] = data.get("country_code")
                    result["location"] = data.get("location")
                    result["carrier"] = data.get("carrier")
                    result["line_type"] = data.get("line_type")
                elif resp.status_code == 401:
                    raise HTTPException(status_code=401, detail="Invalid NumLookup API key")
                else:
                    result["api_error"] = f"NumLookup returned {resp.status_code}"
        except HTTPException:
            raise
        except Exception as e:
            result["api_error"] = str(e)

    # Build lookup links
    digits_only = re.sub(r'[^\d]', '', normalized)
    result["lookup_links"] = {
        "TrueCaller": f"https://www.truecaller.com/search/{normalized.replace('+', '')}",
        "Spokeo": f"https://www.spokeo.com/phone-lookup/{digits_only}",
        "WhitePages": f"https://www.whitepages.com/phone/{digits_only}",
        "BeenVerified": f"https://www.beenverified.com/phone/{digits_only}/",
        "CallerID Test": f"https://calleridtest.com/query?number={digits_only}",
        "NumVerify": f"https://numverify.com/?number={digits_only}",
    }

    return result
