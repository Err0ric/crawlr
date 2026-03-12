from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
import httpx

router = APIRouter()

KBB_HEADERS = {
    "Origin": "https://www.kbb.com",
    "Referer": "https://www.kbb.com/",
}


class PlateRequest(BaseModel):
    plate: str
    state: str


@router.post("/plate")
async def plate_lookup(req: PlateRequest):
    plate = req.plate.strip().upper()
    state = req.state.strip().upper()

    if not plate or not state or len(state) != 2:
        raise HTTPException(status_code=400, detail="Plate and 2-letter state code required")

    try:
        async with httpx.AsyncClient(timeout=15, follow_redirects=True) as client:
            # Step 1: plate -> VIN
            p2v_resp = await client.get(
                "https://api.kbb.com/ico/v1/plate2vin/lookup",
                params={"stateCode": state, "plateNumber": plate},
                headers=KBB_HEADERS,
            )
            if p2v_resp.status_code != 200:
                return {"error": "No vehicle found or data unavailable"}

            p2v_data = p2v_resp.json()
            vin = p2v_data.get("vin") or p2v_data.get("VIN") or ""
            if not vin:
                # Try nested structures
                if isinstance(p2v_data, dict):
                    for v in p2v_data.values():
                        if isinstance(v, str) and len(v) == 17:
                            vin = v
                            break
            if not vin:
                return {"error": "No vehicle found or data unavailable"}

            # Step 2: VIN -> vehicle details
            detail_resp = await client.get(
                f"https://api.kbb.com/ico/v1/vehicles/vin/{vin}/",
                params={"cadsBypass": "false", "vinVerified": "true"},
                headers=KBB_HEADERS,
            )
            if detail_resp.status_code != 200:
                # Return VIN even if details fail
                return {"vin": vin, "year": "", "make": "", "model": "", "engine": "", "trim": ""}

            detail = detail_resp.json()

            # Extract fields - KBB response structure varies
            year = str(detail.get("yearId", detail.get("year", "")))
            make = detail.get("makeName", detail.get("make", ""))
            model = detail.get("modelName", detail.get("model", ""))
            engine = detail.get("engineName", detail.get("engine", ""))
            trim = detail.get("trimName", detail.get("trim", ""))

            return {
                "vin": vin,
                "year": year,
                "make": make,
                "model": model,
                "engine": engine,
                "trim": trim,
            }

    except Exception:
        return {"error": "No vehicle found or data unavailable"}
