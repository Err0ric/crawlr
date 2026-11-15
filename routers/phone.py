from typing import Optional

from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel, Field

from core import validate
from modules import phone_lookup

router = APIRouter()


class PhoneRequest(BaseModel):
    phone: str = Field(max_length=40)
    # The country a number written without a country code is read as. Two letters; US when absent.
    region: Optional[str] = Field(default=None, max_length=2)


@router.post("/lookup")
async def phone_lookup_endpoint(req: PhoneRequest, x_numlookup_key: Optional[str] = Header(None, max_length=200)):
    number = validate.phone(req.phone)
    region = validate.phone_region(req.region)
    try:
        return await phone_lookup.lookup(number, region, (x_numlookup_key or "").strip() or None)
    except phone_lookup.PhoneInputError as e:
        raise HTTPException(status_code=400, detail=str(e))
