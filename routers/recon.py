from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from modules.sherlock import run_sherlock
from modules.holehe import run_holehe
from modules.harvester import run_harvester

router = APIRouter()


class SherlockRequest(BaseModel):
    username: str


class HoleheRequest(BaseModel):
    email: str


class HarvesterRequest(BaseModel):
    domain: str


@router.get("/ping")
def ping():
    return {"status": "recon router live"}


@router.post("/sherlock")
async def sherlock_scan(req: SherlockRequest):
    username = req.username.strip()
    if not username:
        raise HTTPException(status_code=400, detail="Username is required")
    return await run_sherlock(username)


@router.post("/holehe")
async def holehe_scan(req: HoleheRequest):
    email = req.email.strip()
    if not email or "@" not in email:
        raise HTTPException(status_code=400, detail="Valid email is required")
    return await run_holehe(email)


@router.post("/harvester")
async def harvester_scan(req: HarvesterRequest):
    domain = req.domain.strip()
    if not domain:
        raise HTTPException(status_code=400, detail="Domain is required")
    return await run_harvester(domain)
