from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from modules.sherlock import run_sherlock
from modules.holehe import run_holehe
from modules.harvester import run_harvester
from modules.hibp import run_hibp
from modules.gravatar import run_gravatar
from modules.github import run_github
from modules.enricher import run_enricher

router = APIRouter()


class SherlockRequest(BaseModel):
    username: str


class HoleheRequest(BaseModel):
    email: str


class HarvesterRequest(BaseModel):
    domain: str


class EnricherRequest(BaseModel):
    username: str
    sherlock_sites: list[str] | None = None


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


@router.post("/hibp")
async def hibp_scan(req: HoleheRequest):
    email = req.email.strip()
    if not email or "@" not in email:
        raise HTTPException(status_code=400, detail="Valid email is required")
    return await run_hibp(email)


@router.post("/gravatar")
async def gravatar_scan(req: HoleheRequest):
    email = req.email.strip()
    if not email or "@" not in email:
        raise HTTPException(status_code=400, detail="Valid email is required")
    return await run_gravatar(email)


@router.post("/github")
async def github_scan(req: SherlockRequest):
    username = req.username.strip()
    if not username:
        raise HTTPException(status_code=400, detail="Username is required")
    return await run_github(username)


@router.post("/enrich")
async def enrich_profiles(req: EnricherRequest):
    username = req.username.strip()
    if not username:
        raise HTTPException(status_code=400, detail="Username is required")
    return await run_enricher(username, req.sherlock_sites)
