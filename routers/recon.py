from fastapi import APIRouter, HTTPException, Header
from pydantic import BaseModel
from typing import Optional
from modules.sherlock import run_sherlock
from modules.holehe import run_holehe
from modules.harvester import run_harvester
from modules.hibp import run_hibp
from modules.gravatar import run_gravatar
from modules.github import run_github
from modules.enricher import run_enricher
from modules.platform_check import run_platform_check
from modules.hunter import run_hunter
from modules.shodan_lookup import run_shodan

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


class PlatformCheckRequest(BaseModel):
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


@router.post("/platform-check")
async def platform_check(req: PlatformCheckRequest):
    username = req.username.strip()
    if not username:
        raise HTTPException(status_code=400, detail="Username is required")
    return await run_platform_check(username, req.sherlock_sites)


@router.post("/hunter")
async def hunter_scan(req: HarvesterRequest, x_hunter_key: str = Header(...)):
    domain = req.domain.strip()
    if not domain:
        raise HTTPException(status_code=400, detail="Domain is required")
    if not x_hunter_key:
        raise HTTPException(status_code=401, detail="Hunter.io API key is required")
    return await run_hunter(domain, x_hunter_key)


class ShodanRequest(BaseModel):
    target: str


@router.post("/shodan")
async def shodan_scan(req: ShodanRequest, x_shodan_key: str = Header(...)):
    target = req.target.strip()
    if not target:
        raise HTTPException(status_code=400, detail="Target is required")
    if not x_shodan_key:
        raise HTTPException(status_code=401, detail="Shodan API key is required")
    return await run_shodan(target, x_shodan_key)
