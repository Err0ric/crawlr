from fastapi import APIRouter, HTTPException, Header
from pydantic import BaseModel, Field

from core import validate
from modules.sherlock import run_sherlock
from modules.holehe import run_holehe
from modules.harvester import run_harvester
from modules.hibp import run_hibp
from modules.gravatar import run_gravatar
from modules.github import run_github
from modules.enricher import run_enricher
from modules.platform_check import run_platform_check
from modules.hunter import run_hunter
from modules.profile_scraper import scrape_profiles
from modules.shodan_lookup import run_shodan
from modules.internetdb import run_internetdb
from modules.maigret_mod import run_maigret

router = APIRouter()

# Every user-supplied string has a length cap, and anything that reaches a command line
# or an upstream URL goes through core.validate first.
Short = Field(max_length=320)
SiteList = Field(default=None, max_length=1000)


class SherlockRequest(BaseModel):
    username: str = Short


class MaigretRequest(BaseModel):
    username: str = Short
    nsfw: bool = False   # adult sites are opt-in


class HoleheRequest(BaseModel):
    email: str = Short


class HarvesterRequest(BaseModel):
    domain: str = Short


class EnricherRequest(BaseModel):
    username: str = Short
    sherlock_sites: list[str] | None = SiteList


class PlatformCheckRequest(BaseModel):
    username: str = Short
    sherlock_sites: list[str] | None = SiteList


@router.get("/ping")
def ping():
    return {"status": "recon router live"}


@router.post("/sherlock")
async def sherlock_scan(req: SherlockRequest):
    return await run_sherlock(validate.username(req.username))


@router.post("/maigret")
async def maigret_scan(req: MaigretRequest):
    return await run_maigret(validate.username(req.username), nsfw=req.nsfw)


@router.post("/holehe")
async def holehe_scan(req: HoleheRequest):
    return await run_holehe(validate.email(req.email))


@router.post("/harvester")
async def harvester_scan(req: HarvesterRequest):
    domain = req.domain.strip()
    if "@" in domain:
        domain = domain.split("@", 1)[1]
    return await run_harvester(validate.host(domain, allow_ip=False))


@router.post("/hibp")
async def hibp_scan(req: HoleheRequest):
    return await run_hibp(validate.email(req.email))


@router.post("/gravatar")
async def gravatar_scan(req: HoleheRequest):
    return await run_gravatar(validate.email(req.email))


@router.post("/github")
async def github_scan(req: SherlockRequest):
    return await run_github(validate.username(req.username))


@router.post("/enrich")
async def enrich_profiles(req: EnricherRequest):
    return await run_enricher(validate.username(req.username), req.sherlock_sites)


@router.post("/platform-check")
async def platform_check(req: PlatformCheckRequest):
    return await run_platform_check(validate.username(req.username), req.sherlock_sites)


@router.post("/hunter")
async def hunter_scan(req: HarvesterRequest, x_hunter_key: str = Header(..., max_length=200)):
    if not x_hunter_key:
        raise HTTPException(status_code=401, detail="Hunter.io API key is required")
    return await run_hunter(validate.host(req.domain, allow_ip=False), x_hunter_key)


class ShodanRequest(BaseModel):
    target: str = Short


@router.post("/shodan")
async def shodan_scan(req: ShodanRequest, x_shodan_key: str = Header(..., max_length=200)):
    if not x_shodan_key:
        raise HTTPException(status_code=401, detail="Shodan API key is required")
    return await run_shodan(validate.host(req.target), x_shodan_key)


@router.post("/internetdb")
async def internetdb_scan(req: ShodanRequest):
    """Keyless exposure lookup via Shodan InternetDB (ports, CVEs, hostnames, tags)."""
    return await run_internetdb(validate.host(req.target))


class ProfileUrl(BaseModel):
    site: str = Field(default="", max_length=120)
    url: str = Field(max_length=600)


class ScrapeProfilesRequest(BaseModel):
    urls: list[ProfileUrl] = Field(max_length=20)


@router.post("/scrape-profiles")
async def scrape_profiles_endpoint(req: ScrapeProfilesRequest):
    """Active technique: fetches the listed profile pages. Each URL (and every redirect it
    takes) must be a public http(s) address; see core.netguard."""
    if not req.urls:
        raise HTTPException(status_code=400, detail="URLs list is required")
    results = await scrape_profiles([u.model_dump() for u in req.urls])
    return {
        "total": len(results),
        "scraped": sum(1 for r in results if "error" not in r),
        "results": results,
    }
