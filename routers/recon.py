from fastapi import APIRouter, HTTPException, Header, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from core import adult_guard, profile_record, validate
from modules.adult_check import run_adult_check
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
    nsfw: bool = False         # adult sites are opt-in
    adult_only: bool = False   # and are always their own pass: nsfw and adult_only go together


class MaigretRequest(BaseModel):
    username: str = Short
    nsfw: bool = False
    adult_only: bool = False


class UsernameRequest(BaseModel):
    username: str = Short


class AdultCheckRequest(BaseModel):
    username: str = Short


def _adult_gate(username: str) -> JSONResponse | None:
    """What every adult or dating path answers with when the minor guard refuses: 400
    minor_guard (the handle, or a profile found for it), or 409 mainstream_first (no ordinary
    source has run for the handle yet). Nothing is run and no site is contacted. There is no
    way to switch this off."""
    refused = adult_guard.gate(username)
    return JSONResponse(status_code=refused[0], content=refused[1]) if refused else None


def _adult_pass(req) -> bool:
    """Is this the adult pass? nsfw and adult_only must be sent together: adult and dating
    sites are never mixed into an ordinary run."""
    if req.nsfw != req.adult_only:
        raise HTTPException(status_code=400, detail=adult_guard.PASS_MESSAGE)
    return req.nsfw


def _mine(request: Request) -> None:
    """The record of the ordinary sources is kept per visitor: the random session ID that
    middleware/run_session.py issued in the crawlr_run cookie (core.profile_record.bind)."""
    profile_record.bind(getattr(request.state, "run_session", ""))


def _noted(username: str, source: str, answer: dict) -> dict:
    """Keep what an ordinary source returned for the handle (core.profile_record), so the
    adult pass can be held to the content check here as well as in the page."""
    profile_record.note(username, source, answer)
    return answer


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
async def sherlock_scan(req: SherlockRequest, request: Request):
    _mine(request)
    username = validate.username(req.username)
    if _adult_pass(req):
        return _adult_gate(username) or await run_sherlock(username, nsfw=True, adult_only=True)
    return _noted(username, "sherlock", await run_sherlock(username))


@router.post("/maigret")
async def maigret_scan(req: MaigretRequest, request: Request):
    _mine(request)
    username = validate.username(req.username)
    if _adult_pass(req):
        return _adult_gate(username) or await run_maigret(username, nsfw=True, adult_only=True)
    return _noted(username, "maigret", await run_maigret(username))


@router.post("/adult-check")
async def adult_check_scan(req: AdultCheckRequest, request: Request):
    """Opt-in: verified existence checks on adult and dating sites. Text metadata only.
    The UI calls this only when the investigator switched the adult mode on, after the
    ordinary sources, and only when its own check of the profiles they found is clean."""
    _mine(request)
    username = validate.username(req.username)
    return _adult_gate(username) or await run_adult_check(username)


@router.post("/minor-guard")
async def minor_guard_verdict(req: AdultCheckRequest, request: Request):
    """The guard's answer for a handle and nothing else: no site is contacted. The page asks
    when its own check has blocked the adult pass, so the block is decided (and logged, by
    rule ID only) on the server as well. 200 allowed, or the same 400 and 409 as the adult pass."""
    _mine(request)
    username = validate.username(req.username)
    return _adult_gate(username) or {"allowed": True}


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
async def github_scan(req: UsernameRequest, request: Request):
    _mine(request)
    username = validate.username(req.username)
    return _noted(username, "github", await run_github(username))


@router.post("/enrich")
async def enrich_profiles(req: EnricherRequest, request: Request):
    _mine(request)
    username = validate.username(req.username)
    return _noted(username, "enricher", await run_enricher(username, req.sherlock_sites))


@router.post("/platform-check")
async def platform_check(req: PlatformCheckRequest, request: Request):
    _mine(request)
    username = validate.username(req.username)
    return _noted(username, "platform_check", await run_platform_check(username, req.sherlock_sites))


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
    # The handle the pages were found for. With it, what is read goes on the visitor's record
    # for the minor guard. Optional, so a request without one is answered as before.
    username: str = Field(default="", max_length=320)


@router.post("/scrape-profiles")
async def scrape_profiles_endpoint(req: ScrapeProfilesRequest, request: Request):
    """Active technique: fetches the listed profile pages. Each URL (and every redirect it
    takes) must be a public http(s) address; see core.netguard."""
    if not req.urls:
        raise HTTPException(status_code=400, detail="URLs list is required")
    _mine(request)
    username = validate.username(req.username) if req.username.strip() else ""      # 400 before any page is fetched
    results = await scrape_profiles([u.model_dump() for u in req.urls])
    if username:
        # The names and bios read from the pages are profile text like any other, so the minor
        # guard's content check reads them (the page's own check reads the same rows). Text to
        # scan only: this is not a profile reader, so it never opens the adult pass.
        rows = [{"state": "found", "site": r.get("site") or "Profile", "url": r.get("url", ""),
                 "display_name": r.get("display_name", ""), "bio": r.get("bio", "")}
                for r in results if isinstance(r, dict) and not r.get("error")]
        if rows:
            profile_record.note(username, "profiles", {"profiles": rows})
    return {
        "total": len(results),
        "scraped": sum(1 for r in results if "error" not in r),
        "results": results,
    }
