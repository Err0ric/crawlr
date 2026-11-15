"""Identity evidence that goes deeper than a profile lookup: GitHub's public extras, avatar
hashes, and a check that an account link really leads to a profile."""

from urllib.parse import urlsplit

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from core import validate
from modules.avatar_hash import MAX_IMAGES, run_avatar_hash
from modules.github import run_github_deep
from modules.handle_probe import run_handle_probe
from modules.link_verify import MAX_LINKS, run_link_verify

router = APIRouter()


class GithubDeepRequest(BaseModel):
    username: str = Field(max_length=320)


class HandleProbeRequest(BaseModel):
    username: str = Field(max_length=320)


class AvatarImage(BaseModel):
    id: str = Field(min_length=1, max_length=80)
    url: str = Field(min_length=1, max_length=600)


class AvatarHashRequest(BaseModel):
    images: list[AvatarImage] = Field(max_length=MAX_IMAGES)


class VerifyLink(BaseModel):
    id: str = Field(min_length=1, max_length=80)
    site: str = Field(default="", max_length=120)
    url: str = Field(min_length=1, max_length=600)


class VerifyLinksRequest(BaseModel):
    username: str = Field(max_length=320)
    links: list[VerifyLink] = Field(min_length=1, max_length=MAX_LINKS)
    adult: bool = False   # the adult and dating opt-in: without it no link on such a site is opened


@router.post("/github-deep")
async def github_deep(req: GithubDeepRequest):
    return await run_github_deep(validate.username(req.username))


@router.post("/handle-probe")
async def handle_probe(req: HandleProbeRequest):
    """One similar handle, on a click: GitHub, the platform check and Bluesky, with the
    pictures hashed here. Never Sherlock or Maigret, never an adult or dating site."""
    return await run_handle_probe(validate.username(req.username))


@router.post("/avatar-hash")
async def avatar_hash(req: AvatarHashRequest):
    # Each URL is vetted by core.netguard inside the module, hop by hop.
    return await run_avatar_hash([i.model_dump() for i in req.images])


@router.post("/verify-links")
async def verify_links(req: VerifyLinksRequest):
    username = validate.username(req.username)
    links = []
    for link in req.links:
        url = link.url.strip()
        try:
            parts = urlsplit(url)
            # Profile links are plain web addresses: no credentials and no port, so the
            # endpoint cannot be pointed at an arbitrary service.
            ok = (parts.scheme.lower() in ("http", "https") and bool(parts.hostname)
                  and not (parts.username or parts.password) and parts.port is None)
        except ValueError:
            ok = False
        if not ok:
            raise HTTPException(status_code=400, detail="Every link must be an http or https URL without a port.")
        links.append({"id": link.id, "site": link.site, "url": url})
    # The module only opens links on sites the username tools know and that name this handle,
    # and each one is vetted by core.netguard hop by hop.
    # A link on an adult or dating site is opened only with the opt-in, and never for a handle
    # that suggests a minor (core.adult_guard, inside the module).
    return await run_link_verify(username, links, adult=req.adult)
