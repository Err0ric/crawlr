"""Identity evidence that goes deeper than a profile lookup: GitHub's public extras, avatar
hashes, and a check that an account link really leads to a profile."""

from urllib.parse import urlsplit

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from core import profile_record, validate
from modules.avatar_hash import MAX_IMAGES, run_avatar_hash
from modules.github import run_github_deep
from modules.handle_probe import run_handle_probe
from modules.link_verify import MAX_LINKS, run_link_verify
from modules.profile_archive import MAX_URL as ARCHIVE_MAX_URL, run_profile_archive
from modules.profiles import run_profiles

router = APIRouter()


class GithubDeepRequest(BaseModel):
    username: str = Field(max_length=320)


class HandleProbeRequest(BaseModel):
    username: str = Field(max_length=320)


class ProfilesRequest(BaseModel):
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


class ProfileArchiveRequest(BaseModel):
    url: str = Field(min_length=1, max_length=ARCHIVE_MAX_URL)


@router.post("/github-deep")
async def github_deep(req: GithubDeepRequest):
    return await run_github_deep(validate.username(req.username))


@router.post("/handle-probe")
async def handle_probe(req: HandleProbeRequest):
    """One similar handle, on a click: GitHub, the platform check and Bluesky, with the
    pictures hashed here. Never Sherlock or Maigret, never an adult or dating site."""
    return await run_handle_probe(validate.username(req.username))


@router.post("/profiles")
async def profiles(req: ProfilesRequest, request: Request):
    """What the handle's public record says on sites with an official, keyless API (the list is
    in modules/profiles). Fixed hosts only, never an adult or dating site, pictures hashed here."""
    profile_record.bind(getattr(request.state, "run_session", ""))      # the names and bios go on this visitor's record
    username = validate.username(req.username)
    answer = await run_profiles(username)
    # The minor guard's content check reads these names and bios too. This source is not a
    # profile reader for the adult pass: it only adds text to scan.
    profile_record.note(username, "profiles", answer)
    return answer


@router.post("/avatar-hash")
async def avatar_hash(req: AvatarHashRequest):
    # Each URL is vetted by core.netguard inside the module, hop by hop.
    return await run_avatar_hash([i.model_dump() for i in req.images])


@router.post("/verify-links")
async def verify_links(req: VerifyLinksRequest, request: Request):
    profile_record.bind(getattr(request.state, "run_session", ""))      # the minor guard reads this visitor's record
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
    # A link on an adult or dating site is opened only with the opt-in, and only when the minor
    # guard allows an adult pass for the handle (core.adult_guard.gate, inside the module).
    return await run_link_verify(username, links, adult=req.adult)


@router.post("/profile-archive")
async def profile_archive(req: ProfileArchiveRequest):
    """Which copies of one profile page the Internet Archive holds, on a click. One request to
    the archive's index; the archived page and the profile's own host are never fetched. The
    module checks the URL and refuses adult and dating sites before any request, with the
    state `refused` (there is no opt-in on this route)."""
    return await run_profile_archive(req.url)
