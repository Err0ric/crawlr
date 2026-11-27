"""Lookups about a person: search by name, the accounts and keys behind an email address, and
when a GitHub account or an account on a site with public post times is active. Name results are candidates: a name is shared by many people."""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from core import validate
from modules.email_accounts import run_email_accounts
from modules.github_activity import run_github_activity
from modules.name_search import run_name_search
from modules.post_activity import SITES as POST_ACTIVITY_SITES, default_instance, mastodon_instances, run_post_activity

router = APIRouter()


class NameSearchRequest(BaseModel):
    name: str = Field(max_length=200)
    # Used only to rank and annotate what comes back. Never sent to a source.
    location: str = Field(default="", max_length=80)
    employer: str = Field(default="", max_length=80)
    keyword: str = Field(default="", max_length=80)


class EmailAccountsRequest(BaseModel):
    email: str = Field(max_length=320)


class GithubActivityRequest(BaseModel):
    username: str = Field(max_length=320)


class PostActivityRequest(BaseModel):
    site: str = Field(max_length=40)
    username: str = Field(max_length=320)
    instance: str = Field(default="", max_length=253)    # Mastodon only; empty is the default instance


@router.post("/name-search")
async def name_search(req: NameSearchRequest):
    return await run_name_search(validate.person_name(req.name), req.location, req.employer, req.keyword)


@router.post("/email-accounts")
async def email_accounts(req: EmailAccountsRequest):
    """GitHub accounts and OpenPGP keys tied to an address. Three requests to two fixed hosts."""
    return await run_email_accounts(validate.email(req.email))


@router.post("/github-activity")
async def github_activity(req: GithubActivityRequest):
    """Hours, weekdays and repositories from an account's public events. The offset range is a hint."""
    return await run_github_activity(validate.username(req.username))


@router.post("/post-activity")
async def post_activity(req: PostActivityRequest):
    """Hours and weekdays from an account's public post times on one site (Hacker News, Mastodon
    or Lobsters), on a click. Fixed hosts only; a Mastodon instance must be on the allowlist in
    modules/profiles/mastodon.py. The offset range is a hint."""
    site = req.site.strip().lower()
    if site not in POST_ACTIVITY_SITES:
        raise HTTPException(status_code=400, detail="Choose one of: " + ", ".join(sorted(POST_ACTIVITY_SITES)) + ".")
    username = validate.username(req.username)
    instance = ""
    if site == "mastodon":
        instance = validate.host(req.instance, allow_ip=False) if req.instance.strip() else default_instance()
        if instance not in mastodon_instances():
            raise HTTPException(status_code=400, detail="CrawlR does not read this Mastodon instance.")
    return await run_post_activity(site, username, instance)
