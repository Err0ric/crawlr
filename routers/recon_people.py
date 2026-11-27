"""Lookups about a person: search by name, the accounts and keys behind an email address, and
when a GitHub account is active. Name results are candidates: a name is shared by many people."""

from fastapi import APIRouter
from pydantic import BaseModel, Field

from core import validate
from modules.email_accounts import run_email_accounts
from modules.github_activity import run_github_activity
from modules.name_search import run_name_search

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
