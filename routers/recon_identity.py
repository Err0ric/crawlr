"""Identity evidence that goes deeper than a profile lookup: GitHub's public extras and avatar hashes."""

from fastapi import APIRouter
from pydantic import BaseModel, Field

from core import validate
from modules.avatar_hash import MAX_IMAGES, run_avatar_hash
from modules.github import run_github_deep

router = APIRouter()


class GithubDeepRequest(BaseModel):
    username: str = Field(max_length=320)


class AvatarImage(BaseModel):
    id: str = Field(min_length=1, max_length=80)
    url: str = Field(min_length=1, max_length=600)


class AvatarHashRequest(BaseModel):
    images: list[AvatarImage] = Field(max_length=MAX_IMAGES)


@router.post("/github-deep")
async def github_deep(req: GithubDeepRequest):
    return await run_github_deep(validate.username(req.username))


@router.post("/avatar-hash")
async def avatar_hash(req: AvatarHashRequest):
    # Each URL is vetted by core.netguard inside the module, hop by hop.
    return await run_avatar_hash([i.model_dump() for i in req.images])
