"""Search by a person's name. Results are candidates: a name is shared by many people."""

from fastapi import APIRouter
from pydantic import BaseModel, Field

from core import validate
from modules.name_search import run_name_search

router = APIRouter()


class NameSearchRequest(BaseModel):
    name: str = Field(max_length=200)
    # Used only to rank and annotate what comes back. Never sent to a source.
    location: str = Field(default="", max_length=80)
    employer: str = Field(default="", max_length=80)
    keyword: str = Field(default="", max_length=80)


@router.post("/name-search")
async def name_search(req: NameSearchRequest):
    return await run_name_search(validate.person_name(req.name), req.location, req.employer, req.keyword)
