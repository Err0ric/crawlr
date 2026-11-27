"""Ownership pivots for a domain: the tracker and ad account IDs on its home page, and the
metadata inside the documents it publishes. Both request the target's own site, on a click."""

from fastapi import APIRouter
from pydantic import BaseModel, Field

from core import validate
from modules.doc_metadata import run_doc_metadata
from modules.tracker_ids import run_tracker_ids

router = APIRouter()


class DomainRequest(BaseModel):
    domain: str = Field(max_length=320)


@router.post("/tracker-ids")
async def tracker_ids(req: DomainRequest):
    """Analytics, tag and ad account IDs in the home page's markup. One request to the domain."""
    return await run_tracker_ids(validate.host(req.domain, allow_ip=False))


@router.post("/doc-metadata")
async def doc_metadata(req: DomainRequest):
    """Metadata inside public PDFs and Office files. One request to the Internet Archive's
    index, then up to 8 documents from the domain itself."""
    return await run_doc_metadata(validate.host(req.domain, allow_ip=False))
