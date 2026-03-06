from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from modules.sherlock import run_sherlock

router = APIRouter()


class SherlockRequest(BaseModel):
    username: str


@router.get("/ping")
def ping():
    return {"status": "recon router live"}


@router.post("/sherlock")
async def sherlock_scan(req: SherlockRequest):
    username = req.username.strip()
    if not username:
        raise HTTPException(status_code=400, detail="Username is required")
    return await run_sherlock(username)
