from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from modules.sherlock import run_sherlock
from modules.holehe import run_holehe

router = APIRouter()


class SherlockRequest(BaseModel):
    username: str


class HoleheRequest(BaseModel):
    email: str


@router.get("/ping")
def ping():
    return {"status": "recon router live"}


@router.post("/sherlock")
async def sherlock_scan(req: SherlockRequest):
    username = req.username.strip()
    if not username:
        raise HTTPException(status_code=400, detail="Username is required")
    return await run_sherlock(username)


@router.post("/holehe")
async def holehe_scan(req: HoleheRequest):
    email = req.email.strip()
    if not email or "@" not in email:
        raise HTTPException(status_code=400, detail="Valid email is required")
    return await run_holehe(email)
