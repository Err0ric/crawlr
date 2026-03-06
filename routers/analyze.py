from fastapi import APIRouter, HTTPException, Header
from pydantic import BaseModel
from typing import Optional
import anthropic
import time

router = APIRouter()


class AnalyzeRequest(BaseModel):
    target: str
    sherlock: Optional[dict] = None
    holehe: Optional[dict] = None
    harvester: Optional[dict] = None


@router.get("/ping")
def ping():
    return {"status": "analyze router live"}


@router.post("/summarize")
async def summarize(req: AnalyzeRequest, x_api_key: str = Header(...)):
    if not x_api_key:
        raise HTTPException(status_code=401, detail="API key is required")

    prompt_parts = [f"Target: {req.target}\n"]

    if req.sherlock and req.sherlock.get("results"):
        sites = [r["site"] for r in req.sherlock["results"]]
        prompt_parts.append(
            f"Sherlock found {req.sherlock['total']} username matches on: {', '.join(sites[:30])}"
            + (f" (and {len(sites)-30} more)" if len(sites) > 30 else "")
        )

    if req.holehe and req.holehe.get("results"):
        accounts = [r["site"] for r in req.holehe["results"]]
        prompt_parts.append(
            f"Holehe found email registered on {req.holehe['total']} services: {', '.join(accounts)}"
        )

    if req.harvester:
        hosts = req.harvester.get("hosts", [])
        emails = req.harvester.get("emails", [])
        if hosts:
            prompt_parts.append(
                f"theHarvester found {len(hosts)} subdomains/hosts: {', '.join(hosts[:20])}"
                + (f" (and {len(hosts)-20} more)" if len(hosts) > 20 else "")
            )
        if emails:
            prompt_parts.append(
                f"theHarvester found {len(emails)} emails: {', '.join(emails[:10])}"
            )

    recon_data = "\n".join(prompt_parts)

    client = anthropic.Anthropic(api_key=x_api_key)
    t0 = time.time()

    message = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=1024,
        messages=[
            {
                "role": "user",
                "content": (
                    "You are an OSINT analyst assistant. Based on the following reconnaissance "
                    "data, provide a concise intelligence summary. Include:\n"
                    "1. A brief overview of the target's digital footprint\n"
                    "2. Notable findings or patterns\n"
                    "3. 2-4 specific suggested next investigative steps (each on its own line prefixed with →)\n\n"
                    "Keep the summary factual, concise, and actionable. Do not use markdown headers. "
                    "Use plain text with → for action items.\n\n"
                    f"Recon data:\n{recon_data}"
                ),
            }
        ],
    )

    elapsed = round(time.time() - t0, 1)
    text = message.content[0].text
    tokens = message.usage.input_tokens + message.usage.output_tokens

    return {
        "summary": text,
        "model": message.model,
        "tokens": tokens,
        "elapsed": elapsed,
    }
