from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from routers import recon, analyze, recon_infra, hash_lookup, email_headers, phone, vehicles
from middleware.rate_limit import SoftRateLimitMiddleware
from middleware.observability import RequestContextMiddleware, SecurityHeadersMiddleware
from core.logging import configure_logging, get_logger
from core.house_key import quota_status
from middleware.observability import client_ip
from fastapi import Request

configure_logging()
log = get_logger("crawlr")

APP_VERSION = "0.1.0"

@asynccontextmanager
async def lifespan(_app: FastAPI):
    log.info("crawlr started", extra={"version": APP_VERSION})
    yield
    log.info("crawlr stopping")


app = FastAPI(title="CrawlR", version=APP_VERSION, lifespan=lifespan)

# Middleware runs in reverse registration order on the way in, so the
# request-context (request id + access log) is registered last to wrap everything.
app.add_middleware(SoftRateLimitMiddleware)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RequestContextMiddleware)

app.mount("/static", StaticFiles(directory="static"), name="static")

app.include_router(recon.router, prefix="/api/recon", tags=["recon"])
app.include_router(analyze.router, prefix="/api/analyze", tags=["analyze"])
app.include_router(recon_infra.router, prefix="/api/infra", tags=["infra"])
app.include_router(hash_lookup.router, prefix="/api/hash", tags=["hash"])
app.include_router(email_headers.router, prefix="/api/email", tags=["email"])
app.include_router(phone.router, prefix="/api/phone", tags=["phone"])
app.include_router(vehicles.router, prefix="/api/vehicles", tags=["vehicles"])

@app.get("/")
def root():
    return FileResponse("static/v2/index.html")


@app.get("/classic")
def classic():
    """Original single-file interface, kept reachable during the v2 rollout."""
    return FileResponse("static/index.html")


@app.get("/v2")
def v2():
    """Alias for links shared during the v2 rollout."""
    return FileResponse("static/v2/index.html")


@app.get("/api/quota", tags=["meta"])
def quota(request: Request):
    """Free-AI availability and remaining calls for the caller's IP. Drives the Settings UI."""
    return quota_status(client_ip(request))


@app.get("/api/health", tags=["meta"])
def health():
    """Liveness probe for Railway and uptime monitors."""
    return {"status": "ok", "service": "crawlr", "version": APP_VERSION}
