import hashlib
import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles

from core.house_key import quota_status
from core.logging import configure_logging, get_logger
from middleware.observability import BodyLimitMiddleware, RequestContextMiddleware, SecurityHeadersMiddleware, client_ip
from middleware.rate_limit import RateLimitMiddleware
from modules.ai_provider import AIError
from routers import recon, analyze, recon_infra, hash_lookup, email_headers, phone, recon_identity

configure_logging()
log = get_logger("crawlr")

APP_VERSION = "0.2.0"
SITE_URL = os.getenv("SITE_URL", "https://crawlr.lol").rstrip("/")
UI_DIR = Path("static/v2")


@asynccontextmanager
async def lifespan(_app: FastAPI):
    log.info("crawlr started", extra={"version": APP_VERSION, "assets": asset_fingerprint()})
    yield
    log.info("crawlr stopping")


# The generated API docs are for development. In production they only advertise the
# endpoint list, so they are off unless ENABLE_API_DOCS is set.
API_DOCS = os.getenv("ENABLE_API_DOCS", "").strip().lower() in ("1", "true", "yes", "on")

app = FastAPI(
    title="CrawlR", version=APP_VERSION, lifespan=lifespan,
    docs_url="/docs" if API_DOCS else None,
    redoc_url=None,
    openapi_url="/openapi.json" if API_DOCS else None,
)

# Middleware runs in reverse registration order on the way in, so the request context
# (request id + access log) is registered last to wrap everything, and gzip sits just
# inside it so every response body can be compressed.
app.add_middleware(RateLimitMiddleware)
app.add_middleware(BodyLimitMiddleware)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(GZipMiddleware, minimum_size=1024)
app.add_middleware(RequestContextMiddleware)


@app.exception_handler(AIError)
async def ai_error_handler(_request: Request, exc: AIError):
    """Provider failures (bad key, rate limit, outage) become a typed JSON error, not a bare 500."""
    headers = {"Retry-After": str(exc.retry_after)} if exc.retry_after else None
    return JSONResponse(status_code=exc.status, content={"detail": exc.message, "code": exc.code}, headers=headers)


# ---- static assets ---------------------------------------------------------------
# The UI is plain ES modules with no build step. To make them cacheable forever without
# renaming files, the page references them under /assets/<fingerprint>/..., where the
# fingerprint is a hash of every file in static/v2. Relative imports between modules
# resolve under the same prefix, so one changed file gives every asset a new URL.
_fingerprint_cache: tuple[tuple, str] | None = None


def asset_fingerprint() -> str:
    global _fingerprint_cache
    files = sorted(p for p in UI_DIR.rglob("*") if p.is_file() and p.suffix != ".md")
    signature = tuple((str(p), p.stat().st_mtime_ns, p.stat().st_size) for p in files)
    if _fingerprint_cache and _fingerprint_cache[0] == signature:
        return _fingerprint_cache[1]
    h = hashlib.sha256()
    for p in files:
        h.update(str(p.relative_to(UI_DIR)).encode())
        h.update(p.read_bytes())
    _fingerprint_cache = (signature, h.hexdigest()[:12])
    return _fingerprint_cache[1]


def render_index() -> str:
    html = (UI_DIR / "index.html").read_text(encoding="utf-8")
    return html.replace("/static/v2/", f"/assets/{asset_fingerprint()}/").replace("{{SITE_URL}}", SITE_URL)


class FingerprintedStatic(StaticFiles):
    """Serves static/v2 under /assets/<anything>/. The first path segment is only a cache
    key, so a page loaded before a deploy can still fetch its assets afterwards."""

    async def get_response(self, path: str, scope):
        _, _, rest = path.partition("/")
        return await super().get_response(rest, scope)


app.mount("/assets", FingerprintedStatic(directory=str(UI_DIR)), name="assets")
app.mount("/static", StaticFiles(directory="static"), name="static")

app.include_router(recon.router, prefix="/api/recon", tags=["recon"])
app.include_router(recon_identity.router, prefix="/api/recon", tags=["recon"])
app.include_router(analyze.router, prefix="/api/analyze", tags=["analyze"])
app.include_router(recon_infra.router, prefix="/api/infra", tags=["infra"])
app.include_router(hash_lookup.router, prefix="/api/hash", tags=["hash"])
app.include_router(email_headers.router, prefix="/api/email", tags=["email"])
app.include_router(phone.router, prefix="/api/phone", tags=["phone"])


# HEAD is allowed on pages so uptime monitors, link checkers and crawlers get a 200.
@app.api_route("/", methods=["GET", "HEAD"], response_class=HTMLResponse, include_in_schema=False)
def root():
    return HTMLResponse(render_index())


@app.api_route("/v2", methods=["GET", "HEAD"], include_in_schema=False)
def v2():
    """Alias for links shared during the v2 rollout."""
    return RedirectResponse("/", status_code=308)


@app.api_route("/classic", methods=["GET", "HEAD"], include_in_schema=False)
def classic():
    """The original single-file interface was retired; old bookmarks land on the current UI."""
    return RedirectResponse("/", status_code=308)


@app.api_route("/robots.txt", methods=["GET", "HEAD"], include_in_schema=False)
def robots():
    return PlainTextResponse(f"User-agent: *\nAllow: /\nDisallow: /api/\n\nSitemap: {SITE_URL}/sitemap.xml\n")


@app.api_route("/sitemap.xml", methods=["GET", "HEAD"], include_in_schema=False)
def sitemap():
    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
        f"  <url><loc>{SITE_URL}/</loc><changefreq>weekly</changefreq><priority>1.0</priority></url>\n"
        "</urlset>\n"
    )
    return Response(content=xml, media_type="application/xml")


@app.api_route("/favicon.ico", methods=["GET", "HEAD"], include_in_schema=False)
def favicon():
    return RedirectResponse("/static/favicon.svg", status_code=308)


@app.get("/api/quota", tags=["meta"])
def quota(request: Request):
    """Free-AI availability and remaining calls for the caller's IP. Drives the Settings UI."""
    return quota_status(client_ip(request))


@app.get("/api/health", tags=["meta"])
def health():
    """Liveness probe for Railway and uptime monitors."""
    return {"status": "ok", "service": "crawlr", "version": APP_VERSION}


@app.head("/api/health", include_in_schema=False)
def health_head():
    """HEAD for monitors that do not send GET. Kept out of the schema so the operation id stays unique."""
    return Response()
