from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from routers import recon, analyze, recon_infra, hash_lookup, email_headers
from middleware.rate_limit import SoftRateLimitMiddleware

app = FastAPI(title="CrawlR", version="0.1.0")

app.add_middleware(SoftRateLimitMiddleware)

app.mount("/static", StaticFiles(directory="static"), name="static")

app.include_router(recon.router, prefix="/api/recon", tags=["recon"])
app.include_router(analyze.router, prefix="/api/analyze", tags=["analyze"])
app.include_router(recon_infra.router, prefix="/api/infra", tags=["infra"])
app.include_router(hash_lookup.router, prefix="/api/hash", tags=["hash"])
app.include_router(email_headers.router, prefix="/api/email", tags=["email"])

@app.get("/")
def root():
    return FileResponse("static/index.html")