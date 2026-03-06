from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from routers import recon, analyze, recon_infra

app = FastAPI(title="Crawlr", version="0.1.0")

app.mount("/static", StaticFiles(directory="static"), name="static")

app.include_router(recon.router, prefix="/api/recon", tags=["recon"])
app.include_router(analyze.router, prefix="/api/analyze", tags=["analyze"])
app.include_router(recon_infra.router, prefix="/api/infra", tags=["infra"])

@app.get("/")
def root():
    return FileResponse("static/index.html")