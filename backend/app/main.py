import pathlib

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.routers import detect

# The extension folder lives alongside backend/ in the project root.
EXTENSION_DIR = pathlib.Path(__file__).resolve().parents[2] / "phishshield-extension"

app = FastAPI(title="PhishShield Backend")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # the extension calls this from a service worker context
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(detect.router)


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.get("/dashboard")
async def dashboard():
    return FileResponse(EXTENSION_DIR / "dashboard.html")


# Serves dashboard.css, js/api.js, lib/lib/scanner.js, etc. at the same
# relative paths the extension's own HTML expects. Registered last so it
# doesn't shadow the routes above.
if EXTENSION_DIR.exists():
    app.mount("/", StaticFiles(directory=str(EXTENSION_DIR), html=True), name="extension-assets")
