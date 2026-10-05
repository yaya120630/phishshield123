import logging
import pathlib

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.config import CORS_ALLOW_ORIGINS
from app.routers import detect
from app.services import virustotal

logger = logging.getLogger("phishshield")

# The web copy of the dashboard/landing page lives in the repo's public/
# folder (what Firebase Hosting deploys). backend/app/main.py -> parents[2]
# is the repo root, so the public dir is <root>/public.
REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
PUBLIC_DIR = REPO_ROOT / "public"

app = FastAPI(title="PhishShield Backend")

# ----- CORS -----
# allow_origins=["*"] together with allow_credentials=True is rejected by
# browsers, so we pin the real origins instead. These cover the Firebase
# Hosting site (the web dashboard + landing page) and local development.
# The extension itself sends requests from a chrome-extension:// origin,
# which is not subject to this list, so it keeps working regardless.
_default_origins = [
    "https://phishshield-904ab.web.app",
    "https://phishshield-904ab.firebaseapp.com",
    "http://localhost:8000",
    "http://127.0.0.1:8000",
    "http://localhost:5000",
    "http://127.0.0.1:5000",
]
_extra_origins = [o.strip() for o in CORS_ALLOW_ORIGINS.split(",") if o.strip()]
ALLOWED_ORIGINS = _default_origins + _extra_origins

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    # Requests authenticate with the X-PhishShield-Key header, not cookies,
    # so credentials are not needed — leaving this False keeps the pinned
    # origin list valid.
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

# Register API routers FIRST so routes take priority
app.include_router(detect.router)


@app.on_event("startup")
async def _warn_if_no_vt_key() -> None:
    """Log a clear warning at startup if the VirusTotal key is not configured,
    so a missing key is obvious in the Render logs rather than silent."""
    if not virustotal._api_key():
        logger.warning(
            "VT_API_KEY is not set — VirusTotal lookups are disabled and every "
            "scan will report 'VirusTotal had no data'. Set VT_API_KEY in "
            "Render > Environment (a valid key is 64 hex characters)."
        )
    else:
        logger.info("VirusTotal API key detected — VT lookups enabled.")


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.get("/dashboard")
async def dashboard():
    return FileResponse(PUBLIC_DIR / "index.html")


# Mount the static web assets LAST to avoid route interception.
if PUBLIC_DIR.exists():
    app.mount("/", StaticFiles(directory=str(PUBLIC_DIR), html=True), name="public")
