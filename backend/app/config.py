"""
Configuration for the PhishShield backend.

All secrets come from environment variables (loaded from a .env file if
present). Never hardcode API keys here — copy .env.example to .env and
fill in your own keys.
"""
import os
from dotenv import load_dotenv

load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY", "")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.0-flash")

# Optional shared secret between the extension and this backend. If set,
# requests to /api/detect must include a matching X-PhishShield-Key
# header (see public/js/config.js). Leave unset to keep the endpoint
# open, which is fine for local-only development.
PHISHSHIELD_API_KEY = os.getenv("PHISHSHIELD_API_KEY", "")

# Extra CORS origins (comma-separated) on top of the built-in Firebase
# Hosting + localhost origins. Only needed if you add a custom domain.
CORS_ALLOW_ORIGINS = os.getenv("CORS_ALLOW_ORIGINS", "")

HOST = os.getenv("PHISHSHIELD_HOST", "127.0.0.1")
PORT = int(os.getenv("PHISHSHIELD_PORT", "8000"))
