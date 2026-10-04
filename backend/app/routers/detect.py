# backend/app/routers/detect.py

import asyncio
import time
from fastapi import APIRouter, Header, HTTPException, Request
from pydantic import BaseModel

from app.config import PHISHSHIELD_API_KEY
from app.services import virustotal, gemini, domain_age, heuristics

router = APIRouter()

class DetectRequest(BaseModel):
    url: str

# In-memory rate limiter (20 requests / 60 seconds per IP)
RATE_LIMIT_MAX_REQUESTS = 20
RATE_LIMIT_WINDOW_SECONDS = 60
_request_log: dict[str, list[float]] = {}

def _check_rate_limit(client_ip: str) -> None:
    now = time.monotonic()
    window_start = now - RATE_LIMIT_WINDOW_SECONDS
    recent = [t for t in _request_log.get(client_ip, []) if t > window_start]
    if len(recent) >= RATE_LIMIT_MAX_REQUESTS:
        raise HTTPException(
            status_code=429,
            detail=f"Too many requests - limit is {RATE_LIMIT_MAX_REQUESTS} per {RATE_LIMIT_WINDOW_SECONDS}s. Try again shortly."
        )
    recent.append(now)
    _request_log[client_ip] = recent

def _combine(vt: dict, ai: dict, heur: dict, age_days) -> dict:
    """
    Weighted blend of signals into a single 0-100 risk score.
    """
    signals = []

    if vt.get("enabled"):
        total = max(vt.get("total_engines", 0), 1)
        flagged = vt.get("malicious", 0) * 1.0 + vt.get("suspicious", 0) * 0.5
        vt_risk = min((flagged / total) * 100 * 3, 100)
        signals.append((vt_risk, 0.5))

    if ai.get("available") and ai.get("verdict") is not None:
        verdict_risk = {"phishing": 90, "suspicious": 55, "safe": 10}.get(ai["verdict"], 10)
        conf = ai.get("confidence")
        ai_risk = verdict_risk if conf is None else (verdict_risk * conf + 10 * (1 - conf))
        signals.append((ai_risk, 0.35))

    signals.append((heur.get("score", 0), 0.15))

    total_weight = sum(w for _, w in signals) or 1.0
    risk = sum(r * w for r, w in signals) / total_weight

    if age_days is not None and age_days < 30:
        risk = min(risk + 10, 100)

    if risk >= 70:
        verdict = "phishing"
    elif risk >= 35:
        verdict = "suspicious"
    else:
        verdict = "safe"

    # Override verdict if any single signal flags significant risk
    vt_flagged = vt.get("malicious", 0) + vt.get("suspicious", 0)
    vt_total = max(vt.get("total_engines", 0), 1)
    vt_hit = vt.get("enabled") and (
        vt.get("malicious", 0) >= 3 or (vt_flagged / vt_total) >= 0.05
    )
    heur_hit = bool(heur.get("reasons")) and heur["reasons"][0] != "No local risk indicators"
    ai_hit = ai.get("verdict") in ("suspicious", "phishing")

    if verdict == "safe" and (vt_hit or heur_hit or ai_hit):
        verdict = "suspicious"
        risk = max(risk, 35)

    return {"risk_score": risk, "verdict": verdict}

def _fallback_message(verdict: str, vt: dict, age_days, heur: dict) -> str:
    parts = []
    if verdict != "safe" and vt.get("enabled") and (vt.get("malicious") or vt.get("suspicious")):
        parts.append(
            f"Flagged by {vt['malicious']} of {vt['total_engines']} VirusTotal security vendors."
        )
    if age_days is not None and age_days < 30:
        parts.append(f"Domain was registered only {age_days} day(s) ago.")
    if not parts and heur.get("reasons") and heur["reasons"][0] != "No local risk indicators":
        parts.append(heur["reasons"][0] + ".")
    if not parts:
        parts.append("No strong risk indicators found." if verdict == "safe" else "Exercise caution with this link.")
    return " ".join(parts)

async def _run_detection(url: str) -> dict:
    url = url.strip()

    heur_result = heuristics.score_url(url)

    # VirusTotal and domain age run concurrently first, then Gemini gets
    # their results as context for a better verdict.
    vt_result, age_days = await asyncio.gather(
        virustotal.check_url(url),
        domain_age.get_domain_age_days(url),
    )

    ai_result = await gemini.analyze_url(url, vt_result, age_days)

    combined = _combine(vt_result, ai_result, heur_result, age_days)

    message = ai_result.get("message") or _fallback_message(
        combined["verdict"], vt_result, age_days, heur_result
    )

    vt_ok = bool(vt_result.get("enabled"))

    return {
        "url": url,
        "verdict": combined["verdict"],
        "confidence_score": round(combined["risk_score"] / 100, 4),
        "vt_positives": vt_result.get("malicious", 0) if vt_ok else None,
        "vt_total_engines": vt_result.get("total_engines", 0) if vt_ok else None,
        "vt_vendors": vt_result.get("vendors", []) if vt_ok else [],
        "vt_details": vt_result.get("details", {}) if vt_ok else {},
        "domain_age_days": age_days,
        "awareness_message": message,
        "vt_enabled": vt_ok,
        "vt_error": vt_result.get("error"),
    }

@router.post("/api/detect")
async def detect(req: DetectRequest, request: Request, x_phishshield_key: str | None = Header(default=None)):
    if PHISHSHIELD_API_KEY and x_phishshield_key != PHISHSHIELD_API_KEY:
        raise HTTPException(status_code=401, detail="Missing or invalid X-PhishShield-Key header")

    client_ip = request.client.host if request.client else "unknown"
    _check_rate_limit(client_ip)

    return await _run_detection(req.url)

# Alias so the frontend's '/detect' fallback path also works.
@router.post("/detect")
async def detect_alias(req: DetectRequest, request: Request, x_phishshield_key: str | None = Header(default=None)):
    return await detect(req, request, x_phishshield_key)
