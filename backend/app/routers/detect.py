"""
POST /api/detect

This is the endpoint background.js / popup.js / dashboard js/api.js all
call. It runs the URL through VirusTotal, Gemini, a WHOIS domain-age
lookup, and a local heuristic scorer, then combines them into one
verdict + confidence score.

Response shape matches what background.js's normalizeDetectionResponse()
expects:
  { url, verdict, confidence_score, vt_positives, domain_age_days,
    awareness_message, vt_total_engines, vt_vendors, vt_details }

vt_details carries VirusTotal's own "Details" tab fields (categories,
submission/analysis dates, last HTTP response, HTML title, etc.) — see
app/services/virustotal.py's _extract_details() for the full shape.
"""
import asyncio
import time

from fastapi import APIRouter, Header, HTTPException, Request
from pydantic import BaseModel, HttpUrl

from app.config import PHISHSHIELD_API_KEY
from app.services import virustotal, gemini, domain_age, heuristics

router = APIRouter()


class DetectRequest(BaseModel):
    url: str


# ---------------------------------------------------------------------
# Minimal in-memory rate limiter.
#
# Once this backend is public, every /api/detect call spends your
# VirusTotal quota (4/min, 500/day on the free tier) and your Gemini
# quota. Without a limit, one abusive client — or just a bug in
# someone's copy of the extension — can burn through your whole day's
# quota in seconds. This is a per-process sliding window, not a
# distributed one: fine for a single free-tier instance (which is what
# you'll be running), not meant to scale past that.
# ---------------------------------------------------------------------
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
            detail=f"Too many requests — limit is {RATE_LIMIT_MAX_REQUESTS} per "
                   f"{RATE_LIMIT_WINDOW_SECONDS}s. Try again shortly.",
        )
    recent.append(now)
    _request_log[client_ip] = recent


def _combine(vt: dict, ai: dict, heur: dict, age_days) -> dict:
    """
    Weighted blend of the three signals into a single 0-100 risk score.
    Weights are renormalized based on which signals actually returned
    data, so a missing API key doesn't silently zero out the score.
    """
    signals = []  # list of (risk_0_100, weight)

    if vt.get("enabled"):
        total = max(vt.get("total_engines", 0), 1)
        flagged = vt.get("malicious", 0) * 1.0 + vt.get("suspicious", 0) * 0.5
        vt_risk = min((flagged / total) * 100 * 3, 100)  # a few hits is already bad
        signals.append((vt_risk, 0.5))

    if ai.get("available") and ai.get("verdict") is not None:
        verdict_risk = {"phishing": 90, "suspicious": 55, "safe": 10}[ai["verdict"]]
        conf = ai.get("confidence")
        ai_risk = verdict_risk if conf is None else (verdict_risk * conf + 10 * (1 - conf))
        signals.append((ai_risk, 0.35))

    signals.append((heur["score"], 0.15))

    total_weight = sum(w for _, w in signals)
    risk = sum(r * w for r, w in signals) / total_weight

    if age_days is not None and age_days < 30:
        risk = min(risk + 10, 100)

    if risk >= 70:
        verdict = "phishing"
    elif risk >= 35:
        verdict = "suspicious"
    else:
        verdict = "safe"

    # A weighted average can bury a real signal — e.g. VirusTotal flagging
    # 4/90 vendors only nudges the blended score up a little, so it still
    # landed on "safe" even though VT genuinely flagged something. That's
    # misleading: one real hit from any signal is now enough on its own
    # to call it at least "suspicious". Verdict is only ever pushed UP
    # here, never downgraded — a high blended score can still mean
    # "phishing" even if, say, VT itself found nothing.
    vt_flagged = vt.get("malicious", 0) + vt.get("suspicious", 0)
    vt_total = max(vt.get("total_engines", 0), 1)
    vt_hit = vt.get("enabled") and (
        vt.get("malicious", 0) >= 3 or (vt_flagged / vt_total) >= 0.05
    )
    heur_hit = bool(heur.get("reasons")) and heur["reasons"][0] != "No local risk indicators"
    ai_hit = ai.get("verdict") in ("suspicious", "phishing")

    if verdict == "safe" and (vt_hit or heur_hit or ai_hit):
        verdict = "suspicious"

    return {"risk_score": risk, "verdict": verdict}


def _fallback_message(verdict: str, vt: dict, age_days, heur: dict) -> str:
    parts = []
    if verdict != "safe" and vt.get("enabled") and (vt.get("malicious") or vt.get("suspicious")):
        parts.append(
            f"Flagged by {vt['malicious']} of {vt['total_engines']} VirusTotal security vendors."
        )
    if age_days is not None and age_days < 30:
        parts.append(f"Domain was registered only {age_days} day(s) ago.")
    if not parts and heur["reasons"] and heur["reasons"][0] != "No local risk indicators":
        parts.append(heur["reasons"][0] + ".")
    if not parts:
        parts.append("No strong risk indicators found." if verdict == "safe" else "Exercise caution with this link.")
    return " ".join(parts)


@router.post("/api/detect")
async def detect(req: DetectRequest, request: Request, x_phishshield_key: str | None = Header(default=None)):
    # Only enforced if PHISHSHIELD_API_KEY is set in .env — see config.py.
    # Keeps local/dev usage simple (no key needed) while giving anyone
    # who wants it a way to stop other local processes from hitting the
    # endpoint and burning the VirusTotal/Gemini quota.
    if PHISHSHIELD_API_KEY and x_phishshield_key != PHISHSHIELD_API_KEY:
        raise HTTPException(status_code=401, detail="Missing or invalid X-PhishShield-Key header")

    _check_rate_limit(request.client.host if request.client else "unknown")

    url = req.url

    # Run VirusTotal, Gemini, and the WHOIS lookup all CONCURRENTLY.
    # VirusTotal alone can take up to ~8s for a URL it hasn't seen before
    # (submit + poll for analysis), and previously nothing else started
    # until that finished. Gemini analyzes the URL/domain structure
    # directly rather than waiting on VT context, so total wall-clock
    # time is now max(VT, Gemini, WHOIS) instead of VT + max(Gemini, WHOIS).
    heur_result = heuristics.score_url(url)

    vt_result, ai_result, age_days = await asyncio.gather(
    virustotal.check_url(url),
    gemini.analyze_url(url, {}, None),
    domain_age.get_domain_age_days(url),
)

    combined = _combine(vt_result, ai_result, heur_result, age_days)

    message = ai_result.get("message") or _fallback_message(
        combined["verdict"], vt_result, age_days, heur_result
    )

    return {
        "url": url,
        "verdict": combined["verdict"],
        "confidence_score": round(combined["risk_score"] / 100, 4),
        "vt_positives": vt_result.get("malicious", 0) if vt_result.get("enabled") else None,
        "vt_total_engines": vt_result.get("total_engines", 0) if vt_result.get("enabled") else None,
        "vt_vendors": vt_result.get("vendors", []) if vt_result.get("enabled") else [],
        "vt_details": vt_result.get("details", {}) if vt_result.get("enabled") else {},
        "domain_age_days": age_days,
        "awareness_message": message,
    }
