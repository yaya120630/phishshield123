"""
Gemini integration — asks the model to look at the URL (plus VirusTotal
and domain-age context) and return a structured verdict + a short,
human-readable explanation for the popup/dashboard.

analyze_url() never raises — on any failure it returns available=False
so detect.py can fall back to VirusTotal + local heuristics alone.
"""
import json
import httpx

from app.config import GEMINI_API_KEY, GEMINI_MODEL

GEMINI_URL = (
    f"https://generativelanguage.googleapis.com/v1beta/models/"
    f"{GEMINI_MODEL}:generateContent"
)

UNAVAILABLE = {"available": False, "verdict": None, "confidence": None, "message": ""}


def _build_prompt(url: str, vt_result: dict, domain_age_days) -> str:
    return f"""You are a phishing-detection assistant embedded in a browser extension.
Analyze this URL and respond with ONLY a JSON object — no markdown fences, no extra text.

URL: {url}
VirusTotal: {vt_result.get('malicious', 0)} malicious / {vt_result.get('suspicious', 0)} suspicious \
out of {vt_result.get('total_engines', 0)} engines (data available: {vt_result.get('enabled')})
Domain age: {domain_age_days if domain_age_days is not None else 'unknown'} days

Consider: domain structure, brand impersonation / typosquatting, suspicious keywords \
(login, verify, secure, account, etc.), IP-address hosts, URL shorteners, unusual or \
lookalike TLDs, punycode, and excessive subdomains.

Respond with exactly this JSON shape:
{{"verdict": "phishing" | "suspicious" | "safe", "confidence": <number 0.0-1.0>, \
"message": "<one short sentence a non-technical user can understand>"}}"""


async def analyze_url(url: str, vt_result: dict, domain_age_days) -> dict:
    if not GEMINI_API_KEY:
        return {**UNAVAILABLE, "reason": "no_api_key"}

    payload = {
        "contents": [{"parts": [{"text": _build_prompt(url, vt_result, domain_age_days)}]}],
        "generationConfig": {
            "temperature": 0.1,
            "responseMimeType": "application/json",
        },
    }

    try:
        async with httpx.AsyncClient(timeout=20) as client:
            resp = await client.post(
                GEMINI_URL, params={"key": GEMINI_API_KEY}, json=payload
            )
            resp.raise_for_status()
            data = resp.json()
            text = data["candidates"][0]["content"]["parts"][0]["text"]
            parsed = json.loads(text)

            verdict = str(parsed.get("verdict", "")).lower()
            if verdict not in ("phishing", "suspicious", "safe"):
                verdict = None

            confidence = parsed.get("confidence")
            try:
                confidence = float(confidence)
            except (TypeError, ValueError):
                confidence = None

            return {
                "available": True,
                "verdict": verdict,
                "confidence": confidence,
                "message": str(parsed.get("message", ""))[:300],
            }
    except Exception as e:
        return {**UNAVAILABLE, "reason": str(e)}
