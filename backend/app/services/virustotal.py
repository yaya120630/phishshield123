"""
VirusTotal v3 URL check for PhishShield.

Uses only the Python standard library, so nothing new has to be added to
requirements.txt.

check_url(url) returns a dict with these keys (what app/routers/detect.py expects):
    enabled        True only when VirusTotal really answered with engine results
    malicious      number of vendors that flagged the URL as malicious
    suspicious     number of vendors that flagged it as suspicious
    total_engines  number of vendors that took part
    vendors        [{"engine": ..., "category": ..., "result": ...}, ...]
    details        VirusTotal "Details" tab fields (categories, dates, title, ...)
    error          None when it worked, otherwise a short human-readable reason

When VirusTotal cannot be used (no key, bad key, rate limit, timeout), enabled is
False and error says why. detect.py passes that reason on as "vt_error".
"""
import asyncio
import base64
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

API = "https://www.virustotal.com/api/v3"

# Any of these environment variable names will be accepted.
_KEY_NAMES = ("VIRUSTOTAL_API_KEY", "VT_API_KEY", "VIRUSTOTAL_KEY", "VIRUS_TOTAL_API_KEY")
VT_API_KEY = os.getenv("VT_API_KEY") or os.getenv("VIRUSTOTAL_API_KEY")
# The free key allows only 4 requests per minute, so remember recent answers.
_CACHE_TTL_SECONDS = 600
_CACHE_MAX_ITEMS = 500
_cache: dict = {}


def _api_key() -> str:
    for name in _KEY_NAMES:
        value = os.environ.get(name)
        if value and value.strip():
            return value.strip()
    try:  # also look in app/config.py in case the key is exposed there
        from app import config as cfg
        for name in _KEY_NAMES:
            value = getattr(cfg, name, None)
            if value and str(value).strip():
                return str(value).strip()
    except Exception:
        pass
    return ""


def _off(message: str) -> dict:
    return {
        "enabled": False,
        "error": message,
        "malicious": 0,
        "suspicious": 0,
        "total_engines": 0,
        "vendors": [],
        "details": {},
    }


def _request(method: str, path: str, key: str, data=None, timeout: int = 10) -> dict:
    headers = {"x-apikey": key, "accept": "application/json"}
    body = None
    if data is not None:
        body = urllib.parse.urlencode(data).encode("utf-8")
        headers["content-type"] = "application/x-www-form-urlencoded"
    req = urllib.request.Request(API + path, data=body, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _url_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").rstrip("=")


def _fetch_attributes(url: str, key: str) -> dict:
    """Blocking. Returns VirusTotal's attributes for this URL (submits it if new)."""
    uid = _url_id(url)

    # 1) Ask for an existing report.
    try:
        return _request("GET", "/urls/" + uid, key)["data"]["attributes"]
    except urllib.error.HTTPError as e:
        if e.code != 404:
            raise

    # 2) VirusTotal has never seen this URL: submit it and wait for the analysis.
    submitted = _request("POST", "/urls", key, data={"url": url})
    analysis_id = submitted["data"]["id"]
    analysis_attrs = {}
    for _ in range(6):
        time.sleep(2)
        analysis = _request("GET", "/analyses/" + analysis_id, key)
        analysis_attrs = analysis["data"]["attributes"]
        if analysis_attrs.get("status") == "completed":
            break

    # 3) Prefer the full URL report, fall back to the analysis itself.
    try:
        return _request("GET", "/urls/" + uid, key)["data"]["attributes"]
    except urllib.error.HTTPError:
        return analysis_attrs


def _iso(ts):
    try:
        return datetime.fromtimestamp(int(ts), tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return None


def _parse(attrs: dict) -> dict:
    stats = attrs.get("last_analysis_stats") or attrs.get("stats") or {}
    results = attrs.get("last_analysis_results") or attrs.get("results") or {}

    malicious = int(stats.get("malicious", 0) or 0)
    suspicious = int(stats.get("suspicious", 0) or 0)
    total = sum(int(v) for v in stats.values() if isinstance(v, (int, float)))

    if total == 0:
        return _off("VirusTotal analysis was not ready yet - try again in a minute")

    vendors = []
    for name, r in results.items():
        vendors.append({
            "engine": r.get("engine_name") or name,
            "category": r.get("category") or "undetected",
            "result": r.get("result"),
        })
    order = {"malicious": 0, "suspicious": 1}
    vendors.sort(key=lambda v: (order.get(v["category"], 2), str(v["engine"]).lower()))

    details = {
        "categories": attrs.get("categories") or {},
        "first_submission_date": _iso(attrs.get("first_submission_date")),
        "last_analysis_date": _iso(attrs.get("last_analysis_date")),
        "last_http_response_code": attrs.get("last_http_response_code"),
        "title": attrs.get("title"),
        "final_url": attrs.get("last_final_url"),
        "times_submitted": attrs.get("times_submitted"),
        "reputation": attrs.get("reputation"),
    }

    return {
        "enabled": True,
        "error": None,
        "malicious": malicious,
        "suspicious": suspicious,
        "total_engines": total,
        "vendors": vendors,
        "details": details,
    }


async def check_url(url: str) -> dict:
    key = _api_key()
    if not key:
        return _off("VirusTotal API key is not set on the server (add VT_API_KEY in Render > Environment)")

    cached = _cache.get(url)
    if cached and (time.time() - cached[0]) < _CACHE_TTL_SECONDS:
        return cached[1]

    try:
        attrs = await asyncio.to_thread(_fetch_attributes, url, key)
        result = _parse(attrs)
    except urllib.error.HTTPError as e:
        messages = {
            401: "VirusTotal rejected the API key (401) - check the key on Render",
            403: "VirusTotal refused the request (403) - the key may not be allowed to use this endpoint",
            429: "VirusTotal limit reached (429) - the free key allows 4 requests/minute and 500/day",
        }
        result = _off(messages.get(e.code, "VirusTotal returned HTTP " + str(e.code)))
    except Exception as e:
        result = _off("VirusTotal request failed: " + type(e).__name__)

    if result.get("enabled"):
        if len(_cache) >= _CACHE_MAX_ITEMS:
            _cache.clear()
        _cache[url] = (time.time(), result)
    return result
