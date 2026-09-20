"""
VirusTotal integration (API v3).

check_url() never raises — on any failure (no key, network error, rate
limit, etc.) it returns enabled=False with zeroed-out counts so the rest
of the detection pipeline can fall back gracefully instead of erroring
out the whole scan.
"""
import base64
import asyncio
import httpx

from app.config import VT_API_KEY

VT_BASE = "https://www.virustotal.com/api/v3"

EMPTY_RESULT = {
    "enabled": False,
    "malicious": 0,
    "suspicious": 0,
    "total_engines": 0,
    "vendors": [],
    "details": {},
}


def _url_id(url: str) -> str:
    """VT identifies URLs by the base64 (no padding) of the URL itself."""
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")


def _extract_vendors(results: dict) -> list:
    """
    Returns every engine VirusTotal reports on (clean + flagged), so the
    UI can render a full vendor grid like virustotal.com does — not just
    the handful that flagged something.

    Flagged engines are sorted first so they're always visible even if a
    caller only renders/truncates the top N.
    """
    flagged, clean = [], []
    for engine, data in results.items():
        category = data.get("category")
        entry = {"engine": engine, "category": category, "result": data.get("result")}
        if category in ("malicious", "suspicious"):
            flagged.append(entry)
        else:
            clean.append(entry)

    # Cap so the response (and chrome.storage entry) stays reasonably
    # small — VT typically reports ~70-90 engines total, well under this.
    return (flagged + clean)[:100]


def _extract_details(attrs: dict) -> dict:
    """
    Pulls VirusTotal's own "Details" tab fields out of the same URL-object
    response we already have (`GET /urls/{id}`) — no extra API calls for
    URLs VT has already seen. Fields VT doesn't have for this URL are left
    as None/empty so the frontend can skip rendering them, same as
    VirusTotal's own Details tab omits blank sections.

    NOT included here: "Network Requests / HTTPS Transactions" and
    "JavaScript Global Variables" — those come from VT's sandbox/behavior
    analysis, a separate premium endpoint, not the standard URL lookup.
    """
    html_meta = attrs.get("html_meta") or {}
    title_list = html_meta.get("title") or []
    total_votes = attrs.get("total_votes") or {}

    return {
        "categories": attrs.get("categories") or {},
        "tags": attrs.get("tags") or [],
        "reputation": attrs.get("reputation"),
        "times_submitted": attrs.get("times_submitted"),
        "first_submission_date": attrs.get("first_submission_date"),
        "last_submission_date": attrs.get("last_submission_date"),
        "last_analysis_date": attrs.get("last_analysis_date"),
        "last_modification_date": attrs.get("last_modification_date"),
        "last_final_url": attrs.get("last_final_url"),
        "last_http_response_code": attrs.get("last_http_response_code"),
        "last_http_response_content_length": attrs.get("last_http_response_content_length"),
        "last_http_response_content_sha256": attrs.get("last_http_response_content_sha256"),
        "last_http_response_headers": attrs.get("last_http_response_headers") or {},
        "html_title": title_list[0] if title_list else None,
        "threat_names": attrs.get("threat_names") or [],
        "total_votes_harmless": total_votes.get("harmless"),
        "total_votes_malicious": total_votes.get("malicious"),
    }


async def check_url(url: str) -> dict:
    if not VT_API_KEY:
        return {**EMPTY_RESULT, "reason": "no_api_key"}

    headers = {"x-apikey": VT_API_KEY}
    url_id = _url_id(url)

    async with httpx.AsyncClient(timeout=15) as client:
        try:
            resp = await client.get(f"{VT_BASE}/urls/{url_id}", headers=headers)

            if resp.status_code == 404:
                # VT has never seen this URL — submit it for a fresh scan.
                submit = await client.post(
                    f"{VT_BASE}/urls", headers=headers, data={"url": url}
                )
                submit.raise_for_status()
                analysis_id = submit.json()["data"]["id"]

                # VT queues new analyses; poll briefly rather than blocking
                # the user's scan indefinitely.
                for _ in range(3):
                    await asyncio.sleep(1.5)
                    poll = await client.get(
                        f"{VT_BASE}/analyses/{analysis_id}", headers=headers
                    )
                    poll.raise_for_status()
                    data = poll.json()["data"]
                    if data["attributes"]["status"] == "completed":
                        stats = data["attributes"]["stats"]
                        results = data["attributes"].get("results", {})
                        total = sum(stats.values())

                        # The analysis object we just polled only has
                        # verdict stats, not the URL's own properties
                        # (categories, HTTP response, HTML title, etc.).
                        # One more GET on the now-analyzed URL object gets
                        # us that data too, same as an already-seen URL.
                        details = {}
                        try:
                            fresh = await client.get(
                                f"{VT_BASE}/urls/{url_id}", headers=headers
                            )
                            fresh.raise_for_status()
                            details = _extract_details(fresh.json()["data"]["attributes"])
                        except Exception:
                            pass  # verdict still stands even if this extra call fails

                        return {
                            "enabled": True,
                            "malicious": stats.get("malicious", 0),
                            "suspicious": stats.get("suspicious", 0),
                            "total_engines": total,
                            "vendors": _extract_vendors(results),
                            "details": details,
                        }
                return {**EMPTY_RESULT, "enabled": True, "reason": "analysis_pending"}

            resp.raise_for_status()
            attrs = resp.json()["data"]["attributes"]
            stats = attrs.get("last_analysis_stats", {})
            results = attrs.get("last_analysis_results", {})
            total = sum(stats.values())
            return {
                "enabled": True,
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "total_engines": total,
                "vendors": _extract_vendors(results),
                "details": _extract_details(attrs),
            }

        except httpx.HTTPStatusError as e:
            return {**EMPTY_RESULT, "reason": f"http_{e.response.status_code}"}
        except Exception as e:
            return {**EMPTY_RESULT, "reason": str(e)}
