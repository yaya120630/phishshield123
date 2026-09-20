"""
Lightweight rule-based URL scoring, used as a third signal alongside
VirusTotal and Gemini (and as the only signal if neither API key is
configured, so the endpoint still returns something useful).
"""
import re
from urllib.parse import urlparse

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "secure", "account", "update", "confirm",
    "signin", "banking", "password", "billing", "suspend",
]

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
}

IP_HOST_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def score_url(url: str) -> dict:
    """Returns {score: 0-100, reasons: [str, ...]}."""
    reasons = []
    score = 0

    try:
        parsed = urlparse(url)
        host = parsed.hostname or ""
    except Exception:
        return {"score": 50, "reasons": ["Could not parse URL"]}

    if parsed.scheme != "https":
        score += 15
        reasons.append("Not using HTTPS")

    if IP_HOST_RE.match(host):
        score += 30
        reasons.append("Uses a raw IP address instead of a domain name")

    if host in SHORTENERS:
        score += 15
        reasons.append("Uses a URL shortener, which hides the real destination")

    if "@" in (parsed.netloc or ""):
        score += 25
        reasons.append("Contains an '@' in the host, often used to disguise the real domain")

    subdomain_count = max(host.count("."), 0)
    if subdomain_count >= 4:
        score += 15
        reasons.append("Unusually many subdomains")

    lower_url = url.lower()
    hit_keywords = [k for k in SUSPICIOUS_KEYWORDS if k in lower_url]
    if hit_keywords:
        score += min(10 * len(hit_keywords), 25)
        reasons.append("Contains sensitive-sounding keywords: " + ", ".join(hit_keywords[:4]))

    if "xn--" in host:
        score += 20
        reasons.append("Uses punycode, sometimes used to spoof lookalike domains")

    if "-" in host and subdomain_count >= 2:
        score += 5
        reasons.append("Hyphenated, multi-level domain")

    score = min(score, 100)
    if not reasons:
        reasons.append("No local risk indicators")

    return {"score": score, "reasons": reasons}
