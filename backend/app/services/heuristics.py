"""
Lightweight rule-based URL scoring, used as a third signal alongside
VirusTotal and Gemini (and as the only signal if neither API key is
configured, so the endpoint still returns something useful).

Additive RISK model: start at 0 and add points per red flag. Tuned to
catch obvious phishing tells when it is the only live signal, while
leaving well-known official domains alone.
"""
import re
from urllib.parse import urlparse

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "secure", "account", "update", "confirm",
    "signin", "banking", "password", "billing", "suspend", "unlock",
    "authenticate", "recover", "wallet",
]

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorte.st",
}

RISKY_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "work", "click", "link",
    "country", "stream", "gdn", "loan", "win", "review", "zip", "mov",
}

BRANDS = [
    "microsoft", "outlook", "office365", "google", "gmail", "paypal",
    "apple", "icloud", "facebook", "instagram", "amazon", "netflix",
    "linkedin", "maybank", "cimb", "publicbank", "rhb", "hsbc", "dhl",
]

OFFICIAL_DOMAINS = [
    "microsoft.com", "live.com", "office.com", "microsoftonline.com", "outlook.com",
    "office365.com", "sharepoint.com", "windows.com", "bing.com", "azure.com",
    "google.com", "gmail.com", "youtube.com", "googleusercontent.com",
    "paypal.com", "apple.com", "icloud.com", "facebook.com", "fb.com", "messenger.com",
    "instagram.com", "meta.com", "amazon.com", "amazon.co.uk", "amazon.sg",
    "netflix.com", "linkedin.com", "maybank2u.com.my", "maybank.com",
    "cimbclicks.com.my", "cimb.com.my", "cimb.com", "pbebank.com", "publicbank.com.my",
    "rhbgroup.com", "rhbbank.com.my", "hsbc.com", "hsbc.com.my", "dhl.com",
]

TRUSTED_SUFFIXES = (
    ".edu.my", ".gov.my", ".mil.my", ".edu", ".gov", ".mil",
    ".ac.uk", ".gov.uk", ".edu.sg", ".gov.sg",
)

IP_HOST_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def _host_matches(host: str, domain: str) -> bool:
    return host == domain or host.endswith("." + domain)


def _is_official(host: str) -> bool:
    return any(_host_matches(host, d) for d in OFFICIAL_DOMAINS)


def _is_trusted(host: str) -> bool:
    return host.endswith(TRUSTED_SUFFIXES)


def score_url(url: str) -> dict:
    """Returns {score: 0-100 risk, reasons: [str, ...]}."""
    reasons = []
    risk = 0

    try:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
    except Exception:
        return {"score": 50, "reasons": ["Could not parse URL"]}

    if not host:
        return {"score": 50, "reasons": ["Could not parse URL host"]}

    # Known-good official / institutional domains are safe.
    if _is_official(host) or _is_trusted(host):
        return {"score": 0, "reasons": ["No local risk indicators"]}

    tld = host.rsplit(".", 1)[-1]
    lower_url = url.lower()

    # Brand impersonation on an unofficial domain.
    host_tokens = re.split(r"[^a-z0-9]+", host)
    brand_hit = next((b for b in BRANDS if b in host_tokens or b in host), None)
    if brand_hit:
        risk += 55
        reasons.append(f"Impersonates a known brand ({brand_hit}) on an unofficial domain")

    if parsed.scheme != "https":
        risk += 20
        reasons.append("Not using HTTPS")

    if IP_HOST_RE.match(host):
        risk += 45
        reasons.append("Uses a raw IP address instead of a domain name")

    if host in SHORTENERS:
        risk += 30
        reasons.append("Uses a URL shortener, which hides the real destination")

    if tld in RISKY_TLDS:
        risk += 35
        reasons.append(f"Risky top-level domain (.{tld})")

    if "@" in (parsed.netloc or ""):
        risk += 40
        reasons.append("Contains an '@' in the host, often used to disguise the real domain")

    if "xn--" in host:
        risk += 40
        reasons.append("Uses punycode, sometimes used to spoof lookalike domains")

    hit_keywords = [k for k in SUSPICIOUS_KEYWORDS if k in lower_url]
    if hit_keywords:
        risk += min(18 * len(hit_keywords), 45)
        reasons.append("Contains sensitive-sounding keywords: " + ", ".join(hit_keywords[:4]))

    hyphen_count = host.count("-")
    if hyphen_count >= 2:
        risk += 15
        reasons.append(f"Hyphen-stuffed hostname ({hyphen_count} hyphens)")

    subdomain_count = host.count(".")
    if subdomain_count >= 4:
        risk += 15
        reasons.append("Unusually many subdomains")

    if len(host) > 40:
        risk += 10
        reasons.append("Unusually long hostname")

    risk = max(0, min(risk, 100))
    if not reasons:
        reasons.append("No local risk indicators")

    return {"score": risk, "reasons": reasons}
