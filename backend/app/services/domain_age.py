"""
Domain age lookup via WHOIS. Newly-registered domains are a classic
phishing signal, so this feeds into the final risk score alongside
VirusTotal and Gemini.

get_domain_age_days() never raises — WHOIS servers are flaky and slow,
so any failure or timeout just returns None (treated as "unknown" by
the caller, not as risky).
"""
import asyncio
import contextlib
import io
from datetime import datetime, timezone
from urllib.parse import urlparse

import whois

# python-whois prints noisy "Error trying to connect to socket..." lines
# directly to stdout instead of only raising — harmless, but clutters
# the server console. We suppress that output while still catching the
# underlying exception normally.
_WHOIS_RETRIES = 2


def _sync_domain_age(url: str):
    try:
        host = urlparse(url).hostname or url
        parts = host.split(".")
        domain = ".".join(parts[-2:]) if len(parts) >= 2 else host

        created = None
        for attempt in range(_WHOIS_RETRIES):
            try:
                with contextlib.redirect_stdout(io.StringIO()), \
                     contextlib.redirect_stderr(io.StringIO()):
                    w = whois.whois(domain)
                created = w.creation_date
                if created:
                    break
            except Exception:
                if attempt == _WHOIS_RETRIES - 1:
                    return None
                continue

        if isinstance(created, list):
            created = created[0]
        if created is None:
            return None
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)

        return (datetime.now(timezone.utc) - created).days
    except Exception:
        return None


async def get_domain_age_days(url: str):
    try:
        # whois is blocking — run off the event loop with a timeout so a
        # slow/unresponsive WHOIS server can't stall a scan.
        return await asyncio.wait_for(asyncio.to_thread(_sync_domain_age, url), timeout=8)
    except asyncio.TimeoutError:
        return None
