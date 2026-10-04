# PhishShield — Backend Setup

The `public/` folder (the extension + web dashboard) talks to a backend
at `http://127.0.0.1:8000/api/detect` (see the comments in
`public/js/background.js`). The backend lives in `backend/`, wired up to
VirusTotal and Gemini.

## 1. Get API keys

- **VirusTotal**: https://www.virustotal.com/gui/my-apikey (free tier: 4
  requests/min, 500/day — fine for personal use/testing)
- **Gemini**: https://aistudio.google.com/apikey (free tier available)

## 2. Configure the backend

```bash
cd backend
cp .env.example .env
# edit .env and paste in VT_API_KEY and GEMINI_API_KEY
```

## 3. Install and run

```bash
cd backend
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

Leave this running — it's what the extension talks to. Visit
`http://127.0.0.1:8000/health` to confirm it's up, or
`http://127.0.0.1:8000/dashboard` to see the full dashboard served directly.

## 4. Load the extension in Chrome

1. `chrome://extensions` → enable **Developer mode** (top right)
2. **Load unpacked** → select the `public` folder
3. Browse normally — PhishShield auto-scans pages on navigation and
   pops an alert on phishing/suspicious sites. Use the popup or the
   dashboard's "Scan URL" box to check a link manually.

## How a scan works

1. **VirusTotal** — checks if the URL/domain is already flagged by
   security vendors (submits for a fresh scan if it's never been seen).
2. **Gemini** — looks at the URL structure itself (typosquatting, brand
   impersonation, suspicious keywords, punycode, etc.) and returns a
   verdict + a plain-English explanation.
3. **WHOIS domain age** — newly-registered domains are weighted as
   riskier.
4. **Local heuristics** — a small rule-based scorer (HTTPS, IP-hosts,
   shorteners, `@` tricks, subdomain count) that runs regardless, so the
   endpoint still returns a useful verdict even with no API keys set.

These four signals are blended into one `confidence_score` and verdict
(`phishing` / `suspicious` / `safe`) in `backend/app/routers/detect.py`
— that's the file to tune if you want to change the weighting or
thresholds.

## Notes

- If a key is missing, that signal is just skipped (weights renormalize
  automatically) — the app keeps working, just less accurately.
- VirusTotal's free tier is rate-limited; if you hit it, `vt_positives`
  etc. come back as `null` for that scan and the other signals carry it.
- CORS allows the Firebase Hosting origins plus `localhost`/`127.0.0.1`
  (see `backend/app/main.py`). The Chrome extension sends from a
  `chrome-extension://` origin, which isn't subject to that list, so it
  works regardless. If you add a custom domain for the web dashboard, add
  it via the `CORS_ALLOW_ORIGINS` env var.

## 5. Sharing this with someone else / putting it on Chrome for real

This local setup only works on your own machine — anyone else's copy
of the extension would try to reach their own `127.0.0.1:8000` and
find nothing running. See `DEPLOY.md` for deploying the backend
somewhere public (Render) so other people can actually use it.
