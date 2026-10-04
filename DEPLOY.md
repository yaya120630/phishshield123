# PhishShield — Deploying

PhishShield has two deployable parts:

- **Backend** (FastAPI) → **Render**, auto-deployed from GitHub.
- **Web dashboard + landing page** (the `public/` folder) → **Firebase Hosting**.

The Chrome extension loads the same `public/` files locally and talks to
the Render backend. Local-only setup (`http://127.0.0.1:8000`) still
works for development — see `SETUP.md`.

---

## 1. Push this project to GitHub

The repo needs `backend/`, `render.yaml`, `firebase.json`, and `public/`
at the root. Secrets stay out of git: `backend/.env` and anything
matching `*.env` are gitignored — never commit them.

Render is already connected to this repo and auto-deploys the backend on
every push to the default branch.

## 2. Backend on Render

The backend is live at:

```
https://phishshield-api-qsuo.onrender.com
```

Render reads `render.yaml` automatically (service name `phishshield-api`,
`rootDir: backend`). To (re)create it: Render → New → Blueprint → connect
this repo.

In the Render dashboard → **Environment**, set the real values for the
variables marked `sync: false` in `render.yaml`:

- `VT_API_KEY` — your VirusTotal key
- `GEMINI_API_KEY` — your Gemini key
- `PHISHSHIELD_API_KEY` — optional shared secret. If you set it, you MUST
  put the same string in `public/js/config.js` (`API_KEY` field) or every
  request is rejected with 401.
- `CORS_ALLOW_ORIGINS` — optional, only if you add a custom domain for the
  web dashboard (comma-separated). The Firebase Hosting origins are
  already allowed by default.

> The frontend (`public/js/config.js`) already points `API_BASE` at the
> URL above. If you deploy under a different Render URL, update that one
> field.

## 3. Web dashboard + landing page on Firebase Hosting

`firebase.json` deploys the `public/` folder. The site is served at:

```
https://phishshield-904ab.web.app
```

Deploy with one command from the repo root:

```bash
firebase deploy --only hosting
```

(First time only: `npm install -g firebase-tools` then `firebase login`.
The project is pinned in `.firebaserc` to `phishshield-904ab`.)

### CORS

The backend already allows `https://phishshield-904ab.web.app` and
`https://phishshield-904ab.firebaseapp.com`. If the web dashboard's scans
fail with a CORS error, confirm the backend has been redeployed with the
latest `backend/app/main.py` and that your origin is in that list (or in
`CORS_ALLOW_ORIGINS`).

## 4. Share the extension

Zip the `public/` folder and send it, or share a link. The person testing:

1. Opens `chrome://extensions`
2. Enables **Developer mode**
3. Clicks **Load unpacked** → selects the folder

No Python, no `.env`, no command line on their end — the backend is
already running on Render.

## Notes

- **Render free tier sleeps after inactivity.** The first request after
  sleeping takes ~20–30s to wake up. Both the popup and the dashboard have
  timeouts for this; open the dashboard a minute early before a live demo.
- **Rate limiting** is in place (20 requests/min per IP). Adjust
  `RATE_LIMIT_MAX_REQUESTS` in `backend/app/routers/detect.py` if needed.
- **The web dashboard is per-browser.** On a website, the dashboard reads
  its scan history from that browser's `localStorage`, so it shows only
  scans made on the site itself. The extension keeps its history in
  `chrome.storage`. "From all connected browsers" is only literally true
  once scans are synced through the Firebase Realtime Database — which is
  initialised in `public/js/config.js` but not yet wired up. Ask if you
  want that sync built.
