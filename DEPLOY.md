# PhishShield — Deploying the backend (Render)

This makes the backend reachable by anyone's copy of the extension,
not just your own machine. Local-only setup (`http://127.0.0.1:8000`)
still works fine for development — this is only needed once you want
someone else to test the extension.

## 1. Push this project to GitHub

The repo needs `backend/`, `render.yaml`, and `phishshield-extension-updated/`
at the root. `backend/.env` is already gitignored — never commit it.

## 2. Create the Render service

1. Go to https://render.com → New → Blueprint
2. Connect your GitHub repo — Render reads `render.yaml` automatically
   and creates the web service from it
3. In the Render dashboard, set the real values for `VT_API_KEY` and
   `GEMINI_API_KEY` (the ones marked `sync: false` in render.yaml —
   Render won't ask you to commit them, you paste them in directly)
4. Optionally set `PHISHSHIELD_API_KEY` to a random string — if you
   do, you MUST also set the same string in
   `phishshield-extension/js/config.js` (`API_KEY` field) or the
   extension's requests will be rejected with 401

## 3. Point the extension at the deployed backend

Once deployed, Render gives you a URL like
`https://phishshield-backend.onrender.com`. Edit
`phishshield-extension/js/config.js`:

```js
const PHISHSHIELD_CONFIG = {
    API_BASE: 'https://phishshield-backend.onrender.com',
    API_KEY: ''  // fill in only if you set PHISHSHIELD_API_KEY above
};
```

## 4. Share the extension

Zip just the `phishshield-extension` folder and send it, or share it
as a Drive/WeTransfer link. The person testing it:

1. Opens `chrome://extensions`
2. Enables **Developer mode**
3. Clicks **Load unpacked** → selects the extension folder

No Python, no `.env`, no command line on their end — the backend is
already running on Render.

## Notes

- **Free tier sleeps after inactivity.** The first request after
  sleeping takes ~20–30s to wake up. Fine for testing, worth knowing
  before a live demo — open the dashboard a minute early to warm it up.
- **Rate limiting is now in place** (20 requests/min per IP) to stop
  the VirusTotal/Gemini free-tier quota from being burned by one
  abusive client once the backend is public. Adjust
  `RATE_LIMIT_MAX_REQUESTS` in `backend/app/routers/detect.py` if
  needed.
