// config.js - shared settings for background.js, popup.js, and dashboard.
//
// API_KEY is an OPTIONAL shared secret. Right now the backend at
// http://127.0.0.1:8000 accepts requests from anything on your machine
// that knows the URL — fine for a local demo, but worth locking down if
// this ever runs somewhere less trusted. To enable it:
//   1. Set PHISHSHIELD_API_KEY=<some-random-string> in backend/.env
//   2. Put that same string below
//   3. Restart the backend
// Leave API_KEY as '' to keep auth disabled (the default).
const PHISHSHIELD_CONFIG = {
    API_BASE: 'http://127.0.0.1:8000',
    API_KEY: ''
};

// Expose for both service-worker (importScripts) and page (<script>) contexts.
if (typeof self !== 'undefined') {
    self.PHISHSHIELD_CONFIG = PHISHSHIELD_CONFIG;
}
