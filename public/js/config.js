// config.js - shared settings for background.js, popup.js, and dashboard.
//
// API_KEY is an OPTIONAL shared secret.
// Set API_BASE to your live backend server or Firebase Hosting domain.

// config.js - Shared settings for background.js, popup.js, and dashboard

var PHISHSHIELD_CONFIG = PHISHSHIELD_CONFIG || {
    API_BASE: 'https://phishshield-api-qsuo.onrender.com',
    API_KEY: ''
};

if (typeof self !== 'undefined') {
    self.PHISHSHIELD_CONFIG = PHISHSHIELD_CONFIG;
}