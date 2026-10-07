// public/js/config.js — PhishShield Configuration & Firebase Compatibility Layer
//
// This file is loaded in two very different environments:
//   1. In the dashboard/landing pages (index.html, popup.html) as a <script>,
//      where `window`, `document`, and the Firebase compat SDK all exist.
//   2. In the MV3 service worker (background.js) via importScripts(), where
//      there is NO `window`/`document` and the Firebase SDK is not loaded.
// So everything here must be guarded to work in a plain worker too — touching
// `window` unconditionally throws "window is not defined" in the worker and
// takes background.js down with it.

// Global object that exists in both pages (window) and workers (self).
var PS_GLOBAL = (typeof self !== 'undefined') ? self
    : (typeof globalThis !== 'undefined') ? globalThis
    : this;

var PHISHSHIELD_CONFIG = {
    API_BASE: 'https://phishshield-api-qsuo.onrender.com',
    API_KEY: '' // Optional API Key if required by Render backend
};
// Expose on the global so importScripts() consumers (background.js) see it.
PS_GLOBAL.PHISHSHIELD_CONFIG = PHISHSHIELD_CONFIG;

// Initialize Firebase App
//
// ⚠️ REPLACE THE PLACEHOLDER VALUES BELOW with your real web-app config
// from the Firebase console:
//   Firebase console → Project settings → General → Your apps → Web app →
//   "SDK setup and configuration" → Config.
//
// Firebase Hosting (serving this dashboard/landing page) works WITHOUT
// these. They are only needed for Firebase Auth and the Realtime Database
// (cross-browser scan sync). Until you paste the real values, those
// features are disabled automatically instead of crashing the page.
var firebaseConfig = {
    apiKey: "AIzaSyBYBHsnMWgQvEXyxaMUYWVP2zw7ujEStR8",
    authDomain: "phishshield-904ab.firebaseapp.com",
    databaseURL: "https://phishshield-904ab-default-rtdb.asia-southeast1.firebasedatabase.app",
    projectId: "phishshield-904ab",
    storageBucket: "phishshield-904ab.firebasestorage.app",
    messagingSenderId: "90864629721",
    appId: "1:90864629721:web:7cd18093e62e406d4fcbc8",
    measurementId: "G-9K9CB26H0K"
};

// True while config.js still holds the shipped placeholders. When true we
// skip Firebase Auth / Database init so the dummy key can't throw.
var FIREBASE_CONFIG_IS_PLACEHOLDER =
    firebaseConfig.apiKey.indexOf("Dummy") !== -1 ||
    firebaseConfig.messagingSenderId === "1234567890";

// Fire a 'firebase-ready' DOM event, but only in a page that has a document.
// In the service worker there is no document, so this is a no-op.
function psDispatchFirebaseReady() {
    try {
        if (typeof document !== 'undefined' &&
            typeof PS_GLOBAL.dispatchEvent === 'function' &&
            typeof Event === 'function') {
            PS_GLOBAL.dispatchEvent(new Event('firebase-ready'));
        }
    } catch (e) { /* ignore — not in a page */ }
}

if (typeof firebase !== 'undefined' && !FIREBASE_CONFIG_IS_PLACEHOLDER) {
    if (!firebase.apps.length) {
        firebase.initializeApp(firebaseConfig);
    }

    var db = firebase.database();

    // 🔴 CRITICAL FIX FOR MANIFEST V3 CSP: Force WebSockets to disable script-injection (.lp) long-polling
    if (db && db.INTERNAL && db.INTERNAL.forceWebSockets) {
        try {
            db.INTERNAL.forceWebSockets();
        } catch (e) {
            console.warn("Could not force WebSockets on Firebase DB:", e);
        }
    }

    // Bind global objects expected by index.js
    PS_GLOBAL.firebaseDB = db;
    PS_GLOBAL.firebaseAuth = firebase.auth ? firebase.auth() : { onAuthStateChanged: function () {} };
    PS_GLOBAL.GoogleAuthProvider = firebase.auth ? firebase.auth.GoogleAuthProvider : null;
    PS_GLOBAL.signInWithPopup = function (auth, provider) { return auth.signInWithPopup(provider); };

    PS_GLOBAL.dbRefs = {
        ref: function (database, path) { return database.ref(path); },
        push: function (refObj, val) { return refObj.push(val); },
        onValue: function (refObj, cb) { return refObj.on('value', function (snap) { cb(snap); }); },
        query: function (refObj) { return refObj; },
        limitToLast: function (num) {
            return { ref: function (database, path) { return database.ref(path).limitToLast(num); } };
        }
    };

    // Mark Firebase as actually available for cross-browser sync.
    PS_GLOBAL.firebaseReady = true;

    psDispatchFirebaseReady();

    console.log("Firebase compatibility initialized successfully (WebSockets enforced).");
} else {
    // Firebase is unavailable in this environment — either the SDK is not
    // loaded (e.g. the service worker, or missing script tag), or config.js
    // still holds the placeholder values. The dashboard runs fine without it
    // (per-browser localStorage via the chrome-shim in api.js); only
    // cross-browser sync and Auth are off.
    PS_GLOBAL.firebaseReady = false;
    PS_GLOBAL.firebaseDB = null;
    PS_GLOBAL.firebaseAuth = { onAuthStateChanged: function () {} };
    PS_GLOBAL.GoogleAuthProvider = null;
    PS_GLOBAL.signInWithPopup = function () {
        return Promise.reject(new Error("Firebase is not configured"));
    };

    // Firebase is optional — it only powers cross-browser sync and Auth,
    // neither of which is wired up yet. Its absence is a normal, supported
    // state (the dashboard runs on chrome.storage / localStorage), so this is
    // a single calm info line, not a warning that looks like an error.
    var reason = (typeof firebase === 'undefined')
        ? "SDK not loaded on this page"
        : (FIREBASE_CONFIG_IS_PLACEHOLDER ? "config is still the placeholder" : "disabled");
    console.info(
        "PhishShield: Firebase optional features off (" + reason + "). " +
        "Scanning, VirusTotal and local history are unaffected."
    );

    // Still signal readiness so any page listener waiting on this proceeds.
    psDispatchFirebaseReady();
}
