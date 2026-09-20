// background.js - Complete with auto-alert for malicious links

// Loads phishshieldScoreUrl() (a fast, local, rule-based URL scorer) for
// an instant pre-check — see the auto-scan listener below. It's the same
// scorer popup.js uses as an offline fallback, so results stay consistent.
importScripts('lib/lib/scanner.js');
// Shared backend URL + optional API key — see js/config.js.
importScripts('js/config.js');

// Store scan history locally
let scanHistory = [];
let stats = {
    scanned: 0,
    threats: 0,
    safe: 0
};

// Load saved data on startup
function loadData() {
    chrome.storage.local.get(['history', 'stats'], function(result) {
        if (result.history) scanHistory = result.history;
        if (result.stats) stats = result.stats;
    });
}

loadData();

// ===== BADGE STATE =====
// Tracks the last verdict per tab so the toolbar badge (and a
// newly-opened popup) reflect the CURRENT tab's status, not whichever
// tab was scanned most recently.
const tabVerdicts = {};

function setBadgeForVerdict(tabId, status) {
    if (status === 'phishing') {
        chrome.action.setBadgeText({ tabId, text: '!' });
        chrome.action.setBadgeBackgroundColor({ tabId, color: '#FF4757' });
    } else if (status === 'suspicious') {
        chrome.action.setBadgeText({ tabId, text: '?' });
        chrome.action.setBadgeBackgroundColor({ tabId, color: '#FFA502' });
    } else {
        chrome.action.setBadgeText({ tabId, text: '' });
    }
}

// Chrome only allows chrome.action.openPopup() to auto-open the popup
// when this extension's window is the focused one — silently reject
// otherwise (e.g. user is on a different app), so this is wrapped
// defensively and never throws into the caller.
async function autoOpenPopupForTab(tabId) {
    try {
        const win = await chrome.windows.getLastFocused();
        const [activeTab] = await chrome.tabs.query({ active: true, windowId: win.id });
        if (activeTab && activeTab.id === tabId && typeof chrome.action.openPopup === 'function') {
            await chrome.action.openPopup();
        }
    } catch (error) {
        // Expected in many cases (unsupported Chrome version, window not
        // focused, etc.) — the badge + in-page banner still warn the user.
        console.log('Auto-open popup skipped:', error.message);
    }
}

// ===== RATE LIMITING / DEDUPE =====
// VirusTotal's free tier allows ~4 requests/minute. SPA navigations,
// redirect chains, and reloads can otherwise fire several backend scans
// for what is effectively the same page in a few seconds and burn
// through that quota fast. This remembers the last URL scanned per tab
// and skips re-scanning the exact same URL within the cooldown window.
const lastScanByTab = {}; // tabId -> { url, time }
const RESCAN_COOLDOWN_MS = 15000;

function shouldSkipScan(tabId, url) {
    const last = lastScanByTab[tabId];
    if (last && last.url === url && (Date.now() - last.time) < RESCAN_COOLDOWN_MS) {
        return true;
    }
    lastScanByTab[tabId] = { url, time: Date.now() };
    return false;
}

// ===== HARD BLOCKING =====
// Everything above this point only ever WARNS after a page has already
// loaded (badge, popup, in-page banner) — the actual site is still fully
// rendered and interactive underneath. This section adds a real block:
// a clearly-dangerous URL is intercepted BEFORE it loads and the tab is
// redirected to blocked.html instead, with the real page never painting.
//
// "Clearly-dangerous" here means the instant local heuristic scorer
// (phishshieldScoreUrl — same one used for the badge pre-check above)
// returns its highest-severity verdict. It has to be the fast local
// check, not the full VirusTotal/Gemini backend scan: that takes a
// couple of seconds, and by the time it responded the browser would
// already have finished loading the page. The trade-off is the same
// one any local heuristic has — occasional false positives — which is
// exactly why "Continue anyway" exists below rather than a dead end.
//
// Persisted in chrome.storage.session (not a plain in-memory Set) since
// MV3 service workers can be killed and restarted by Chrome at any time
// — an in-memory-only list would forget the user's "continue anyway"
// choice mid-session and re-block a page they already chose to view.
// storage.session clears automatically when the browser closes.
const ALLOWLIST_KEY = 'allowedPhishingUrls';

async function isUrlAllowed(url) {
    try {
        const result = await chrome.storage.session.get(ALLOWLIST_KEY);
        const list = result[ALLOWLIST_KEY];
        return Array.isArray(list) && list.includes(url);
    } catch (error) {
        console.error('isUrlAllowed error:', error);
        return false;
    }
}

async function allowUrlThisSession(url) {
    try {
        const result = await chrome.storage.session.get(ALLOWLIST_KEY);
        const list = Array.isArray(result[ALLOWLIST_KEY]) ? result[ALLOWLIST_KEY] : [];
        if (!list.includes(url)) list.push(url);
        await chrome.storage.session.set({ [ALLOWLIST_KEY]: list });
    } catch (error) {
        console.error('allowUrlThisSession error:', error);
    }
}

chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
    if (details.frameId !== 0) return;
    const url = details.url;
    if (!url || url.startsWith('chrome://') || url.startsWith('chrome-extension://') ||
        url.startsWith('about:') || url.startsWith('edge://')) {
        return;
    }
    if (typeof phishshieldScoreUrl !== 'function') return;

    const quick = phishshieldScoreUrl(url);
    if (quick.verdict !== 'danger') return; // only hard-block the worst tier; "warn" still just badges/warns

    if (await isUrlAllowed(url)) {
        console.log('⚠️ Allowing previously-overridden URL to load:', url);
        return;
    }

    console.log('🚫 Blocking navigation before it loads:', url);
    tabVerdicts[details.tabId] = 'phishing';
    setBadgeForVerdict(details.tabId, 'phishing');

    const blockedUrl = chrome.runtime.getURL('blocked.html') +
        '?url=' + encodeURIComponent(url) +
        '&score=' + encodeURIComponent(quick.score) +
        '&reasons=' + encodeURIComponent(JSON.stringify(quick.reasons || []));

    chrome.tabs.update(details.tabId, { url: blockedUrl });

    // The tab never actually loads the real page, but the full backend
    // scan (VirusTotal + Gemini) still runs here so the dashboard/history/
    // bell get the complete picture instead of just the quick heuristic.
    scanUrl(url).then((result) => {
        tabVerdicts[details.tabId] = result.status;
        setBadgeForVerdict(details.tabId, result.status);
    }).catch((error) => console.error('Background scan after block failed:', error));
});

// ===== CERTIFICATE / CONNECTION ERRORS =====
// A cert mismatch (or other TLS failure) never reaches onCompleted below —
// Chrome swaps in its own "Your connection is not private" interstitial
// before the real page loads, so the normal auto-scan never fires and the
// person just sees Chrome's generic warning with no PhishShield verdict.
// Treat the fatal TLS error codes as a strong phishing signal ourselves and
// redirect to our own blocked page instead.
const CERT_ERROR_CODES = new Set([
    'net::ERR_CERT_COMMON_NAME_INVALID',
    'net::ERR_CERT_AUTHORITY_INVALID',
    'net::ERR_CERT_DATE_INVALID',
    'net::ERR_CERT_WEAK_SIGNATURE_ALGORITHM',
    'net::ERR_CERT_REVOKED',
    'net::ERR_SSL_PROTOCOL_ERROR'
]);

chrome.webNavigation.onErrorOccurred.addListener(async (details) => {
    if (details.frameId !== 0) return;
    const url = details.url;
    if (!url || !CERT_ERROR_CODES.has(details.error)) return;
    if (!url.startsWith('http://') && !url.startsWith('https://')) return;

    if (await isUrlAllowed(url)) {
        console.log('⚠️ Allowing previously-overridden URL despite cert error:', url);
        return;
    }

    console.log('🚫 Cert/TLS error treated as phishing signal:', url, details.error);
    tabVerdicts[details.tabId] = 'phishing';
    setBadgeForVerdict(details.tabId, 'phishing');

    const blockedUrl = chrome.runtime.getURL('blocked.html') +
        '?url=' + encodeURIComponent(url) +
        '&score=' + encodeURIComponent(100) +
        '&reasons=' + encodeURIComponent(JSON.stringify([`Invalid or untrusted certificate (${details.error})`]));

    chrome.tabs.update(details.tabId, { url: blockedUrl });

    // Still run the full backend scan in the background so the dashboard
    // and scan history reflect a complete verdict, not just the cert flag.
    scanUrl(url).then((result) => {
        tabVerdicts[details.tabId] = result.status;
        setBadgeForVerdict(details.tabId, result.status);
    }).catch((error) => console.error('Background scan after cert-error block failed:', error));
});

// ===== AUTO-SCAN ON NAVIGATION =====
chrome.webNavigation.onCompleted.addListener(async (details) => {
    // Only scan main frame
    if (details.frameId === 0) {
        const url = details.url;
        // Don't scan chrome:// pages
        if (!url.startsWith('chrome://') && !url.startsWith('chrome-extension://')) {
            if (shouldSkipScan(details.tabId, url)) {
                console.log('⏭️ Skipping re-scan (same URL, within cooldown):', url);
                return;
            }
            console.log('🔄 Auto-scanning:', url);

            // INSTANT LOCAL PRE-CHECK — the real backend scan (VirusTotal +
            // Gemini + a WHOIS lookup) can take a few seconds, longer for
            // a URL VirusTotal has never seen before. This local, rule-
            // based check runs in milliseconds, so a clearly risky URL
            // flags the badge and opens the popup right away instead of
            // making the person wait for the full scan to finish.
            let quickStatus = null;
            if (typeof phishshieldScoreUrl === 'function') {
                const quick = phishshieldScoreUrl(url);
                quickStatus = quick.verdict === 'danger' ? 'phishing'
                    : quick.verdict === 'warn' ? 'suspicious' : 'safe';
                if (quickStatus === 'phishing' || quickStatus === 'suspicious') {
                    tabVerdicts[details.tabId] = quickStatus;
                    setBadgeForVerdict(details.tabId, quickStatus);
                    autoOpenPopupForTab(details.tabId);
                }
            }

            try {
                const result = await scanUrl(url);
                tabVerdicts[details.tabId] = result.status;
                setBadgeForVerdict(details.tabId, result.status);

                // If phishing detected, show the in-page alert popup.
                // Suspicious sites no longer get an in-page popup — just
                // the toolbar badge/auto-opened extension popup.
                // Only auto-open again here if the quick check above
                // didn't already do it, so the popup doesn't pop open
                // twice for the same page load.
                const alreadyOpened = quickStatus === 'phishing' || quickStatus === 'suspicious';
                if (result.status === 'phishing') {
                    showPhishingAlert(url, result);
                    if (!alreadyOpened) autoOpenPopupForTab(details.tabId);
                } else if (result.status === 'suspicious' && !alreadyOpened) {
                    autoOpenPopupForTab(details.tabId);
                }
            } catch (error) {
                console.error('Auto-scan error:', error);
            }
        }
    }
});

// Clear stale badge/verdict state once a tab navigates away or closes.
chrome.tabs.onRemoved.addListener((tabId) => {
    delete tabVerdicts[tabId];
    delete lastScanByTab[tabId];
});

// ===== MESSAGE LISTENER =====
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'scanUrl') {
        scanUrl(request.url)
            .then(result => sendResponse(result))
            .catch(error => sendResponse({ 
                status: 'error', 
                message: error.message,
                awareness_message: 'Could not connect to security server.'
            }));
        return true;
    }
    
    if (request.action === 'getStats') {
        sendResponse(stats);
        return true;
    }
    
    if (request.action === 'getHistory') {
        sendResponse(scanHistory);
        return true;
    }

    if (request.action === 'getTabVerdict') {
        sendResponse({ status: tabVerdicts[request.tabId] || null });
        return true;
    }

    // Sent from the in-page warning-banner buttons (injected into the
    // visited site via chrome.scripting.executeScript). Inline onclick
    // attributes on that injected HTML run in the PAGE's own JS context,
    // which has no chrome.* APIs at all — so the banner sends a message
    // here instead, and the background worker (which does have full API
    // access) performs the actual tab action.
    if (request.action === 'openDashboard') {
        chrome.tabs.create({ url: chrome.runtime.getURL('dashboard.html') });
        return true;
    }

    if (request.action === 'closeThisTab') {
        if (sender.tab && sender.tab.id != null) {
            chrome.tabs.remove(sender.tab.id);
        }
        return true;
    }

    // From blocked.html's "Continue anyway" button. Remembers the URL as
    // allowed for the rest of this browser session (see allowUrlThisSession
    // above) so navigating there doesn't just get blocked again, then
    // sends the tab on to the real page.
    if (request.action === 'continueToBlockedUrl') {
        (async () => {
            if (request.url) {
                await allowUrlThisSession(request.url);
                if (sender.tab && sender.tab.id != null) {
                    chrome.tabs.update(sender.tab.id, { url: request.url });
                }
            }
            sendResponse({ ok: true });
        })();
        return true;
    }

    // From blocked.html's "Back to safety" button. Tries normal back-
    // navigation first (so the user lands wherever they came from); if
    // there's no history to go back to (e.g. the link was opened in a
    // new tab), falls back to a neutral safe page instead of leaving the
    // block screen up or closing the user's only tab out from under them.
    if (request.action === 'goBackFromBlocked') {
        if (sender.tab && sender.tab.id != null) {
            const tabId = sender.tab.id;
            chrome.tabs.goBack(tabId, () => {
                if (chrome.runtime.lastError) {
                    chrome.tabs.update(tabId, { url: 'https://www.google.com' });
                }
            });
        }
        return true;
    }
});

// ===== BACKEND RESPONSE ADAPTER =====
// The backend's /api/detect endpoint (app/routers/detect.py) returns:
//   { url, verdict, confidence_score, vt_positives, domain_age_days,
//     awareness_message, vt_total_engines, vt_vendors }
// This normalizes that into the flatter shape the rest of this file
// (and popup.js / dashboard.js, via chrome.storage) expects.
function normalizeDetectionResponse(url, raw) {
    const verdict = (raw.verdict || 'safe').toLowerCase(); // 'phishing' | 'suspicious' | 'safe'
    const confidencePct = Math.round((raw.confidence_score || 0) * 100);
    return {
        url: url,
        status: verdict,
        confidence: confidencePct,
        risk_score: confidencePct,
        message: raw.awareness_message || '',
        ai_analysis: raw.awareness_message || null,
        virus_total: {
            enabled: raw.vt_total_engines != null,
            malicious: raw.vt_positives || 0,
            suspicious: 0,
            total_engines: raw.vt_total_engines || 0,
            vendors: raw.vt_vendors || [],
            details: raw.vt_details || null
        },
        domain_age_days: raw.domain_age_days
    };
}

// Persists a scan result entry to history + stats, and to
// chrome.storage.local — shared by both the real backend path and the
// offline local-heuristic fallback below, so both save the exact same
// shape and neither can drift out of sync with the other.
function recordScan(entry) {
    stats.scanned++;
    if (entry.status === 'phishing' || entry.status === 'suspicious') {
        stats.threats++;
    } else if (entry.status === 'safe') {
        stats.safe++;
    }

    scanHistory.unshift(entry);
    if (scanHistory.length > 100) scanHistory.pop();

    chrome.storage.local.set({
        history: scanHistory,
        stats: stats
    });
}

// Backend unreachable (not running, network error, etc.) — score the URL
// with the same fast local heuristic used for the pre-check/hard-block
// above (lib/lib/scanner.js) instead of giving up. Keeps auto-scan,
// badges, and history all working with the backend off, just without
// VirusTotal/Gemini data. Returns the SAME normalized shape scanUrl()'s
// success path does, so every caller (popup, dashboard, this file) can
// treat it identically.
function scanUrlLocally(url) {
    if (typeof phishshieldScoreUrl !== 'function') {
        // Shared scanner failed to load too — nothing left to fall back
        // to, so degrade honestly rather than guessing a verdict.
        return {
            status: 'error',
            message: 'Could not connect to security server',
            awareness_message: 'Please ensure the PhishShield backend is running at http://127.0.0.1:8000',
            confidence: 'N/A',
            virus_total: null,
            ai_analysis: null,
            risk_score: 0
        };
    }

    const result = phishshieldScoreUrl(url); // { score: 0-100, verdict: 'danger'|'warn'|'safe', reasons: [] }
    const status = result.verdict === 'danger' ? 'phishing' : (result.verdict === 'warn' ? 'suspicious' : 'safe');
    const reasonsText = (result.reasons || []).join('; ');

    const data = {
        url: url,
        status: status,
        confidence: result.score,
        risk_score: result.score,
        message: 'Backend offline — scored locally: ' + reasonsText,
        awareness_message: 'Backend offline — scored locally: ' + reasonsText,
        ai_analysis: null,
        virus_total: null,
        domain_age_days: null
    };

    recordScan({
        url: url,
        status: data.status,
        confidence: data.confidence,
        timestamp: new Date().toISOString(),
        message: data.message,
        risk_score: data.risk_score,
        vt_positives: null,
        vt_total_engines: null,
        vt_vendors: null,
        vt_details: null
    });

    return data;
}

// ===== SCAN URL FUNCTION =====
async function scanUrl(url) {
    try {
        console.log('🔍 Sending scan request to backend:', url);

        const apiBase = (typeof PHISHSHIELD_CONFIG !== 'undefined' && PHISHSHIELD_CONFIG.API_BASE) || 'http://127.0.0.1:8000';
        const apiKey = (typeof PHISHSHIELD_CONFIG !== 'undefined') ? PHISHSHIELD_CONFIG.API_KEY : '';
        const headers = { 'Content-Type': 'application/json', 'Accept': 'application/json' };
        if (apiKey) headers['X-PhishShield-Key'] = apiKey;

        const response = await fetch(`${apiBase}/api/detect`, {
            method: 'POST',
            headers: headers,
            body: JSON.stringify({ url: url })
        });

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }

        const raw = await response.json();
        console.log('✅ Scan result:', raw);
        const data = normalizeDetectionResponse(url, raw);

        // Save to history
        // Includes the VirusTotal vendor breakdown and Gemini message so the
        // mini dashboard (popup.js) and full dashboard (js/api.js) can show
        // real VT/AI data for past scans, not just a live scan's alert popup.
        recordScan({
            url: url,
            status: data.status,
            confidence: data.confidence,
            timestamp: new Date().toISOString(),
            message: data.message,
            risk_score: data.risk_score || 0,
            vt_positives: data.virus_total ? data.virus_total.malicious : null,
            vt_total_engines: data.virus_total ? data.virus_total.total_engines : null,
            vt_vendors: data.virus_total ? data.virus_total.vendors : null,
            vt_details: data.virus_total ? data.virus_total.details : null
        });

        return data;

    } catch (error) {
        console.warn('⚠️ Backend unreachable, scoring locally instead:', error.message);
        return scanUrlLocally(url);
    }
}

// ===== SHOW PHISHING ALERT =====
function psEscapeHtml(str) {
    return String(str == null ? '' : str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function showPhishingAlert(url, result) {
    // Everything below is injected into the live page's DOM via
    // chrome.scripting.executeScript — url and any AI/message text are
    // attacker-influenced (the URL is literally what's being judged, and
    // the AI message is generated from analyzing it), so every one of
    // them MUST be escaped before going into this template. An
    // unescaped URL like https://evil.com/<img src=x onerror=...> would
    // otherwise execute arbitrary script in the visited page.
    const safeUrl = psEscapeHtml(url);
    const safeMessage = psEscapeHtml(result.message || 'This is a confirmed phishing attempt!');
    const safeAiAnalysis = result.ai_analysis ? psEscapeHtml(result.ai_analysis) : '';
    const alertHTML = `
        <div style="
            position: fixed;
            top: 20px;
            right: 20px;
            width: 440px;
            max-width: 90vw;
            background: linear-gradient(135deg, #1a0a0a, #2d0a0a);
            border: 2px solid #ff4757;
            border-radius: 16px;
            padding: 20px;
            z-index: 999999;
            box-shadow: 0 20px 60px rgba(255, 71, 87, 0.5);
            animation: slideIn 0.5s ease-out;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        ">
            <div style="display: flex; align-items: flex-start; gap: 12px; margin-bottom: 12px;">
                <span style="font-size: 36px; animation: pulse 1s infinite;">🚨</span>
                <div style="flex: 1;">
                    <div style="display: flex; align-items: center; gap: 8px;">
                        <h2 style="margin: 0; color: #ff4757; font-size: 18px; font-weight: 700;">PHISHING DETECTED!</h2>
                        <span style="
                            display: inline-block;
                            padding: 2px 10px;
                            background: #ff4757;
                            border-radius: 12px;
                            font-size: 10px;
                            font-weight: 700;
                            color: #fff;
                            animation: pulse 1.5s infinite;
                        ">HIGH RISK</span>
                    </div>
                    <p style="margin: 4px 0 0 0; color: rgba(255,255,255,0.5); font-size: 12px;">⚠️ Immediate action required</p>
                </div>
                <button onclick="this.parentElement.parentElement.parentElement.remove()" style="
                    background: rgba(255,255,255,0.1);
                    border: none;
                    color: #fff;
                    font-size: 20px;
                    cursor: pointer;
                    width: 30px;
                    height: 30px;
                    border-radius: 50%;
                    transition: all 0.3s ease;
                    flex-shrink: 0;
                " onmouseover="this.style.background='rgba(255,255,255,0.2)'" onmouseout="this.style.background='rgba(255,255,255,0.1)'">✕</button>
            </div>
            
            <div style="
                background: rgba(255, 71, 87, 0.1);
                border-radius: 8px;
                padding: 12px;
                margin-bottom: 12px;
            ">
                <p style="margin: 0; color: rgba(255,255,255,0.7); font-size: 12px; font-weight: 600;">DETECTED URL</p>
                <p style="margin: 4px 0 0 0; color: rgba(255,255,255,0.9); font-size: 13px; word-break: break-all; font-family: monospace;">
                    ${safeUrl}
                </p>
                <p style="margin: 8px 0 0 0; color: #ff4757; font-size: 14px; font-weight: 600;">
                    ⚠️ ${safeMessage}
                </p>
                ${safeAiAnalysis ? `
                <p style="margin: 8px 0 0 0; color: rgba(255,255,255,0.6); font-size: 12px; border-top: 1px solid rgba(255,71,87,0.2); padding-top: 8px;">
                    🧠 ${safeAiAnalysis}
                </p>
                ` : ''}
                ${result.virus_total && result.virus_total.enabled ? `
                <p style="margin: 8px 0 0 0; color: rgba(255,255,255,0.5); font-size: 11px;">
                    🔍 VirusTotal: ${result.virus_total.malicious || 0} malicious, ${result.virus_total.suspicious || 0} suspicious detections
                </p>
                ` : ''}
            </div>
            
            <div style="display: flex; gap: 10px; margin-top: 12px;">
                <button id="ps-view-dashboard-btn" style="
                    flex: 1;
                    padding: 10px 16px;
                    background: linear-gradient(135deg, #4facfe, #00f2fe);
                    border: none;
                    border-radius: 8px;
                    color: #0a0e1a;
                    font-weight: 600;
                    font-size: 13px;
                    cursor: pointer;
                    transition: all 0.3s ease;
                " onmouseover="this.style.transform='scale(1.02)'" onmouseout="this.style.transform='scale(1)'">
                    📊 View Dashboard
                </button>
                <button id="ps-close-tab-btn" style="
                    padding: 10px 16px;
                    background: rgba(255, 71, 87, 0.2);
                    border: 1px solid #ff4757;
                    border-radius: 8px;
                    color: #ff4757;
                    font-weight: 600;
                    font-size: 13px;
                    cursor: pointer;
                    transition: all 0.3s ease;
                " onmouseover="this.style.background='rgba(255,71,87,0.3)'" onmouseout="this.style.background='rgba(255,71,87,0.2)'">
                    🛑 Close Tab
                </button>
            </div>
            
            <div style="margin-top: 12px; padding-top: 12px; border-top: 1px solid rgba(255,71,87,0.2); display: flex; gap: 12px; align-items: center;">
                <span style="font-size: 14px;">🛡️</span>
                <p style="margin: 0; color: rgba(255,255,255,0.3); font-size: 10px;">
                    PhishShield AI-Powered Protection • ${new Date().toLocaleTimeString()}
                </p>
            </div>
        </div>
        <style>
            @keyframes slideIn {
                from {
                    transform: translateX(100%);
                    opacity: 0;
                }
                to {
                    transform: translateX(0);
                    opacity: 1;
                }
            }
            @keyframes pulse {
                0%, 100% { transform: scale(1); }
                50% { transform: scale(1.1); }
            }
        </style>
    `;

    // Inject the alert into the current page
    chrome.tabs.query({ active: true, currentWindow: true }, function(tabs) {
        if (tabs[0]) {
            chrome.scripting.executeScript({
                target: { tabId: tabs[0].id },
                func: (html) => {
                    // Remove any existing alerts
                    const existing = document.getElementById('phishshield-alert');
                    if (existing) existing.remove();
                    
                    // Create container
                    const container = document.createElement('div');
                    container.id = 'phishshield-alert';
                    container.innerHTML = html;
                    document.body.appendChild(container);

                    // Wire real listeners here (isolated world — has
                    // chrome.runtime access) instead of inline onclick
                    // attributes on the injected HTML, which run in the
                    // page's own context and can't reach chrome.* APIs.
                    var dashBtn = container.querySelector('#ps-view-dashboard-btn');
                    if (dashBtn) dashBtn.addEventListener('click', function () {
                        chrome.runtime.sendMessage({ action: 'openDashboard' });
                        container.remove();
                    });
                    var closeBtn = container.querySelector('#ps-close-tab-btn');
                    if (closeBtn) closeBtn.addEventListener('click', function () {
                        chrome.runtime.sendMessage({ action: 'closeThisTab' });
                        container.remove();
                    });
                    
                    // Auto-remove after 30 seconds if user doesn't interact
                    setTimeout(() => {
                        const alert = document.getElementById('phishshield-alert');
                        if (alert) alert.remove();
                    }, 30000);
                },
                args: [alertHTML]
            });
        }
    });

    // Also show Chrome notification
    chrome.notifications.create({
        type: 'basic',
        iconUrl: 'icons/icon128.png',
        title: '🚨 PHISHING ALERT!',
        message: `PhishShield detected a phishing attempt on the current page!`,
        priority: 2,
        buttons: [
            { title: 'View Dashboard' },
            { title: 'Close Tab' }
        ]
    });
}

// ===== NOTIFICATION HANDLER =====
chrome.notifications.onButtonClicked.addListener((notificationId, buttonIndex) => {
    if (buttonIndex === 0) {
        chrome.tabs.create({ url: chrome.runtime.getURL('dashboard.html') });
    } else if (buttonIndex === 1) {
        chrome.tabs.query({ active: true, currentWindow: true }, function(tabs) {
            if (tabs[0]) {
                chrome.tabs.remove(tabs[0].id);
            }
        });
    }
});

console.log('🛡️ PhishShield background service worker loaded');
console.log('🔗 Backend URL: http://127.0.0.1:8000');
console.log('🔄 Auto-alert system active - Phishing alerts will pop up automatically!');