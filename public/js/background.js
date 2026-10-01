// background.js - Complete with auto-alert for malicious links

// Root-relative script imports for Manifest V3 service workers
try {
    importScripts('/lib/scanner.js');
    importScripts('/js/config.js');
} catch (e) {
    try {
        importScripts('../lib/scanner.js');
        importScripts('config.js');
    } catch (err) {
        console.error('Failed to import background scripts:', err);
    }
}

// Store scan history locally
let scanHistory = [];
let stats = {
    scanned: 0,
    threats: 0,
    safe: 0
};

// Load saved data on startup
const dataReady = new Promise((resolve) => {
    chrome.storage.local.get(['history', 'stats'], function (result) {
        if (result.history) scanHistory = result.history;
        if (result.stats) stats = result.stats;
        resolve();
    });
});

function getApiBase() {
    return (typeof PHISHSHIELD_CONFIG !== 'undefined' && PHISHSHIELD_CONFIG.API_BASE) || 'http://127.0.0.1:8000';
}

// ===== BADGE STATE =====
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

async function autoOpenPopupForTab(tabId) {
    try {
        const win = await chrome.windows.getLastFocused();
        const [activeTab] = await chrome.tabs.query({ active: true, windowId: win.id });
        if (activeTab && activeTab.id === tabId && typeof chrome.action.openPopup === 'function') {
            await chrome.action.openPopup();
        }
    } catch (error) {
        console.log('Auto-open popup skipped:', error.message);
    }
}

// ===== RATE LIMITING / DEDUPE =====
const lastScanByTab = {};
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
    if (quick.verdict !== 'danger') return;

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

    scanUrl(url).then((result) => {
        tabVerdicts[details.tabId] = result.status;
        setBadgeForVerdict(details.tabId, result.status);
    }).catch((error) => console.error('Background scan after block failed:', error));
});

// ===== CERTIFICATE / CONNECTION ERRORS =====
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

    scanUrl(url).then((result) => {
        tabVerdicts[details.tabId] = result.status;
        setBadgeForVerdict(details.tabId, result.status);
    }).catch((error) => console.error('Background scan after cert-error block failed:', error));
});

// ===== AUTO-SCAN ON NAVIGATION =====
chrome.webNavigation.onCompleted.addListener(async (details) => {
    if (details.frameId !== 0) return;

    const url = details.url;
    if (!url || !/^https?:\/\//i.test(url)) return;

    if (shouldSkipScan(details.tabId, url)) {
        console.log('⏭️ Skipping re-scan (same URL, within cooldown):', url);
        return;
    }
    console.log('🔄 Auto-scanning:', url);

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

        const alreadyOpened = quickStatus === 'phishing' || quickStatus === 'suspicious';
        if (result.status === 'phishing') {
            showPhishingAlert(details.tabId, url, result);
            if (!alreadyOpened) autoOpenPopupForTab(details.tabId);
        } else if (result.status === 'suspicious' && !alreadyOpened) {
            autoOpenPopupForTab(details.tabId);
        }
    } catch (error) {
        console.error('Auto-scan error:', error);
    }
});

chrome.tabs.onRemoved.addListener((tabId) => {
    delete tabVerdicts[tabId];
    delete lastScanByTab[tabId];
});

const DASHBOARD_PAGE = 'index.html';

// ===== MESSAGE LISTENER =====
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'scanUrl') {
        fetch(`${PHISHSHIELD_CONFIG.API_BASE}/detect`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: request.url })
        })
        .then(res => res.json())
        .then(data => {
            // ONLY trigger blocked page / action if verdict is strictly DANGER or PHISHING
            if (data.verdict === 'danger' || data.verdict === 'phishing') {
                if (sender.tab && sender.tab.id) {
                    chrome.tabs.update(sender.tab.id, {
                        url: chrome.runtime.getURL(`blocked.html?url=${encodeURIComponent(request.url)}`)
                    });
                }
            }
            sendResponse(data);
        })
        .catch(err => {
            console.warn('Render backend waking up or unreachable. Presuming safe fallback.', err);
            sendResponse({ verdict: 'safe', score: 100, message: 'Backend unreachable - temporary safe mode' });
        });
        
        return true; // Keep message channel open for async response
    }
});

function normalizeDetectionResponse(url, raw) {
    const verdict = (raw.verdict || 'safe').toLowerCase();
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

async function recordScan(entry) {
    await dataReady;

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

async function scanUrlLocally(url) {
    if (typeof phishshieldScoreUrl !== 'function') {
        return {
            status: 'error',
            message: 'Could not connect to security server',
            awareness_message: 'Please ensure the PhishShield backend is running at ' + getApiBase(),
            confidence: 'N/A',
            virus_total: null,
            ai_analysis: null,
            risk_score: 0
        };
    }

    const result = phishshieldScoreUrl(url);
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

    await recordScan({
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

async function scanUrl(url) {
    try {
        const apiBase = getApiBase();
        console.log('🔍 Sending scan request to backend:', url);

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

        await recordScan({
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
        console.warn('⚠️️ Backend unreachable, scoring locally instead:', error.message);
        return scanUrlLocally(url);
    }
}

function psEscapeHtml(str) {
    return String(str == null ? '' : str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function showPhishingAlert(tabId, url, result) {
    if (!url || !/^https?:\/\//i.test(url)) return;

    const safeUrl = psEscapeHtml(url);
    const safeMessage = psEscapeHtml(result.message || 'This is a confirmed phishing attempt!');
    const safeAiAnalysis = result.ai_analysis ? psEscapeHtml(result.ai_analysis) : '';
    const vt = result.virus_total;
    const vtMalicious = vt ? (vt.malicious || 0) : 0;
    const vtSuspicious = vt ? (vt.suspicious || 0) : 0;

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
            z-index: 2147483647;
            box-shadow: 0 20px 60px rgba(255, 71, 87, 0.5);
            animation: psSlideIn 0.5s ease-out;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        ">
            <div style="display: flex; align-items: flex-start; gap: 12px; margin-bottom: 12px;">
                <span style="font-size: 36px; animation: psPulse 1s infinite;">🚨</span>
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
                            animation: psPulse 1.5s infinite;
                        ">HIGH RISK</span>
                    </div>
                    <p style="margin: 4px 0 0 0; color: rgba(255,255,255,0.5); font-size: 12px;">⚠️ Immediate action required</p>
                </div>
                <button id="ps-alert-close" style="
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
                ">✕</button>
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
                ${vt && vt.enabled ? `
                <p style="margin: 8px 0 0 0; color: rgba(255,255,255,0.5); font-size: 11px;">
                    🔍 VirusTotal: ${vtMalicious} malicious,${vtSuspicious} suspicious detections
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
                ">
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
                ">
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
            @keyframes psSlideIn {
                from { transform: translateX(100%); opacity: 0; }
                to { transform: translateX(0); opacity: 1; }
            }
            @keyframes psPulse {
                0%, 100% { transform: scale(1); }
                50% { transform: scale(1.1); }
            }
            #ps-alert-close:hover { background: rgba(255,255,255,0.2) !important; }
            #ps-view-dashboard-btn:hover { transform: scale(1.02); }
            #ps-close-tab-btn:hover { background: rgba(255,71,87,0.3) !important; }
        </style>
    `;

    chrome.scripting.executeScript({
        target: { tabId: tabId },
        func: (html) => {
            const existing = document.getElementById('phishshield-alert');
            if (existing) existing.remove();

            const container = document.createElement('div');
            container.id = 'phishshield-alert';
            container.innerHTML = html;
            document.body.appendChild(container);

            const closeX = container.querySelector('#ps-alert-close');
            if (closeX) closeX.addEventListener('click', function () {
                container.remove();
            });
            const dashBtn = container.querySelector('#ps-view-dashboard-btn');
            if (dashBtn) dashBtn.addEventListener('click', function () {
                chrome.runtime.sendMessage({ action: 'openDashboard' });
                container.remove();
            });
            const closeBtn = container.querySelector('#ps-close-tab-btn');
            if (closeBtn) closeBtn.addEventListener('click', function () {
                chrome.runtime.sendMessage({ action: 'closeThisTab' });
                container.remove();
            });

            setTimeout(() => {
                const el = document.getElementById('phishshield-alert');
                if (el) el.remove();
            }, 30000);
        },
        args: [alertHTML]
    }).catch((error) => {
        console.log('Could not show in-page alert:', error.message);
    });

    chrome.notifications.create({
        type: 'basic',
        iconUrl: chrome.runtime.getURL('icons/icon128.png'),
        title: '🚨 PHISHING ALERT!',
        message: `PhishShield detected a phishing attempt on the current page!`,
        priority: 2,
        buttons: [
            { title: 'View Dashboard' },
            { title: 'Close Tab' }
        ]
    }, () => {
        if (chrome.runtime.lastError) {
            console.log('Notification failed:', chrome.runtime.lastError.message);
        }
    });
}

// ===== NOTIFICATION HANDLER =====
chrome.notifications.onButtonClicked.addListener((notificationId, buttonIndex) => {
    if (buttonIndex === 0) {
        chrome.tabs.create({ url: chrome.runtime.getURL(DASHBOARD_PAGE) });
    } else if (buttonIndex === 1) {
        chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
            if (tabs[0]) {
                chrome.tabs.remove(tabs[0].id);
            }
        });
    }
});

console.log('🛡️ PhishShield background service worker loaded');
console.log('🔗 Backend URL:', getApiBase());
console.log('🔄 Auto-alert system active - Phishing alerts will pop up automatically!');