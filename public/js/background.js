// background.js - Full auto-scan, VirusTotal data extraction & chrome.storage bridge

// In an MV3 service worker, importScripts() paths resolve from the extension
// root (the manifest registers this worker as "js/background.js"), so these
// are root-relative. scanner.js provides phishshieldScoreUrl(); config.js
// provides PHISHSHIELD_CONFIG (and is worker-safe — it only touches `window`
// behind guards).
try {
    importScripts('/lib/scanner.js', '/js/config.js');
} catch (err) {
    console.error('Failed to import background scripts:', err);
}

let scanHistory = [];
let stats = { scanned: 0, threats: 0, safe: 0 };

const dataReady = new Promise((resolve) => {
    chrome.storage.local.get(['history', 'stats'], function (result) {
        if (result.history) scanHistory = result.history;
        if (result.stats) stats = result.stats;
        resolve();
    });
});

function getApiBase() {
    return (typeof PHISHSHIELD_CONFIG !== 'undefined' && PHISHSHIELD_CONFIG.API_BASE) || 'https://phishshield-api-qsuo.onrender.com';
}

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

const ALLOWLIST_KEY = 'allowedPhishingUrls';

async function isUrlAllowed(url) {
    try {
        const result = await chrome.storage.session.get(ALLOWLIST_KEY);
        const list = result[ALLOWLIST_KEY];
        return Array.isArray(list) && list.includes(url);
    } catch (error) {
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

// Navigation & Hard Block
chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
    if (details.frameId !== 0) return;
    const url = details.url;
    if (!url || url.startsWith('chrome://') || url.startsWith('chrome-extension://') ||
        url.startsWith('about:') || url.startsWith('edge://')) return;

    if (typeof phishshieldScoreUrl !== 'function') return;

    const quick = phishshieldScoreUrl(url);
    if (quick.verdict !== 'danger') return;

    if (await isUrlAllowed(url)) return;

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
    }).catch(err => console.error(err));
});

// Auto Scan on Load Complete
// Show the in-page warning banner on a suspicious/phishing tab. content.js is
// not a registered content script (so it never slows down safe pages), so we
// inject it on demand, then message it. Safe pages get nothing.
async function warnTabIfRisky(tabId, result) {
    if (!result || (result.status !== 'suspicious' && result.status !== 'phishing')) return;
    try {
        await chrome.scripting.executeScript({ target: { tabId: tabId }, files: ['js/content.js'] });
        chrome.tabs.sendMessage(tabId, {
            type: 'SHOW_WARNING',
            data: {
                verdict: result.status,
                awareness_message: result.message || ''
            }
        }, function () { void chrome.runtime.lastError; });
    } catch (e) {
        // Injection can fail on protected pages (chrome://, web store) — ignore.
    }
}

chrome.webNavigation.onCompleted.addListener(async (details) => {
    if (details.frameId !== 0) return;
    const url = details.url;
    if (!url || !/^https?:\/\//i.test(url)) return;

    if (shouldSkipScan(details.tabId, url)) return;

    // FAST PATH: score locally first (instant, no network) so a clearly risky
    // page warns immediately, before the slower backend scan returns.
    try {
        if (typeof phishshieldScoreUrl === 'function') {
            const quick = phishshieldScoreUrl(url);
            const quickStatus = quick.verdict === 'danger' ? 'phishing'
                : (quick.verdict === 'warn' ? 'suspicious' : 'safe');
            if (quickStatus !== 'safe') {
                setBadgeForVerdict(details.tabId, quickStatus);
                warnTabIfRisky(details.tabId, {
                    status: quickStatus,
                    message: (quick.reasons || []).slice(0, 2).join('; ')
                });
            }
        }
    } catch (e) { /* ignore */ }

    try {
        const result = await scanUrl(url);
        tabVerdicts[details.tabId] = result.status;
        setBadgeForVerdict(details.tabId, result.status);
        // Confirm/upgrade the warning with the full backend verdict.
        warnTabIfRisky(details.tabId, result);
    } catch (error) {
        console.error('Auto-scan error:', error);
    }
});

chrome.tabs.onRemoved.addListener((tabId) => {
    delete tabVerdicts[tabId];
    delete lastScanByTab[tabId];
});

// Normalize API payload & extract VirusTotal data
function normalizeDetectionResponse(url, raw) {
    const verdict = (raw.verdict || 'safe').toLowerCase();
    const score = Math.round((raw.confidence_score || raw.risk_score || raw.score || 0) * (raw.confidence_score <= 1 ? 100 : 1));
    
    const vtPositives = raw.vt_positives !== undefined ? raw.vt_positives : (raw.virus_total ? raw.virus_total.malicious : null);
    const vtTotal = raw.vt_total_engines !== undefined ? raw.vt_total_engines : (raw.virus_total ? raw.virus_total.total_engines : null);
    const vtVendors = raw.vt_vendors || raw.vendors || (raw.virus_total ? raw.virus_total.vendors : []);

    return {
        url: url,
        status: verdict === 'danger' ? 'phishing' : (verdict === 'warn' ? 'suspicious' : verdict),
        confidence: score,
        risk_score: score,
        message: raw.awareness_message || raw.message || 'Scan completed.',
        ai_analysis: raw.awareness_message || raw.message || null,
        vt_positives: vtPositives,
        vt_total_engines: vtTotal || 90,
        vt_vendors: vtVendors,
        hasVtData: vtPositives !== null && vtPositives !== undefined,
        domain_age_days: raw.domain_age_days !== undefined ? raw.domain_age_days : null
    };
}

async function recordScan(entry) {
    await dataReady;

    stats.scanned++;
    if (entry.status === 'phishing' || entry.status === 'suspicious') stats.threats++;
    else if (entry.status === 'safe') stats.safe++;

    scanHistory.unshift(entry);
    if (scanHistory.length > 100) scanHistory.pop();

    const detections = scanHistory.map(item => ({
        url: item.url,
        riskScore: item.risk_score || item.confidence || 0,
        result: item.status,
        message: item.message,
        timestamp: item.timestamp,
        hasVtData: item.hasVtData,
        vt_positives: item.vt_positives,
        vt_total_engines: item.vt_total_engines,
        vt_vendors: item.vt_vendors,
        domain_age_days: item.domain_age_days
    }));

    // Broadcast to dashboard index.js
    chrome.storage.local.set({
        history: scanHistory,
        detections: detections,
        stats: stats
    });
}

async function scanUrlLocally(url) {
    if (typeof phishshieldScoreUrl !== 'function') return null;

    const result = phishshieldScoreUrl(url);
    const status = result.verdict === 'danger' ? 'phishing' : (result.verdict === 'warn' ? 'suspicious' : 'safe');
    const reasonsText = (result.reasons || []).join('; ');

    const entry = {
        url: url,
        status: status,
        confidence: result.score,
        risk_score: result.score,
        timestamp: new Date().toISOString(),
        message: 'Backend offline — scored locally: ' + (reasonsText || 'Local heuristic scan.'),
        hasVtData: false,
        vt_positives: null,
        vt_total_engines: null,
        vt_vendors: [],
        domain_age_days: null
    };

    await recordScan(entry);
    return entry;
}

async function scanUrl(url) {
    try {
        const apiBase = getApiBase();
        const apiKey = (typeof PHISHSHIELD_CONFIG !== 'undefined') ? PHISHSHIELD_CONFIG.API_KEY : '';
        const headers = { 'Content-Type': 'application/json', 'Accept': 'application/json' };
        if (apiKey) headers['X-PhishShield-Key'] = apiKey;

        const response = await fetch(`${apiBase}/api/detect`, {
            method: 'POST',
            headers: headers,
            body: JSON.stringify({ url: url })
        });

        if (!response.ok) throw new Error(`HTTP ${response.status}`);

        const raw = await response.json();
        const data = normalizeDetectionResponse(url, raw);

        await recordScan({
            url: url,
            status: data.status,
            confidence: data.confidence,
            timestamp: new Date().toISOString(),
            message: data.message,
            risk_score: data.risk_score,
            hasVtData: data.hasVtData,
            vt_positives: data.vt_positives,
            vt_total_engines: data.vt_total_engines,
            vt_vendors: data.vt_vendors,
            domain_age_days: data.domain_age_days
        });

        return data;

    } catch (error) {
        return scanUrlLocally(url);
    }
}

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'getTabVerdict') {
        const status = tabVerdicts[request.tabId] || null;
        sendResponse(status ? { status } : null);
        return false;
    }
    if (request.action === 'openDashboard') {
        chrome.tabs.create({ url: chrome.runtime.getURL('index.html') });
        sendResponse({ ok: true });
        return true;
    }
    if (request.action === 'closeThisTab') {
        if (sender.tab && sender.tab.id) chrome.tabs.remove(sender.tab.id);
        sendResponse({ ok: true });
        return true;
    }

    // "Go back to safety" on blocked.html — leave the blocked page. Go back in
    // this tab's history if possible; if there's nowhere to go back to (the
    // blocked navigation was the first thing in the tab), close the tab.
    if (request.action === 'goBackFromBlocked') {
        const tabId = sender.tab && sender.tab.id;
        if (tabId == null) { sendResponse({ ok: false }); return true; }
        chrome.tabs.goBack(tabId, () => {
            if (chrome.runtime.lastError) {
                // No history entry to go back to — close the tab instead.
                chrome.tabs.remove(tabId);
            }
        });
        sendResponse({ ok: true });
        return true;
    }

    // "Continue anyway" on blocked.html — allow this URL for the rest of the
    // browsing session, then navigate the tab to it. onBeforeNavigate sees the
    // allowlist entry and lets it through instead of blocking again.
    if (request.action === 'continueToBlockedUrl') {
        const tabId = sender.tab && sender.tab.id;
        const url = request.url;
        if (tabId == null || !url) { sendResponse({ ok: false }); return true; }
        allowUrlThisSession(url).then(() => {
            chrome.tabs.update(tabId, { url: url }, () => {
                sendResponse({ ok: !chrome.runtime.lastError });
            });
        }).catch(() => sendResponse({ ok: false }));
        return true; // async sendResponse
    }
});