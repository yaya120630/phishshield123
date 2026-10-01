console.log('PhishShield popup loading...');

// If anything crashes, show the reason inside the popup so it is never a silent "stuck" screen.
function psShowFatal(text) {
    try {
        var loadingEl = document.getElementById('loadingState');
        var sectionEl = document.getElementById('resultSection');
        var msgEl = document.getElementById('warningMessage');
        if (loadingEl) loadingEl.style.display = 'none';
        if (sectionEl) sectionEl.style.display = 'block';
        if (msgEl) msgEl.textContent = 'Something went wrong: ' + text;
    } catch (e) { /* nothing more we can do */ }
}
window.addEventListener('error', function (ev) {
    psShowFatal((ev && ev.message ? ev.message : 'unknown error') + (ev && ev.lineno ? ' (line ' + ev.lineno + ')' : ''));
});
window.addEventListener('unhandledrejection', function (ev) {
    psShowFatal(ev && ev.reason && ev.reason.message ? ev.reason.message : 'unknown error');
});

// ===== TAB SWITCHING (independent safety net) =====
// Uses event delegation at the top level so the Scanner/Dashboard tabs still
// work even if some other part of this file throws an error while loading.
document.addEventListener('click', function (e) {
    var tab = e.target && e.target.closest ? e.target.closest('.tab') : null;
    if (!tab || !tab.dataset || !tab.dataset.target) return;
    try {
        document.querySelectorAll('.tab').forEach(function (t) { t.classList.toggle('active', t === tab); });
        document.querySelectorAll('.screen').forEach(function (s) { s.classList.toggle('active', s.id === tab.dataset.target); });
        if (tab.dataset.target === 'dashboard') {
            if (typeof loadMiniDashboard === 'function') loadMiniDashboard();
            if (typeof populateDetails === 'function') populateDetails();
        }
    } catch (err) {
        console.error('Tab switch error:', err);
    }
});



// ===== LIVE SYNC =====
// The popup, the full dashboard, and background.js's auto-scanner all
// read/write the SAME chrome.storage.local keys ('history', 'stats').
// That's the whole "sync" mechanism — no messages needed. This listener
// fires the instant any of them writes, so if e.g. the full dashboard
// (open in another tab) runs a scan, or background.js auto-scans a new
// page, this popup's stats + mini dashboard update immediately too.
try {
    chrome.storage.onChanged.addListener(function (changes, area) {
        if (area !== 'local') return;

        if (changes.stats) {
            updateStatsDisplay(changes.stats.newValue || { scanned: 0, threats: 0, safe: 0 });
        }
        if (changes.history) {
            renderMiniDashboard(changes.history.newValue || []);
        }
        // The top verdict badge updates live as scans complete (e.g. the
        // popup's own 2-second auto-scan of the current tab, which runs
        // AFTER this listener is wired and can land after the Details
        // panel was already opened with an older/different scan's data).
        // Without this, "View Details" could keep showing a stale scan
        // (even for a different URL) after the badge above it moves on.
        if (changes.currentScanData) {
            // The details block lives in the Dashboard tab now; repaint
            // it whenever the scan data changes so it's fresh the next
            // time someone switches tabs (or if it's already open).
            populateDetails();
        }
    });
} catch (error) {
    console.error('Error wiring storage sync listener:', error);
}

function psEscapeHtml(str) {
    return String(str == null ? '' : str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

document.addEventListener('DOMContentLoaded', function() {
    console.log('DOM loaded');

    checkElements();
    setupTabs();
    fixViewDetailsButton();

    // getCurrentTabUrl() first sets the "Detected URL" text, THEN decides
    // whether to paint the stored lastScanResult — only if it's actually
    // for THIS url. Previously loadLastScanResult() ran unconditionally
    // and would briefly paint whatever URL was scanned last (even from a
    // different site) as if it were this tab's result, until the 2s
    // auto-scan below overwrote it.
    getCurrentTabUrl(function(currentUrl) {
        chrome.storage.local.get(['lastScanResult'], function(result) {
            var stored = result && result.lastScanResult;
            if (stored && stored.url === currentUrl) {
                updateResultDisplay(stored);
            }
            // else: leave the "Scanning..." state as-is until the
            // auto-scan below completes, rather than showing a
            // mismatched previous result.
        });
    });

    // If background.js already flagged this tab (badge set from the
    // auto-scan on navigation), reflect that immediately instead of
    // waiting for this popup's own rescan to finish.
    try {
        chrome.tabs.query({ active: true, currentWindow: true }, function(tabs) {
            if (!tabs || !tabs[0]) return;
            chrome.runtime.sendMessage({ action: 'getTabVerdict', tabId: tabs[0].id }, function(res) {
                if (res && (res.status === 'phishing' || res.status === 'suspicious')) {
                    var badge = document.getElementById('resultBadge');
                    var section = document.getElementById('resultSection');
                    if (badge) badge.style.display = 'flex';
                    if (section) section.style.display = 'block';
                }
            });
        });
    } catch (error) {
        console.error('Error checking tab verdict:', error);
    }

    loadStats();
    loadMiniDashboard();

    // Was a fixed 2s delay before scanning even started — now scans as
    // soon as the tab URL is available (still deferred one tick so the
    // "Detected URL" text has definitely been set first).
    setTimeout(function() {
        var urlEl = document.getElementById('detectedUrl');
        if (urlEl && urlEl.textContent &&
            urlEl.textContent !== 'Loading...' &&
            urlEl.textContent !== 'No active tab' &&
            (urlEl.textContent.startsWith('http://') ||
             urlEl.textContent.startsWith('https://'))) {
            console.log('Auto-scanning:', urlEl.textContent);
            scanUrl(urlEl.textContent);
        } else {
            var loadingEl = document.getElementById('loadingState');
            var noteEl = document.getElementById('warningMessage');
            var sectionEl = document.getElementById('resultSection');
            if (loadingEl) loadingEl.style.display = 'none';
            if (noteEl) noteEl.textContent = 'This page cannot be scanned. Open a website (http or https) and try again.';
            if (sectionEl) sectionEl.style.display = 'block';
        }
    }, 150);
});

function setupTabs() {
    var tabs = document.querySelectorAll('.tab');
    var screens = document.querySelectorAll('.screen');

    tabs.forEach(function(tab) {
        tab.addEventListener('click', function() {
            tabs.forEach(function(t) { t.classList.remove('active'); });
            screens.forEach(function(s) { s.classList.remove('active'); });

            tab.classList.add('active');
            var target = document.getElementById(tab.dataset.target);
            if (target) target.classList.add('active');

            if (tab.dataset.target === 'dashboard') {
                loadMiniDashboard();
                populateDetails();
            }
        });
    });
}

function checkElements() {
    var elements = [
        'detectedUrl', 'verdictDisplay', 'confidenceValue',
        'warningMessage', 'resultSection', 'resultBadge', 'resultIcon',
        'detailsContainer',
        'scannedCount', 'threatsBlocked', 'safeSites',
        'dashboardBtn', 'rescanBtn', 'loadingState',
        'detailUrl', 'detailVerdict', 'detailConfidence',
        'detailRiskScore', 'detailIndicators', 'detailTips'
    ];

    var missing = [];
    for (var i = 0; i < elements.length; i++) {
        if (!document.getElementById(elements[i])) {
            missing.push(elements[i]);
        }
    }

    if (missing.length > 0) {
        console.warn('Missing elements:', missing.join(', '));
    } else {
        console.log('All elements found');
    }
}

function fixViewDetailsButton() {
    // The full details block (URL/Verdict/Confidence/Risk score/
    // Indicators/tips) now lives in the Dashboard tab, not the Scanner
    // tab. Paint it eagerly so it's ready the moment someone switches
    // tabs — populateDetails() itself handles the "no scan yet" state.
    populateDetails();

    ['dashboardBtn', 'dashboardBtn2'].forEach(function(id) {
        var el = document.getElementById(id);
        if (el) {
            el.onclick = function() {
                chrome.tabs.create({ url: chrome.runtime.getURL('index.html') });
            };
        }
    });

    var rescanBtn = document.getElementById('rescanBtn');
    if (rescanBtn) {
        rescanBtn.onclick = function() {
            var el = document.getElementById('detectedUrl');
            if (el && /^https?:\/\//i.test(el.textContent)) {
                scanUrl(el.textContent);
            }
        };
    }
}

function getCurrentTabUrl(callback) {
    try {
        chrome.tabs.query({ active: true, currentWindow: true }, function(tabs) {
            if (tabs && tabs[0]) {
                var url = tabs[0].url;
                var el = document.getElementById('detectedUrl');
                if (el) {
                    el.textContent = url;
                }
                if (typeof callback === 'function') callback(url);
            } else {
                var noTab = document.getElementById('detectedUrl');
                if (noTab) noTab.textContent = 'No active tab';
                if (typeof callback === 'function') callback(null);
            }
        });
    } catch (error) {
        console.error('Error getting URL:', error);
    }
}

function loadStats() {
    try {
        chrome.storage.local.get(['stats'], function(result) {
            var stats = result && result.stats ? result.stats : { scanned: 0, threats: 0, safe: 0 };
            updateStatsDisplay(stats);
        });
    } catch (error) {
        console.error('Error loading stats:', error);
    }
}

function updateStatsDisplay(stats) {
    var scanned = document.getElementById('scannedCount');
    var threats = document.getElementById('threatsBlocked');
    var safe = document.getElementById('safeSites');
    if (scanned) scanned.textContent = stats.scanned || 0;
    if (threats) threats.textContent = stats.threats || 0;
    if (safe) safe.textContent = stats.safe || 0;
}

function updateStatsAfterScan(data) {
    try {
        chrome.storage.local.get(['stats'], function(result) {
            var stats = result && result.stats ? result.stats : { scanned: 0, threats: 0, safe: 0 };

            if (data.verdict === 'Safe') {
                stats.safe = (stats.safe || 0) + 1;
            } else if (data.verdict === 'Suspicious' || data.verdict === 'Phishing') {
                stats.threats = (stats.threats || 0) + 1;
            }
            stats.scanned = (stats.scanned || 0) + 1;

            chrome.storage.local.set({ stats: stats });
            updateStatsDisplay(stats);
        });
    } catch (error) {
        console.error('Error updating stats:', error);
    }
}

function saveToHistory(data) {
    try {
        chrome.storage.local.get(['history'], function(result) {
            var history = (result && result.history) ? result.history : [];

            history.unshift({
                url: data.url,
                status: data.verdict === 'Phishing' ? 'phishing' :
                         data.verdict === 'Suspicious' ? 'suspicious' : 'safe',
                confidence: data.confidence || 0,
                risk_score: data.riskScore || data.confidence || 0,
                message: data.description || '',
                timestamp: new Date().toISOString(),
                vt_positives: data.vt_positives != null ? data.vt_positives : null,
                vt_total_engines: data.vt_total_engines != null ? data.vt_total_engines : null,
                vt_vendors: data.vt_vendors || null,
                vt_details: data.vt_details || null
            });

            if (history.length > 200) {
                history = history.slice(0, 200);
            }

            chrome.storage.local.set({ history: history }, function() {
                loadMiniDashboard();
            });
        });
    } catch (error) {
        console.error('Error saving history:', error);
    }
}

function loadMiniDashboard() {
    try {
        chrome.storage.local.get(['history'], function(result) {
            var history = (result && result.history) ? result.history : [];
            renderMiniDashboard(history);
        });
    } catch (error) {
        console.error('Error loading mini dashboard:', error);
    }
}

function renderMiniDashboard(history) {
    var total = history.length;
    var safeCount = 0, susCount = 0, phishCount = 0;

    for (var i = 0; i < history.length; i++) {
        if (history[i].status === 'phishing') phishCount++;
        else if (history[i].status === 'suspicious') susCount++;
        else safeCount++;
    }

    var safePct = total > 0 ? Math.round((safeCount / total) * 100) : 0;
    var susPct = total > 0 ? Math.round((susCount / total) * 100) : 0;
    var phishPct = total > 0 ? Math.max(0, 100 - safePct - susPct) : 0;

    var totalEl = document.getElementById('miniDonutTotal');
    var safeEl = document.getElementById('miniSafePct');
    var susEl = document.getElementById('miniSusPct');
    var phishEl = document.getElementById('miniPhishPct');
    var donut = document.getElementById('miniDonut');

    if (totalEl) totalEl.textContent = total;
    if (safeEl) safeEl.textContent = safePct + '%';
    if (susEl) susEl.textContent = susPct + '%';
    if (phishEl) phishEl.textContent = phishPct + '%';

    if (donut) {
        if (total === 0) {
            donut.style.background = '#E4E7F0';
        } else {
            var safeEnd = safePct;
            var susEnd = safePct + susPct;
            donut.style.background =
                'conic-gradient(' +
                'var(--safe) 0% ' + safeEnd + '%, ' +
                'var(--suspicious) ' + safeEnd + '% ' + susEnd + '%, ' +
                'var(--phishing) ' + susEnd + '% 100%)';
        }
    }

    var safeCountEl = document.getElementById('miniSafeCount');
    var flaggedCountEl = document.getElementById('miniFlaggedCount');
    var blockedCountEl = document.getElementById('miniBlockedCount');
    if (safeCountEl) safeCountEl.textContent = safeCount;
    if (flaggedCountEl) flaggedCountEl.textContent = susCount;
    if (blockedCountEl) blockedCountEl.textContent = phishCount;
}

function formatPct(num) {
    if (typeof num !== 'number' || isNaN(num)) return '0';
    var rounded = Math.round(num);
    if (rounded < 0) rounded = 0;
    if (rounded > 100) rounded = 100;
    return String(rounded);
}

function updateResultDisplay(data) {
    var verdict = document.getElementById('verdictDisplay');
    var confidence = document.getElementById('confidenceValue');
    var confidenceLabel = document.getElementById('confidenceLabel');
    var message = document.getElementById('warningMessage');
    var section = document.getElementById('resultSection');
    var badge = document.getElementById('resultBadge');
    var icon = document.getElementById('resultIcon');

    if (!verdict || !confidence || !message) {
        console.error('Result elements missing!');
        return;
    }

    if (section) section.style.display = 'block';
    if (badge) badge.style.display = 'flex';

    var riskPct = typeof data.riskPct === 'number' ? data.riskPct : data.confidence;
    var safetyPctRaw = typeof data.safetyPct === 'number' ? data.safetyPct : (100 - (data.confidence || 0));
    var safetyPct = Math.min(safetyPctRaw, 99);

    if (data.verdict === 'Safe') {
        if (confidenceLabel) confidenceLabel.textContent = 'Safety Score';
        confidence.textContent = formatPct(safetyPct) + '%';
    } else {
        if (confidenceLabel) confidenceLabel.textContent = 'Risk Score';
        confidence.textContent = formatPct(riskPct) + '%';
    }

    try {
        chrome.storage.local.set({ currentScanData: data });
    } catch (error) {
        console.error('Error saving data:', error);
    }

    if (data.verdict === 'Safe') {
        verdict.textContent = formatPct(safetyPct) + '% Safe';
        verdict.className = 'result-status safe';
        message.textContent = data.description || 'This URL appears to be safe.';
        if (badge) badge.className = 'status-banner result-badge safe';
        if (icon) icon.textContent = '✓';
    } else if (data.verdict === 'Suspicious') {
        verdict.textContent = 'Suspicious';
        verdict.className = 'result-status suspicious';
        message.textContent = data.description || 'This URL has suspicious characteristics. Please be cautious.';
        if (badge) badge.className = 'status-banner result-badge suspicious';
        if (icon) icon.textContent = '!';
    } else if (data.verdict === 'Phishing') {
        verdict.textContent = 'Phishing Detected!';
        verdict.className = 'result-status phishing';
        message.textContent = data.description || 'This URL is a phishing threat! Do NOT enter any personal information.';
        if (badge) badge.className = 'status-banner result-badge phishing';
        if (icon) icon.textContent = '✕';
    } else {
        verdict.textContent = 'Unknown';
        verdict.className = 'result-status unknown';
        message.textContent = data.description || 'Unable to determine URL safety.';
        if (badge) badge.className = 'status-banner result-badge unknown';
        if (icon) icon.textContent = '?';
    }
}

function adaptDetectionResponse(url, raw) {
    var verdictMap = { phishing: 'Phishing', suspicious: 'Suspicious', safe: 'Safe' };
    var verdict = verdictMap[(raw.verdict || 'safe').toLowerCase()] || 'Unknown';
    var confidence = Math.round((raw.confidence_score || 0) * 100);
    var riskPct = (raw.confidence_score || 0) * 100;
    var safetyPct = 100 - riskPct;

    var indicators = [];
    if (raw.vt_positives > 0) {
        indicators.push('Flagged by ' + raw.vt_positives + ' VirusTotal security vendor(s)');
    }
    if (raw.vt_vendors) {
        raw.vt_vendors
            .filter(function (v) { return v.category === 'malicious' || v.category === 'suspicious'; })
            .slice(0, 5)
            .forEach(function (v) {
                indicators.push(v.engine + ': ' + (v.result || v.category));
            });
    }
    if (raw.domain_age_days != null && raw.domain_age_days < 30) {
        indicators.push('Domain registered only ' + raw.domain_age_days + ' day(s) ago');
    }
    if (indicators.length === 0) {
        indicators.push('No suspicious indicators detected');
    }

    return {
        url: url,
        verdict: verdict,
        confidence: confidence,
        riskScore: confidence,
        riskPct: riskPct,
        safetyPct: safetyPct,
        description: raw.awareness_message || '',
        indicators: indicators,
        tips: verdict === 'Safe'
            ? 'Always verify the domain name before entering personal information.'
            : 'Do not enter personal information on this site. Verify the sender through a separate, trusted channel.',
        vt_positives: raw.vt_positives != null ? raw.vt_positives : null,
        vt_total_engines: raw.vt_total_engines != null ? raw.vt_total_engines : null,
        vt_vendors: raw.vt_vendors || null,
        vt_details: raw.vt_details || null
    };
}

// ===== PAGE CONTENT CHECK =====
// A URL alone can look harmless while the page itself is a fake login (for example a
// copy of the Microsoft sign-in page on a free host). So we also read the open page and
// look for: a well-known brand + a login field + a domain that is NOT that brand's own.
var PS_PAGE_BRANDS = [
    { name: 'Microsoft', words: ['microsoft', 'outlook', 'office 365', 'office365', 'onedrive'],
      official: ['microsoft.com', 'live.com', 'office.com', 'microsoftonline.com', 'outlook.com', 'office365.com', 'sharepoint.com', 'windows.com', 'bing.com', 'azure.com'] },
    { name: 'Google', words: ['google', 'gmail'], official: ['google.com', 'gmail.com', 'youtube.com', 'google.com.my', 'googleusercontent.com'] },
    { name: 'PayPal', words: ['paypal'], official: ['paypal.com'] },
    { name: 'Apple', words: ['apple id', 'icloud'], official: ['apple.com', 'icloud.com'] },
    { name: 'Facebook', words: ['facebook'], official: ['facebook.com', 'fb.com', 'messenger.com'] },
    { name: 'Instagram', words: ['instagram'], official: ['instagram.com'] },
    { name: 'Amazon', words: ['amazon'], official: ['amazon.com', 'amazon.co.uk', 'amazon.de', 'amazon.sg'] },
    { name: 'Netflix', words: ['netflix'], official: ['netflix.com'] },
    { name: 'LinkedIn', words: ['linkedin'], official: ['linkedin.com'] },
    { name: 'Maybank', words: ['maybank'], official: ['maybank2u.com.my', 'maybank.com'] },
    { name: 'CIMB', words: ['cimb'], official: ['cimbclicks.com.my', 'cimb.com.my', 'cimb.com'] },
    { name: 'Public Bank', words: ['public bank', 'publicbank'], official: ['pbebank.com', 'publicbank.com.my'] },
    { name: 'RHB', words: ['rhb'], official: ['rhbgroup.com', 'rhbbank.com.my'] },
    { name: 'HSBC', words: ['hsbc'], official: ['hsbc.com', 'hsbc.com.my'] },
    { name: 'DHL', words: ['dhl'], official: ['dhl.com'] }
];

// Runs INSIDE the web page (via chrome.scripting) - must not use anything from this file.
function psPageProbe() {
    var body = document.body ? document.body.innerText.slice(0, 5000) : '';
    var imgs = Array.prototype.map.call(document.images || [], function (i) {
        return (i.alt || '') + ' ' + (i.getAttribute('src') || '');
    }).join(' ').toLowerCase();
    var fields = Array.prototype.filter.call(document.querySelectorAll('input'), function (el) {
        var t = (el.type || 'text').toLowerCase();
        if (t === 'hidden' || t === 'submit' || t === 'button' || t === 'checkbox' || t === 'radio' || t === 'search') return false;
        var hint = ((el.name || '') + ' ' + (el.id || '') + ' ' + (el.autocomplete || '')).toLowerCase();
        return t === 'password' || t === 'email' || t === 'tel' || /user|login|mail|phone|account|pass/.test(hint);
    });
    return {
        host: location.hostname.toLowerCase(),
        title: (document.title || '').toLowerCase(),
        text: body.toLowerCase(),
        images: imgs,
        hasCredentialField: fields.length > 0,
        hasPassword: !!document.querySelector('input[type=password]'),
        isHttp: location.protocol === 'http:'
    };
}

function psReadPageSignals(callback) {
    var done = false;
    function finish(v) { if (!done) { done = true; callback(v); } }
    setTimeout(function () { finish(null); }, 1500);
    try {
        if (!chrome.scripting || !chrome.tabs) return finish(null);
        chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
            if (!tabs || !tabs[0] || !/^https?:/i.test(tabs[0].url || '')) return finish(null);
            chrome.scripting.executeScript({ target: { tabId: tabs[0].id }, func: psPageProbe }, function (res) {
                if (chrome.runtime.lastError || !res || !res[0]) return finish(null);
                finish(res[0].result || null);
            });
        });
    } catch (e) { finish(null); }
}

function psCountOccurrences(text, word) {
    var count = 0, idx = 0;
    while ((idx = text.indexOf(word, idx)) !== -1) { count++; idx += word.length; }
    return count;
}

// Only ever RAISES the risk, never lowers it.
function psApplyPageSignals(data, url, sig) {
    if (!sig || !data) return data;
    var host = '';
    try { host = new URL(url).hostname.toLowerCase(); } catch (e) { return data; }
    if (sig.host && sig.host !== host) return data; // the tab changed while scanning

    var found = null;
    for (var i = 0; i < PS_PAGE_BRANDS.length && !found; i++) {
        var b = PS_PAGE_BRANDS[i];
        var isOfficial = b.official.some(function (d) { return host === d || host.slice(-(d.length + 1)) === '.' + d; });
        if (isOfficial) continue;
        var evidence = 0;
        b.words.forEach(function (w) {
            if (sig.title.indexOf(w) !== -1) evidence += 2;
            evidence += Math.min(3, psCountOccurrences(sig.text, w));
            if (sig.images.indexOf(w) !== -1) evidence += 1;
        });
        if (evidence >= 3) found = b;
    }

    var extra = null;
    if (found && sig.hasCredentialField) {
        var weakUrl = sig.isHttp || data.confidence >= 20 || data.verdict !== 'Safe';
        if (weakUrl) {
            extra = {
                verdict: 'Phishing', risk: 92,
                text: 'This page imitates ' + found.name + ' and asks for a login, but it is not on a ' + found.name + ' domain. It is very likely a fake login page.',
                tips: 'Do NOT enter your email, phone or password. Close this page and open ' + found.name + ' by typing its address yourself.'
            };
        } else {
            extra = {
                verdict: 'Suspicious', risk: 55,
                text: 'This page mentions ' + found.name + ' and has a login field, but it is not on a ' + found.name + ' domain. Check the address carefully.',
                tips: 'Read the domain name in the address bar before typing any password.'
            };
        }
    } else if (sig.hasPassword && sig.isHttp) {
        extra = {
            verdict: 'Suspicious', risk: 45,
            text: 'This page asks for a password over an insecure (HTTP) connection.',
            tips: 'Do not type passwords on pages that are not HTTPS.'
        };
    }
    if (!extra) return data;

    var rank = { Safe: 0, Unknown: 0, Suspicious: 1, Phishing: 2 };
    if (rank[extra.verdict] <= (rank[data.verdict] || 0) && data.verdict !== 'Safe') return data;

    var risk = Math.max(extra.risk, data.confidence || 0);
    var upgraded = {};
    for (var k in data) upgraded[k] = data[k];
    upgraded.verdict = extra.verdict;
    upgraded.confidence = risk;
    upgraded.riskScore = risk;
    upgraded.riskPct = risk;
    upgraded.safetyPct = 100 - risk;
    upgraded.description = extra.text;
    upgraded.tips = extra.tips;
    upgraded.indicators = [extra.text].concat((data.indicators || []).filter(function (t) { return t !== 'No suspicious indicators detected' && t.indexOf('No risk indicators') === -1; }));
    return upgraded;
}

// Shows the URL-based result straight away, then refines it once the page check is done.
function psShowThenRefine(data, url) {
    try { updateResultDisplay(data); } catch (e) { console.error('Display error:', e); }
    psReadPageSignals(function (sig) {
        var finalData = data;
        try { finalData = psApplyPageSignals(data, url, sig); } catch (e) { console.error('Page check error:', e); }
        psFinishScan(finalData);
    });
}

function psFinishScan(data) {
    try {
        chrome.storage.local.set({ lastScanResult: data, currentScanData: data });
    } catch (error) {
        console.error('Error saving:', error);
    }
    updateResultDisplay(data);
    if (data.verdict !== 'Unknown') {
        updateStatsAfterScan(data);
        saveToHistory(data);
    }
}

function scanUrl(url) {
    var verdict = document.getElementById('verdictDisplay');
    var loading = document.getElementById('loadingState');
    var section = document.getElementById('resultSection');

    if (verdict) {
        verdict.textContent = 'Scanning...';
        verdict.className = 'result-status';
    }
    if (loading) loading.style.display = 'block';
    if (section) section.style.display = 'block';

    var apiBase = (typeof PHISHSHIELD_CONFIG !== 'undefined' && PHISHSHIELD_CONFIG.API_BASE) || 'http://127.0.0.1:8000';
    var apiKey = (typeof PHISHSHIELD_CONFIG !== 'undefined') ? PHISHSHIELD_CONFIG.API_KEY : '';
    var scanHeaders = { 'Content-Type': 'application/json' };
    if (apiKey) scanHeaders['X-PhishShield-Key'] = apiKey;

    var controller = (typeof AbortController !== 'undefined') ? new AbortController() : null;
    var timeoutId = controller ? setTimeout(function () { controller.abort(); }, 10000) : null;

    fetch(apiBase + '/api/detect', {
        method: 'POST',
        headers: scanHeaders,
        body: JSON.stringify({ url: url }),
        signal: controller ? controller.signal : undefined
    })
    .then(function(response) {
        if (timeoutId) clearTimeout(timeoutId);
        if (!response.ok) {
            throw new Error('Server error: ' + response.status);
        }
        return response.json();
    })
    .then(function(raw) {
        var data = adaptDetectionResponse(url, raw);
        if (loading) loading.style.display = 'none';
        psShowThenRefine(data, url);
    })
    .catch(function(error) {
        if (timeoutId) clearTimeout(timeoutId);
        console.warn('Backend error, using fallback:', error);
        if (loading) loading.style.display = 'none';

        var message = document.getElementById('warningMessage');
        if (message) {
            message.textContent = 'Backend offline. Using local analysis.';
        }

        var fallback = null;
        try {
            fallback = generateFallbackResult(url);
        } catch (fbErr) {
            console.error('Local scoring failed, using built-in rules:', fbErr);
            try {
                var b = psBuiltinScore(url);
                var bv = b.verdict === 'danger' ? 'Phishing' : (b.verdict === 'warn' ? 'Suspicious' : 'Safe');
                fallback = {
                    url: url, verdict: bv, confidence: b.score, riskScore: b.score, riskPct: b.score,
                    safetyPct: 100 - b.score, description: 'Backend offline. Checked with basic built-in rules only.',
                    indicators: b.reasons, tips: 'Always verify the domain name before entering personal information.'
                };
            } catch (fbErr2) {
                console.error('Built-in scoring failed too:', fbErr2);
            }
        }
        if (!fallback) {
            fallback = {
                url: url, verdict: 'Unknown', confidence: 0, riskScore: 0, riskPct: 0, safetyPct: 0,
                description: 'Backend offline and this URL could not be analysed.',
                indicators: ['No analysis available'], tips: 'Try again once the PhishShield backend is running.'
            };
        }
        try {
            psShowThenRefine(fallback, url);
        } catch (showErr) {
            psShowFatal(showErr && showErr.message ? showErr.message : String(showErr));
        }
    });
}

// Small built-in scorer, used only if lib/scanner.js could not be loaded.
function psBuiltinScore(rawUrl) {
    var reasons = [], score = 0, u;
    try { u = new URL(rawUrl); } catch (e) { return { score: 50, verdict: 'warn', reasons: ['Could not read this address'] }; }
    var host = u.hostname.toLowerCase();
    if (u.protocol !== 'https:') { score += 20; reasons.push('Connection is not HTTPS'); }
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) { score += 35; reasons.push('Uses a raw IP address instead of a domain'); }
    if (rawUrl.indexOf('@') !== -1) { score += 25; reasons.push('Contains an @ symbol that can hide the real site'); }
    if (host.indexOf('xn--') !== -1) { score += 25; reasons.push('Uses look-alike (punycode) characters'); }
    if (host.split('.').length > 4) { score += 15; reasons.push('Has many subdomains'); }
    if (/(hstn\.me|000webhostapp\.com|infinityfreeapp\.com|netlify\.app|pages\.dev|github\.io|glitch\.me|herokuapp\.com|vercel\.app|onrender\.com|web\.app|firebaseapp\.com|blogspot\.com|wixsite\.com|weebly\.com|ngrok\.io|duckdns\.org)$/.test(host)) {
        score += 30; reasons.push('Hosted on a free-hosting domain often abused for phishing');
    }
    if (host.length > 40) { score += 10; reasons.push('Very long domain name'); }
    if (/\.(tk|ml|ga|cf|gq|xyz|top|click|zip)$/.test(host)) { score += 20; reasons.push('Uses a domain ending often seen in scams'); }
    if (/(login|verify|secure|account|update|banking|paypal|wallet)/.test(host) && host.split('-').length > 2) {
        score += 20; reasons.push('Sensitive words combined with many hyphens');
    }
    if (score > 100) score = 100;
    if (reasons.length === 0) reasons.push('No risk indicators found');
    return { score: score, verdict: score >= 60 ? 'danger' : (score >= 30 ? 'warn' : 'safe'), reasons: reasons };
}

function generateFallbackResult(url) {
    if (typeof phishshieldScoreUrl !== 'function') {
        var b = psBuiltinScore(url);
        var bv = b.verdict === 'danger' ? 'Phishing' : (b.verdict === 'warn' ? 'Suspicious' : 'Safe');
        return {
            url: url,
            verdict: bv,
            confidence: b.score,
            riskScore: b.score,
            riskPct: b.score,
            safetyPct: 100 - b.score,
            description: 'Backend offline. Checked with basic built-in rules only.',
            indicators: b.reasons,
            tips: bv === 'Safe'
                ? 'Always verify the domain name before entering personal information.'
                : 'Do not enter personal information on this site until you have verified it.'
        };
    }
    var result = phishshieldScoreUrl(url);
    var verdictMap = { danger: 'Phishing', warn: 'Suspicious', safe: 'Safe' };
    var verdict = verdictMap[result.verdict] || 'Unknown';

    var tips;
    if (verdict === 'Phishing') {
        tips = 'Do NOT enter any personal information on this site.';
    } else if (verdict === 'Suspicious') {
        tips = 'A padlock icon only means the connection is encrypted — it says nothing about whether the site itself is genuine. Always read the actual domain name.';
    } else {
        tips = 'Always verify the domain name before entering personal information.';
    }

    return {
        url: url,
        verdict: verdict,
        confidence: result.score,
        riskScore: result.score,
        riskPct: result.score,
        safetyPct: 100 - result.score,
        description: verdict === 'Phishing' ? 'Multiple phishing indicators detected!'
            : verdict === 'Suspicious' ? 'This URL has suspicious characteristics. Please be cautious.'
            : 'This URL appears to be safe.',
        indicators: result.reasons || [],
        tips: tips
    };
}

function populateDetails() {
    try {
        chrome.storage.local.get(['currentScanData'], function(result) {
            var data = result && result.currentScanData ? result.currentScanData : null;

            var urlEl = document.getElementById('detailUrl');
            var verdictEl = document.getElementById('detailVerdict');
            var confEl = document.getElementById('detailConfidence');
            var riskEl = document.getElementById('detailRiskScore');
            var indEl = document.getElementById('detailIndicators');
            var tipsEl = document.getElementById('detailTips');

            if (data) {
                if (urlEl) urlEl.textContent = data.url || '-';
                if (verdictEl) {
                    verdictEl.textContent = data.verdict || '-';
                    if (data.verdict === 'Safe') {
                        verdictEl.className = 'detail-value safe';
                    } else if (data.verdict === 'Suspicious') {
                        verdictEl.className = 'detail-value suspicious';
                    } else if (data.verdict === 'Phishing') {
                        verdictEl.className = 'detail-value phishing';
                    }
                }
                if (confEl) confEl.textContent = data.confidence !== undefined ? data.confidence + '%' : '-';
                if (riskEl) riskEl.textContent = data.riskScore !== undefined ? data.riskScore + '/100' : (data.confidence !== undefined ? data.confidence + '/100' : '-');

                if (indEl) {
                    if (data.indicators && data.indicators.length > 0) {
                        var html = '';
                        for (var i = 0; i < data.indicators.length; i++) {
                            html += '<li>' + psEscapeHtml(data.indicators[i]) + '</li>';
                        }
                        indEl.innerHTML = html;
                    } else {
                        indEl.innerHTML = '<li>No suspicious indicators detected</li>';
                    }
                }

                if (tipsEl) {
                    tipsEl.textContent = data.tips || 'Always verify the domain name.';
                }
            } else {
                if (urlEl) urlEl.textContent = 'No data - scan a URL first';
                if (verdictEl) verdictEl.textContent = 'Scan a URL first';
                if (confEl) confEl.textContent = '-';
                if (riskEl) riskEl.textContent = '-';
                if (indEl) indEl.innerHTML = '<li>Scan a URL to see indicators</li>';
                if (tipsEl) tipsEl.textContent = 'Scan a URL to get security tips.';
            }
        });
    } catch (error) {
        console.error('Error populating details:', error);
    }
}

console.log('PhishShield popup ready!');