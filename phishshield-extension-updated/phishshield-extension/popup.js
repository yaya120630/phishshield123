console.log('PhishShield popup loading...');

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
                chrome.tabs.create({ url: chrome.runtime.getURL('dashboard.html') });
            };
        }
    });

    var rescanBtn = document.getElementById('rescanBtn');
    if (rescanBtn) {
        rescanBtn.onclick = function() {
            var el = document.getElementById('detectedUrl');
            if (el && el.textContent) {
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

            // Same entry shape as background.js's scanUrl() so the mini
            // dashboard and full dashboard show identical detail (real VT
            // vendor breakdown + Gemini message) regardless of whether the
            // scan came from auto-scan, the popup, or the full dashboard's
            // scan box.
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

// Formats a 0-100 score for display as a plain whole-number percentage
// (no decimal points, e.g. "97" not "97.42").
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
    // Never claim a site is 100% safe — no scan is a perfect guarantee,
    // so a "safe" result tops out at 99%.
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
        verdict.className = 'result-status';
        message.textContent = data.description || 'Unable to determine URL safety.';
    }
}

// Converts the backend's /api/detect response shape:
//   { url, verdict: 'phishing'|'suspicious'|'safe', confidence_score (0-1),
//     vt_positives, domain_age_days, awareness_message, vt_total_engines, vt_vendors }
// into the shape this popup's UI code expects:
//   { url, verdict: 'Phishing'|'Suspicious'|'Safe', confidence (0-100),
//     riskScore, description, indicators: [], tips }
function adaptDetectionResponse(url, raw) {
    var verdictMap = { phishing: 'Phishing', suspicious: 'Suspicious', safe: 'Safe' };
    var verdict = verdictMap[(raw.verdict || 'safe').toLowerCase()] || 'Unknown';
    var confidence = Math.round((raw.confidence_score || 0) * 100);
    // Full decimal precision (not rounded to a whole %) so a near-perfect
    // safe result can render as "99.99% Safe" instead of "100% Safe" or
    // "99% Safe" — matches the resolution of the backend's own score.
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
        // Carried through so saveToHistory() can persist real VT/AI data —
        // otherwise the mini/full dashboard only ever show the generic
        // local heuristic for scans made from the popup's Scanner tab.
        vt_positives: raw.vt_positives != null ? raw.vt_positives : null,
        vt_total_engines: raw.vt_total_engines != null ? raw.vt_total_engines : null,
        vt_vendors: raw.vt_vendors || null,
        vt_details: raw.vt_details || null
    };
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

    fetch(apiBase + '/api/detect', {
        method: 'POST',
        headers: scanHeaders,
        body: JSON.stringify({ url: url })
    })
    .then(function(response) {
        if (!response.ok) {
            throw new Error('Server error: ' + response.status);
        }
        return response.json();
    })
    .then(function(raw) {
        var data = adaptDetectionResponse(url, raw);
        if (loading) loading.style.display = 'none';
        try {
            chrome.storage.local.set({ lastScanResult: data, currentScanData: data });
        } catch (error) {
            console.error('Error saving:', error);
        }
        updateResultDisplay(data);
        updateStatsAfterScan(data);
        saveToHistory(data);
    })
    .catch(function(error) {
        console.warn('Backend error, using fallback:', error);
        if (loading) loading.style.display = 'none';

        var message = document.getElementById('warningMessage');
        if (message) {
            message.textContent = 'Backend offline. Using local analysis.';
        }

        var fallback = generateFallbackResult(url);
        try {
            chrome.storage.local.set({ lastScanResult: fallback, currentScanData: fallback });
        } catch (err) {
            console.error('Error saving fallback:', err);
        }
        updateResultDisplay(fallback);
        updateStatsAfterScan(fallback);
        saveToHistory(fallback);
    });
}

// Backend unreachable — fall back to the SAME shared heuristic scorer
// used by the dashboard and background worker (lib/lib/scanner.js), so
// the popup can't silently disagree with the rest of the extension.
//
// Both `confidence` and `riskScore` intentionally hold the SAME number:
// throughout this app that number always means "how risky this URL is"
// (0 = safe, 100 = phishing) — never "how sure we are of the verdict".
// A prior version of this function computed a separate, inverted
// "confidence in the verdict" value and then mislabeled it as riskScore,
// which could show something like "Safe" next to "Risk score: 90/100".
function generateFallbackResult(url) {
    if (typeof phishshieldScoreUrl !== 'function') {
        // Shared scanner failed to load — degrade honestly instead of
        // guessing, so the UI never shows an unfounded verdict.
        return {
            url: url,
            verdict: 'Unknown',
            confidence: 0,
            riskScore: 0,
            description: 'Backend offline and local scanner unavailable — could not analyze this URL.',
            indicators: ['No analysis available'],
            tips: 'Try again once the PhishShield backend is running.'
        };
    }

    var result = phishshieldScoreUrl(url); // { score: 0-100, verdict: 'danger'|'warn'|'safe', reasons: [] }
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
        indicators: result.reasons,
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
                if (confEl) confEl.textContent = data.confidence ? data.confidence + '%' : '-';
                if (riskEl) riskEl.textContent = data.riskScore ? data.riskScore + '/100' : (data.confidence ? data.confidence + '/100' : '-');

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