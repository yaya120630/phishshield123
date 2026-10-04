// js/blocked.js - wires up blocked.html
//
// blocked.html is an extension page (not a content script injected into a website),
// so this can talk to background.js directly via chrome.runtime.sendMessage.
 
(function () {
    var params = new URLSearchParams(window.location.search);
    // URLSearchParams.get() already decodes; decoding again can corrupt URLs
    var blockedUrl = params.get('url') || '';
 
    var reasons = [];
    try {
        reasons = JSON.parse(params.get('reasons') || '[]');
    } catch (error) {
        reasons = [];
    }
 
    // ----- Blocked URL -----
    var urlEl = document.getElementById('blocked-url');
    if (urlEl) urlEl.textContent = blockedUrl || 'Unknown URL';
 
    // ----- Reasons -----
    var listEl = document.getElementById('reasons-list');
    if (listEl) {
        var flagged = reasons.filter(function (r) {
            return r.indexOf('No risk indicators') === -1;
        });
        if (flagged.length === 0) {
            listEl.innerHTML = '<li class="empty">This URL matched PhishShield\'s highest-risk local pattern check.</li>';
        } else {
            listEl.innerHTML = flagged.map(function (r) {
                return '<li>' + escapeHtml(r) + '</li>';
            }).join('');
        }
    }
 
    // ----- Local risk score -----
    // The "score" in the link comes from lib/scanner.js, which is a SAFETY score
    // (99 = safest). Risk is therefore 100 - score. It is a rule-based number,
    // NOT a probability.
    var riskEl = document.getElementById('risk-value');
    if (riskEl) {
        var raw = params.get('score');
        var safety = (raw !== null && raw !== '') ? Number(raw) : NaN;
        if (isNaN(safety)) {
            riskEl.textContent = 'N/A';
        } else {
            var risk = Math.max(0, Math.min(100, 100 - Math.round(safety)));
            riskEl.textContent = risk + '%';
            riskEl.style.color = risk >= 50 ? 'var(--danger)' : 'var(--warn)';
        }
    }
 
    // ----- VirusTotal (asked live from the PhishShield backend) -----
    // Only the URL is sent, the same as the popup does. The page itself is never opened.
    function loadVirusTotal() {
        var vtEl = document.getElementById('vt-value');
        var subEl = document.getElementById('vt-sub');
        if (!vtEl) return;
 
        function show(value, sub, color) {
            vtEl.textContent = value;
            if (subEl) subEl.textContent = sub;
            if (color) vtEl.style.color = color;
        }
 
        if (!blockedUrl || !/^https?:\/\//i.test(blockedUrl)) {
            show('N/A', 'This address cannot be checked', null);
            return;
        }
 
        var cfg = (typeof PHISHSHIELD_CONFIG !== 'undefined') ? PHISHSHIELD_CONFIG : {};
        var apiBase = cfg.API_BASE || 'https://phishshield-api-qsuo.onrender.com';
        var headers = { 'Content-Type': 'application/json' };
        if (cfg.API_KEY) headers['X-PhishShield-Key'] = cfg.API_KEY;
 
        // The free Render server can take 30-60s to wake up.
        var controller = (typeof AbortController !== 'undefined') ? new AbortController() : null;
        var timeoutId = controller ? setTimeout(function () { controller.abort(); }, 45000) : null;
 
        show('Checking\u2026', 'contacting scan server (can take up to 45 seconds)', null);
 
        fetch(apiBase + '/api/detect', {
            method: 'POST',
            headers: headers,
            body: JSON.stringify({ url: blockedUrl }),
            signal: controller ? controller.signal : undefined
        })
        .then(function (res) {
            if (timeoutId) clearTimeout(timeoutId);
            if (!res.ok) throw new Error('Server error: ' + res.status);
            return res.json();
        })
        .then(function (data) {
            if (data && data.vt_total_engines != null) {
                var pos = data.vt_positives || 0;
                show(pos + ' / ' + data.vt_total_engines,
                     pos > 0 ? 'security vendors flagged this URL' : 'security vendors flagged this URL (none yet)',
                     pos > 0 ? 'var(--danger)' : 'var(--safe)');
            } else {
                show('No result', 'VirusTotal returned nothing for this URL', null);
            }
        })
        .catch(function () {
            if (timeoutId) clearTimeout(timeoutId);
            show('Unavailable', 'scan server offline or too slow', null);
        });
    }
    loadVirusTotal();
 
    // ----- Buttons -----
    var goBackBtn = document.getElementById('go-back-btn');
    if (goBackBtn) {
        goBackBtn.addEventListener('click', function () {
            chrome.runtime.sendMessage({ action: 'goBackFromBlocked' });
        });
    }
 
    var continueBtn = document.getElementById('continue-btn');
    if (continueBtn) {
        continueBtn.addEventListener('click', function () {
            if (!blockedUrl) return;
            continueBtn.disabled = true;
            continueBtn.textContent = 'Continuing\u2026';
            chrome.runtime.sendMessage({ action: 'continueToBlockedUrl', url: blockedUrl }, function () {
                if (chrome.runtime.lastError) {
                    continueBtn.disabled = false;
                    continueBtn.textContent = 'Continue anyway (not recommended)';
                }
            });
        });
    }
 
    function escapeHtml(str) {
        return String(str == null ? '' : str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    }
})();
 