// js/blocked.js — wires up blocked.html
//
// blocked.html has no chrome.* API access issues (it's an extension page,
// not a content script injected into a website), so this can talk to
// background.js directly via chrome.runtime.sendMessage.

(function () {
    var params = new URLSearchParams(window.location.search);
    var rawUrl = params.get('url') || '';
    var blockedUrl = rawUrl;
    
    try {
        blockedUrl = decodeURIComponent(rawUrl);
    } catch (e) {
        blockedUrl = rawUrl;
    }

    var reasons = [];
    try {
        reasons = JSON.parse(params.get('reasons') || '[]');
    } catch (error) {
        reasons = [];
    }

    var urlEl = document.getElementById('blocked-url');
    if (urlEl) urlEl.textContent = blockedUrl || 'Unknown URL';

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
            continueBtn.textContent = 'Continuing…';
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