// PhishShield Dashboard Engine & Firebase Integration — public/js/index.js

document.addEventListener('DOMContentLoaded', function () {
    console.log('PhishShield Dashboard initialized');

    // ===== 1. Firebase Initialization & Realtime Data Engine =====
    let db, auth, dbRefs;

    let checkAttempts = 0;
    const firebaseCheckInterval = setInterval(() => {
        checkAttempts++;
        if (window.firebaseDB && window.firebaseAuth && window.dbRefs) {
            clearInterval(firebaseCheckInterval);
            db = window.firebaseDB;
            auth = window.firebaseAuth;
            dbRefs = window.dbRefs;
            initFirebaseFeatures();
        } else if (checkAttempts >= 100) {
            clearInterval(firebaseCheckInterval);
            console.warn('Firebase SDK initialization timed out.');
        }
    }, 100);

    function initFirebaseFeatures() {
        const { ref, push, onValue, query, limitToLast } = dbRefs;

        // --- Authentication Listener ---
        auth.onAuthStateChanged((user) => {
            const avatarEl = document.getElementById('user-avatar');
            const greetingEl = document.getElementById('greeting-h1') || document.querySelector('h1, .greeting');

            if (user) {
                const name = user.displayName || user.email.split('@')[0];
                if (greetingEl) greetingEl.textContent = `Hello, ${name} 👋`;
                if (avatarEl) avatarEl.textContent = name.substring(0, 2).toUpperCase();
                showNotification(`Logged in as ${name}`, 'success');
            } else {
                if (greetingEl) greetingEl.textContent = 'Good morning 👋';
                if (avatarEl) avatarEl.textContent = '🔑';
            }
        });

        // Avatar Click -> Google Sign-In
        document.getElementById('user-avatar')?.addEventListener('click', () => {
            if (!auth.currentUser && window.GoogleAuthProvider && window.signInWithPopup) {
                const provider = new window.GoogleAuthProvider();
                window.signInWithPopup(auth, provider)
                    .catch(err => showNotification(`Auth Error: ${err.message}`, 'error'));
            } else if (auth.currentUser) {
                showNotification(`Currently logged in as ${auth.currentUser.email}`, 'info');
            }
        });

        // --- Live Detections Listener ---
        const detectionsRef = query(ref(db, 'detections'), limitToLast(25));
        onValue(detectionsRef, (snapshot) => {
            const data = snapshot.val();
            if (!data) {
                updateTableAndStats([]);
                return;
            }
            const detectionList = Object.keys(data).map(key => ({ id: key, ...data[key] })).reverse();
            updateTableAndStats(detectionList);
        });

        // --- Community Comments Listener ---
        onValue(ref(db, 'community_comments'), (snapshot) => {
            const comments = snapshot.val();
            const commentListEl = document.getElementById('comment-list');
            if (!commentListEl) return;

            if (!comments) {
                commentListEl.innerHTML = `<p class="empty-state">No comments posted yet.</p>`;
                return;
            }

            commentListEl.innerHTML = '';
            Object.values(comments).reverse().forEach(c => {
                const authorName = c.author || 'Community Member';
                const item = document.createElement('div');
                item.className = 'comment';
                item.innerHTML = `
                    <div class="cav" style="background:var(--accent);">${escapeHtml(authorName.substring(0, 2).toUpperCase())}</div>
                    <div class="body">
                        <div class="hd">
                            <span class="who">${escapeHtml(authorName)}</span>
                            <span class="when">${new Date(c.timestamp).toLocaleTimeString()}</span>
                        </div>
                        <div class="txt">${escapeHtml(c.text || '')}</div>
                    </div>
                `;
                commentListEl.appendChild(item);
            });
        });

        // --- Post Comment Handler ---
        const commentBtn = document.getElementById('comment-btn');
        const commentInput = document.getElementById('comment-input');

        const handlePostComment = () => {
            const text = commentInput?.value.trim();
            if (!text) return;

            const commentData = {
                text: text,
                author: auth.currentUser ? (auth.currentUser.displayName || auth.currentUser.email) : 'Community Member',
                timestamp: new Date().toISOString()
            };

            push(ref(db, 'community_comments'), commentData)
                .then(() => {
                    commentInput.value = '';
                    showNotification('Comment posted successfully!', 'success');
                })
                .catch(err => showNotification(`Failed to post: ${err.message}`, 'error'));
        };

        commentBtn?.addEventListener('click', handlePostComment);
        commentInput?.addEventListener('keyup', (e) => {
            if (e.key === 'Enter') handlePostComment();
        });
    }

    // ===== 2. Scan Engine (live API -> local heuristic fallback) =====
    // Wired OUTSIDE initFirebaseFeatures so scanning still works even if
    // Firebase is slow or fails to load. Results are saved to Firebase
    // only when it's ready.
    const scanBtn = document.getElementById('scan-btn') || document.getElementById('scanBtn') ||
        document.querySelector('.btn-scan') || document.querySelector('button:has(span)');
    const manualCheckBtn = document.getElementById('manual-check-btn');
    const urlInput = document.getElementById('url-input') || document.getElementById('urlInput') ||
        document.querySelector("input[type='text']");

    let scanInFlight = false;

    async function executeScan(presetUrl) {
        const rawUrl = (presetUrl || (urlInput ? urlInput.value : '') || '').trim();
        if (!rawUrl) {
            showNotification('Please enter a valid URL to scan.', 'warning');
            return;
        }
        if (scanInFlight) return;
        scanInFlight = true;

        const urlDisplay = document.getElementById('scannedUrl') || document.querySelector('.scanned-url');
        if (urlDisplay) urlDisplay.textContent = rawUrl;

        showNotification(`Scanning URL: ${rawUrl}...`, 'info');

        try {
            const result = await runDashboardScan(rawUrl);
            if (!result) {
                showNotification('Scan failed: backend offline and no local scanner available.', 'error');
                return;
            }

            renderScanResults(result);
            await saveDetection(result);

            if (urlInput) urlInput.value = '';
            showNotification(
                `Scan complete! Result: ${result.result.toUpperCase()}`,
                result.result === 'phishing' ? 'error' : 'success'
            );
        } finally {
            scanInFlight = false;
        }
    }

    // Calls the live API (tries /api/detect, then /detect); on any failure
    // falls back to the local heuristic. Returns a normalized result.
    async function runDashboardScan(urlToScan) {
        const cfg = (typeof PHISHSHIELD_CONFIG !== 'undefined') ? PHISHSHIELD_CONFIG : {};
        const apiBase = cfg.API_BASE || 'https://phishshield-api-qsuo.onrender.com';
        const headers = { 'Content-Type': 'application/json' };
        if (cfg.API_KEY) headers['X-PhishShield-Key'] = cfg.API_KEY;

        const endpoints = ['/api/detect', '/detect'];
        for (const path of endpoints) {
            try {
                const response = await fetch(apiBase + path, {
                    method: 'POST',
                    headers: headers,
                    body: JSON.stringify({ url: urlToScan })
                });
                if (response.status === 404) continue; // try the next path
                if (!response.ok) throw new Error(`API error: ${response.status}`);

                const data = await response.json();
                return normalizeScanResult(urlToScan, data, false);
            } catch (err) {
                console.warn(`Live API (${path}) unavailable, trying fallback:`, err);
                break;
            }
        }

        // Local heuristic fallback
        if (typeof phishshieldScoreUrl === 'function') {
            return normalizeScanResult(urlToScan, phishshieldScoreUrl(urlToScan), true);
        }
        return null;
    }

    // Accepts both the backend shape (verdict, confidence_score 0-1,
    // awareness_message, vt_*) and the local scorer shape
    // (verdict danger/warn/safe, score, reasons).
    function normalizeScanResult(url, data, isLocalHeuristic) {
        const v = String(data.verdict || '').toLowerCase();
        let score;
        if (typeof data.risk_score === 'number') score = data.risk_score;
        else if (typeof data.score === 'number') score = data.score;
        else if (typeof data.confidence_score === 'number') score = Math.round(data.confidence_score * 100);
        else score = 0;
        score = Math.max(0, Math.min(100, Math.round(score)));

        let status;
        if (v === 'phishing' || v === 'danger') status = 'phishing';
        else if (v === 'suspicious' || v === 'warn') status = 'suspicious';
        else if (v === 'safe') status = 'safe';
        else status = score > 60 ? 'phishing' : (score > 30 ? 'suspicious' : 'safe');

        const message = data.message || data.awareness_message ||
            (Array.isArray(data.reasons) && data.reasons.length ? data.reasons.join(', ') : 'Scan complete.');

        const hasVt = !isLocalHeuristic && data.vt_positives !== null && data.vt_positives !== undefined;

        return {
            url: url,
            riskScore: score,
            result: status,
            message: message,
            isLocalHeuristic: isLocalHeuristic,
            hasVtData: hasVt,
            vt_positives: hasVt ? data.vt_positives : null,
            vt_total_engines: hasVt ? (data.vt_total_engines || null) : null
        };
    }

    // Updates the scan-result widgets (only the ones that exist in your HTML).
    function renderScanResults(result) {
        const scoreEl = document.getElementById('riskScore') || document.querySelector('.risk-score');
        const verdictEl = document.getElementById('verdictText') || document.querySelector('.verdict-text');
        const messageEl = document.getElementById('scanMessage') || document.querySelector('.scan-message');
        const vendorChecksHeader = document.querySelector('.vendor-checks-header') || document.getElementById('vendorChecks');
        const infoBanner = document.querySelector('.virustotal-info-banner') || document.querySelector('.info-banner');

        if (scoreEl) scoreEl.textContent = `${result.riskScore}%`;
        if (verdictEl) {
            verdictEl.textContent = result.result.toUpperCase();
            verdictEl.className = `verdict-text ${result.result}`;
        }
        if (messageEl) messageEl.textContent = result.message;

        if (vendorChecksHeader) {
            vendorChecksHeader.textContent = result.hasVtData
                ? `${result.vt_total_engines || 90} checks · VirusTotal API`
                : '1 checks · local heuristic';
        }
        if (infoBanner) infoBanner.style.display = result.hasVtData ? 'none' : 'block';
    }

    // Saves the scan to Firebase if it's ready (the live listener then
    // refreshes the table and "Latest Detection" card automatically).
    function saveDetection(result) {
        if (!db || !dbRefs || !dbRefs.push || !dbRefs.ref) {
            console.warn('Firebase not ready; scan shown locally but not saved.');
            return Promise.resolve();
        }
        const newScan = {
            url: result.url,
            riskScore: result.riskScore,
            result: result.result,
            message: result.message,
            source: result.isLocalHeuristic ? 'local' : 'api',
            vt_positives: result.vt_positives,
            vt_total_engines: result.vt_total_engines,
            timestamp: new Date().toISOString(),
            user: auth && auth.currentUser ? auth.currentUser.email : 'Anonymous'
        };
        return dbRefs.push(dbRefs.ref(db, 'detections'), newScan)
            .catch(err => showNotification(`Saving scan failed: ${err.message}`, 'error'));
    }

    scanBtn?.addEventListener('click', () => executeScan());
    manualCheckBtn?.addEventListener('click', () => {
        urlInput?.focus();
        if (urlInput?.value.trim()) executeScan();
    });

    // Auto-scan a URL passed in the query string (e.g. index.html?url=...)
    const targetUrl = new URLSearchParams(window.location.search).get('url');
    if (targetUrl) {
        if (urlInput) urlInput.value = targetUrl;
        executeScan(targetUrl);
    }

    // ===== 3. Render Utilities =====
    function updateTableAndStats(detections) {
        const tableBody = document.getElementById('detections-table-body');
        const statTotal = document.getElementById('stat-total');
        const statSafe = document.getElementById('stat-safe');
        const statSuspicious = document.getElementById('stat-suspicious');
        const statPhishing = document.getElementById('stat-phishing');

        const latestTimeEl = document.getElementById('latest-time');
        const latestContentEl = document.getElementById('latest-content');

        let safeCount = 0, suspCount = 0, phishCount = 0;

        if (tableBody) tableBody.innerHTML = '';

        if (detections.length === 0) {
            if (tableBody) {
                tableBody.innerHTML = `<tr><td colspan="4" class="empty-state">No scans recorded yet.</td></tr>`;
            }
            if (latestTimeEl) latestTimeEl.textContent = '';
            if (latestContentEl) {
                latestContentEl.innerHTML = `<p class="empty-state">No scans yet — paste a URL above and click Scan URL to test.</p>`;
            }
            if (statTotal) statTotal.textContent = 0;
            if (statSafe) statSafe.textContent = 0;
            if (statSuspicious) statSuspicious.textContent = 0;
            if (statPhishing) statPhishing.textContent = 0;
            return;
        }

        detections.forEach((item, index) => {
            if (item.result === 'safe') safeCount++;
            else if (item.result === 'suspicious') suspCount++;
            else if (item.result === 'phishing') phishCount++;

            // Update Primary "Latest Detection" Card
            if (index === 0 && latestContentEl) {
                if (latestTimeEl) latestTimeEl.textContent = new Date(item.timestamp).toLocaleTimeString();

                const bgStyle = item.result === 'phishing' ? 'var(--danger-bg)' : (item.result === 'suspicious' ? 'var(--warning-bg)' : 'var(--safe-bg)');
                const colorStyle = item.result === 'phishing' ? 'var(--danger)' : (item.result === 'suspicious' ? 'var(--warning)' : 'var(--safe)');
                const analysis = item.message ||
                    'Automated heuristic analysis evaluated host pattern matching, SSL indicators, and domain trust heuristics.';

                latestContentEl.innerHTML = `
                    <div class="report-grid">
                        <div class="ring-wrap">
                            <div class="ring">
                                <div class="ring-txt">
                                    <span class="n">${escapeHtml(item.riskScore)}</span>
                                    <span class="d">RISK SCORE</span>
                                </div>
                            </div>
                            <span class="verdict" style="background:${bgStyle}; color:${colorStyle}">
                                ${escapeHtml(String(item.result).toUpperCase())}
                            </span>
                        </div>
                        <div class="url-meta">
                            <div class="name">${escapeHtml(item.url)}</div>
                            <div class="ai-box">
                                <span class="ai-tag">PhishShield AI Analysis</span>
                                ${escapeHtml(analysis)}
                            </div>
                        </div>
                    </div>
                `;
            }

            // Append Row to Recent Detections Table
            if (tableBody) {
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td class="mono">${escapeHtml(item.url)}</td>
                    <td class="mono">${escapeHtml(item.riskScore)}/100</td>
                    <td class="mono">${new Date(item.timestamp).toLocaleTimeString()}</td>
                    <td>
                        <span class="pill ${escapeHtml(item.result)}">
                            <span class="icn"></span>${escapeHtml(String(item.result).toUpperCase())}
                        </span>
                    </td>
                `;
                tableBody.appendChild(row);
            }
        });

        if (statTotal) statTotal.textContent = detections.length;
        if (statSafe) statSafe.textContent = safeCount;
        if (statSuspicious) statSuspicious.textContent = suspCount;
        if (statPhishing) statPhishing.textContent = phishCount;
    }

    function escapeHtml(str) {
        if (str === null || str === undefined) return '';
        return String(str).replace(/[&<>"']/g, (m) => ({
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#039;'
        }[m]));
    }

    // ===== 4. Navigation & Tab Switching =====
    const navItems = document.querySelectorAll('.nav-item');
    navItems.forEach(item => {
        item.addEventListener('click', function () {
            navItems.forEach(n => n.classList.remove('active'));
            this.classList.add('active');

            const targetId = this.getAttribute('data-target');
            const targetEl = document.getElementById(targetId);
            if (targetEl) {
                targetEl.scrollIntoView({ behavior: 'smooth' });
                showNotification(`Navigated to: ${this.textContent.trim()}`);
            }
        });
    });

    // ===== 5. Quick Actions & Toolbar Controls =====
    const themeBtn = document.getElementById('themeToggle');
    themeBtn?.addEventListener('click', () => {
        document.body.classList.toggle('dark');
        const isDark = document.body.classList.contains('dark');
        themeBtn.textContent = isDark ? '☀️' : '🌙';
        showNotification(`Theme set to ${isDark ? 'Dark Mode' : 'Light Mode'}`);
    });

    // ===== 6. Toast Notification System =====
    function showNotification(message, type = 'info') {
        const existing = document.querySelector('.notification-toast');
        if (existing) existing.remove();

        const colors = {
            info: '#4b7cf7',
            success: '#1FAE7A',
            warning: '#E08A1E',
            error: '#E0503E'
        };

        const toast = document.createElement('div');
        toast.className = 'notification-toast';
        toast.innerHTML = `<span>${escapeHtml(message)}</span>`;
        toast.style.cssText = `
            position: fixed;
            bottom: 24px;
            right: 24px;
            background: var(--panel, #1a2332);
            border-left: 4px solid ${colors[type] || colors.info};
            border-radius: 10px;
            padding: 14px 20px;
            color: var(--text, #e8edf5);
            font-size: 13.5px;
            font-weight: 600;
            z-index: 1000;
            display: flex;
            align-items: center;
            box-shadow: 0 10px 30px rgba(0,0,0,0.3);
            animation: slideUp 0.3s ease;
            max-width: 420px;
        `;

        document.body.appendChild(toast);

        setTimeout(() => {
            toast.style.animation = 'slideDown 0.3s ease';
            setTimeout(() => toast.remove(), 300);
        }, 3200);
    }

    // Dynamic Animation Styles
    const style = document.createElement('style');
    style.textContent = `
        @keyframes slideUp {
            from { transform: translateY(40px); opacity: 0; }
            to { transform: translateY(0); opacity: 1; }
        }
        @keyframes slideDown {
            from { transform: translateY(0); opacity: 1; }
            to { transform: translateY(40px); opacity: 0; }
        }
    `;
    document.head.appendChild(style);
});