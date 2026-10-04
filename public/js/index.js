// public/js/index.js - Render Dashboard & Sync chrome.storage with VirusTotal output

document.addEventListener('DOMContentLoaded', function () {
    console.log('PhishShield Dashboard initialized');

    // ===== 1. Read Chrome Storage Data & Realtime Updates =====
    function loadStorageDetections() {
        if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
            chrome.storage.local.get({ detections: [] }, (res) => {
                updateTableAndStats(res.detections || []);
            });
        }
    }

    // Load saved detections when page opens
    loadStorageDetections();

    // Listen for incoming live auto-scans from background.js
    if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.onChanged) {
        chrome.storage.onChanged.addListener((changes, area) => {
            if (area === 'local' && changes.detections) {
                updateTableAndStats(changes.detections.newValue || []);
            }
        });
    }

    // ===== 2. Manual Scan Engine =====
    const scanBtn = document.getElementById('scan-btn') || document.getElementById('scanBtn') || document.querySelector('.btn-scan');
    const urlInput = document.getElementById('url-input') || document.getElementById('urlInput') || document.querySelector("input[type='text']");
    let scanInFlight = false;

async function executeScan(presetUrl) {
        const rawUrl = (presetUrl || (urlInput ? urlInput.value : '') || '').trim();
        if (!rawUrl) {
            showNotification('Please enter a valid URL to scan.', 'warning');
            return;
        }
        if (scanInFlight) return;
        scanInFlight = true;

        showNotification(`Scanning URL: ${rawUrl}...`, 'info');

        try {
            const result = await runDashboardScan(rawUrl);
            if (result) {
                renderScanResults(result);

                // Save to chrome.storage.local so dashboard cards and table update
                if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
                    chrome.storage.local.get({ detections: [] }, (res) => {
                        const updated = [result, ...(res.detections || [])].slice(0, 100);
                        chrome.storage.local.set({ detections: updated }, () => {
                            updateTableAndStats(updated);
                        });
                    });
                }

                showNotification(
                    `Scan complete! Verdict: ${result.result.toUpperCase()}`,
                    result.result === 'phishing' ? 'error' : (result.result === 'suspicious' ? 'warning' : 'success')
                );
            }
        } catch (err) {
            console.error('Scan execution error:', err);
            showNotification('An error occurred while executing the scan.', 'error');
        } finally {
            scanInFlight = false;
        }
    }

    async function runDashboardScan(urlToScan) {
        const cfg = (typeof PHISHSHIELD_CONFIG !== 'undefined') ? PHISHSHIELD_CONFIG : {};
        const apiBase = cfg.API_BASE || 'https://phishshield-api-qsuo.onrender.com';
        const headers = { 'Content-Type': 'application/json', 'Accept': 'application/json' };
        if (cfg.API_KEY) headers['X-PhishShield-Key'] = cfg.API_KEY;

        const endpoints = ['/detect', '/api/detect'];

        for (const path of endpoints) {
            try {
                console.log(`Connecting to Render API endpoint: ${apiBase}${path}`);

                // Set a 25-second timeout controller for Render cold starts
                const controller = new AbortController();
                const timeoutId = setTimeout(() => controller.abort(), 25000);

                const response = await fetch(apiBase + path, {
                    method: 'POST',
                    headers: headers,
                    body: JSON.stringify({ url: urlToScan }),
                    signal: controller.signal
                });
                clearTimeout(timeoutId);

                if (response.status === 404) {
                    console.warn(`Route ${path} returned 404, checking fallback route...`);
                    continue;
                }

                if (!response.ok) throw new Error(`HTTP ${response.status}: ${response.statusText}`);

                const data = await response.json();
                console.log('✅ Live Render API Response:', data);
                return normalizeScanResult(urlToScan, data, false);

            } catch (err) {
                if (err.name === 'AbortError') {
                    console.warn(`Request to ${path} timed out while waiting for Render to wake up.`);
                } else {
                    console.warn(`Attempt on ${path} failed:`, err.message);
                }
            }
        }

        console.warn('⚠️ Render API unreachable or sleeping. Falling back to client local heuristic scanner.');
        if (typeof phishshieldScoreUrl === 'function') {
            return normalizeScanResult(urlToScan, phishshieldScoreUrl(urlToScan), true);
        }
        return null;
    }

    function normalizeScanResult(url, data, isLocalHeuristic) {
        const v = String(data.verdict || '').toLowerCase();
        let score = typeof data.riskScore === 'number' ? data.riskScore : (typeof data.confidence_score === 'number' ? Math.round(data.confidence_score * 100) : 0);

        let status = v === 'phishing' || v === 'danger' ? 'phishing' : (v === 'suspicious' || v === 'warn' ? 'suspicious' : 'safe');
        const hasVt = !isLocalHeuristic && (data.vt_enabled || data.vt_positives !== null);

        return {
            url: url,
            riskScore: score,
            result: status,
            message: data.message || data.awareness_message || 'Scan complete.',
            hasVtData: hasVt,
            vt_positives: hasVt ? (data.vt_positives || 0) : null,
            vt_total_engines: hasVt ? (data.vt_total_engines || 90) : null,
            vt_vendors: data.vt_vendors || data.vendors || [],
            domain_age_days: data.domain_age_days !== undefined ? data.domain_age_days : null
        };
    }

    // ===== 3. Render VirusTotal & UI Output =====
    function renderScanResults(result) {
        const scoreEl = document.getElementById('riskScore') || document.querySelector('.risk-score');
        const verdictEl = document.getElementById('verdictText') || document.querySelector('.verdict-text');
        const messageEl = document.getElementById('scanMessage') || document.querySelector('.scan-message');
        const vendorCardBody = document.querySelector('#vendor-analysis .card-body, .vendor-card-body');
        const detailsContent = document.querySelector('#details-content, #details .card-body');

        if (scoreEl) scoreEl.textContent = `${result.riskScore}%`;
        if (verdictEl) {
            verdictEl.textContent = result.result.toUpperCase();
            verdictEl.className = `verdict-text ${result.result}`;
        }
        if (messageEl) messageEl.textContent = result.message;

        // Render VirusTotal Security Vendor Card
        if (vendorCardBody) {
            const positives = result.vt_positives !== null ? result.vt_positives : 0;
            const total = result.vt_total_engines || 90;

            let vendorListHtml = '';
            if (result.hasVtData && Array.isArray(result.vt_vendors) && result.vt_vendors.length > 0) {
                const flagged = result.vt_vendors.filter(v => v.category === 'malicious' || v.category === 'suspicious').slice(0, 5);
                if (flagged.length > 0) {
                    vendorListHtml = `<ul style="margin-top: 8px; padding-left: 20px; font-size: 0.875rem; color: #ef4444;">` +
                        flagged.map(v => `<li><strong>${escapeHtml(v.engine)}:</strong> ${escapeHtml(v.result || v.category)}</li>`).join('') +
                        `</ul>`;
                }
            }

            vendorCardBody.innerHTML = `
                <div style="padding: 12px 0;">
                    <p style="font-size: 1.15rem; font-weight: 700; margin-bottom: 4px;">
                        ${positives} / ${total} security vendors flagged this site
                    </p>
                    <p style="color: #6b7280; font-size: 0.875rem;">
                        ${result.hasVtData ? 'Live threat analysis retrieved from VirusTotal API v3.' : 'Evaluated using local browser heuristic engine.'}
                    </p>
                    ${vendorListHtml}
                </div>
            `;
        }

        // Render Domain Details
        if (detailsContent) {
            const ageStr = result.domain_age_days !== null ? `${result.domain_age_days} days` : 'N/A';
            detailsContent.innerHTML = `
                <div style="padding: 12px 0;">
                    <p style="margin-bottom: 6px;"><strong>Analysis Message:</strong> ${escapeHtml(result.message)}</p>
                    <p style="margin-bottom: 6px;"><strong>Domain Age:</strong> ${escapeHtml(ageStr)}</p>
                    <p style="margin-bottom: 0;"><strong>Detection Source:</strong> ${result.hasVtData ? 'Render FastAPI + VirusTotal API v3' : 'Client Local Scanner'}</p>
                </div>
            `;
        }
    }

    function updateTableAndStats(detections) {
        const tableBody = document.getElementById('detections-table-body');
        const statTotal = document.getElementById('stat-total');
        const statSafe = document.getElementById('stat-safe');
        const statSuspicious = document.getElementById('stat-suspicious');
        const statPhishing = document.getElementById('stat-phishing');

        let safeCount = 0, suspCount = 0, phishCount = 0;

        if (tableBody) tableBody.innerHTML = '';

        if (!detections || detections.length === 0) {
            if (tableBody) tableBody.innerHTML = `<tr><td colspan="4" class="empty-state">No scans recorded yet.</td></tr>`;
            if (statTotal) statTotal.textContent = 0;
            if (statSafe) statSafe.textContent = 0;
            if (statSuspicious) statSuspicious.textContent = 0;
            if (statPhishing) statPhishing.textContent = 0;
            return;
        }

        detections.forEach((item, index) => {
            const itemResult = String(item.result || item.verdict || 'safe').toLowerCase();

            if (itemResult === 'safe') safeCount++;
            else if (itemResult === 'suspicious' || itemResult === 'warn') suspCount++;
            else if (itemResult === 'phishing' || itemResult === 'danger') phishCount++;

            if (index === 0) {
                renderScanResults(item);
            }

            if (tableBody) {
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td class="mono">${escapeHtml(item.url)}</td>
                    <td class="mono">${escapeHtml(item.riskScore !== undefined ? item.riskScore : item.risk_score || 0)}/100</td>
                    <td class="mono">${item.timestamp ? new Date(item.timestamp).toLocaleTimeString() : 'Recently'}</td>
                    <td>
                        <span class="pill ${escapeHtml(itemResult)}">
                            ${escapeHtml(itemResult.toUpperCase())}
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
        if (!str) return '';
        return String(str).replace(/[&<>"']/g, (m) => ({
            '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;'
        }[m]));
    }

    scanBtn?.addEventListener('click', () => executeScan());
});

function showNotification(message, type = 'info') {
    console.log(`[${type.toUpperCase()}] ${message}`);
}