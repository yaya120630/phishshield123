// ===== chrome-shim (merged here) =====
// Lets this dashboard run as a normal website (e.g. Firebase hosting), where the
// `chrome` object does not exist. Does nothing inside the real extension.
// chrome-shim.js - lets the dashboard (index.html) run as a normal website,
// e.g. after "firebase deploy". On a website there is no `chrome` object, so
// api.js / theme.js crashed on their first chrome.storage call and none of the
// buttons worked. This file only activates when chrome.storage is missing, so
// inside the real extension it does nothing.
(function () {
  if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) return;

  var PREFIX = 'ps_';
  var listeners = [];

  function readKey(k) {
    try {
      var raw = localStorage.getItem(PREFIX + k);
      return raw == null ? undefined : JSON.parse(raw);
    } catch (e) { return undefined; }
  }
  function writeKey(k, v) {
    try { localStorage.setItem(PREFIX + k, JSON.stringify(v)); } catch (e) {}
  }

  var storageLocal = {
    get: function (keys, cb) {
      var out = {}, list;
      if (keys == null) list = [];
      else if (typeof keys === 'string') list = [keys];
      else if (Array.isArray(keys)) list = keys;
      else { list = Object.keys(keys); out = Object.assign({}, keys); }
      list.forEach(function (k) { var v = readKey(k); if (v !== undefined) out[k] = v; });
      if (cb) setTimeout(function () { cb(out); }, 0);
    },
    set: function (obj, cb) {
      var changes = {};
      Object.keys(obj).forEach(function (k) {
        changes[k] = { oldValue: readKey(k), newValue: obj[k] };
        writeKey(k, obj[k]);
      });
      setTimeout(function () {
        listeners.forEach(function (fn) { try { fn(changes, 'local'); } catch (e) {} });
        if (cb) cb();
      }, 0);
    }
  };

  // Scan through the backend directly (there is no background.js on a website)
  function scanViaBackend(url, respond) {
    var cfg = window.PHISHSHIELD_CONFIG || {};
    var base = cfg.API_BASE || 'https://phishshield-api-qsuo.onrender.com';
    var headers = { 'Content-Type': 'application/json' };
    if (cfg.API_KEY) headers['X-PhishShield-Key'] = cfg.API_KEY;

    // Render's free tier sleeps and can take 30-60s to wake on the first
    // request, so allow 60s before falling back to the local heuristic.
    var ctrl = (typeof AbortController !== 'undefined') ? new AbortController() : null;
    var t = ctrl ? setTimeout(function () { ctrl.abort(); }, 60000) : null;

    fetch(base + '/api/detect', {
      method: 'POST', headers: headers, body: JSON.stringify({ url: url }),
      signal: ctrl ? ctrl.signal : undefined
    })
    .then(function (r) { if (t) clearTimeout(t); if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); })
    .then(function (raw) {
      var status = String(raw.verdict || 'safe').toLowerCase();
      var pct = Math.round((raw.confidence_score || 0) * 100);
      storageLocal.get(['history', 'stats'], function (res) {
        var history = res.history || [];
        var stats = res.stats || { scanned: 0, threats: 0, safe: 0 };
        history.unshift({
          url: url, status: status, confidence: pct, risk_score: pct,
          message: raw.awareness_message || '', timestamp: new Date().toISOString(),
          vt_positives: raw.vt_positives != null ? raw.vt_positives : null,
          vt_total_engines: raw.vt_total_engines != null ? raw.vt_total_engines : null,
          vt_vendors: raw.vt_vendors || null, vt_details: raw.vt_details || null,
          vt_error: raw.vt_error || null
        });
        if (history.length > 200) history = history.slice(0, 200);
        stats.scanned = (stats.scanned || 0) + 1;
        if (status === 'safe') stats.safe = (stats.safe || 0) + 1; else stats.threats = (stats.threats || 0) + 1;
        storageLocal.set({ history: history, stats: stats }, function () { respond({ status: status }); });
      });
    })
    .catch(function () { if (t) clearTimeout(t); respond(undefined); }); // api.js then scores it locally
  }

  window.chrome = {
    storage: {
      local: storageLocal,
      onChanged: { addListener: function (fn) { listeners.push(fn); } }
    },
    runtime: {
      sendMessage: function (msg, cb) {
        cb = cb || function () {};
        if (msg && msg.action === 'scanUrl') scanViaBackend(msg.url, cb);
        else setTimeout(function () { cb(undefined); }, 0);
      },
      getURL: function (p) { return p; }
    },
    tabs: { create: function (o) { window.open(o.url, '_blank'); } }
  };
})();

// ===== end chrome-shim =====

// js/api.js
//
// This connects the full dashboard to real data.
// All three surfaces (background.js scanner, popup.js mini-dashboard, and this full dashboard)
// read and write the SAME chrome.storage.local keys ('history', 'stats').
// chrome.storage.onChanged fires in every open extension view the instant any one of them writes.

var PS_VERDICT_COLORS = {
    danger: { fg: '#E0503E', bg: '#FCEAE7' },
    warn:   { fg: '#E08A1E', bg: '#FDF2E0' },
    safe:   { fg: '#1FAE7A', bg: '#E7F9F1' }
};

// A reason is a FLAG unless it is a "no risk" all-clear line. Matches
// "No risk indicators", "No local risk indicators" and "No strong risk
// indicators" so those never render red as Flagged.
var PS_NO_RISK_RE = /^no (local |strong )?risk indicators/i;
function psReasonIsFlag(reason) {
    return !PS_NO_RISK_RE.test(String(reason || '').trim());
}

var psState = {
    history: [],
    stats: { scanned: 0, threats: 0, safe: 0 },
    community: {},
    selectedIndex: 0
};

document.addEventListener('DOMContentLoaded', function () {
    loadAll();
    wireScanBox();
    wireCommunity();
    wireNotificationBell();
    showExtensionStatus();

    // ===== LIVE SYNC =====
    chrome.storage.onChanged.addListener(function (changes, area) {
        if (area !== 'local') return;

        if (changes.history || changes.stats) {
            loadAll();
        }
        if (changes.community) {
            psState.community = (changes.community.newValue) || {};
            renderCommunity();
        }
    });
});

// ===== NOTIFICATIONS BELL =====
var NOTIF_SEEN_KEY = 'lastSeenThreatTs';

function wireNotificationBell() {
    var bell = document.getElementById('notif-bell');
    var dropdown = document.getElementById('notif-dropdown');
    if (!bell || !dropdown) return;

    bell.addEventListener('click', function (e) {
        e.stopPropagation();
        var isOpen = dropdown.classList.contains('open');
        if (isOpen) {
            dropdown.classList.remove('open');
            return;
        }
        renderNotifDropdown();
        dropdown.classList.add('open');
        markThreatsSeen();
    });

    document.addEventListener('click', function (e) {
        if (!dropdown.classList.contains('open')) return;
        var wrap = document.getElementById('notif-wrap');
        if (wrap && !wrap.contains(e.target)) {
            dropdown.classList.remove('open');
        }
    });
}

function getThreatEntries() {
    return psState.history.filter(function (e) {
        return e.status === 'phishing' || e.status === 'suspicious';
    });
}

function updateNotifBadge() {
    var badge = document.getElementById('notif-badge');
    if (!badge) return;
    chrome.storage.local.get([NOTIF_SEEN_KEY], function (result) {
        var lastSeen = result[NOTIF_SEEN_KEY] ? new Date(result[NOTIF_SEEN_KEY]).getTime() : 0;
        var unseen = getThreatEntries().filter(function (e) {
            return e.timestamp && new Date(e.timestamp).getTime() > lastSeen;
        });
        if (unseen.length > 0) {
            badge.textContent = unseen.length > 9 ? '9+' : String(unseen.length);
            badge.style.display = 'flex';
        } else {
            badge.style.display = 'none';
        }
    });
}

function markThreatsSeen() {
    var threats = getThreatEntries();
    var latestTs = threats.length ? (threats[0].timestamp || new Date().toISOString()) : new Date().toISOString();
    var toSave = {};
    toSave[NOTIF_SEEN_KEY] = latestTs;
    chrome.storage.local.set(toSave, updateNotifBadge);
}

function renderNotifDropdown() {
    var dropdown = document.getElementById('notif-dropdown');
    if (!dropdown) return;
    var threats = getThreatEntries().slice(0, 8);

    if (threats.length === 0) {
        dropdown.innerHTML = '<div class="notif-hd">Recent threats</div><p class="empty-state">No threats detected yet.</p>';
        return;
    }

    var itemsHtml = threats.map(function (raw) {
        var entry = psNormalize(raw);
        var idx = psState.history.indexOf(raw);
        return '<div class="notif-item" data-index="' + idx + '">' +
            '<span class="notif-dot ' + entry.verdictClass + '"></span>' +
            '<div class="notif-body">' +
            '<div class="notif-url">' + escapeHtml(truncate(entry.url, 42)) + '</div>' +
            '<div class="notif-meta">' + entry.verdictLabel + ' · ' + psFormatTime(entry.timestamp) + '</div>' +
            '</div></div>';
    }).join('');

    dropdown.innerHTML = '<div class="notif-hd">Recent threats (' + threats.length + ')</div>' + itemsHtml;

    Array.prototype.forEach.call(dropdown.querySelectorAll('.notif-item'), function (item) {
        item.addEventListener('click', function () {
            psState.selectedIndex = parseInt(item.getAttribute('data-index'), 10);
            renderSelected();
            renderTable();
            dropdown.classList.remove('open');
            var panel = document.querySelector('.panel');
            if (panel) panel.scrollIntoView({ behavior: 'smooth', block: 'start' });
        });
    });
}

// ===== LOAD =====
function loadAll() {
    chrome.storage.local.get(['history', 'stats', 'community'], function (result) {
        psState.history = result.history || [];
        psState.stats = result.stats || computeStatsFromHistory(psState.history);
        psState.community = result.community || {};

        if (psState.selectedIndex >= psState.history.length) {
            psState.selectedIndex = 0;
        }

        renderStats();
        renderSelected();
        renderTable();
        renderCommunity();
        updateNotifBadge();
    });
}

function computeStatsFromHistory(history) {
    var stats = { scanned: history.length, threats: 0, safe: 0 };
    history.forEach(function (e) {
        if (e.status === 'phishing' || e.status === 'suspicious') stats.threats++;
        else stats.safe++;
    });
    return stats;
}

// ===== NORMALIZATION =====
function psNormalize(entry) {
    var status = (entry.status || 'safe').toLowerCase();
    var verdictClass = status === 'phishing' ? 'danger' : (status === 'suspicious' ? 'warn' : 'safe');
    var verdictLabel = status === 'phishing' ? 'Phishing' : (status === 'suspicious' ? 'Suspicious' : 'Safe');

    var confidence = entry.confidence;
    if (typeof confidence === 'string') confidence = parseFloat(confidence);
    if (typeof confidence !== 'number' || isNaN(confidence)) confidence = 0;

    var riskScore = entry.risk_score;
    if (typeof riskScore !== 'number' || isNaN(riskScore)) riskScore = confidence;

    return {
        url: entry.url || '',
        status: status,
        verdictClass: verdictClass,
        verdictLabel: verdictLabel,
        confidence: Math.round(confidence),
        riskScore: Math.round(riskScore),
        timestamp: entry.timestamp || null,
        message: entry.message || null,
        vtPositives: entry.vt_positives != null ? entry.vt_positives : null,
        vtTotalEngines: entry.vt_total_engines != null ? entry.vt_total_engines : null,
        vtVendors: Array.isArray(entry.vt_vendors) ? entry.vt_vendors : null,
        vtDetails: (entry.vt_details && typeof entry.vt_details === 'object') ? entry.vt_details : null,
        vtError: entry.vt_error || null
    };
}

function psFormatUnixDate(seconds) {
    if (seconds == null) return null;
    return new Date(seconds * 1000).toLocaleString();
}

function psBytes(n) {
    if (n == null) return null;
    if (n < 1024) return n + ' B';
    if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB';
    return (n / (1024 * 1024)).toFixed(1) + ' MB';
}

function psHostname(url) {
    try { return new URL(url).hostname; } catch (e) { return url; }
}

function psFormatTime(iso) {
    if (!iso) return '—';
    var parsed = new Date(iso);
    if (isNaN(parsed.getTime())) return '—';
    var abs = parsed.toLocaleString();
    if (typeof phishshieldTimeAgo === 'function') {
        return phishshieldTimeAgo(iso) + ' · ' + abs;
    }
    return abs;
}

// ===== STATS ROW =====
function renderStats() {
    var stats = psState.stats;
    var total = stats.scanned || psState.history.length;
    var safe = stats.safe || 0;
    var threats = stats.threats || 0;

    var suspicious = 0, phishing = 0;
    psState.history.forEach(function (e) {
        if (e.status === 'suspicious') suspicious++;
        else if (e.status === 'phishing') phishing++;
    });
    if (suspicious + phishing === 0 && threats > 0) {
        phishing = threats;
    }

    setText('stat-total', total);
    setText('stat-safe', safe);
    setText('stat-suspicious', suspicious);
    setText('stat-phishing', phishing);
    setText('stat-safe-pct', total > 0 ? Math.round((safe / total) * 100) + '% of total' : '—');
}

// ===== SELECTED DETECTION =====
function getSelectedEntry() {
    return psState.history[psState.selectedIndex] || null;
}

function renderSelected() {
    var raw = getSelectedEntry();
    var latestTime = document.getElementById('latest-time');

    if (!raw) {
        setHTML('latest-content', '<p class="empty-state">No scans yet — paste a URL above and click Scan URL to test.</p>');
        setHTML('vendor-grid', '<p class="empty-state">Scan a URL to see vendor results here.</p>');
        var tip = document.getElementById('vendor-tip');
        if (tip) tip.style.display = 'none';
        setText('vendor-meta', '—');
        setHTML('details-content', '<p class="empty-state">Scan a URL to see its details here.</p>');
        setHTML('relations-content', '<p class="empty-state">Scan a URL to see related detections here.</p>');
        if (latestTime) latestTime.textContent = '—';
        return;
    }

    var entry = psNormalize(raw);
    var heuristic = (typeof phishshieldScoreUrl === 'function')
        ? phishshieldScoreUrl(entry.url)
        : { score: entry.confidence, verdict: entry.verdictClass, reasons: [] };

    if (latestTime) latestTime.textContent = psFormatTime(entry.timestamp);

    renderLatest(entry, heuristic);
    renderVendorGrid(entry, heuristic);
    renderDetails(entry, heuristic);
    renderRelations(entry);
}

function renderLatest(entry, heuristic) {
    var colors = PS_VERDICT_COLORS[entry.verdictClass];
    var isSafe = entry.verdictClass === 'safe';
    var pct = isSafe ? Math.min(100 - entry.confidence, 99) : entry.confidence;
    var pctLabel = isSafe ? 'safety' : 'risk';
    var r = 64, c = 2 * Math.PI * r, offset = c - (pct / 100) * c;

    // When VirusTotal returned no data, a "safe" verdict is only locally
    // checked — mark it Unverified next to the badge instead of a plain green.
    var vtHadNoData = entry.vtTotalEngines == null;
    var unverifiedNote = (isSafe && vtHadNoData)
        ? '<span class="verdict-unverified" title="VirusTotal had no data for this scan, so this verdict is based on local checks only.">Unverified · VirusTotal had no data</span>'
        : '';

    var tagsHtml = '';
    if (heuristic.reasons && heuristic.reasons.length) {
        heuristic.reasons.slice(0, 4).forEach(function (reason) {
            var isFlag = psReasonIsFlag(reason);
            tagsHtml += '<span class="tag' + (isFlag ? ' flag' : '') + '">' + escapeHtml(reason) + '</span>';
        });
    }

    var aiBox = '';
    if (entry.message) {
        aiBox = '<div class="ai-box"><span class="ai-tag">Scan message</span>' + escapeHtml(entry.message) + '</div>';
    }

    var html =
        '<div class="report-grid">' +
        '  <div class="ring-wrap">' +
        '    <div class="ring">' +
        '      <svg width="148" height="148" viewBox="0 0 148 148">' +
        '        <circle cx="74" cy="74" r="' + r + '" fill="none" stroke="#E6E9F0" stroke-width="12"/>' +
        '        <circle cx="74" cy="74" r="' + r + '" fill="none" stroke="' + colors.fg + '" stroke-width="12" ' +
        '          stroke-linecap="round" stroke-dasharray="' + c + '" stroke-dashoffset="' + offset + '"/>' +
        '      </svg>' +
        '      <div class="ring-txt"><div class="n">' + pct + '%</div><div class="d">' + pctLabel + '</div></div>' +
        '    </div>' +
        '    <span class="verdict" style="background:' + colors.bg + ';color:' + colors.fg + '">' + entry.verdictLabel + '</span>' +
        unverifiedNote +
        '  </div>' +
        '  <div class="url-meta">' +
        '    <div class="name">' + escapeHtml(entry.url) + '</div>' +
        aiBox +
        '    <div class="kv-grid">' +
        '      <div class="kv"><span class="k">Risk score</span><span class="v">' + entry.riskScore + '/100</span></div>' +
        '      <div class="kv"><span class="k">Checked</span><span class="v">' + psFormatTime(entry.timestamp) + '</span></div>' +
        (entry.vtTotalEngines != null ?
            '      <div class="kv"><span class="k">VirusTotal</span><span class="v">' + entry.vtPositives + '/' + entry.vtTotalEngines + ' flagged</span></div>' : '') +
        '    </div>' +
        (tagsHtml ? '<div class="tags">' + tagsHtml + '</div>' : '') +
        '  </div>' +
        '</div>';

    setHTML('latest-content', html);
}

function renderVendorGrid(entry, heuristic) {
    var items = [];
    var hasRealVt = Array.isArray(entry.vtVendors) && entry.vtVendors.length > 0;

    items.push({
        name: 'Detection Log',
        clean: entry.verdictClass === 'safe',
        status: entry.verdictLabel
    });

    if (hasRealVt) {
        entry.vtVendors.slice(0, 100).forEach(function (v) {
            var flagged = v.category === 'malicious' || v.category === 'suspicious';
            var label = v.result ? (v.result.length > 30 ? v.result.slice(0, 27) + '…' : v.result) : v.category;
            items.push({
                name: v.engine,
                clean: !flagged,
                status: label
            });
        });
    } else if (heuristic.checks && heuristic.checks.length) {
        heuristic.checks.forEach(function (check) {
            items.push({
                name: check.name,
                clean: !check.flagged,
                status: check.flagged ? 'Flagged' : 'Clean'
            });
        });
    } else if (heuristic.reasons && heuristic.reasons.length) {
        heuristic.reasons.forEach(function (reason) {
            var flagged = psReasonIsFlag(reason);
            items.push({
                name: reason.length > 42 ? reason.slice(0, 39) + '…' : reason,
                clean: !flagged,
                status: flagged ? 'Flagged' : 'Clean'
            });
        });
    }

    var html = items.map(function (item) {
        return '<div class="engine ' + (item.clean ? 'clean' : 'flagged') + '">' +
            '<span class="ename">' + escapeHtml(item.name) + '</span>' +
            '<span class="estatus">' + escapeHtml(item.status) + '</span>' +
            '</div>';
    }).join('');

    setHTML('vendor-grid', html);

    var tip = document.getElementById('vendor-tip');
    if (hasRealVt) {
        var vtSummary = (entry.vtPositives != null ? entry.vtPositives : 0) + ' / ' +
            (entry.vtTotalEngines != null ? entry.vtTotalEngines : entry.vtVendors.length) + ' flagged';
        setText('vendor-meta', items.length + ' checks · VirusTotal (' + vtSummary + ')');
        if (tip) {
            tip.style.display = 'flex';
            tip.textContent = 'ℹ️ Vendor results above are from VirusTotal, aggregating 70+ security engines.';
        }
    } else {
        setText('vendor-meta', items.length + ' checks · local heuristic');
        if (tip) {
            tip.style.display = 'flex';
            if (entry.vtError) {
                // Surface the specific reason (rate limit, bad key, timeout...)
                // instead of the generic "no data" message.
                tip.textContent = 'ℹ️ VirusTotal unavailable: ' + entry.vtError +
                    '. Showing local heuristic checks instead.';
            } else {
                tip.textContent = 'ℹ️ VirusTotal had no data for this scan (new URL, or the backend key/connection wasn\'t available), so these are local heuristic checks run in your browser instead.';
            }
        }
    }
}

function psDetailGrid(rows) {
    var present = rows.filter(function (r) { return r[1] !== null && r[1] !== undefined && r[1] !== ''; });
    if (!present.length) return '';
    return '<div class="details-grid">' + present.map(function (r) {
        return '<div class="detail-row"><span class="k">' + r[0] + '</span><span class="v">' + escapeHtml(String(r[1])) + '</span></div>';
    }).join('') + '</div>';
}

function renderDetails(entry, heuristic) {
    var isSafe = entry.verdictClass === 'safe';
    var scoreLabel = isSafe ? 'Safety score' : 'Risk score';
    var scorePct = isSafe ? Math.min(100 - entry.confidence, 99) : entry.confidence;

    var overviewRows = [
        ['URL', entry.url],
        ['Verdict', entry.verdictLabel],
        [scoreLabel, scorePct + '%'],
        ['Checked', psFormatTime(entry.timestamp)]
    ];

    if (entry.vtTotalEngines != null) {
        overviewRows.push(['VirusTotal', entry.vtPositives + ' / ' + entry.vtTotalEngines + ' engines flagged']);
    }

    overviewRows.push(['Message', entry.message || (heuristic.reasons ? heuristic.reasons.join('; ') : '—')]);

    var html = '<div class="section-sub">Overview</div>' + psDetailGrid(overviewRows);

    var d = entry.vtDetails;
    if (d) {
        var categories = (d.categories && typeof d.categories === 'object')
            ? Object.keys(d.categories).map(function (vendor) { return vendor + ': ' + d.categories[vendor]; }).join(', ')
            : '';

        var basicRows = [
            ['Categories', categories],
            ['Tags', Array.isArray(d.tags) && d.tags.length ? d.tags.join(', ') : ''],
            ['Community score', (d.total_votes_harmless != null || d.total_votes_malicious != null)
                ? ((d.total_votes_harmless || 0) + ' harmless / ' + (d.total_votes_malicious || 0) + ' malicious') : ''],
            ['Reputation', d.reputation != null ? d.reputation : ''],
            ['Threat names', Array.isArray(d.threat_names) && d.threat_names.length ? d.threat_names.join(', ') : '']
        ];
        var basicHtml = psDetailGrid(basicRows);
        if (basicHtml) html += '<div class="section-sub">Basic Properties</div>' + basicHtml;

        var historyRows = [
            ['First submission', psFormatUnixDate(d.first_submission_date)],
            ['Last submission', psFormatUnixDate(d.last_submission_date)],
            ['Last analysis date', psFormatUnixDate(d.last_analysis_date)],
            ['Last modified', psFormatUnixDate(d.last_modification_date)],
            ['Times submitted', d.times_submitted != null ? d.times_submitted : '']
        ];
        var historyHtml = psDetailGrid(historyRows);
        if (historyHtml) html += '<div class="section-sub">History</div>' + historyHtml;

        var httpRows = [
            ['Final URL', d.last_final_url],
            ['Response code', d.last_http_response_code],
            ['Body size', psBytes(d.last_http_response_content_length)],
            ['Body SHA-256', d.last_http_response_content_sha256],
            ['HTML title', d.html_title]
        ];
        var httpHtml = psDetailGrid(httpRows);
        if (httpHtml) html += '<div class="section-sub">HTTP Response</div>' + httpHtml;

        if (!basicHtml && !historyHtml && !httpHtml) {
            html += '<div class="empty-tip">ℹ️ VirusTotal hasn\'t crawled this URL\'s page yet, so it has no categories, history, or HTTP response data — only the vendor verdicts above.</div>';
        }
    } else if (entry.vtTotalEngines != null) {
        html += '<div class="empty-tip">ℹ️ VirusTotal details (categories, history, HTTP response) aren\'t available for this scan.</div>';
    }

    setHTML('details-content', html);
}

function renderRelations(entry) {
    var host = psHostname(entry.url);
    var byHost = {};

    psState.history.forEach(function (e) {
        var h = psHostname(e.url);
        if (!byHost[h]) byHost[h] = { total: 0, threats: 0 };
        byHost[h].total++;
        if (e.status === 'phishing' || e.status === 'suspicious') byHost[h].threats++;
    });

    var hosts = Object.keys(byHost).sort(function (a, b) {
        return byHost[b].total - byHost[a].total;
    }).slice(0, 5);

    if (hosts.length === 0) {
        setHTML('relations-content', '<p class="empty-state">Scan a URL to see related detections here.</p>');
        return;
    }

    var html = '<div class="relation-group"><div class="relation-hd"><span class="t">Seen hostnames</span><span class="c">' + hosts.length + '</span></div>';
    hosts.forEach(function (h) {
        var info = byHost[h];
        var badgeClass = info.threats > 0 ? 'danger' : 'safe';
        var colors = PS_VERDICT_COLORS[badgeClass];
        html += '<div class="rel-item">' +
            '<span class="left"><span class="ic">' + (h === host ? '📍' : '🔗') + '</span>' + escapeHtml(h) + '</span>' +
            '<span class="badge" style="background:' + colors.bg + ';color:' + colors.fg + '">' + info.total + ' scan' + (info.total === 1 ? '' : 's') + '</span>' +
            '</div>';
    });
    html += '</div>';

    setHTML('relations-content', html);
}

// ===== RECENT DETECTIONS TABLE =====
function renderTable() {
    var body = document.getElementById('detections-table-body');
    if (!body) return;

    if (psState.history.length === 0) {
        body.innerHTML = '<tr><td colspan="4" class="empty-state">No scans yet.</td></tr>';
        return;
    }

    var rows = psState.history.slice(0, 50).map(function (raw, i) {
        var entry = psNormalize(raw);
        var pillClass = entry.verdictClass;
        return '<tr data-index="' + i + '" class="' + (i === psState.selectedIndex ? 'selected' : '') + '">' +
            '<td class="mono">' + escapeHtml(truncate(entry.url, 60)) + '</td>' +
            '<td>' + entry.confidence + '%</td>' +
            '<td class="mono">' + psFormatTime(entry.timestamp) + '</td>' +
            '<td><span class="pill ' + pillClass + '"><span class="icn"></span>' + entry.verdictLabel + '</span></td>' +
            '</tr>';
    }).join('');

    body.innerHTML = rows;

    Array.prototype.forEach.call(body.querySelectorAll('tr[data-index]'), function (tr) {
        tr.addEventListener('click', function () {
            psState.selectedIndex = parseInt(tr.getAttribute('data-index'), 10);
            renderSelected();
            renderTable();
            var panel = document.querySelector('.panel');
            if (panel) panel.scrollIntoView({ behavior: 'smooth', block: 'start' });
        });
    });
}

// ===== COMMUNITY =====
function renderCommunity() {
    var entry = getSelectedEntry();
    var list = document.getElementById('comment-list');
    var voteUp = document.getElementById('vote-up');
    var voteDown = document.getElementById('vote-down');
    if (!list) return;

    if (!entry) {
        list.innerHTML = '';
        if (voteUp) voteUp.textContent = '0';
        if (voteDown) voteDown.textContent = '0';
        return;
    }

    var url = entry.url;
    var thread = psState.community[url] || { comments: [] };
    var comments = thread.comments || [];

    if (voteUp) voteUp.textContent = String(comments.filter(function (c) { return c.verdict === 'safe'; }).length);
    if (voteDown) voteDown.textContent = String(comments.filter(function (c) { return c.verdict !== 'safe'; }).length);

    if (comments.length === 0) {
        list.innerHTML = '<p class="empty-state">No comments yet for this URL.</p>';
        return;
    }

    list.innerHTML = comments.slice().reverse().map(function (c) {
        return '<div class="comment">' +
            '<div class="cav" style="background:#4C6FE0;">' + escapeHtml((c.who || 'You').slice(0, 2).toUpperCase()) + '</div>' +
            '<div class="body">' +
            '<div class="hd"><span class="who">' + escapeHtml(c.who || 'You') + '</span><span class="when">' + psFormatTime(c.ts) + '</span></div>' +
            '<div class="txt">' + escapeHtml(c.text) + '</div>' +
            '</div></div>';
    }).join('');
}

function wireCommunity() {
    var btn = document.getElementById('comment-btn');
    var input = document.getElementById('comment-input');
    if (!btn || !input) return;

    function post() {
        var text = input.value.trim();
        var entry = getSelectedEntry();
        if (!text || !entry) return;

        var url = entry.url;
        chrome.storage.local.get(['community'], function (result) {
            var community = result.community || {};
            if (!community[url]) community[url] = { comments: [] };
            community[url].comments.push({ who: 'You', text: text, ts: new Date().toISOString() });
            chrome.storage.local.set({ community: community }, function () {
                input.value = '';
            });
        });
    }

    btn.addEventListener('click', post);
    input.addEventListener('keyup', function (e) {
        if (e.key === 'Enter') post();
    });
}

// ===== MANUAL SCAN BOX =====
function wireScanBox() {
    var input = document.getElementById('url-input');
    var scanBtn = document.getElementById('scan-btn');
    var manualBtn = document.getElementById('manual-check-btn');

    if (manualBtn && input) {
        manualBtn.addEventListener('click', function () {
            input.focus();
        });
    }

    if (!input || !scanBtn) return;

    function runScan() {
        var url = input.value.trim();
        if (!url) { input.focus(); return; }
        if (!/^https?:\/\//i.test(url)) url = 'https://' + url;

        scanBtn.disabled = true;
        scanBtn.textContent = 'Scanning…';

        chrome.runtime.sendMessage({ action: 'scanUrl', url: url }, function (data) {
            var finish = function () {
                scanBtn.disabled = false;
                scanBtn.textContent = 'Scan URL';
                input.value = '';
            };

            if (data && data.status && data.status !== 'error') {
                finish();
                return;
            }

            psManualHeuristicScan(url, finish);
        });
    }

    scanBtn.addEventListener('click', runScan);
    input.addEventListener('keyup', function (e) {
        if (e.key === 'Enter') runScan();
    });
}

function psManualHeuristicScan(url, done) {
    if (typeof phishshieldScoreUrl !== 'function') { done(); return; }

    var result = phishshieldScoreUrl(url);
    var status = result.verdict === 'danger' ? 'phishing' : (result.verdict === 'warn' ? 'suspicious' : 'safe');
    var reasonsText = (result.reasons || []).join('; ');

    chrome.storage.local.get(['history', 'stats'], function (res) {
        var history = res.history || [];
        var stats = res.stats || { scanned: 0, threats: 0, safe: 0 };

        history.unshift({
            url: url,
            status: status,
            confidence: result.score,
            risk_score: result.score,
            timestamp: new Date().toISOString(),
            message: 'Backend offline — scored locally: ' + reasonsText
        });
        if (history.length > 200) history = history.slice(0, 200);

        stats.scanned = (stats.scanned || 0) + 1;
        if (status === 'safe') stats.safe = (stats.safe || 0) + 1;
        else stats.threats = (stats.threats || 0) + 1;

        chrome.storage.local.set({ history: history, stats: stats }, done);
    });
}

function showExtensionStatus() {
    var el = document.getElementById('extension-status');
    if (!el) return;
    try {
        var version = chrome.runtime.getManifest().version;
        el.textContent = 'PhishShield v' + version + ' is running in this browser and auto-scanning pages you visit.';
    } catch (e) {
        // Silently fail if not running in extension context
    }
}

// ===== UTILS =====
function setText(id, value) {
    var el = document.getElementById(id);
    if (el) el.textContent = value;
}
function setHTML(id, html) {
    var el = document.getElementById(id);
    if (el) el.innerHTML = html;
}
function truncate(str, n) {
    return str.length > n ? str.slice(0, n - 1) + '…' : str;
}
function escapeHtml(str) {
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

console.log('🛡️ PhishShield dashboard connected to chrome.storage — live sync active');