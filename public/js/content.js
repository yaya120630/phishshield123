// content.js — injected on demand by background.js into suspicious/phishing
// tabs. Chrome does NOT allow an extension to force its toolbar popup open on
// navigation (it is user-triggered only), so we render a faithful copy of the
// Scanner popup as a floating card on the page. It appears automatically on
// every risky site and shows the same risk percentage.

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "SHOW_WARNING") {
    showScannerCard(message.data || {});
  }
});

function psEscapeHtml(str) {
  return String(str == null ? "" : str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function showScannerCard(data) {
  var isPhishing = data.verdict === "phishing";
  var accent = isPhishing ? "#E0503E" : "#E08A1E";
  var accentBg = isPhishing ? "#FCEAE7" : "#FDF2E0";
  var label = isPhishing ? "Phishing" : "Suspicious";
  var icon = isPhishing ? "⛔" : "!";

  var url = data.url || (typeof location !== "undefined" ? location.href : "");
  var risk = (typeof data.risk_score === "number") ? Math.round(data.risk_score) : null;
  var stats = data.stats || { scanned: 0, threats: 0, safe: 0 };

  var vtLine = "";
  if (data.vt_total_engines != null) {
    vtLine = "Flagged by " + (data.vt_positives != null ? data.vt_positives : 0) +
      " of " + data.vt_total_engines + " VirusTotal security vendors.";
  }
  var detailText = data.awareness_message || vtLine ||
    "This site matched PhishShield's risk indicators.";

  // Rebuild in place so the fast local warning can be upgraded by the backend.
  var existing = document.getElementById("phishshield-card");
  if (existing) existing.remove();

  var card = document.createElement("div");
  card.id = "phishshield-card";
  card.setAttribute("role", "alertdialog");
  card.style.cssText = [
    "all:initial",
    "position:fixed", "top:16px", "right:16px", "z-index:2147483647",
    "width:380px", "max-width:calc(100vw - 32px)",
    "background:#F7F8FB", "border-radius:18px",
    "box-shadow:0 24px 70px -18px rgba(20,24,40,0.55)",
    "font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif",
    "color:#1B2233", "overflow:hidden",
    "animation:psSlideIn .25s ease-out"
  ].join(";");

  function tile(num, lbl, color) {
    return '<div style="flex:1;background:#fff;border:1px solid #ECEFF5;border-radius:12px;padding:12px 6px;text-align:center;">' +
      '<div style="font-size:20px;font-weight:800;color:' + color + ';">' + num + '</div>' +
      '<div style="font-size:9px;font-weight:700;letter-spacing:.04em;color:#8A93A6;margin-top:3px;">' + lbl + '</div>' +
      '</div>';
  }

  card.innerHTML =
    '<style>@keyframes psSlideIn{from{opacity:0;transform:translateY(-10px)}to{opacity:1;transform:translateY(0)}}#phishshield-card *{box-sizing:border-box;}</style>' +

    // Header
    '<div style="display:flex;align-items:center;gap:12px;padding:16px 18px;">' +
      '<div style="width:40px;height:40px;border-radius:11px;background:linear-gradient(135deg,#3b4ea8,#1b2a6b);display:flex;align-items:center;justify-content:center;font-size:20px;">🛡️</div>' +
      '<div style="line-height:1.2;">' +
        '<div style="font-weight:800;font-size:17px;letter-spacing:.01em;color:#15203D;">PHISHSHIELD</div>' +
        '<div style="font-size:9.5px;font-weight:700;letter-spacing:.03em;color:#8A93A6;">AI-POWERED PHISHING URL DETECTION</div>' +
      '</div>' +
      '<button id="phishshield-card-close" aria-label="Dismiss" style="margin-left:auto;background:#EEF0F6;border:none;border-radius:9px;width:30px;height:30px;font-size:18px;line-height:1;color:#8A93A6;cursor:pointer;">&times;</button>' +
    '</div>' +

    // Scanner tab bar (visual match)
    '<div style="display:flex;gap:8px;padding:0 18px 14px;">' +
      '<div style="flex:1;text-align:center;padding:11px;border-radius:11px;background:linear-gradient(135deg,#6F82F5,#5A4FE0);color:#fff;font-weight:800;font-size:13px;">Scanner</div>' +
      '<div style="flex:1;text-align:center;padding:11px;border-radius:11px;background:#ECEFF5;color:#8A93A6;font-weight:700;font-size:13px;">Dashboard</div>' +
    '</div>' +

    '<div style="padding:0 18px 18px;">' +
      // Detected URL
      '<div style="background:#fff;border:1px solid #ECEFF5;border-radius:12px;padding:12px 14px;margin-bottom:14px;">' +
        '<div style="font-size:10px;font-weight:800;letter-spacing:.06em;color:#8A93A6;text-transform:uppercase;margin-bottom:5px;">Detected URL</div>' +
        '<div style="font-family:ui-monospace,Menlo,monospace;font-size:12.5px;word-break:break-all;color:#1B2233;">' + psEscapeHtml(url) + '</div>' +
      '</div>' +

      // Verdict banner
      '<div style="display:flex;align-items:center;gap:12px;background:' + accentBg + ';border:1.5px solid ' + accent + ';border-radius:14px;padding:16px;margin-bottom:14px;">' +
        '<span style="width:34px;height:34px;border-radius:9px;background:' + accent + ';color:#fff;display:flex;align-items:center;justify-content:center;font-weight:800;font-size:16px;">' + icon + '</span>' +
        '<span style="font-size:20px;font-weight:800;color:' + accent + ';">' + label + '</span>' +
      '</div>' +

      // Detail note
      '<div style="background:#fff;border:1px solid #ECEFF5;border-radius:12px;padding:13px 14px;font-size:13px;line-height:1.55;color:#3A4257;margin-bottom:14px;">' + psEscapeHtml(detailText) + '</div>' +

      // Risk score
      (risk != null ?
        '<div style="text-align:center;font-size:15px;color:#3A4257;margin-bottom:16px;">Risk Score: <b style="font-size:17px;color:#15203D;">' + risk + '%</b></div>' : '') +

      // Stat tiles
      '<div style="display:flex;gap:10px;">' +
        tile(stats.scanned, "SCANNED TODAY", "#15203D") +
        tile(stats.threats, "THREATS BLOCKED", "#E0503E") +
        tile(stats.safe, "SAFE SITES", "#1FAE7A") +
      '</div>' +
    '</div>';

  var target = document.body || document.documentElement;
  if (target) target.appendChild(card);

  var closeBtn = document.getElementById("phishshield-card-close");
  if (closeBtn) closeBtn.addEventListener("click", function () { card.remove(); });

  // Auto-dismiss after 15s so it doesn't linger.
  setTimeout(function () { if (card && card.parentNode) card.remove(); }, 15000);
}
