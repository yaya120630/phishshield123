// content.js — injected on demand by background.js into suspicious/phishing
// tabs. Chrome does not allow an extension to force its toolbar popup open on
// navigation, so instead we render the same Scanner card as a floating overlay
// directly on the page. It appears automatically whenever a site is risky.

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "SHOW_WARNING") {
    showWarningCard(message.data || {});
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

function showWarningCard(data) {
  var isPhishing = data.verdict === "phishing";
  var accent = isPhishing ? "#E0503E" : "#E08A1E";
  var accentBg = isPhishing ? "#FCEAE7" : "#FDF2E0";
  var label = isPhishing ? "Phishing" : "Suspicious";
  var icon = isPhishing ? "⛔" : "!";

  var url = data.url || (typeof location !== "undefined" ? location.href : "");
  var risk = (typeof data.risk_score === "number") ? Math.round(data.risk_score) : null;
  var msg = data.awareness_message || "";

  // If a card is already shown, update it in place (so the fast local warning
  // can be upgraded by the fuller backend verdict) instead of stacking.
  var existing = document.getElementById("phishshield-card");
  if (existing) existing.remove();

  var card = document.createElement("div");
  card.id = "phishshield-card";
  card.setAttribute("role", "alertdialog");
  card.style.cssText = [
    "position:fixed", "top:18px", "right:18px", "z-index:2147483647",
    "width:360px", "max-width:calc(100vw - 36px)",
    "background:#FFFFFF", "border-radius:16px",
    "border:1px solid " + accent,
    "box-shadow:0 20px 60px -16px rgba(20,24,40,0.45)",
    "font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif",
    "color:#1B2233", "overflow:hidden", "box-sizing:border-box",
    "animation:psSlideIn .25s ease-out"
  ].join(";");

  var vtLine = "";
  if (data.vt_total_engines != null) {
    vtLine = "Flagged by " + (data.vt_positives != null ? data.vt_positives : 0) +
      " of " + data.vt_total_engines + " VirusTotal security vendors.";
  }
  var detailText = msg || vtLine || "This site matched PhishShield's risk indicators.";

  card.innerHTML =
    '<style>@keyframes psSlideIn{from{opacity:0;transform:translateY(-8px)}to{opacity:1;transform:translateY(0)}}</style>' +
    '<div style="display:flex;align-items:center;gap:10px;padding:14px 16px;background:#F7F8FB;border-bottom:1px solid #ECEFF5;">' +
      '<div style="width:30px;height:30px;border-radius:8px;background:linear-gradient(135deg,#5B7CFA,#8B6CF6);display:flex;align-items:center;justify-content:center;color:#fff;font-weight:800;font-size:14px;">PS</div>' +
      '<div style="font-weight:800;font-size:14px;letter-spacing:.02em;">PHISHSHIELD</div>' +
      '<button id="phishshield-card-close" aria-label="Dismiss" style="margin-left:auto;background:transparent;border:none;font-size:20px;line-height:1;color:#8A93A6;cursor:pointer;padding:2px 4px;">&times;</button>' +
    '</div>' +
    '<div style="padding:16px;">' +
      '<div style="font-size:10px;font-weight:800;letter-spacing:.06em;color:#8A93A6;text-transform:uppercase;margin-bottom:4px;">Detected URL</div>' +
      '<div style="font-family:ui-monospace,Menlo,monospace;font-size:12px;word-break:break-all;background:#F2F4F8;border-radius:8px;padding:8px 10px;margin-bottom:14px;">' + psEscapeHtml(url) + '</div>' +
      '<div style="display:flex;align-items:center;gap:10px;background:' + accentBg + ';border:1px solid ' + accent + ';border-radius:12px;padding:12px 14px;margin-bottom:12px;">' +
        '<span style="width:26px;height:26px;border-radius:7px;background:' + accent + ';color:#fff;display:flex;align-items:center;justify-content:center;font-weight:800;">' + icon + '</span>' +
        '<span style="font-size:17px;font-weight:800;color:' + accent + ';">' + label + '</span>' +
        (risk != null ? '<span style="margin-left:auto;font-size:13px;font-weight:700;color:' + accent + ';">Risk ' + risk + '%</span>' : '') +
      '</div>' +
      '<div style="font-size:13px;line-height:1.55;color:#3A4257;">' + psEscapeHtml(detailText) + '</div>' +
    '</div>';

  var target = document.body || document.documentElement;
  if (target) target.appendChild(card);

  var closeBtn = document.getElementById("phishshield-card-close");
  if (closeBtn) closeBtn.addEventListener("click", function () { card.remove(); });

  // Auto-dismiss after 12s so it doesn't linger forever.
  setTimeout(function () { if (card && card.parentNode) card.remove(); }, 12000);
}
