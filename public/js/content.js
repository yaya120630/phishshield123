// content.js

// Listen for messages from background.js
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "SHOW_WARNING") {
    showWarningBanner(message.data);
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

function showWarningBanner(data) {
  // Avoid showing multiple banners if page triggers this more than once
  if (document.getElementById("phishshield-banner")) return;

  const banner = document.createElement("div");
  banner.id = "phishshield-banner";

  // Choose color based on risk status (UPDATED TO data.verdict)
  const bgColor = data.verdict === "phishing" ? "#D85A30" : "#F2A623";

  banner.style.cssText = `
    position: fixed;
    top: 0;
    left: 0;
    width: 100%;
    background: ${bgColor};
    color: #ffffff;
    font-family: Arial, sans-serif;
    font-size: 14px;
    line-height: 1.4;
    padding: 12px 20px;
    z-index: 2147483647;
    display: flex;
    justify-content: space-between;
    align-items: center;
    box-shadow: 0 2px 6px rgba(0,0,0,0.3);
    box-sizing: border-box;
    margin: 0;
  `;

  banner.innerHTML = `
    <div>
      <strong>⚠ PhishShield Warning:</strong>
      This website may be ${data.verdict === "phishing" ? "a phishing site" : "suspicious"}.
      ${data.awareness_message ? " " + psEscapeHtml(data.awareness_message) : ""}
    </div>
    <button id="phishshield-close" style="
      background: rgba(255,255,255,0.2);
      border: none;
      color: white;
      padding: 6px 12px;
      border-radius: 4px;
      cursor: pointer;
      font-size: 13px;
      line-height: 1;
      margin: 0;
    ">Dismiss</button>
  `;

  const target = document.body || document.documentElement;
  if (target) {
    target.prepend(banner);
  }

  // Close button logic
  const closeBtn = document.getElementById("phishshield-close");
  if (closeBtn) {
    closeBtn.addEventListener("click", () => {
      banner.remove();
    });
  }
}