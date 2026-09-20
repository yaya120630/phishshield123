/**
 * PhishShield heuristic URL scorer.
 * Plain script (no ES modules) so it can be loaded via <script> in
 * popup/dashboard AND via importScripts() in the background service worker.
 * Produces a risk score 0-100 and a short list of reasons.
 *
 * NOTE: This is a lightweight, local, rule-based heuristic for demo /
 * prototype purposes. It is not a substitute for a real threat-intel /
 * ML backend, but every extension surface (popup, dashboard, background)
 * calls this same function so results are consistent everywhere.
 */

const PHISHSHIELD_BRANDS = [
  "maybank2u", "maybank", "paypal", "google", "microsoft", "apple",
  "amazon", "facebook", "instagram", "netflix", "dbs", "cimb", "hsbc",
  "publicbank", "rhb", "ambank", "americanexpress", "chase", "wellsfargo"
];

const PHISHSHIELD_OFFICIAL_DOMAINS = [
  "maybank2u.com.my", "paypal.com", "google.com", "microsoft.com",
  "apple.com", "amazon.com", "facebook.com", "instagram.com",
  "netflix.com", "dbs.com", "cimbclicks.com.my", "hsbc.com.my",
  "pbebank.com", "rhbgroup.com", "ambank.com.my", "americanexpress.com",
  "chase.com", "wellsfargo.com"
];

const PHISHSHIELD_SUSPICIOUS_WORDS = [
  "login", "verify", "secure", "update", "confirm", "signin", "account",
  "billing", "suspended", "unlock", "authenticate", "recover"
];

const PHISHSHIELD_SHORTENERS = new Set([
  "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
  "rebrand.ly", "cutt.ly", "shorte.st"
]);

// TLDs that see disproportionately heavy phishing/spam abuse because
// they're cheap or free to register. Not proof of anything on their
// own — just one more signal, same as a real vendor engine would use.
const PHISHSHIELD_RISKY_TLDS = new Set([
  "tk", "ml", "ga", "cf", "gq", "xyz", "top", "work", "click", "link",
  "country", "stream", "gdn", "loan", "win", "review"
]);

/**
 * Every rule below is recorded as a named "check" — flagged or clean —
 * so the UI can render a full VirusTotal-style vendor grid (most rows
 * clean, a few flagged) instead of only listing the handful that hit.
 */
function phishshieldScoreUrl(rawUrl) {
  const checks = [];
  let score = 0;
  let u;

  function addCheck(name, flagged, weight, cleanDetail, flaggedDetail) {
    checks.push({ name: name, flagged: flagged, detail: flagged ? flaggedDetail : cleanDetail });
    if (flagged) score += weight;
  }

  try {
    u = new URL(rawUrl);
  } catch (e) {
    return { score: 0, verdict: "safe", reasons: ["Not a scannable web URL."], checks: [] };
  }

  const host = u.hostname.toLowerCase();
  const full = rawUrl.toLowerCase();

  addCheck(
    "HTTPS Encryption", u.protocol !== "https:", 10,
    "Connection uses HTTPS encryption.",
    "Connection is not using HTTPS."
  );

  addCheck(
    "IP-Address Host", /^(\d{1,3}\.){3}\d{1,3}$/.test(host), 40,
    "Uses a domain name, not a raw IP address.",
    "Uses a raw IP address instead of a domain name."
  );

  addCheck(
    "Credential-Trick ('@') Check", full.includes("@"), 25,
    "No '@' trick found in the URL.",
    "URL contains an '@' character, often used to disguise the real destination."
  );

  addCheck(
    "Punycode / IDN Homograph", host.includes("xn--"), 25,
    "No punycode encoding detected.",
    "Domain uses punycode encoding, a common homograph-attack technique."
  );

  const hyphenCount = (host.match(/-/g) || []).length;
  addCheck(
    "Excessive Hyphens", hyphenCount >= 3, 15,
    "Hyphen count in the domain is normal.",
    "Domain contains an unusually high number of hyphens."
  );

  const labelCount = host.split(".").length;
  addCheck(
    "Subdomain Depth", labelCount >= 5, 10,
    "Subdomain depth is normal.",
    "Domain has an unusually deep subdomain chain."
  );

  addCheck(
    "URL Length", rawUrl.length > 90, 10,
    "URL length is normal.",
    "URL is unusually long."
  );

  addCheck(
    "URL Shortener", PHISHSHIELD_SHORTENERS.has(host), 15,
    "Not a known URL-shortening domain.",
    "Uses a known URL-shortening service, which hides the real destination."
  );

  const tld = host.split(".").pop();
  addCheck(
    "Suspicious TLD", PHISHSHIELD_RISKY_TLDS.has(tld), 10,
    "Top-level domain is not on the commonly-abused list.",
    `Uses a top-level domain (".${tld}") frequently abused for phishing.`
  );

  // Brand impersonation: brand keyword present, but not on that brand's official domain
  const matchedBrand = PHISHSHIELD_BRANDS.find(b => host.includes(b));
  const brandImpersonation = !!matchedBrand &&
    !PHISHSHIELD_OFFICIAL_DOMAINS.some(d => host === d || host.endsWith("." + d));
  addCheck(
    "Brand Domain Match", brandImpersonation, 35,
    matchedBrand ? "Brand mention matches its official domain." : "No known brand name referenced in the domain.",
    `Domain references "${matchedBrand}" but does not match that brand's official domain.`
  );

  // Suspicious action words combined with a brand mention
  const suspiciousWordHit = PHISHSHIELD_SUSPICIOUS_WORDS.find(w => full.includes(w));
  const credentialLanguage = !!(suspiciousWordHit && matchedBrand);
  addCheck(
    "Credential-Harvesting Language", credentialLanguage, 15,
    "No credential-harvesting language paired with a brand mention.",
    `Path/query contains credential-harvesting language ("${suspiciousWordHit}") alongside a brand mention.`
  );

  score = Math.max(1, Math.min(97, score));

  let verdict = "safe";
  if (score >= 60) verdict = "danger";
  else if (score >= 30) verdict = "warn";

  const reasons = checks.filter(c => c.flagged).map(c => c.detail);
  if (reasons.length === 0) {
    reasons.push("No risk indicators found in URL structure.");
  }

  return { score, verdict, reasons, checks };
}

// Expose for both service-worker (importScripts) and page (<script>) contexts.
if (typeof self !== "undefined") {
  self.phishshieldScoreUrl = phishshieldScoreUrl;
}