// lib/scanner.js - local (offline) URL scoring for PhishShield.

const PHISHSHIELD_SUSPICIOUS_WORDS = [
  "login", "verify", "secure", "update", "confirm", "signin", "account",
  "billing", "suspended", "unlock", "authenticate", "recover"
];

const PHISHSHIELD_SHORTENERS = new Set([
  "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
  "rebrand.ly", "cutt.ly", "shorte.st"
]);

const PHISHSHIELD_RISKY_TLDS = new Set([
  "tk", "ml", "ga", "cf", "gq", "xyz", "top", "work", "click", "link",
  "country", "stream", "gdn", "loan", "win", "review"
]);

const PHISHSHIELD_FREE_HOSTS = [
  "blogspot.com", "wordpress.com", "weebly.com", "wixsite.com", "000webhostapp.com"
];

// Institutional suffixes: generic words like "login" are normal here.
const PHISHSHIELD_TRUSTED_SUFFIXES = [
  ".edu.my", ".gov.my", ".mil.my", ".edu", ".gov", ".mil", ".ac.uk", ".gov.uk", ".edu.sg", ".gov.sg"
];

// Add domains here (or load from chrome.storage) that you've verified are safe.
const PHISHSHIELD_USER_ALLOWLIST = [
  "cidos.edu.my"
];

const PS_DEFAULT_BRANDS = [
  "microsoft", "outlook", "google", "gmail", "paypal", "apple", "icloud",
  "facebook", "instagram", "amazon", "netflix", "linkedin",
  "maybank", "cimb", "publicbank", "rhb", "hsbc", "dhl"
];

const PS_DEFAULT_OFFICIAL_DOMAINS = [
  "microsoft.com", "live.com", "office.com", "microsoftonline.com", "outlook.com",
  "office365.com", "sharepoint.com", "windows.com", "bing.com", "azure.com",
  "google.com", "gmail.com", "youtube.com", "google.com.my", "googleusercontent.com",
  "paypal.com", "apple.com", "icloud.com", "facebook.com", "fb.com", "messenger.com",
  "instagram.com", "meta.com", "amazon.com", "amazon.co.uk", "amazon.de", "amazon.sg",
  "netflix.com", "linkedin.com", "maybank2u.com.my", "maybank.com",
  "cimbclicks.com.my", "cimb.com.my", "cimb.com", "pbebank.com", "publicbank.com.my",
  "rhbgroup.com", "rhbbank.com.my", "hsbc.com", "hsbc.com.my", "dhl.com"
];

function psHostMatches(host, domain) {
  return host === domain || host.endsWith("." + domain);
}

function psIsOfficial(host) {
  return PS_DEFAULT_OFFICIAL_DOMAINS.some(d => psHostMatches(host, d));
}

function psIsTrusted(host) {
  return (
    PHISHSHIELD_USER_ALLOWLIST.some(d => psHostMatches(host, d)) ||
    PHISHSHIELD_TRUSTED_SUFFIXES.some(s => host.endsWith(s))
  );
}

function phishshieldScoreUrl(urlStr) {
  let score = 99;
  const reasons = [];

  try {
    const url = new URL(urlStr);
    const host = url.hostname.toLowerCase();
    const tld = host.split(".").pop();

    // 1. Known-good: official brand domains and trusted institutions skip keyword checks.
    if (psIsOfficial(host) || psIsTrusted(host)) {
      return { score: 99, verdict: "safe", reasons: [] };
    }

    let strongFlags = 0;

    // 2. Brand impersonation: brand name in HOSTNAME but not an official domain.
    const hostTokens = host.split(/[^a-z0-9]+/).filter(Boolean);
    const brandHit = PS_DEFAULT_BRANDS.find(b => hostTokens.includes(b) || host.includes(b));
    if (brandHit) {
      score -= 50;
      strongFlags++;
      reasons.push("Contains brand impersonation keywords (" + brandHit + ")");
    }

    // 3. Free hosting / blogging platforms.
    if (PHISHSHIELD_FREE_HOSTS.some(d => host.endsWith(d))) {
      const sub = host.split(".")[0];
      if (sub.length > 10 || /[^a-z0-9]/i.test(sub) || /[0-9]{3,}/.test(sub)) {
        score -= 40;
        strongFlags++;
        reasons.push("Suspicious or long free subdomain structure");
      } else {
        score -= 20;
        strongFlags++;
        reasons.push("Hosted on free public blogging platform");
      }
    }

    // 4. Other strong signals.
    if (PHISHSHIELD_SHORTENERS.has(host)) {
      score -= 25; strongFlags++;
      reasons.push("URL shortener hides the real destination");
    }
    if (PHISHSHIELD_RISKY_TLDS.has(tld)) {
      score -= 25; strongFlags++;
      reasons.push("Risky top-level domain (." + tld + ")");
    }
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
      score -= 35; strongFlags++;
      reasons.push("Uses a raw IP address instead of a domain");
    }
    if (host.includes("xn--")) {
      score -= 30; strongFlags++;
      reasons.push("Punycode (look-alike characters) in domain");
    }
    if (url.protocol !== "https:") {
      score -= 10;
      reasons.push("Connection is not HTTPS");
    }

    // 5. Generic words (login, verify...) only count when something else is already suspicious.
    const full = (host + url.pathname).toLowerCase();
    const word = SUSPICIOUS_FIND(full);
    if (word && strongFlags > 0) {
      score -= 15;
      reasons.push('Contains suspicious word "' + word + '"');
    }

    score = Math.max(0, score);
    let verdict = "safe";
    if (score < 50) verdict = "danger";
    else if (score < 80) verdict = "warn";

    return { score, verdict, reasons };
  } catch (e) {
    return { score: 50, verdict: "warn", reasons: ["Invalid URL format"] };
  }
}

function SUSPICIOUS_FIND(full) {
  return PHISHSHIELD_SUSPICIOUS_WORDS.find(w => full.includes(w));
}

if (typeof self !== "undefined") {
  self.phishshieldScoreUrl = phishshieldScoreUrl;
}