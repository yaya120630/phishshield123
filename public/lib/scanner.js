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

// Additive RISK model: start at 0 and add points for each red flag. This is
// the only signal when the backend (VirusTotal + Gemini) is unreachable, so
// it is tuned to catch obvious phishing tells rather than err toward "safe".
//
// Risk -> verdict:  >= 60 danger (phishing),  >= 25 warn (suspicious),  else safe.
// The returned `score` is a 0-99 SAFETY score (100 - risk) so the UI ring and
// the verdict always agree.
function phishshieldScoreUrl(urlStr) {
  const reasons = [];
  let risk = 0;

  try {
    const url = new URL(urlStr);
    const host = url.hostname.toLowerCase();
    const tld = host.split(".").pop();
    const path = (url.pathname + url.search).toLowerCase();
    const full = (host + path);

    // 1. Known-good: official brand domains and trusted institutions are safe.
    if (psIsOfficial(host) || psIsTrusted(host)) {
      return { score: 99, verdict: "safe", reasons: [] };
    }

    // 2. Brand impersonation: a known brand name appears in the hostname but
    //    the domain is NOT the brand's official domain. Strong phishing tell.
    const hostTokens = host.split(/[^a-z0-9]+/).filter(Boolean);
    const brandHit = PS_DEFAULT_BRANDS.find(b => hostTokens.includes(b) || host.includes(b));
    if (brandHit) {
      risk += 55;
      reasons.push("Impersonates a known brand (" + brandHit + ") on an unofficial domain");
    }

    // 3. Free hosting / blogging platforms used as the site host.
    if (PHISHSHIELD_FREE_HOSTS.some(d => host.endsWith(d))) {
      const sub = host.split(".")[0];
      if (sub.length > 10 || /[0-9]{3,}/.test(sub)) {
        risk += 35;
        reasons.push("Suspicious free-hosting subdomain");
      } else {
        risk += 20;
        reasons.push("Hosted on a free public platform");
      }
    }

    // 4. Raw IP address instead of a domain name.
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
      risk += 45;
      reasons.push("Uses a raw IP address instead of a domain");
    }

    // 5. URL shortener hides the real destination.
    if (PHISHSHIELD_SHORTENERS.has(host)) {
      risk += 30;
      reasons.push("URL shortener hides the real destination");
    }

    // 6. Risky / abused top-level domain.
    if (PHISHSHIELD_RISKY_TLDS.has(tld)) {
      risk += 35;
      reasons.push("Risky top-level domain (." + tld + ")");
    }

    // 7. Punycode / look-alike characters.
    if (host.includes("xn--")) {
      risk += 40;
      reasons.push("Punycode (look-alike characters) in domain");
    }

    // 8. '@' trick in the authority — the real host is after the '@'.
    if (urlStr.split("/").slice(0, 3).join("/").includes("@")) {
      risk += 40;
      reasons.push("Contains an '@' that disguises the real destination");
    }

    // 9. Not HTTPS.
    if (url.protocol !== "https:") {
      risk += 20;
      reasons.push("Connection is not secure (no HTTPS)");
    }

    // 10. Suspicious keywords (login, verify, secure, account...). These now
    //     count on their own and stack — multiple sensitive words is a tell.
    const hitWords = PHISHSHIELD_SUSPICIOUS_WORDS.filter(w => full.includes(w));
    if (hitWords.length) {
      risk += Math.min(18 * hitWords.length, 45);
      reasons.push('Contains sensitive keyword(s): ' + hitWords.slice(0, 4).join(", "));
    }

    // 11. Hyphen-stuffed hostname (e.g. secure-paypal-login-verify).
    const hyphenCount = (host.match(/-/g) || []).length;
    if (hyphenCount >= 2) {
      risk += 15;
      reasons.push("Hostname is hyphen-stuffed (" + hyphenCount + " hyphens)");
    }

    // 12. Excessive subdomains.
    const dotCount = (host.match(/\./g) || []).length;
    if (dotCount >= 4) {
      risk += 15;
      reasons.push("Unusually many subdomains");
    }

    // 13. Very long hostname is often used to bury a deceptive domain.
    if (host.length > 40) {
      risk += 10;
      reasons.push("Unusually long hostname");
    }

    risk = Math.max(0, Math.min(risk, 100));
    const score = 100 - risk; // safety score for the UI

    let verdict = "safe";
    if (risk >= 60) verdict = "danger";
    else if (risk >= 25) verdict = "warn";

    if (!reasons.length) reasons.push("No local risk indicators");

    return { score, verdict, reasons };
  } catch (e) {
    return { score: 40, verdict: "warn", reasons: ["Invalid or unparseable URL"] };
  }
}

function SUSPICIOUS_FIND(full) {
  return PHISHSHIELD_SUSPICIOUS_WORDS.find(w => full.includes(w));
}

if (typeof self !== "undefined") {
  self.phishshieldScoreUrl = phishshieldScoreUrl;
}