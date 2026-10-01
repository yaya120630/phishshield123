// lib/scanner.js - local (offline) URL scoring for PhishShield.
// FIXED: PHISHSHIELD_BRANDS and PHISHSHIELD_OFFICIAL_DOMAINS were used but never defined,
// which made phishshieldScoreUrl() throw a ReferenceError on every call.

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

// Defaults used only if another file has not already defined these lists.
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
  "instagram.com", "amazon.com", "amazon.co.uk", "amazon.de", "amazon.sg",
  "netflix.com", "linkedin.com", "maybank2u.com.my", "maybank.com",
  "cimbclicks.com.my", "cimb.com.my", "cimb.com", "pbebank.com", "publicbank.com.my",
  "rhbgroup.com", "rhbbank.com.my", "hsbc.com", "hsbc.com.my", "dhl.com"
];

// Inside phishshieldScoreUrl(url) function in scanner.js

function phishshieldScoreUrl(urlStr) {
    let score = 99;
    const reasons = [];
    
    try {
        const url = new URL(urlStr);
        const host = url.hostname.toLowerCase();
        
        // Check for free hosting / blogging platforms commonly abused for phishing
        const freeHostingDomains = ['blogspot.com', 'wordpress.com', 'weebly.com', 'wixsite.com', '000webhostapp.com'];
        const isFreeHost = freeHostingDomains.some(domain => host.endsWith(domain));
        
        if (isFreeHost) {
            // Check for random gibberish subdomain names (e.g., moalgagaljoon)
            const subdomain = host.split('.')[0];
            if (subdomain.length > 10 || /[^a-z0-9]/i.test(subdomain) || /[0-9]{3,}/.test(subdomain)) {
                score -= 40;
                reasons.push('Suspicious or long free subdomain structure');
            } else {
                score -= 20;
                reasons.push('Hosted on free public blogging platform');
            }
        }

        // Detect Facebook / social media impersonation keywords in non-official domains
        const sensitiveKeywords = ['facebook', 'fb', 'login', 'verify', 'account', 'secure', 'meta'];
        if (!host.includes('facebook.com') && !host.includes('meta.com')) {
            const hasKeyword = sensitiveKeywords.some(kw => urlStr.toLowerCase().includes(kw));
            if (hasKeyword) {
                score -= 50;
                reasons.push('Contains brand impersonation keywords');
            }
        }

        // Determine Verdict based on updated score
        let verdict = 'safe';
        if (score < 50) verdict = 'danger';
        else if (score < 80) verdict = 'warn';

        return { score, verdict, reasons };
    } catch (e) {
        return { score: 50, verdict: 'warn', reasons: ['Invalid URL format'] };
    }
}
function SUSPICIOUS_FIND(full) {
  return PHISHSHIELD_SUSPICIOUS_WORDS.find(w => full.includes(w));
}

// Expose for both service-worker (importScripts) and page (<script>) contexts.
if (typeof self !== "undefined") {
  self.phishshieldScoreUrl = phishshieldScoreUrl;
}