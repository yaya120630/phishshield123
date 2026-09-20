"""
Evaluates PHISHSHIELD's heuristics.score_url() against a small labelled
test set of phishing-pattern URLs and legitimate URLs.

IMPORTANT SCOPE NOTE:
This only evaluates the local rule-based heuristic scorer
(backend/app/services/heuristics.py). It does NOT evaluate VirusTotal
or Gemini, because both require live API keys + internet access to
their respective APIs, neither of which is available in this
environment. In the real pipeline (routers/detect.py), VirusTotal
(weight 0.5) and Gemini (weight 0.35) dominate the blended score;
heuristics only carries weight 0.15 when all three signals are
present. So this number is a lower bound / partial-system result,
not the full-system accuracy your supervisor asked for.

Verdict threshold mirrors _combine() in detect.py when heuristics is
the only available signal (VT/Gemini disabled): risk>=70 -> phishing,
risk>=35 -> suspicious, else -> safe. "Detected" = phishing OR
suspicious (i.e., flagged as risky in any way).
"""
import os
import sys

# Assumes this script sits next to your project's "backend" folder
# (i.e. you placed it inside phishshield-full-project-updated/).
# Adjust this path if you put the script somewhere else.
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "backend"))

from app.services.heuristics import score_url

# Labelled test set. Phishing-pattern URLs below are ILLUSTRATIVE strings
# built to mimic real-world phishing characteristics (typosquatting,
# IP hosts, suspicious keywords, punycode, shorteners) - not live sites.
PHISHING_URLS = [
    "http://192.168.45.12/login/verify-account",
    "http://paypal-secure-login.com.verify-account.info/signin",
    "https://appleid-confirm-billing.xyz/account/update",
    "http://bit.ly/3xJ9k2a",
    "https://www.paypa1.com/signin",
    "http://secure-bankofamerica.account-update.tk/login",
    "https://xn--80ak6aa92e.com/login",
    "http://amaz0n-account-suspend.com/verify",
    "https://facebook-security-alert.confirm-login.net/",
    "http://192.0.2.55/banking/secure/confirm",
    "https://login-microsoftonline.verify-billing.com/",
    "http://tinyurl.com/2p8x7fcd",
    "https://www.dropbox-file-share.password-reset.co/",
    "http://update-icloud-account.suspend.info/signin",
    "https://secure.chase-verify-account.billing-update.com/",
    "http://goo.gl/aB3xY9",
    "https://netflix-billing-suspended.account-confirm.top/",
    "http://192.168.1.1@paypal.com/login",
    "https://www.instagram-copyright-appeal.verify-now.xyz/",
    "http://wellsfargo.account-locked.confirm-login.info/",
]

LEGITIMATE_URLS = [
    "https://www.google.com/",
    "https://github.com/anthropics",
    "https://www.wikipedia.org/",
    "https://www.python.org/downloads/",
    "https://www.microsoft.com/en-us/",
    "https://www.apple.com/",
    "https://www.amazon.com/",
    "https://www.nytimes.com/section/technology",
    "https://stackoverflow.com/questions",
    "https://www.bbc.com/news",
    "https://www.npmjs.com/package/docx",
    "https://docs.python.org/3/library/re.html",
    "https://www.reddit.com/r/programming/",
    "https://www.linkedin.com/",
    "https://www.spotify.com/",
    "https://www.dropbox.com/",
    "https://www.paypal.com/",
    "https://mail.google.com/",
    "https://www.cloudflare.com/",
    "https://www.mozilla.org/en-US/firefox/",
]


def classify(score: int) -> str:
    if score >= 70:
        return "phishing"
    elif score >= 35:
        return "suspicious"
    else:
        return "safe"


def run_eval():
    rows = []
    for url in PHISHING_URLS:
        r = score_url(url)
        pred = classify(r["score"])
        rows.append((url, "phishing", pred, r["score"], r["reasons"]))
    for url in LEGITIMATE_URLS:
        r = score_url(url)
        pred = classify(r["score"])
        rows.append((url, "legitimate", pred, r["score"], r["reasons"]))

    tp = fp = fn = tn = 0
    for url, actual, pred, score, reasons in rows:
        detected = pred in ("phishing", "suspicious")
        if actual == "phishing" and detected:
            tp += 1
        elif actual == "phishing" and not detected:
            fn += 1
        elif actual == "legitimate" and detected:
            fp += 1
        else:
            tn += 1

    total = tp + fp + fn + tn
    accuracy = (tp + tn) / total if total else 0
    precision = tp / (tp + fp) if (tp + fp) else 0
    recall = tp / (tp + fn) if (tp + fn) else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0

    print(f"{'URL':60s} {'Actual':11s} {'Predicted':11s} {'Score':>5s}")
    print("-" * 95)
    for url, actual, pred, score, reasons in rows:
        print(f"{url[:58]:60s} {actual:11s} {pred:11s} {score:5d}")

    print("\n=== Confusion Matrix (heuristics-only, N=%d) ===" % total)
    print(f"TP={tp}  FP={fp}  FN={fn}  TN={tn}")
    print(f"\nAccuracy:  {accuracy*100:.1f}%")
    print(f"Precision: {precision*100:.1f}%")
    print(f"Recall:    {recall*100:.1f}%")
    print(f"F1-score:  {f1*100:.1f}%")


if __name__ == "__main__":
    run_eval()
