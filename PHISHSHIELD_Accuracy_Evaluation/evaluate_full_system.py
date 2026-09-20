"""
Evaluates PHISHSHIELD's FULL detection pipeline (VirusTotal + Gemini +
WHOIS domain-age + local heuristics, combined via _combine() in
routers/detect.py) against a labelled test set of phishing and
legitimate URLs.

HOW TO RUN THIS:
1. Make sure your backend is running with real API keys configured:
     cd backend
     cp .env.example .env        # if not done already
     # edit .env and set VT_API_KEY and GEMINI_API_KEY
     pip install -r requirements.txt
     uvicorn app.main:app --reload --port 8000

2. In another terminal, install the one dependency this script needs:
     pip install httpx

3. Run this script (from anywhere, as long as the backend is up):
     python evaluate_full_system.py

   Optional: point it at a different backend URL or a bigger test set:
     python evaluate_full_system.py --base-url http://127.0.0.1:8000 --dataset urls.csv

This calls your REAL /api/detect endpoint once per URL, so it will
consume VirusTotal + Gemini API quota (VT free tier: 4 req/min, 500/day
-- this script has a small delay between calls to respect that).

OUTPUT:
- Prints a per-URL table + confusion matrix + accuracy/precision/recall/F1
  to the console.
- Writes results.csv (per-URL raw results) and results_summary.json
  (the final metrics) in the current directory, so you can paste the
  numbers straight into your abstract / Chapter 5 (Results).
"""
import argparse
import asyncio
import csv
import json
import sys
import time

import httpx

# ---------------------------------------------------------------------
# Labelled test set. Phishing-pattern URLs below are ILLUSTRATIVE
# strings built to mimic real-world phishing characteristics
# (typosquatting, IP hosts, suspicious keywords, punycode, shorteners)
# for TESTING PURPOSES ONLY -- they are not guaranteed to be live,
# and are not sent anywhere except your own local /api/detect endpoint.
# For a stronger evaluation, replace/extend this list with real,
# recently-reported URLs from a source like PhishTank (phishing) and
# Tranco/Alexa top sites (legitimate).
# ---------------------------------------------------------------------
DEFAULT_DATASET = [
    ("http://192.168.45.12/login/verify-account", "phishing"),
    ("http://paypal-secure-login.com.verify-account.info/signin", "phishing"),
    ("https://appleid-confirm-billing.xyz/account/update", "phishing"),
    ("http://bit.ly/3xJ9k2a", "phishing"),
    ("https://www.paypa1.com/signin", "phishing"),
    ("http://secure-bankofamerica.account-update.tk/login", "phishing"),
    ("https://xn--80ak6aa92e.com/login", "phishing"),
    ("http://amaz0n-account-suspend.com/verify", "phishing"),
    ("https://facebook-security-alert.confirm-login.net/", "phishing"),
    ("http://192.0.2.55/banking/secure/confirm", "phishing"),
    ("https://login-microsoftonline.verify-billing.com/", "phishing"),
    ("http://tinyurl.com/2p8x7fcd", "phishing"),
    ("https://www.dropbox-file-share.password-reset.co/", "phishing"),
    ("http://update-icloud-account.suspend.info/signin", "phishing"),
    ("https://secure.chase-verify-account.billing-update.com/", "phishing"),
    ("http://goo.gl/aB3xY9", "phishing"),
    ("https://netflix-billing-suspended.account-confirm.top/", "phishing"),
    ("http://192.168.1.1@paypal.com/login", "phishing"),
    ("https://www.instagram-copyright-appeal.verify-now.xyz/", "phishing"),
    ("http://wellsfargo.account-locked.confirm-login.info/", "phishing"),
    ("https://www.google.com/", "legitimate"),
    ("https://github.com/anthropics", "legitimate"),
    ("https://www.wikipedia.org/", "legitimate"),
    ("https://www.python.org/downloads/", "legitimate"),
    ("https://www.microsoft.com/en-us/", "legitimate"),
    ("https://www.apple.com/", "legitimate"),
    ("https://www.amazon.com/", "legitimate"),
    ("https://www.nytimes.com/section/technology", "legitimate"),
    ("https://stackoverflow.com/questions", "legitimate"),
    ("https://www.bbc.com/news", "legitimate"),
    ("https://www.npmjs.com/package/docx", "legitimate"),
    ("https://docs.python.org/3/library/re.html", "legitimate"),
    ("https://www.reddit.com/r/programming/", "legitimate"),
    ("https://www.linkedin.com/", "legitimate"),
    ("https://www.spotify.com/", "legitimate"),
    ("https://www.dropbox.com/", "legitimate"),
    ("https://www.paypal.com/", "legitimate"),
    ("https://mail.google.com/", "legitimate"),
    ("https://www.cloudflare.com/", "legitimate"),
    ("https://www.mozilla.org/en-US/firefox/", "legitimate"),
]


def load_dataset(path: str | None):
    if not path:
        return DEFAULT_DATASET
    rows = []
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.reader(f)
        for row in reader:
            if not row or row[0].strip().lower() == "url":
                continue  # skip header/blank lines
            url, label = row[0].strip(), row[1].strip().lower()
            rows.append((url, label))
    return rows


async def detect_one(client: httpx.AsyncClient, base_url: str, url: str) -> dict:
    try:
        resp = await client.post(f"{base_url}/api/detect", json={"url": url}, timeout=30.0)
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        return {"error": str(e), "verdict": None}


async def run(base_url: str, dataset, delay_seconds: float):
    results = []
    async with httpx.AsyncClient() as client:
        for i, (url, label) in enumerate(dataset, 1):
            print(f"[{i}/{len(dataset)}] Scanning: {url}")
            r = await detect_one(client, base_url, url)
            results.append({
                "url": url,
                "actual": label,
                "verdict": r.get("verdict"),
                "confidence_score": r.get("confidence_score"),
                "vt_positives": r.get("vt_positives"),
                "domain_age_days": r.get("domain_age_days"),
                "error": r.get("error"),
            })
            # Be polite to VirusTotal's free-tier rate limit (4 req/min).
            if i < len(dataset):
                time.sleep(delay_seconds)
    return results


def summarize(results):
    tp = fp = fn = tn = errors = 0
    for r in results:
        if r["error"] or r["verdict"] is None:
            errors += 1
            continue
        detected = r["verdict"] in ("phishing", "suspicious")
        actual_phishing = r["actual"] == "phishing"
        if actual_phishing and detected:
            tp += 1
        elif actual_phishing and not detected:
            fn += 1
        elif not actual_phishing and detected:
            fp += 1
        else:
            tn += 1

    total = tp + fp + fn + tn
    accuracy = (tp + tn) / total if total else 0
    precision = tp / (tp + fp) if (tp + fp) else 0
    recall = tp / (tp + fn) if (tp + fn) else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0

    return {
        "n_evaluated": total,
        "n_errors": errors,
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "accuracy": round(accuracy * 100, 1),
        "precision": round(precision * 100, 1),
        "recall": round(recall * 100, 1),
        "f1_score": round(f1 * 100, 1),
    }


def main():
    parser = argparse.ArgumentParser(description="Evaluate PHISHSHIELD's full /api/detect pipeline.")
    parser.add_argument("--base-url", default="http://127.0.0.1:8000", help="Backend base URL")
    parser.add_argument("--dataset", default=None, help="Optional CSV file: url,label (label = phishing|legitimate)")
    parser.add_argument("--delay", type=float, default=15.0, help="Seconds to wait between requests (VT free tier = 4/min)")
    args = parser.parse_args()

    dataset = load_dataset(args.dataset)
    print(f"Loaded {len(dataset)} labelled URLs. Backend: {args.base_url}\n")

    results = asyncio.run(run(args.base_url, dataset, args.delay))

    print(f"\n{'URL':55s} {'Actual':11s} {'Verdict':11s} {'Score':>6s}")
    print("-" * 90)
    for r in results:
        score = r["confidence_score"]
        score_str = f"{score:.2f}" if isinstance(score, (int, float)) else "ERR"
        print(f"{r['url'][:53]:55s} {r['actual']:11s} {str(r['verdict']):11s} {score_str:>6s}")

    summary = summarize(results)
    print("\n=== Full-System Confusion Matrix ===")
    print(f"TP={summary['tp']}  FP={summary['fp']}  FN={summary['fn']}  TN={summary['tn']}  "
          f"(errors/skipped: {summary['n_errors']})")
    print(f"\nAccuracy:  {summary['accuracy']}%")
    print(f"Precision: {summary['precision']}%")
    print(f"Recall:    {summary['recall']}%")
    print(f"F1-score:  {summary['f1_score']}%")

    with open("results.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(results[0].keys()))
        writer.writeheader()
        writer.writerows(results)

    with open("results_summary.json", "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    print("\nSaved per-URL results to results.csv")
    print("Saved summary metrics to results_summary.json")
    print("\nSuggested abstract sentence:")
    print(
        f'  "Sistem ini mencapai ketepatan (accuracy) sebanyak {summary["accuracy"]}%, '
        f'precision {summary["precision"]}%, dan recall {summary["recall"]}% berdasarkan '
        f'pengujian ke atas {summary["n_evaluated"]} sampel URL."'
    )


if __name__ == "__main__":
    main()
