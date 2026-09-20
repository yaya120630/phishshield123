# PHISHSHIELD — Detection Accuracy Evaluation Kit

This folder helps you produce the measurable accuracy result your
supervisor asked for (Chapter 5 / Abstract):

> "How accurate is the phishing detection? Include measurable
> evaluation results, particularly the performance of the phishing
> URL detection model."

It contains two scripts:

| Script | Tests | Needs API keys? | Needs backend running? |
|---|---|---|---|
| `evaluate_heuristics.py` | Local rule-based scorer only (`heuristics.py`) | No | No |
| `evaluate_full_system.py` | **Full pipeline**: VirusTotal + Gemini + WHOIS + heuristics, combined (`_combine()` in `detect.py`) | **Yes** | **Yes** |

For your report, use **`evaluate_full_system.py`** — that's the one
that reflects the actual system your supervisor is asking about.
`evaluate_heuristics.py` is included only for comparison (it's what
was already run for you, giving 70.0% accuracy / 100% precision /
40% recall / 57.1% F1 on 40 URLs — but that's just one of four
signals, weighted only 0.15 in the real system).

---

## Steps to run the full-system evaluation

### 1. Start your backend with real API keys

```bash
cd backend
cp .env.example .env
# edit .env and set:
#   VT_API_KEY=your_virustotal_key       (https://www.virustotal.com/gui/my-apikey)
#   GEMINI_API_KEY=your_gemini_key       (https://aistudio.google.com/apikey)

pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

Leave this terminal running. Confirm it's up by visiting
`http://127.0.0.1:8000/health` in your browser.

### 2. Install the one extra dependency the evaluation script needs

In a **second terminal**:

```bash
pip install httpx
```

### 3. Run the evaluation

```bash
python evaluate_full_system.py
```

This sends each of the 40 labelled test URLs (20 phishing-pattern, 20
legitimate — built into the script) to your real `/api/detect`
endpoint, one at a time, with a 15-second delay between requests so
you don't exceed VirusTotal's free-tier limit (4 requests/min).

With 40 URLs and a 15s delay, expect this to take **roughly 10
minutes**.

### 4. Read the results

The script prints a table and a confusion matrix straight to your
terminal, and also saves:

- `results.csv` — every URL, its true label, the system's verdict,
  and confidence score (useful as a results table/appendix in your
  report)
- `results_summary.json` — the final accuracy/precision/recall/F1
  numbers

At the end it also prints a ready-to-use sentence in Malay you can
paste straight into your abstract.

---

## Using your own / a bigger dataset (recommended)

The built-in 40-URL set is illustrative. For a stronger, more
defensible result, replace it with real reported URLs:

- **Phishing URLs**: export a sample from [PhishTank](https://phishtank.org/) or [OpenPhish](https://openphish.com/)
- **Legitimate URLs**: use the [Tranco top sites list](https://tranco-list.eu/) or similar

Save them as a CSV with two columns (`url,label`, where label is
`phishing` or `legitimate`), then run:

```bash
python evaluate_full_system.py --dataset your_urls.csv
```

A larger, more realistic dataset (aim for 100+ URLs per class if you
have time) will make your accuracy figure much more convincing to
your supervisor than 40 illustrative examples.

---

## Notes

- The scripts never modify your project code — they only call the
  already-existing `/api/detect` endpoint (full system) or import
  `heuristics.py` directly (heuristics-only).
- If a request errors (e.g. VT rate limit hit), it's recorded as an
  error/skipped row rather than silently counted as correct or
  incorrect — check the `n_errors` field in `results_summary.json`.
- If you rerun this multiple times on the same URLs, VirusTotal
  results should be stable (already-scanned URLs return cached
  vendor verdicts), but Gemini's phrasing/verdict may vary slightly
  between runs since it's a generative model — this is normal.
