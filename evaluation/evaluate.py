"""Evaluate PhishGuard's URL analyzer on a labeled CSV dataset.

Primary binary decision rule:
    score >= threshold  -> phishing/suspicious
    score < threshold   -> legitimate/not flagged

The default threshold is 40 because PhishGuard classifies scores from 40-69
as MEDIUM RISK and 70+ as HIGH RISK.

Usage:
    python -m evaluation.evaluate
    python -m evaluation.evaluate --threshold 40
"""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from phishguard.url_analyzer import analyze_url
from evaluation.metrics import classification_metrics


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DATASET = ROOT / "data" / "evaluation_dataset.csv"
RESULTS_DIR = Path(__file__).resolve().parent / "results"


def load_dataset(path: Path):
    if not path.exists():
        raise FileNotFoundError(
            f"Dataset not found: {path}\n"
            "Build it first with: python -m evaluation.fetch_dataset"
        )

    rows = []
    with path.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        required = {"url", "label"}
        missing = required - set(reader.fieldnames or [])
        if missing:
            raise ValueError(
                "Dataset is missing required columns: " + ", ".join(sorted(missing))
            )

        for row in reader:
            try:
                label = int(row["label"])
            except (TypeError, ValueError):
                raise ValueError(f"Invalid label: {row.get('label')!r}")

            if label not in {0, 1}:
                raise ValueError("Labels must be 0 (legitimate) or 1 (phishing).")

            url = (row.get("url") or "").strip()
            if not url:
                continue

            row["label"] = label
            rows.append(row)

    if not rows:
        raise ValueError("Dataset contains no usable rows.")
    return rows


def evaluate_rows(rows, threshold: int):
    detailed = []
    indicator_counts = Counter()

    for row in rows:
        result = analyze_url(row["url"])
        score = int(result["score"])
        prediction = 1 if score >= threshold else 0
        codes = [item["code"] for item in result["indicators"]]
        indicator_counts.update(codes)

        detailed.append({
            **row,
            "score": score,
            "risk": result["risk"],
            "prediction": prediction,
            "prediction_name": "phishing" if prediction else "legitimate",
            "correct": prediction == int(row["label"]),
            "indicator_count": len(codes),
            "indicators": "|".join(codes),
        })

    labels = [int(r["label"]) for r in detailed]
    predictions = [int(r["prediction"]) for r in detailed]
    metrics = classification_metrics(labels, predictions)
    return detailed, metrics, indicator_counts


def threshold_sweep(rows):
    scores = []
    labels = []
    for row in rows:
        scores.append(int(analyze_url(row["url"])["score"]))
        labels.append(int(row["label"]))

    sweep = []
    for threshold in range(10, 91, 5):
        predictions = [1 if score >= threshold else 0 for score in scores]
        m = classification_metrics(labels, predictions)
        sweep.append({"threshold": threshold, **m})
    return sweep


def _write_csv(path: Path, rows):
    rows = list(rows)
    if not rows:
        path.write_text("", encoding="utf-8")
        return

    fieldnames = list(rows[0].keys())
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def _pct(value):
    return f"{100 * value:.1f}%"


def write_report(metrics, threshold, total, phishing_n, legitimate_n, output):
    report = f"""# PhishGuard Evaluation Report

**Generated:** {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")}  
**Dataset size:** {total} URLs  
**Phishing samples:** {phishing_n}  
**Legitimate samples:** {legitimate_n}  
**Decision threshold:** score >= {threshold} is flagged as phishing/suspicious

## Results

| Metric | Result |
|---|---:|
| Accuracy | {_pct(metrics['accuracy'])} |
| Precision | {_pct(metrics['precision'])} |
| Recall | {_pct(metrics['recall'])} |
| F1 score | {_pct(metrics['f1'])} |
| Specificity | {_pct(metrics['specificity'])} |
| False-positive rate | {_pct(metrics['false_positive_rate'])} |
| False-negative rate | {_pct(metrics['false_negative_rate'])} |

## Confusion Matrix

|  | Predicted phishing | Predicted legitimate |
|---|---:|---:|
| Actual phishing | {metrics['tp']} | {metrics['fn']} |
| Actual legitimate | {metrics['fp']} | {metrics['tn']} |

## Interpretation

- **Precision** measures how often a URL flagged by PhishGuard was actually labeled phishing.
- **Recall** measures how many labeled phishing URLs PhishGuard successfully flagged.
- **F1** balances precision and recall.
- **Specificity** measures how well PhishGuard avoided flagging legitimate URLs.
- False positives and false negatives are saved separately for error analysis.

## Methodology Notes

PhishGuard performs static, rule-based analysis of URL strings. It does not
connect to, open, or crawl any URL in the evaluation dataset. The primary
threshold is 40 because the application labels scores of 40-69 as MEDIUM
RISK and 70+ as HIGH RISK.

The dataset builder uses verified-online PhishTank records for the phishing
class and Tranco-ranked domains for the legitimate class. These labels are
useful for evaluation but are not perfect ground truth; popular domains can
be compromised, and phishing feeds can change over time.

See `threshold_sweep.csv`, `misclassified_samples.csv`, and
`indicator_breakdown.csv` for deeper analysis.
"""
    output.write_text(textwrap_cleanup(report), encoding="utf-8")


def textwrap_cleanup(text):
    # Remove the indentation caused by embedding the markdown in source code.
    lines = text.splitlines()
    cleaned = []
    for line in lines:
        cleaned.append(line[4:] if line.startswith("    ") else line)
    return "\n".join(cleaned).strip() + "\n"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    parser.add_argument("--threshold", type=int, default=40)
    args = parser.parse_args()

    if not 0 <= args.threshold <= 100:
        raise SystemExit("Threshold must be between 0 and 100.")

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    rows = load_dataset(args.dataset)

    detailed, metrics, indicator_counts = evaluate_rows(rows, args.threshold)
    sweep = threshold_sweep(rows)

    phishing_n = sum(int(r["label"]) == 1 for r in rows)
    legitimate_n = sum(int(r["label"]) == 0 for r in rows)

    metrics_payload = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "dataset": str(args.dataset),
        "dataset_size": len(rows),
        "phishing_samples": phishing_n,
        "legitimate_samples": legitimate_n,
        "threshold": args.threshold,
        **metrics,
    }

    (RESULTS_DIR / "metrics.json").write_text(
        json.dumps(metrics_payload, indent=2),
        encoding="utf-8"
    )
    _write_csv(RESULTS_DIR / "evaluation_results.csv", detailed)
    _write_csv(
        RESULTS_DIR / "misclassified_samples.csv",
        [r for r in detailed if not r["correct"]]
    )
    _write_csv(RESULTS_DIR / "threshold_sweep.csv", sweep)

    indicator_rows = [
        {"indicator": code, "detections": count}
        for code, count in indicator_counts.most_common()
    ]
    _write_csv(RESULTS_DIR / "indicator_breakdown.csv", indicator_rows)

    write_report(
        metrics,
        args.threshold,
        len(rows),
        phishing_n,
        legitimate_n,
        RESULTS_DIR / "evaluation_report.md",
    )

    print(f"Evaluated {len(rows)} URLs at threshold {args.threshold}.")
    print(f"Accuracy:  {metrics['accuracy']:.3f}")
    print(f"Precision: {metrics['precision']:.3f}")
    print(f"Recall:    {metrics['recall']:.3f}")
    print(f"F1:        {metrics['f1']:.3f}")
    print(f"Results written to: {RESULTS_DIR}")


if __name__ == "__main__":
    main()
