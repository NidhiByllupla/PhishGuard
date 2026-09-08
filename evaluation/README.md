# PhishGuard Evaluation Pipeline

This directory contains the reproducible evaluation workflow for the URL
analyzer.

## What it does

1. Downloads phishing URL records from the verified-online PhishTank feed.
2. Downloads legitimate domains from the Tranco top-sites ranking.
3. Creates a balanced, labeled dataset.
4. Runs every URL through PhishGuard without visiting the listed sites.
5. Calculates accuracy, precision, recall, F1, specificity, FPR, and FNR.
6. Saves every prediction, all misclassifications, an indicator breakdown,
   and a threshold sweep for error analysis.

## Build the default 500-URL dataset

```bash
python -m evaluation.fetch_dataset
```

Default class balance:

- 250 verified-online phishing URLs
- 250 Tranco-ranked legitimate domains

For a larger evaluation:

```bash
python -m evaluation.fetch_dataset --phishing 500 --legitimate 500
```

PhishTank may rate-limit unauthenticated downloads. If you create a free
application key, set it before running:

```bash
export PHISHTANK_APP_KEY="your_key_here"
```

Do not commit your key to GitHub.

## Run the evaluation

```bash
python -m evaluation.evaluate
```

The primary threshold is 40 because scores of 40 or higher are already
classified by PhishGuard as Medium or High Risk.

## Generated outputs

The `evaluation/results/` folder will contain:

- `metrics.json`
- `evaluation_report.md`
- `evaluation_results.csv`
- `misclassified_samples.csv`
- `threshold_sweep.csv`
- `indicator_breakdown.csv`

These should be reviewed before publishing any performance claim.

## Important interpretation note

Evaluation metrics depend on the dataset, sampling date, class balance, and
threshold. Do not describe the results as universal phishing-detection
accuracy. Report the dataset size, sources, and threshold alongside the
metrics.
