# PhishGuard Evaluation Report

**Generated:** 2026-09-19 20:25 UTC  
**Dataset size:** 500 URLs  
**Phishing samples:** 250  
**Legitimate samples:** 250  
**Decision threshold:** score >= 5 is flagged as phishing/suspicious

## Results

| Metric | Result |
|---|---:|
| Accuracy | 74.2% |
| Precision | 96.9% |
| Recall | 50.0% |
| F1 score | 66.0% |
| Specificity | 98.4% |
| False-positive rate | 1.6% |
| False-negative rate | 50.0% |

## Confusion Matrix

|  | Predicted phishing | Predicted legitimate |
|---|---:|---:|
| Actual phishing | 125 | 125 |
| Actual legitimate | 4 | 246 |

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
