# 🛡️ PhishGuard

**Live Demo:** https://phishguard-nidhi.streamlit.app

**PhishGuard** is an independently developed cybersecurity platform that
analyzes URLs and email content for phishing and social-engineering
indicators.

The application combines transparent rule-based detection with a weighted
0–100 risk-scoring system, allowing users to see not only whether content
appears suspicious, but also which technical or social-engineering
indicators contributed to the result.

> PhishGuard analyzes URL strings and email text locally. It does **not**
> visit submitted links.

## Why I Built It

Phishing attacks often succeed through a combination of technical deception
and psychological manipulation. I created PhishGuard to explore both sides
of that problem by analyzing suspicious URL structures alongside common
social-engineering tactics such as urgency, credential requests, account
threats, and financial pressure.

The project was designed around explainability rather than black-box
classification, so users can understand how individual warning signs
contribute to an overall risk assessment.

## Features

### URL analysis

PhishGuard checks for indicators including:

- HTTP instead of HTTPS
- IP-address hosts
- URL-shortening services
- suspicious account/login keywords
- excessive subdomains
- unusually long URLs
- `@` symbols
- excessive hyphenation
- punycode/IDN encoding
- encoded characters
- non-standard ports
- selected suspicious TLD patterns
- possible digit substitution
- brand-impersonation-style patterns

### Email analysis

PhishGuard evaluates email content for:

- urgency and pressure language
- account suspension/security-alert language
- credential requests
- financial/payment language
- common social-engineering phrases
- excessive punctuation or uppercase text
- embedded URLs
- suspicious embedded URLs

### Evaluation pipeline

PhishGuard now includes a reproducible evaluation workflow that can:

- build a balanced labeled URL dataset from PhishTank and Tranco
- evaluate the URL analyzer without opening any listed URL
- calculate accuracy, precision, recall, F1, specificity, FPR, and FNR
- save false positives and false negatives for error analysis
- compare performance across multiple score thresholds
- display committed evaluation metrics in the Streamlit app

See [`evaluation/README.md`](evaluation/README.md).

## Explainable Risk Scoring

Each indicator contributes a documented weight to the overall score.

| Score | Classification |
|---|---|
| 0–39 | Low Risk |
| 40–69 | Medium Risk |
| 70–100 | High Risk |

Every result includes the indicators that affected the score.

## Technical Design

PhishGuard is organized as a modular Python application with separate
components for:

- URL feature extraction
- email/social-engineering analysis
- weighted risk scoring
- shared utility functions
- automated testing
- reproducible performance evaluation
- Streamlit-based web deployment

This structure makes the project easier to test, maintain, evaluate, and
expand.

## Project Structure

```text
PhishGuard/
├── app.py
├── phishguard/
│   ├── __init__.py
│   ├── url_analyzer.py
│   ├── email_analyzer.py
│   ├── scoring.py
│   └── utils.py
├── evaluation/
│   ├── fetch_dataset.py
│   ├── evaluate.py
│   ├── metrics.py
│   ├── README.md
│   └── results/
├── tests/
├── data/
├── docs/
├── .github/workflows/tests.yml
├── README.md
├── requirements.txt
├── LICENSE
└── .gitignore
```

## Run Locally

Install dependencies:

```bash
pip install -r requirements.txt
```

Run the web application:

```bash
streamlit run app.py
```

## Run Tests

```bash
pytest -q
```

GitHub Actions also runs the test suite automatically on pushes and pull
requests to `main`.

## Build a 500-URL Evaluation Dataset

```bash
python -m evaluation.fetch_dataset
```

This creates a balanced dataset of 250 PhishTank phishing URLs and 250
Tranco-ranked legitimate domains.

Then evaluate:

```bash
python -m evaluation.evaluate
```

Generated outputs include:

- `metrics.json`
- `evaluation_report.md`
- `evaluation_results.csv`
- `misclassified_samples.csv`
- `threshold_sweep.csv`
- `indicator_breakdown.csv`

**Performance claims should only be published after reviewing these actual
outputs.**

## Methodology

See [`docs/methodology.md`](docs/methodology.md) for the scoring approach,
design decisions, safety model, and limitations.

## Limitations

PhishGuard is an educational cybersecurity tool and is **not** a replacement
for professional threat intelligence, browser protections, secure email
gateways, or endpoint-security products.

Rule-based detection can produce both false positives and false negatives.
A low score does not guarantee that a URL or email is safe.

Evaluation results depend on the selected datasets, date, class balance,
and threshold and should not be interpreted as universal real-world
detection accuracy.

## Future Improvements

Planned directions include:

- error-driven rule refinement using evaluation results
- email-header analysis
- improved brand-impersonation detection
- domain-reputation integrations using safe external APIs
- optional machine-learning comparison model
- larger and temporally separated test sets

## Technologies

- Python
- Streamlit
- pytest
- GitHub Actions
- `urllib.parse`
- regular expressions
- IP address parsing

## Author

**Nidhi Byllupla**
