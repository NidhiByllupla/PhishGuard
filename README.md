# 🛡️ PhishGuard
**Live Demo:** https://phishguard-nidhi.streamlit.app

**GitHub Repository:** https://github.com/NidhiByllupla/PhishGuard

PhishGuard is an independently developed cybersecurity platform that analyzes URLs and email content for phishing and social-engineering indicators.

The application combines explainable, rule-based detection with a weighted 0–100 risk-scoring system, allowing users to see not only whether content appears suspicious, but also which technical or social-engineering indicators contributed to the result.

> PhishGuard analyzes URL strings and email text locally. It does **not** visit
> submitted links.

## Why I Built It

Phishing attacks often succeed through a combination of technical deception and psychological manipulation. I created PhishGuard to explore both sides of that problem by analyzing suspicious URL structures alongside common social-engineering tactics such as urgency, credential requests, account threats, and financial pressure.

The project was designed around explainability rather than black-box classification, so users can understand how individual warning signs contribute to an overall risk assessment.

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

## Explainable Risk Scoring

Each indicator contributes a documented weight to the overall score.

| Score | Classification |
|---|---|
| 0–39 | Low Risk |
| 40–69 | Medium Risk |
| 70–100 | High Risk |

Every result includes the indicators that affected the score.

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
├── tests/
│   ├── test_url_analyzer.py
│   └── test_email_analyzer.py
├── data/
│   └── sample_test_cases.csv
├── docs/
│   └── methodology.md
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

Then open the local Streamlit address shown in your terminal.

## Run Tests

```bash
pytest
```

## Example

A URL such as:

```text
http://paypa1-account-login-secure.example.com/verify
```

may trigger multiple indicators, including:

- HTTP usage
- suspicious account/login terminology
- excessive hyphenation
- possible digit substitution

PhishGuard then calculates a risk score and explains each detected feature.

## Methodology

See [`docs/methodology.md`](docs/methodology.md) for the current scoring
approach, design decisions, safety model, and limitations.

## Technical Design

PhishGuard is organized as a modular Python application with separate components for:

- URL feature extraction
- email/social-engineering analysis
- weighted risk scoring
- shared utility functions
- automated testing
- Streamlit-based web deployment

This structure makes the project easier to test, maintain, and expand as new detection methods are added.

## Limitations

PhishGuard is an educational cybersecurity tool and is **not** a replacement
for professional threat intelligence, browser protections, secure email
gateways, or endpoint-security products.

Rule-based detection can produce both false positives and false negatives.
A low score does not guarantee that a URL or email is safe.

## Future Improvements

Planned directions include:

- evaluation on a larger labeled dataset
- precision / recall / F1 measurement
- email-header analysis
- improved brand-impersonation detection
- domain-reputation integrations using safe external APIs
- optional machine-learning comparison model

## Technologies

- Python
- Streamlit
- pytest
- `urllib.parse`
- regular expressions
- IP address parsing

## Author

**Nidhi Byllupla**
