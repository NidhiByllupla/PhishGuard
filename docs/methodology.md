# PhishGuard Methodology

## Overview

PhishGuard is an explainable, rule-based cybersecurity project that evaluates
URLs and email text for common phishing and social-engineering indicators.

The system is intentionally transparent: each detected feature contributes a
documented number of points to an overall risk score.

## Design Goals

1. **Explainability** — users can see why a score was assigned.
2. **Safety** — submitted URLs are analyzed as strings and are not visited.
3. **Modularity** — URL and email analysis are separated into reusable modules.
4. **Testability** — core behaviors are covered by automated tests.
5. **Honest limitations** — the project does not claim to replace professional
   email gateways, browser protections, or threat-intelligence services.

## URL Features

The URL analyzer currently evaluates features including:

- HTTP vs. HTTPS
- IP-address hosts
- URL-shortening services
- suspicious authentication/account keywords
- excessive subdomains
- unusually long URLs
- `@` symbols
- excessive hyphenation
- punycode/IDN encoding
- multiple percent-encoded characters
- non-standard ports
- selected high-abuse-style TLD patterns
- possible digit substitution
- brand-impersonation-style domain structures

## Email Features

The email analyzer evaluates:

- urgency and pressure language
- account-threat language
- credential-verification language
- financial/payment language
- common social-engineering phrases
- excessive punctuation
- excessive uppercase text
- embedded URLs
- embedded URLs that independently trigger phishing indicators

## Risk Levels

- **0–39:** Low Risk
- **40–69:** Medium Risk
- **70–100:** High Risk

The numerical weights are heuristic and are designed for educational
experimentation rather than production threat detection.

## Privacy and Safety

PhishGuard does **not** automatically open or request submitted URLs.
Analysis is performed locally on text structure. This reduces the risk of
accidentally interacting with malicious websites during analysis.

## Limitations

PhishGuard can produce false positives and false negatives. Examples include:

- legitimate account-recovery messages that use urgent language
- sophisticated phishing pages hosted on otherwise normal-looking domains
- attacks that rely primarily on sender spoofing or malicious attachments
- newly registered or compromised domains that do not exhibit lexical warning signs

## Future Evaluation

A future version can evaluate the tool against a larger labeled dataset and
report metrics such as:

- precision
- recall
- F1 score
- false-positive rate
- false-negative rate

These metrics should only be published after the dataset and evaluation method
are documented.
