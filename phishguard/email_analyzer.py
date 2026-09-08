"""Explainable email/social-engineering analysis."""

import re

from .scoring import clamp_score, risk_level
from .utils import extract_urls, dedupe_preserve_order
from .url_analyzer import analyze_url


URGENCY_TERMS = [
    "urgent", "immediately", "act now", "within 24 hours", "final warning",
    "verify now", "expires today", "limited time", "right away"
]

ACCOUNT_THREAT_TERMS = [
    "account suspended", "account has been suspended", "account locked", "account disabled",
    "unusual activity", "security alert", "unauthorized login",
    "confirm your identity"
]

CREDENTIAL_TERMS = [
    "password", "login", "sign in", "credentials",
    "verify your account", "confirm your account", "one-time code",
    "verification code", "mfa code"
]

FINANCIAL_TERMS = [
    "wire transfer", "gift card", "invoice", "refund", "bank account",
    "payment", "crypto", "wallet", "routing number"
]

SOCIAL_ENGINEERING_TERMS = [
    "click here", "download attachment", "open attachment",
    "you have won", "claim your prize", "keep this confidential",
    "do not contact", "boss asked", "ceo requested"
]


def _match_terms(text, terms):
    return dedupe_preserve_order([term for term in terms if term in text])


def analyze_email(email_text: str) -> dict:
    """Analyze email body text for phishing/social-engineering indicators."""
    text = (email_text or "").strip()
    lower = text.lower()
    indicators = []

    if not text:
        return {
            "type": "Email",
            "input": email_text,
            "score": 0,
            "risk": "LOW RISK",
            "indicators": [],
            "urls": [],
            "summary": "No email text was provided."
        }

    urgency = _match_terms(lower, URGENCY_TERMS)
    if urgency:
        indicators.append({
            "code": "URGENCY_LANGUAGE",
            "weight": min(5 * len(urgency), 18),
            "message": "Uses urgency or pressure language.",
            "evidence": ", ".join(urgency)
        })

    threats = _match_terms(lower, ACCOUNT_THREAT_TERMS)
    if threats:
        indicators.append({
            "code": "ACCOUNT_THREATS",
            "weight": min(7 * len(threats), 21),
            "message": "Uses account-threat or security-alert language.",
            "evidence": ", ".join(threats)
        })

    credentials = _match_terms(lower, CREDENTIAL_TERMS)
    if credentials:
        indicators.append({
            "code": "CREDENTIAL_LANGUAGE",
            "weight": min(8 * len(credentials), 24),
            "message": "References credentials or account-verification actions.",
            "evidence": ", ".join(credentials)
        })

    financial = _match_terms(lower, FINANCIAL_TERMS)
    if financial:
        indicators.append({
            "code": "FINANCIAL_LANGUAGE",
            "weight": min(7 * len(financial), 21),
            "message": "Contains financial or payment-related language.",
            "evidence": ", ".join(financial)
        })

    social = _match_terms(lower, SOCIAL_ENGINEERING_TERMS)
    if social:
        indicators.append({
            "code": "SOCIAL_ENGINEERING_LANGUAGE",
            "weight": min(6 * len(social), 18),
            "message": "Contains language commonly associated with social engineering.",
            "evidence": ", ".join(social)
        })

    # Excessive punctuation / shouting
    exclamation_count = text.count("!")
    if exclamation_count >= 3:
        indicators.append({
            "code": "EXCESSIVE_EXCLAMATION",
            "weight": 5,
            "message": "Uses excessive exclamation marks, which can reinforce urgency.",
            "evidence": str(exclamation_count)
        })

    uppercase_words = re.findall(r"\b[A-Z]{4,}\b", text)
    if len(uppercase_words) >= 3:
        indicators.append({
            "code": "EXCESSIVE_UPPERCASE",
            "weight": 5,
            "message": "Contains multiple all-uppercase words.",
            "evidence": ", ".join(uppercase_words[:8])
        })

    # URL analysis
    urls = extract_urls(text)
    suspicious_urls = []

    for url in urls:
        result = analyze_url(url)
        if result["score"] >= 40:
            suspicious_urls.append({
                "url": url,
                "score": result["score"],
                "risk": result["risk"]
            })

    if urls:
        indicators.append({
            "code": "CONTAINS_LINKS",
            "weight": 6,
            "message": "Contains one or more links that should be independently verified.",
            "evidence": str(len(urls))
        })

    if suspicious_urls:
        indicators.append({
            "code": "SUSPICIOUS_LINKS",
            "weight": min(14 * len(suspicious_urls), 28),
            "message": "Contains URL(s) that independently trigger phishing indicators.",
            "evidence": ", ".join(item["url"] for item in suspicious_urls[:3])
        })

    score = clamp_score(sum(item["weight"] for item in indicators))

    return {
        "type": "Email",
        "input": email_text,
        "score": score,
        "risk": risk_level(score),
        "indicators": indicators,
        "urls": urls,
        "suspicious_urls": suspicious_urls,
        "summary": (
            "No major social-engineering indicators detected by the current rule set."
            if not indicators
            else f"Detected {len(indicators)} phishing/social-engineering indicator(s)."
        )
    }
