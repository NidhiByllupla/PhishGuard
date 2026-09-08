"""Explainable URL phishing analysis."""

import re
from urllib.parse import urlparse

from .scoring import clamp_score, risk_level
from .utils import normalize_url, hostname_from_url, is_ip_address, dedupe_preserve_order


SUSPICIOUS_KEYWORDS = [
    "login", "verify", "secure", "account", "update", "confirm",
    "password", "signin", "payment", "wallet", "invoice",
    "recover", "unlock", "authentication", "security-alert"
]

URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "cutt.ly", "rebrand.ly", "tiny.cc"
]

COMMON_BRANDS = [
    "paypal", "microsoft", "apple", "google", "amazon", "netflix",
    "facebook", "instagram", "chase", "wellsfargo", "bankofamerica"
]

SUSPICIOUS_TLDS = {
    "zip", "mov", "click", "top", "xyz", "work", "support", "country"
}


def _add_indicator(indicators, code, weight, message, evidence=None):
    indicators.append({
        "code": code,
        "weight": weight,
        "message": message,
        "evidence": evidence
    })


def analyze_url(url: str) -> dict:
    """
    Analyze a URL using transparent heuristics.

    Important:
    PhishGuard analyzes the URL string only. It does not visit the site.
    """
    normalized = normalize_url(url)

    if not normalized:
        return {
            "type": "URL",
            "input": url,
            "normalized": "",
            "score": 0,
            "risk": "LOW RISK",
            "indicators": [],
            "summary": "No URL was provided."
        }

    parsed = urlparse(normalized)
    hostname = hostname_from_url(normalized)
    full_url = normalized.lower()
    indicators = []

    # 1. HTTP rather than HTTPS
    if parsed.scheme == "http":
        _add_indicator(
            indicators, "HTTP_SCHEME", 12,
            "Uses HTTP instead of HTTPS."
        )

    # 2. IP-based host
    if hostname and is_ip_address(hostname):
        _add_indicator(
            indicators, "IP_HOST", 24,
            "Uses an IP address instead of a standard domain name.",
            hostname
        )

    # 3. URL shortener
    if any(hostname == s or hostname.endswith("." + s) for s in URL_SHORTENERS):
        _add_indicator(
            indicators, "URL_SHORTENER", 12,
            "Uses a URL-shortening service.",
            hostname
        )

    # 4. Suspicious keywords
    keyword_matches = dedupe_preserve_order(
        [word for word in SUSPICIOUS_KEYWORDS if word in full_url]
    )
    if keyword_matches:
        weight = min(4 * len(keyword_matches), 16)
        _add_indicator(
            indicators, "SUSPICIOUS_KEYWORDS", weight,
            "Contains words commonly used in phishing or account-verification lures.",
            ", ".join(keyword_matches)
        )

    # 5. Excessive subdomains
    dot_count = hostname.count(".")
    if dot_count >= 4:
        _add_indicator(
            indicators, "MANY_SUBDOMAINS", 10,
            "Contains an unusually high number of subdomains.",
            str(dot_count + 1) + " domain labels"
        )

    # 6. Long URL
    if len(normalized) > 120:
        _add_indicator(
            indicators, "LONG_URL", 9,
            "URL is unusually long.",
            f"{len(normalized)} characters"
        )

    # 7. @ symbol
    if "@" in normalized:
        _add_indicator(
            indicators, "AT_SYMBOL", 18,
            "Contains an @ symbol, which can obscure the actual destination."
        )

    # 8. Excessive hyphens
    hyphens = hostname.count("-")
    if hyphens >= 3:
        _add_indicator(
            indicators, "MANY_HYPHENS", 8,
            "Domain contains an unusual number of hyphens.",
            f"{hyphens} hyphens"
        )

    # 9. Punycode / IDN
    if "xn--" in hostname:
        _add_indicator(
            indicators, "PUNYCODE", 16,
            "Uses punycode/IDN encoding, which can be abused for lookalike domains."
        )

    # 10. Encoded characters
    percent_count = normalized.count("%")
    if percent_count >= 2:
        _add_indicator(
            indicators, "ENCODED_CHARS", 6,
            "Contains multiple encoded characters that make the URL harder to read.",
            f"{percent_count} encoded markers"
        )

    # 11. Non-standard port
    try:
        port = parsed.port
    except ValueError:
        port = None

    if port and port not in {80, 443}:
        _add_indicator(
            indicators, "NONSTANDARD_PORT", 8,
            "Uses a non-standard network port.",
            str(port)
        )

    # 12. Suspicious TLD
    if "." in hostname:
        tld = hostname.rsplit(".", 1)[-1]
        if tld in SUSPICIOUS_TLDS:
            _add_indicator(
                indicators, "SUSPICIOUS_TLD", 7,
                "Uses a top-level domain that is sometimes abused in phishing campaigns.",
                "." + tld
            )

    # 13. Brand-like text with digit substitution
    if re.search(r"[a-z]{2,}[01][a-z]{2,}", hostname):
        _add_indicator(
            indicators, "DIGIT_SUBSTITUTION", 14,
            "Domain appears to use digit substitution that may imitate a legitimate brand.",
            hostname
        )

    # 14. Brand name outside the leftmost registered-looking label
    for brand in COMMON_BRANDS:
        if brand in hostname and not hostname.startswith(brand + ".") and not hostname == brand:
            if any(token in hostname for token in ("login", "secure", "verify", "account", "support")):
                _add_indicator(
                    indicators, "BRAND_IMPERSONATION_PATTERN", 12,
                    "Domain structure resembles a possible brand-impersonation pattern.",
                    brand
                )
                break

    score = clamp_score(sum(item["weight"] for item in indicators))

    return {
        "type": "URL",
        "input": url,
        "normalized": normalized,
        "hostname": hostname,
        "score": score,
        "risk": risk_level(score),
        "indicators": indicators,
        "summary": (
            "No major phishing indicators detected by the current rule set."
            if not indicators
            else f"Detected {len(indicators)} phishing-related indicator(s)."
        )
    }
