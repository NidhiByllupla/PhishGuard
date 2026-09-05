from urllib.parse import urlparse
import ipaddress
import re


SUSPICIOUS_KEYWORDS = [
    "login",
    "verify",
    "secure",
    "account",
    "update",
    "confirm",
    "password",
    "bank",
    "signin",
    "payment"
]

URL_SHORTENERS = [
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly"
]


def has_ip_address(domain):
    """Check whether a domain is actually an IP address."""
    try:
        ipaddress.ip_address(domain)
        return True
    except ValueError:
        return False


def analyze_url(url):
    """Analyze a URL for common phishing indicators."""

    score = 0
    reasons = []

    # Add a scheme if the user did not enter one
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)

    domain = parsed.netloc.lower()
    full_url = url.lower()

    # Check for HTTP instead of HTTPS
    if parsed.scheme == "http":
        score += 15
        reasons.append("Uses HTTP instead of HTTPS.")

    # Check whether an IP address is being used as the domain
    if has_ip_address(domain.split(":")[0]):
        score += 25
        reasons.append(
            "Uses an IP address instead of a normal domain name."
        )

    # Search for suspicious words
    detected_keywords = [
        word for word in SUSPICIOUS_KEYWORDS
        if word in full_url
    ]

    if detected_keywords:
        score += min(len(detected_keywords) * 5, 20)
        reasons.append(
            "Contains suspicious keywords: "
            + ", ".join(detected_keywords)
        )

    # Check for excessive subdomains
    domain_parts = domain.split(".")

    if len(domain_parts) > 4:
        score += 10
        reasons.append(
            "Contains an unusually high number of subdomains."
        )

    # Check URL length
    if len(url) > 100:
        score += 10
        reasons.append("URL is unusually long.")

    # Check for URL-shortening services
    if any(shortener in domain for shortener in URL_SHORTENERS):
        score += 15
        reasons.append("Uses a URL-shortening service.")

    # Check for @ symbol
    if "@" in url:
        score += 20
        reasons.append(
            "Contains an @ symbol, which can obscure the real destination."
        )

    # Check for excessive hyphens
    if domain.count("-") >= 3:
        score += 10
        reasons.append(
            "Domain contains an unusual number of hyphens."
        )

    # Look for possible character substitution
    if re.search(r"[a-z]+[01][a-z]+", domain):
        score += 15
        reasons.append(
            "Domain may contain character substitutions used for impersonation."
        )

    score = min(score, 100)

    if score >= 70:
        risk = "HIGH RISK"
    elif score >= 40:
        risk = "MEDIUM RISK"
    else:
        risk = "LOW RISK"

    return {
        "url": url,
        "score": score,
        "risk": risk,
        "reasons": reasons
    }


def display_result(result):
    """Display the results of the analysis."""

    print("\nPHISHGUARD ANALYSIS")
    print("-" * 40)

    print("URL:", result["url"])
    print("Risk Score:", f'{result["score"]}/100')
    print("Risk Level:", result["risk"])

    print("\nDetected Indicators:")

    if result["reasons"]:
        for reason in result["reasons"]:
            print("-", reason)
    else:
        print("- No major warning signs detected.")

    print("\nImportant:")
    print(
        "A low score does not guarantee that a website is safe. "
        "Always verify suspicious links independently."
    )


if __name__ == "__main__":
    user_url = input("Enter a URL to analyze: ")

    result = analyze_url(user_url)

    display_result(result)
