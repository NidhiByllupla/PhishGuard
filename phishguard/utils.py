"""Shared utility functions."""

import ipaddress
import re
from urllib.parse import urlparse


URL_REGEX = re.compile(r"https?://[^\s<>\"]+", re.IGNORECASE)


def normalize_url(url: str) -> str:
    """Return a trimmed URL with an explicit scheme."""
    url = (url or "").strip()
    if not url:
        return ""

    if not url.startswith(("http://", "https://")):
        return "http://" + url

    return url


def hostname_from_url(url: str) -> str:
    """Extract a lowercase hostname from a URL."""
    parsed = urlparse(normalize_url(url))
    return (parsed.hostname or "").lower()


def is_ip_address(hostname: str) -> bool:
    """Return True if the hostname is an IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def extract_urls(text: str):
    """Extract HTTP/HTTPS URLs from text."""
    return URL_REGEX.findall(text or "")


def dedupe_preserve_order(items):
    """Remove duplicates while preserving first appearance."""
    seen = set()
    result = []

    for item in items:
        if item not in seen:
            seen.add(item)
            result.append(item)

    return result
