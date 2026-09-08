"""PhishGuard package."""

from .url_analyzer import analyze_url
from .email_analyzer import analyze_email

__all__ = ["analyze_url", "analyze_email"]
