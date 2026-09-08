"""Risk scoring helpers for PhishGuard."""

def clamp_score(score: int) -> int:
    return max(0, min(int(score), 100))


def risk_level(score: int) -> str:
    score = clamp_score(score)

    if score >= 70:
        return "HIGH RISK"
    if score >= 40:
        return "MEDIUM RISK"
    return "LOW RISK"
