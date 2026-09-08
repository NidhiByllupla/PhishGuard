from phishguard.url_analyzer import analyze_url


def test_legitimate_https_url_scores_low():
    result = analyze_url("https://www.github.com")
    assert result["score"] < 40
    assert result["risk"] == "LOW RISK"


def test_ip_login_url_scores_at_least_medium():
    result = analyze_url("http://192.168.10.24/login")
    assert result["score"] >= 40


def test_obfuscated_url_has_multiple_indicators():
    result = analyze_url(
        "http://paypa1-account-login-secure.example.com/verify"
    )
    assert len(result["indicators"]) >= 3
