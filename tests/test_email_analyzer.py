from phishguard.email_analyzer import analyze_email


def test_normal_message_scores_low():
    result = analyze_email(
        "Hi, our meeting is tomorrow at 2 PM. "
        "Please let me know if that time still works."
    )
    assert result["score"] < 40


def test_phishing_style_message_scores_high():
    result = analyze_email(
        """
        URGENT SECURITY ALERT!!!
        Your account has been suspended.
        Verify your account immediately and enter your password.
        Click here:
        http://paypa1-account-login-secure.example.com/verify
        """
    )
    assert result["score"] >= 70
    assert result["risk"] == "HIGH RISK"
