from evaluation.evaluate import evaluate_rows


def test_evaluation_pipeline_returns_metrics_and_details():
    rows = [
        {
            "sample_id": "T1",
            "url": "https://www.google.com/",
            "label": 0,
            "label_name": "legitimate",
            "source": "test",
            "source_id": "1",
            "source_metadata": "",
        },
        {
            "sample_id": "T2",
            "url": "http://paypa1-account-login-secure.example.com/verify",
            "label": 1,
            "label_name": "phishing",
            "source": "test",
            "source_id": "2",
            "source_metadata": "",
        },
    ]

    details, metrics, indicators = evaluate_rows(rows, threshold=40)

    assert len(details) == 2
    assert details[0]["prediction"] in {0, 1}
    assert details[1]["prediction"] in {0, 1}
    assert 0.0 <= metrics["accuracy"] <= 1.0
    assert sum(indicators.values()) >= 1
