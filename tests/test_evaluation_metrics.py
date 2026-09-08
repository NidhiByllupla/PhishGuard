from evaluation.metrics import confusion_counts, classification_metrics


def test_confusion_counts():
    labels = [1, 1, 0, 0]
    predictions = [1, 0, 1, 0]
    assert confusion_counts(labels, predictions) == {
        "tp": 1, "tn": 1, "fp": 1, "fn": 1
    }


def test_classification_metrics_perfect():
    metrics = classification_metrics([1, 1, 0, 0], [1, 1, 0, 0])
    assert metrics["accuracy"] == 1.0
    assert metrics["precision"] == 1.0
    assert metrics["recall"] == 1.0
    assert metrics["specificity"] == 1.0
    assert metrics["f1"] == 1.0


def test_classification_metrics_handles_zero_denominator():
    metrics = classification_metrics([0, 0], [0, 0])
    assert metrics["precision"] == 0.0
    assert metrics["recall"] == 0.0
    assert metrics["false_positive_rate"] == 0.0
