"""Binary classification metrics for PhishGuard evaluation."""

from __future__ import annotations


def confusion_counts(labels, predictions):
    if len(labels) != len(predictions):
        raise ValueError("labels and predictions must have the same length")

    tp = tn = fp = fn = 0
    for truth, pred in zip(labels, predictions):
        truth = int(truth)
        pred = int(pred)

        if truth == 1 and pred == 1:
            tp += 1
        elif truth == 0 and pred == 0:
            tn += 1
        elif truth == 0 and pred == 1:
            fp += 1
        elif truth == 1 and pred == 0:
            fn += 1
        else:
            raise ValueError("labels and predictions must contain only 0 or 1")

    return {"tp": tp, "tn": tn, "fp": fp, "fn": fn}


def _safe_div(numerator, denominator):
    return numerator / denominator if denominator else 0.0


def classification_metrics(labels, predictions):
    counts = confusion_counts(labels, predictions)
    tp, tn, fp, fn = (
        counts["tp"], counts["tn"], counts["fp"], counts["fn"]
    )

    accuracy = _safe_div(tp + tn, tp + tn + fp + fn)
    precision = _safe_div(tp, tp + fp)
    recall = _safe_div(tp, tp + fn)
    specificity = _safe_div(tn, tn + fp)
    f1 = _safe_div(2 * precision * recall, precision + recall)
    false_positive_rate = _safe_div(fp, fp + tn)
    false_negative_rate = _safe_div(fn, fn + tp)

    return {
        **counts,
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "specificity": specificity,
        "f1": f1,
        "false_positive_rate": false_positive_rate,
        "false_negative_rate": false_negative_rate,
    }
