import json
from pathlib import Path

import streamlit as st

from phishguard.url_analyzer import analyze_url
from phishguard.email_analyzer import analyze_email


st.set_page_config(
    page_title="PhishGuard",
    page_icon="🛡️",
    layout="centered",
)

st.title("🛡️ PhishGuard")
st.caption("Explainable phishing & social-engineering analysis")

st.info(
    "PhishGuard analyzes text and URL structure only. "
    "It does not visit submitted links."
)


def render_result(result):
    score = int(result["score"])
    st.metric("Risk Score", f"{score}/100")
    st.progress(score / 100)
    st.subheader(result["risk"])

    if result["indicators"]:
        st.markdown("**Detected indicators**")
        for item in result["indicators"]:
            evidence = f" — `{item['evidence']}`" if item.get("evidence") else ""
            st.write(
                f"- **{item['message']}** (+{item['weight']}){evidence}"
            )
    else:
        st.success(result["summary"])

    st.caption(
        "A low score does not guarantee safety. "
        "Rule-based analysis can produce false positives or false negatives."
    )


url_tab, email_tab, evaluation_tab = st.tabs(
    ["URL Analyzer", "Email Analyzer", "Evaluation"]
)

with url_tab:
    st.write(
        "Paste a URL to inspect its structure for common phishing indicators."
    )
    url = st.text_input("URL", placeholder="https://example.com")

    if st.button("Analyze URL", use_container_width=True):
        render_result(analyze_url(url))

with email_tab:
    st.write(
        "Paste suspicious email content to inspect common social-engineering indicators."
    )
    email_text = st.text_area(
        "Email content",
        height=220,
        placeholder=(
            "URGENT: Your account has been suspended. "
            "Verify your password immediately..."
        ),
    )

    if st.button("Analyze Email", use_container_width=True):
        render_result(analyze_email(email_text))

with evaluation_tab:
    st.write(
        "PhishGuard includes a reproducible evaluation pipeline using labeled "
        "phishing and legitimate URL samples."
    )

    metrics_path = Path("evaluation/results/metrics.json")
    report_path = Path("evaluation/results/evaluation_report.md")

    if metrics_path.exists():
        metrics = json.loads(metrics_path.read_text(encoding="utf-8"))

        st.markdown("### Latest committed evaluation")
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Samples", metrics.get("dataset_size", "—"))
        c2.metric("Accuracy", f"{100 * metrics.get('accuracy', 0):.1f}%")
        c3.metric("Precision", f"{100 * metrics.get('precision', 0):.1f}%")
        c4.metric("Recall", f"{100 * metrics.get('recall', 0):.1f}%")

        c5, c6, c7 = st.columns(3)
        c5.metric("F1", f"{100 * metrics.get('f1', 0):.1f}%")
        c6.metric("Specificity", f"{100 * metrics.get('specificity', 0):.1f}%")
        c7.metric("Threshold", metrics.get("threshold", "—"))

        st.caption(
            "Metrics apply only to the documented dataset, sampling date, "
            "class balance, and decision threshold."
        )

        if report_path.exists():
            with st.expander("View evaluation report"):
                st.markdown(report_path.read_text(encoding="utf-8"))
    else:
        st.info(
            "No evaluation results have been committed yet. "
            "Run `python -m evaluation.fetch_dataset` and "
            "`python -m evaluation.evaluate`, review the outputs, then commit "
            "the results you want displayed here."
        )

st.divider()
st.caption(
    "Educational cybersecurity project. Rule-based analysis may produce "
    "false positives or false negatives."
)
