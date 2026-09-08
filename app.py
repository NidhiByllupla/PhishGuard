"""Streamlit interface for PhishGuard."""

import streamlit as st

from phishguard import analyze_url, analyze_email


st.set_page_config(
    page_title="PhishGuard",
    page_icon="🛡️",
    layout="centered"
)

st.title("🛡️ PhishGuard")
st.caption("Explainable phishing & social-engineering analysis")

st.info(
    "PhishGuard analyzes text and URL structure only. "
    "It does not visit submitted links."
)

tab_url, tab_email = st.tabs(["URL Analyzer", "Email Analyzer"])


def render_result(result):
    score = result["score"]
    risk = result["risk"]

    st.subheader(f"{risk} — {score}/100")
    st.progress(score / 100)

    st.write(result["summary"])

    if result["indicators"]:
        st.markdown("### Detected indicators")
        for item in result["indicators"]:
            evidence = f" — *{item['evidence']}*" if item.get("evidence") else ""
            st.markdown(
                f"- **{item['message']}** "
                f"(+{item['weight']} points){evidence}"
            )
    else:
        st.success("No major indicators were detected by the current rule set.")

    st.warning(
        "A low score does not guarantee safety. "
        "Verify unexpected messages and links through trusted channels."
    )


with tab_url:
    st.markdown(
        "Paste a URL to inspect its structure for common phishing indicators."
    )

    url = st.text_input(
        "URL",
        placeholder="https://example.com"
    )

    if st.button("Analyze URL", use_container_width=True):
        if url.strip():
            render_result(analyze_url(url))
        else:
            st.error("Enter a URL first.")


with tab_email:
    st.markdown(
        "Paste an email body to inspect it for common social-engineering patterns."
    )

    email_text = st.text_area(
        "Email text",
        height=220,
        placeholder="Paste the email body here..."
    )

    if st.button("Analyze Email", use_container_width=True):
        if email_text.strip():
            render_result(analyze_email(email_text))
        else:
            st.error("Paste email text first.")

st.divider()
st.caption(
    "Educational cybersecurity project. "
    "Rule-based analysis may produce false positives or false negatives."
)
