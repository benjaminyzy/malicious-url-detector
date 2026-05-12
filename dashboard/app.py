"""Streamlit dashboard for the malicious URL detector."""

import matplotlib
import matplotlib.pyplot as plt
import pandas as pd
import requests
import streamlit as st

matplotlib.use("Agg")

API = "http://localhost:8000"

st.set_page_config(
    page_title="Malicious URL Detection Dashboard",
    layout="wide",
    page_icon="shield",
)


@st.cache_data(ttl=10, show_spinner=False)
def get_stats():
    try:
        return requests.get(f"{API}/stats", timeout=5).json()
    except Exception:
        return None


@st.cache_data(ttl=10, show_spinner=False)
def get_history(limit=50):
    try:
        return requests.get(f"{API}/history", params={"limit": limit}, timeout=5).json()
    except Exception:
        return []


def classify(url):
    try:
        return requests.post(f"{API}/classify", json={"url": url}, timeout=15).json()
    except Exception as e:
        return {"error": str(e)}


def find_model_keys(result, suffix):
    return sorted([k for k in result if k.endswith(suffix) and k != "rule_prediction"])


def format_votes(votes_for_malicious, final_label):
    """Display votes as agreement with the final verdict."""
    if final_label == 1:
        return f"{votes_for_malicious}/3 voted malicious"
    return f"{3 - votes_for_malicious}/3 voted safe"


def format_timestamp(iso_string):
    """Convert ISO 8601 string to YYYY-MM-DD HH:MM:SS."""
    if not iso_string:
        return ""
    return iso_string.replace("T", " ").split(".")[0]


# Header
st.title("Malicious URL Detection Dashboard")
st.caption(
    "Majority-voting ensemble (2 ML models + rule engine) with "
    "high-precision rule overrides."
)

col_refresh, _ = st.columns([2, 8])
with col_refresh:
    if st.button("Refresh Dashboard Data"):
        get_stats.clear()
        get_history.clear()
        st.rerun()
st.caption(
    "Refresh updates the metrics, charts, and history from the database. "
    "Your last URL check stays visible until you click 'Clear Result' below."
)
st.divider()

stats = get_stats()
history = get_history(50)


# Metrics
c1, c2, c3, c4 = st.columns(4)
if stats:
    c1.metric("Total URLs Scanned", stats["total_scanned"])
    c2.metric("Total Malicious", stats["total_malicious"])
    c3.metric("Total Benign", stats["total_benign"])
    c4.metric("Malicious %", f"{stats['malicious_percentage']}%")
else:
    for col in (c1, c2, c3, c4):
        col.metric("-", "-")
    st.warning("Could not reach the API at http://localhost:8000. "
               "Is the FastAPI server running?")

st.divider()


# Charts
left, right = st.columns(2)

with left:
    st.subheader("Distribution")
    if stats and stats["total_scanned"] > 0:
        fig, ax = plt.subplots(figsize=(4, 4))
        ax.pie(
            [stats["total_malicious"], stats["total_benign"]],
            labels=["Malicious", "Benign"],
            colors=["#e74c3c", "#2ecc71"],
            autopct="%1.1f%%",
            startangle=90,
        )
        ax.set_title("Malicious vs Benign")
        st.pyplot(fig)
        plt.close(fig)
    else:
        st.info("No data yet.")

with right:
    st.subheader("Last 10 Classifications, Confidence")
    if history:
        recent = history[:10][::-1]
        labels = [
            r["url"][:30] + ("..." if len(r["url"]) > 30 else "") for r in recent
        ]
        colors = [
            "#e74c3c" if r["final_label"] == 1 else "#2ecc71" for r in recent
        ]
        fig2, ax2 = plt.subplots(figsize=(6, 4))
        ax2.barh(labels, [r["confidence"] for r in recent], color=colors)
        ax2.set_xlabel("Confidence (%)")
        ax2.set_xlim(0, 100)
        ax2.set_title("Confidence by URL (red=malicious, green=benign)")
        fig2.tight_layout()
        st.pyplot(fig2)
        plt.close(fig2)
    else:
        st.info("No classifications yet.")

st.divider()


# Recent threats
st.subheader("Recent Threats")
threats = stats["recent_threats"] if stats else []
if threats:
    for t in threats:
        st.markdown(
            f"""<div style="background:#fdecea;border-left:4px solid #e74c3c;
            padding:10px 14px;border-radius:4px;margin-bottom:8px;color:#222">
            <b style="color:#c0392b">MALICIOUS</b> &nbsp;
            <code style="background:#fff;padding:2px 4px;border-radius:3px">{t['url']}</code><br>
            <small>Confidence: <b>{t['confidence']}%</b> &nbsp;|&nbsp;
            {format_timestamp(t['timestamp'])}</small></div>""",
            unsafe_allow_html=True,
        )
else:
    st.info("No malicious URLs detected yet.")

st.divider()


# History table
st.subheader("Classification History")
if history:
    rows = []
    for r in history:
        rules = r.get("triggered_rules") or []
        rows.append({
            "Timestamp": format_timestamp(r["timestamp"]),
            "URL": r["url"],
            "Result": r["final_result"],
            "Confidence": f"{r['confidence']}%",
            "Votes": format_votes(r["votes_for_malicious"], r["final_label"]),
            "Triggered Rules": "; ".join(rules) if rules else "none",
        })
    df = pd.DataFrame(rows)

    def color_result(val):
        color = "#e74c3c" if val == "MALICIOUS" else "#2ecc71"
        return f"color: {color}; font-weight: bold"

    st.dataframe(
        df.style.map(color_result, subset=["Result"]),
        use_container_width=True,
        hide_index=True,
        column_config={
            "URL": st.column_config.TextColumn("URL", width="medium"),
            "Triggered Rules": st.column_config.TextColumn(
                "Triggered Rules", width="large"
            ),
        },
    )
else:
    st.info("No history yet.")

st.divider()


# Live URL checker
st.subheader("Check a URL")

def _submit_url(url):
    if not url.strip():
        st.session_state["check_error"] = "Please enter a URL."
        return
    with st.spinner("Analysing..."):
        result = classify(url.strip())
    if "error" in result:
        st.session_state["check_error"] = f"API error: {result['error']}"
    elif "detail" in result:
        st.session_state["check_error"] = f"Validation error: {result['detail']}"
    else:
        st.session_state["last_result"] = result
        st.session_state.pop("check_error", None)
        get_stats.clear()
        get_history.clear()

url_input = st.text_input(
    "Enter a URL to analyse:",
    placeholder="https://example.com",
    key="url_input_field",
)

col_a, _ = st.columns([1, 9])
with col_a:
    submit_clicked = st.button("Check URL", type="primary")

last_submitted = st.session_state.get("last_submitted_url", "")
enter_submitted = (
    url_input
    and url_input != last_submitted
    and not submit_clicked
)

if submit_clicked or enter_submitted:
    st.session_state["last_submitted_url"] = url_input
    _submit_url(url_input)
    st.rerun()

if "check_error" in st.session_state:
    st.error(st.session_state["check_error"])


if "last_result" in st.session_state:
    result = st.session_state["last_result"]
    is_malicious = result["final_label"] == 1
    badge_color = "#e74c3c" if is_malicious else "#2ecc71"
    badge_text = result["final_result"]
    override_badge = (
        ' <span style="background:#9b59b6;color:white;padding:2px 8px;'
        'border-radius:3px;font-size:0.75em;font-weight:bold">OVERRIDE</span>'
        if result.get("override_applied") else ""
    )

    text_color = "#222"
    st.markdown(
        f"""<div style="background:{'#fdecea' if is_malicious else '#eafaf1'};
        border-left:4px solid {badge_color};padding:14px 18px;
        border-radius:6px;margin-bottom:12px;color:{text_color}">
        <span style="font-size:1.3em;font-weight:bold;color:{badge_color}">
        {badge_text}</span>{override_badge}
        &nbsp;&nbsp;<span style="color:{text_color}">Confidence: <b>{result['confidence']}%</b>
        &nbsp;|&nbsp; <b>{format_votes(result['votes_for_malicious'], result['final_label'])}</b>
        &nbsp;|&nbsp; URL: <code style="background:#fff;padding:2px 4px;border-radius:3px">{result['url']}</code></span>
        </div>""",
        unsafe_allow_html=True,
    )

    v1, v2, v3 = st.columns(3)

    pred_keys = find_model_keys(result, "_prediction")
    proba_keys = find_model_keys(result, "_proba")

    if len(pred_keys) >= 2 and len(proba_keys) >= 2:
        name1 = pred_keys[0].replace("_prediction", "").replace("_", " ").title()
        name2 = pred_keys[1].replace("_prediction", "").replace("_", " ").title()
        v1.metric(
            name1,
            "Malicious" if result[pred_keys[0]] == 1 else "Benign",
            help=f"P(malicious) = {result[proba_keys[0]]}",
        )
        v2.metric(
            name2,
            "Malicious" if result[pred_keys[1]] == 1 else "Benign",
            help=f"P(malicious) = {result[proba_keys[1]]}",
        )

    v3.metric(
        "Rule Engine",
        "Malicious" if result["rule_prediction"] == 1 else "Benign",
    )

    rules = result.get("triggered_rules") or []
    if rules:
        st.markdown("**Triggered rules:**")
        for rule in rules:
            st.markdown(f"- {rule}")
    else:
        st.markdown("**No rules triggered.**")

    if st.button("Clear Result"):
        del st.session_state["last_result"]
        st.rerun()

st.divider()
