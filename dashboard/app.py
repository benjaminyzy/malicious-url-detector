import matplotlib
import matplotlib.pyplot as plt
import requests
import streamlit as st

matplotlib.use("Agg")

API = "http://localhost:8000"

st.set_page_config(
    page_title="Malicious URL Detection Dashboard",
    layout="wide",
    page_icon="shield",
)

# ── Header ────────────────────────────────────────────────────────────────────

st.title("Malicious URL Detection Dashboard")
st.caption(
    "Majority-voting ensemble (Random Forest + XGBoost + Rule Engine) "
    "that classifies URLs as malicious or benign using 18 lexical features."
)
if st.button("Refresh Dashboard"):
    st.rerun()
st.divider()


# ── Fetch data ────────────────────────────────────────────────────────────────

def get_stats():
    try:
        return requests.get(f"{API}/stats", timeout=5).json()
    except Exception:
        return None


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


stats = get_stats()
history = get_history(50)

# ── Metrics row ───────────────────────────────────────────────────────────────

c1, c2, c3, c4 = st.columns(4)
if stats:
    c1.metric("Total URLs Scanned", stats["total_scanned"])
    c2.metric("Total Malicious", stats["total_malicious"])
    c3.metric("Total Benign", stats["total_benign"])
    c4.metric("Malicious %", f"{stats['malicious_percentage']}%")
else:
    for col in (c1, c2, c3, c4):
        col.metric("—", "—")
    st.warning("Could not reach the API at http://localhost:8000 — is the FastAPI server running?")

st.divider()

# ── Charts row ────────────────────────────────────────────────────────────────

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
    st.subheader("Last 10 Classifications — Confidence")
    if history:
        recent = history[:10][::-1]
        labels = [r["url"][:30] + ("..." if len(r["url"]) > 30 else "") for r in recent]
        colors = ["#e74c3c" if r["final_label"] == 1 else "#2ecc71" for r in recent]
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

# ── Recent threats ────────────────────────────────────────────────────────────

st.subheader("Recent Threats")
threats = stats["recent_threats"] if stats else []
if threats:
    for t in threats:
        st.markdown(
            f"""<div style="background:#fdecea;border-left:4px solid #e74c3c;
            padding:10px 14px;border-radius:4px;margin-bottom:8px">
            <b style="color:#c0392b">MALICIOUS</b> &nbsp;
            <code>{t['url']}</code><br>
            <small>Confidence: <b>{t['confidence']}%</b> &nbsp;|&nbsp; {t['timestamp']}</small>
            </div>""",
            unsafe_allow_html=True,
        )
else:
    st.info("No malicious URLs detected yet.")

st.divider()

# ── History table ─────────────────────────────────────────────────────────────

st.subheader("Classification History")
if history:
    import pandas as pd

    rows = []
    for r in history:
        rules = r.get("triggered_rules") or []
        rows.append(
            {
                "Timestamp": r["timestamp"][:19].replace("T", " "),
                "URL": r["url"],
                "Result": r["final_result"],
                "Confidence": f"{r['confidence']}%",
                "Votes": f"{r['votes_for_malicious']}/3",
                "Triggered Rules": "; ".join(rules) if rules else "none",
            }
        )

    df = pd.DataFrame(rows)

    def color_result(val):
        color = "#e74c3c" if val == "MALICIOUS" else "#2ecc71"
        return f"color: {color}; font-weight: bold"

    st.dataframe(
        df.style.map(color_result, subset=["Result"]),
        use_container_width=True,
        hide_index=True,
    )
else:
    st.info("No history yet.")

st.divider()

# ── Live URL checker ──────────────────────────────────────────────────────────

st.subheader("Check a URL")
url_input = st.text_input("Enter a URL to analyse:", placeholder="https://example.com")

if st.button("Check URL", type="primary"):
    if not url_input.strip():
        st.error("Please enter a URL.")
    else:
        with st.spinner("Analysing..."):
            result = classify(url_input.strip())
        if "error" in result:
            st.error(f"API error: {result['error']}")
        else:
            st.session_state["last_result"] = result
            st.rerun()

if "last_result" in st.session_state:
    result = st.session_state["last_result"]
    is_malicious = result["final_label"] == 1
    badge_color = "#e74c3c" if is_malicious else "#2ecc71"
    badge_text = result["final_result"]

    st.markdown(
        f"""<div style="background:{'#fdecea' if is_malicious else '#eafaf1'};
        border-left:4px solid {badge_color};padding:14px 18px;
        border-radius:6px;margin-bottom:12px">
        <span style="font-size:1.3em;font-weight:bold;color:{badge_color}">
        {badge_text}</span>
        &nbsp;&nbsp;Confidence: <b>{result['confidence']}%</b>
        &nbsp;|&nbsp; Votes: <b>{result['votes_for_malicious']}/3</b>
        &nbsp;|&nbsp; URL: <code>{result['url']}</code>
        </div>""",
        unsafe_allow_html=True,
    )

    v1, v2, v3 = st.columns(3)
    rf_key = next((k for k in result if k.endswith("_prediction") and "random_forest" in k), None)
    xgb_key = next((k for k in result if k.endswith("_prediction") and "xgboost" in k), None)
    v1.metric("Random Forest", "Malicious" if result.get(rf_key) == 1 else "Benign")
    v2.metric("XGBoost", "Malicious" if result.get(xgb_key) == 1 else "Benign")
    v3.metric("Rule Engine", "Malicious" if result["rule_prediction"] == 1 else "Benign")

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
