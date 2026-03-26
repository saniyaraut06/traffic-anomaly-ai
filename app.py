import streamlit as st
import pandas as pd
from sklearn.ensemble import IsolationForest
from ai_explainer import explain_threat
import os

# -------------------------------
# Rule-based reason builder
# -------------------------------
def build_reason(row):
    reasons = []

    if row["request_count"] > 1000:
        reasons.append("a very high number of requests")

    if row["response_time"] < 30:
        reasons.append("an unusually low response time")

    if reasons:
        return " and ".join(reasons)
    else:
        return "unusual traffic behavior"

# -------------------------------
# Threat Type Prediction
# -------------------------------
def predict_threat_type(row):
    if row["request_count"] > 1300 and row["response_time"] < 20:
        return "Possible DDoS Attack"
    elif row["request_count"] > 1000 and row["response_time"] < 30:
        return "Possible Bot Traffic"
    elif row["request_count"] > 1000:
        return "Suspicious Traffic Burst"
    else:
        return "Unknown Suspicious Pattern"

# -------------------------------
# Threat Severity
# -------------------------------
def assign_severity(row):
    if row["request_count"] > 1300 and row["response_time"] < 20:
        return "High"
    elif row["request_count"] > 1000 and row["response_time"] < 30:
        return "Medium"
    else:
        return "Low"

# -------------------------------
# Executive Summary Generator
# -------------------------------
def generate_summary(suspicious_df):
    if suspicious_df.empty:
        return "No suspicious traffic was detected in the latest monitoring window."

    total = len(suspicious_df)
    threat_types = suspicious_df["threat_type"].value_counts().to_dict()

    summary = f"{total} suspicious traffic instance(s) were detected. "

    if "Possible DDoS Attack" in threat_types:
        summary += "Potential DDoS-like activity was observed. "
    if "Possible Bot Traffic" in threat_types:
        summary += "Some traffic patterns resemble automated bot behavior. "
    if "Suspicious Traffic Burst" in threat_types:
        summary += "Burst-like abnormal request activity was also found. "

    summary += "Immediate review of flagged IPs is recommended."
    return summary

# -------------------------------
# Streamlit Config
# -------------------------------
st.set_page_config(
    page_title="Traffic Anomaly AI",
    page_icon="🔐",
    layout="wide"
)

st.title("🔐 Near Real-Time Traffic Anomaly & Threat Monitoring System")
st.write("Monitoring simulated live traffic logs using ML-based anomaly detection and AI threat explanations.")

st.caption("🔄 Keep refreshing the page every few seconds to see new incoming logs.")

# -------------------------------
# Load live traffic file
# -------------------------------
live_file = "data/traffic_logs_live.csv"

if not os.path.exists(live_file):
    st.warning("⚠️ Live traffic file not found. Please run `python live_log_generator.py` first.")
    st.stop()

df = pd.read_csv(live_file)

if df.empty:
    st.warning("⚠️ No live traffic data available yet.")
    st.stop()

# Only analyze latest 50 rows
df = df.tail(50)

st.subheader("📄 Latest Incoming Traffic Logs")
st.dataframe(df, use_container_width=True)

# -------------------------------
# ML Detection
# -------------------------------
features = df[["request_count", "response_time"]]

model = IsolationForest(
    n_estimators=100,
    contamination=0.2,
    random_state=42
)

df["anomaly"] = model.fit_predict(features)

df["anomaly_label"] = df["anomaly"].map({
    1: "Normal",
    -1: "Suspicious"
})

df["threat_type"] = "None"
df["severity"] = "None"

suspicious_mask = df["anomaly_label"] == "Suspicious"

df.loc[suspicious_mask, "threat_type"] = df[suspicious_mask].apply(predict_threat_type, axis=1)
df.loc[suspicious_mask, "severity"] = df[suspicious_mask].apply(assign_severity, axis=1)

# -------------------------------
# Summary Metrics
# -------------------------------
total_logs = len(df)
suspicious_count = len(df[df["anomaly_label"] == "Suspicious"])
normal_count = len(df[df["anomaly_label"] == "Normal"])

st.subheader("📊 Monitoring Summary")
col1, col2, col3 = st.columns(3)
col1.metric("Latest Logs", total_logs)
col2.metric("Suspicious Traffic", suspicious_count)
col3.metric("Normal Traffic", normal_count)

# -------------------------------
# Alert Banner
# -------------------------------
if suspicious_count > 0:
    st.error(f"🚨 ALERT: {suspicious_count} suspicious traffic event(s) detected in the latest monitoring window!")
else:
    st.success("✅ No suspicious traffic currently detected.")

# -------------------------------
# Filter by IP
# -------------------------------
st.subheader("🔎 Filter by IP")
ip_options = ["All"] + sorted(df["ip"].unique().tolist())
selected_ip = st.selectbox("Select an IP to inspect", ip_options)

if selected_ip != "All":
    filtered_df = df[df["ip"] == selected_ip]
else:
    filtered_df = df

# -------------------------------
# Results Table
# -------------------------------
st.subheader("🚨 Anomaly Detection Results")
result_df = filtered_df[[
    "timestamp", "ip", "request_count", "response_time",
    "anomaly_label", "threat_type", "severity"
]]
st.dataframe(result_df, use_container_width=True)

# -------------------------------
# Download Report
# -------------------------------
csv = result_df.to_csv(index=False).encode("utf-8")
st.download_button(
    label="📥 Download Latest Anomaly Report",
    data=csv,
    file_name="live_anomaly_report.csv",
    mime="text/csv"
)

# -------------------------------
# Chart
# -------------------------------
st.subheader("📈 Request Count Visualization")
chart_df = filtered_df[["ip", "request_count"]].copy()
chart_df = chart_df.set_index("ip")
st.bar_chart(chart_df)

# -------------------------------
# AI Threat Explanations
# -------------------------------
suspicious_df = filtered_df[filtered_df["anomaly_label"] == "Suspicious"]

if not suspicious_df.empty:
    st.subheader("🧠 AI Threat Explanations")

    for _, row in suspicious_df.iterrows():
        reason = build_reason(row)
        explanation = explain_threat(row["ip"], reason)

        with st.expander(f"IP: {row['ip']} | {row['threat_type']} | Severity: {row['severity']}"):
            st.write(f"**Observed Behavior:** {reason}")
            st.write(explanation)
else:
    st.info("No suspicious traffic to explain right now.")

# -------------------------------
# Executive Summary
# -------------------------------
st.subheader("📝 Executive Summary")
summary_text = generate_summary(df[df["anomaly_label"] == "Suspicious"])
st.info(summary_text)