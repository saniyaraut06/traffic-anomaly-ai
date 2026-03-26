import streamlit as st
import pandas as pd
from sklearn.ensemble import IsolationForest
from ai_explainer import explain_threat

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
# Streamlit UI
# -------------------------------
st.set_page_config(page_title="Traffic Anomaly AI", layout="wide")

st.title("🔐 AI-Powered Traffic Anomaly & Threat Explanation System")
st.write("Upload a traffic log CSV file to detect suspicious traffic and generate AI-based threat explanations.")

uploaded_file = st.file_uploader("Upload traffic log CSV", type=["csv"])

if uploaded_file is not None:
    # Load data
    df = pd.read_csv(uploaded_file)

    st.subheader("📄 Uploaded Traffic Logs")
    st.dataframe(df)

    # Select features
    features = df[["request_count", "response_time"]]

    # Train Isolation Forest
    model = IsolationForest(
        n_estimators=100,
        contamination=0.2,
        random_state=42
    )

    df["anomaly"] = model.fit_predict(features)

    # Convert output
    df["anomaly_label"] = df["anomaly"].map({
        1: "Normal",
        -1: "Suspicious"
    })

    st.subheader("🚨 Detected Traffic Anomalies")
    st.dataframe(df[["timestamp", "ip", "request_count", "response_time", "anomaly_label"]])

    # Show suspicious traffic only
    suspicious_df = df[df["anomaly_label"] == "Suspicious"]

    if not suspicious_df.empty:
        st.subheader("🧠 AI Threat Explanations")

        for _, row in suspicious_df.iterrows():
            reason = build_reason(row)
            explanation = explain_threat(row["ip"], reason)

            st.markdown(f"### IP: {row['ip']}")
            st.write(f"**Observed Behavior:** {reason}")
            st.write(explanation)
            st.markdown("---")
    else:
        st.success("No suspicious traffic detected.")