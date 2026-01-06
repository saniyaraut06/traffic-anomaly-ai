from ai_explainer import explain_threat
import pandas as pd
from sklearn.ensemble import IsolationForest

# Load data
df = pd.read_csv("data/traffic_logs.csv")

# Select features for anomaly detection
features = df[["request_count", "response_time"]]

# Train Isolation Forest
model = IsolationForest(
    n_estimators=100,
    contamination=0.2,
    random_state=42
)

df["anomaly"] = model.fit_predict(features)

# Convert output to readable labels
df["anomaly_label"] = df["anomaly"].map({
    1: "Normal",
    -1: "Suspicious"
})

# Rule-based reasoning (WHY)
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


# Show results
print("\nDetected Traffic Anomalies:\n")
print(df[["timestamp", "ip", "request_count", "response_time", "anomaly_label"]])

print("\nAI Threat Explanations:\n")

# CORRECT LOOP
for _, row in df[df["anomaly_label"] == "Suspicious"].iterrows():
    reason = build_reason(row)

    explanation = explain_threat(
        row["ip"],
        reason
    )

    print(f"IP: {row['ip']}")
    print(explanation)
    print("-" * 60)
