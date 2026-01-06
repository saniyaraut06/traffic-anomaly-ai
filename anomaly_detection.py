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

# Show results
print("\nDetected Traffic Anomalies:\n")
print(df[["timestamp", "ip", "request_count", "response_time", "anomaly_label"]])
