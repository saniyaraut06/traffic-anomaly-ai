# 🔐 Near Real-Time AI-Powered Traffic Anomaly Detection & Threat Explanation System

## 📌 Project Overview
This project is a **near real-time cybersecurity monitoring system** that detects suspicious network traffic and explains potential threats using **Machine Learning** and **Generative AI**.
It simulates incoming traffic logs, identifies anomalies using **Isolation Forest**, and generates human-readable cybersecurity explanations using a **local LLM (phi via Ollama)**.
The project is visualized through an interactive **Streamlit dashboard** for monitoring, filtering, visualization, and threat reporting.

## 🚀 Key Features
- 📡 **Near real-time traffic simulation**
- 🤖 **Anomaly detection using Isolation Forest**
- 🧠 **AI-based threat explanation using local LLM**
- 🛡️ **Threat type prediction** (DDoS, Bot Traffic, etc.)
- 🚨 **Severity classification** (High / Medium / Low)
- 📊 **Interactive Streamlit dashboard**
- 🔎 **Filter traffic by IP**
- 📈 **Traffic visualization**
- 📥 **Downloadable anomaly reports**
- 📝 **Executive summary generation**

## 🧠 Tech Stack
- **Python**
- **Pandas**
- **Scikit-learn**
- **Streamlit**
- **Ollama**
- **phi (Local LLM)**

## 🏗️ Project Architecture

Live Traffic Generator
        ↓
traffic_logs_live.csv
        ↓
Isolation Forest (ML Anomaly Detection)
        ↓
Rule-Based Threat Reasoning
        ↓
Generative AI (Local LLM - phi)
        ↓
Streamlit Dashboard
