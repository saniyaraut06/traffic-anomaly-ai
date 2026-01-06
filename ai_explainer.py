import subprocess

def explain_threat(ip, reason):
    prompt = f"""
You are a cybersecurity analyst.

A machine learning system has flagged suspicious traffic.

IP address: {ip}
Observed behavior: {reason}

Explain clearly:
- why this behavior is suspicious
- what type of cyber threat it may indicate
- the risk level (Low, Medium, or High)

Respond in 2–3 complete sentences.
"""

    result = subprocess.run(
        ["ollama", "run", "phi"],
        input=prompt,
        text=True,
        capture_output=True,
        encoding="utf-8",
        errors="ignore"
    )

    return result.stdout.strip()
