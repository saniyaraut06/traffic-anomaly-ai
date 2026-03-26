import pandas as pd
import random
import time
from datetime import datetime

ip_pool = [
    "192.168.1.10", "192.168.1.11", "192.168.1.12",
    "192.168.1.13", "192.168.1.14", "192.168.1.15",
    "192.168.1.16", "192.168.1.17", "192.168.1.18",
    "192.168.1.19", "192.168.1.20", "192.168.1.21"
]

output_file = "data/traffic_logs_live.csv"

try:
    pd.read_csv(output_file)
except FileNotFoundError:
    df = pd.DataFrame(columns=[
        "timestamp", "ip", "request_count", "response_time", "status_code"
    ])
    df.to_csv(output_file, index=False)

print("Generating live traffic logs... Press Ctrl+C to stop.")

while True:
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ip = random.choice(ip_pool)

    request_count = random.randint(40, 80)
    response_time = random.randint(150, 250)
    status_code = random.choice([200, 404, 500])

    if random.random() < 0.2:
        request_count = random.randint(1100, 1600)
        response_time = random.randint(8, 25)

    new_row = pd.DataFrame([{
        "timestamp": timestamp,
        "ip": ip,
        "request_count": request_count,
        "response_time": response_time,
        "status_code": status_code
    }])

    new_row.to_csv(output_file, mode="a", header=False, index=False)

    print(f"Added: {timestamp}, {ip}, {request_count}, {response_time}")

    time.sleep(2)