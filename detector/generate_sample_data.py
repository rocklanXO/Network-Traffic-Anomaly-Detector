"""
generate_sample_data.py

Builds a synthetic NetFlow/Zeek-style connection log with normal background
traffic plus three embedded anomaly patterns:

  1. Beaconing        - a compromised host calling home at a near-fixed interval
  2. Data exfiltration - one abnormally large outbound transfer
  3. Port scan         - one host sweeping many ports on an internal target

All IPs/timestamps are synthetic. Output: ../data/sample_traffic.csv
"""

import csv
import random
from datetime import datetime, timedelta

random.seed(42)

START = datetime(2026, 9, 20, 0, 0, 0)
rows = []


def add_row(ts, src_ip, dst_ip, dst_port, proto, bytes_sent, bytes_recv, duration):
    rows.append({
        "timestamp": ts.isoformat(),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "proto": proto,
        "bytes_sent": bytes_sent,
        "bytes_recv": bytes_recv,
        "duration_sec": duration,
    })


# --- 1. Normal background traffic: internal hosts browsing the web ---
internal_hosts = [f"10.20.0.{i}" for i in range(10, 40)]
common_sites = [f"93.184.{a}.{b}" for a, b in [(216, 34), (216, 35), (215, 12), (214, 88)]]
common_ports = [443, 443, 443, 80, 443]

for _ in range(600):
    ts = START + timedelta(seconds=random.randint(0, 86400))
    add_row(
        ts,
        random.choice(internal_hosts),
        random.choice(common_sites),
        random.choice(common_ports),
        "tcp",
        random.randint(200, 8000),
        random.randint(500, 50000),
        round(random.uniform(0.1, 12.0), 2),
    )

# --- 2. Beaconing: infected host calling out every ~300s (+/- small jitter) ---
beacon_src = "10.20.0.77"
beacon_dst = "185.220.101.42"
t = START + timedelta(hours=2)
for _ in range(90):
    jitter = random.randint(-8, 8)
    t += timedelta(seconds=300 + jitter)
    add_row(t, beacon_src, beacon_dst, 443, "tcp",
            random.randint(340, 380), random.randint(180, 210), round(random.uniform(0.3, 0.6), 2))

# --- 3. Data exfiltration: one large outbound transfer, off-hours ---
add_row(
    START + timedelta(hours=3, minutes=14),
    "10.20.0.55", "45.61.33.90", 443, "tcp",
    bytes_sent=482_000_000,   # ~482 MB out, way above baseline
    bytes_recv=12_000,
    duration=340.5,
)

# --- 4. Port scan: one host sweeps 120 ports on an internal server in ~30s ---
scan_src = "10.20.0.91"
scan_target = "10.20.0.5"
scan_start = START + timedelta(hours=5, minutes=2)
for i, port in enumerate(random.sample(range(1, 10000), 120)):
    ts = scan_start + timedelta(milliseconds=i * 250)
    add_row(ts, scan_src, scan_target, port, "tcp", 0, 0, 0.01)

rows.sort(key=lambda r: r["timestamp"])

with open("../data/sample_traffic.csv", "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=rows[0].keys())
    writer.writeheader()
    writer.writerows(rows)

print(f"Wrote {len(rows)} rows to data/sample_traffic.csv")
