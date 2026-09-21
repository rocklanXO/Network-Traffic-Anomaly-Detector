"""
anomaly_detector.py

Reads a NetFlow/Zeek-style connection log (CSV) and flags three classic
network anomaly patterns:

  1. Beaconing         - low-jitter, regular-interval connections to one host
  2. Volume outliers    - transfers far above a host's normal baseline (z-score)
  3. Port scanning      - one source hitting many distinct ports in a short window

Usage:
    python anomaly_detector.py ../data/sample_traffic.csv
"""

import sys
import pandas as pd
import numpy as np
from pathlib import Path


# ---------- Detection 1: Beaconing ----------
def detect_beaconing(df, min_events=10, max_cv=0.15):
    """
    Flags src->dst pairs whose connection timing is suspiciously regular.
    CV (coefficient of variation) = stdev(intervals) / mean(intervals).
    Real human/app traffic is bursty (high CV); C2 beacons are not (low CV).
    """
    findings = []
    grouped = df.sort_values("timestamp").groupby(["src_ip", "dst_ip"])
    for (src, dst), g in grouped:
        if len(g) < min_events:
            continue
        times = pd.to_datetime(g["timestamp"], format="ISO8601")
        deltas = times.diff().dropna().dt.total_seconds()
        if deltas.empty or deltas.mean() == 0:
            continue
        cv = deltas.std() / deltas.mean()
        if cv < max_cv:
            findings.append({
                "type": "beaconing",
                "src_ip": src,
                "dst_ip": dst,
                "event_count": len(g),
                "avg_interval_sec": round(deltas.mean(), 1),
                "interval_cv": round(cv, 3),
                "evidence": f"{len(g)} connections, avg interval "
                            f"{deltas.mean():.1f}s, CV={cv:.3f} (< {max_cv} threshold)",
            })
    return findings


# ---------- Detection 2: Volume outliers ----------
def detect_volume_outliers(df, z_thresh=3.0):
    """
    Flags individual transfers whose bytes_sent is a statistical outlier
    relative to the overall traffic distribution (z-score based).
    """
    findings = []
    mean = df["bytes_sent"].mean()
    std = df["bytes_sent"].std()
    if std == 0:
        return findings
    df = df.copy()
    df["z_score"] = (df["bytes_sent"] - mean) / std
    outliers = df[df["z_score"] > z_thresh]
    for _, row in outliers.iterrows():
        findings.append({
            "type": "volume_outlier",
            "src_ip": row["src_ip"],
            "dst_ip": row["dst_ip"],
            "bytes_sent": int(row["bytes_sent"]),
            "z_score": round(row["z_score"], 2),
            "evidence": f"{row['bytes_sent']:,} bytes sent to {row['dst_ip']} "
                        f"(z-score {row['z_score']:.2f}, threshold {z_thresh})",
        })
    return findings


# ---------- Detection 3: Port scan ----------
def detect_port_scan(df, window_sec=60, port_thresh=20):
    """
    Flags a source IP that contacts more than `port_thresh` distinct
    destination ports on the same target within a `window_sec` window.
    """
    findings = []
    df = df.copy()
    df["timestamp"] = pd.to_datetime(df["timestamp"], format="ISO8601")
    df["window"] = df["timestamp"].dt.floor(f"{window_sec}s")

    grouped = df.groupby(["src_ip", "dst_ip", "window"])["dst_port"].nunique()
    for (src, dst, window), port_count in grouped.items():
        if port_count > port_thresh:
            findings.append({
                "type": "port_scan",
                "src_ip": src,
                "dst_ip": dst,
                "window_start": str(window),
                "distinct_ports": int(port_count),
                "evidence": f"{port_count} distinct ports contacted on {dst} "
                            f"within {window_sec}s starting {window}",
            })
    return findings


def main():
    if len(sys.argv) < 2:
        print("Usage: python anomaly_detector.py <traffic_log.csv>")
        sys.exit(1)

    path = Path(sys.argv[1])
    df = pd.read_csv(path)

    all_findings = []
    all_findings += detect_beaconing(df)
    all_findings += detect_volume_outliers(df)
    all_findings += detect_port_scan(df)

    if not all_findings:
        print("No anomalies detected.")
        return

    print(f"\n{len(all_findings)} anomalies detected:\n")
    for f in all_findings:
        print(f"[{f['type'].upper()}] {f['src_ip']} -> {f['dst_ip']}")
        print(f"    {f['evidence']}\n")

    out_df = pd.DataFrame(all_findings)
    out_path = Path(__file__).parent.parent / "reports" / "anomaly_report.csv"
    out_df.to_csv(out_path, index=False)
    print(f"Report written to {out_path}")


if __name__ == "__main__":
    main()
