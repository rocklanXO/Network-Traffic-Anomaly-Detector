# Network Traffic Anomaly Detector

A Python tool that analyzes NetFlow/Zeek-style connection logs and flags
three classic network attack patterns: **beaconing**, **data-volume
outliers**, and **port scanning** — using statistical methods, not
signatures.

> ⚠️ Ships with a synthetic traffic dataset (no real network capture) so
> it's safe to run and publish. Generation script included so the data is
> fully reproducible.

## What it detects

| Pattern | Technique | Real-world equivalent |
|---|---|---|
| Beaconing | Coefficient of variation on connection timing | C2 check-ins, malware callbacks |
| Volume outliers | Z-score on bytes transferred | Data staging / exfiltration |
| Port scanning | Distinct-port count per time window | Recon / lateral movement |

Full methodology and results: [`docs/methodology.md`](docs/methodology.md)

## Quick Start

```bash
pip install -r requirements.txt

# (optional) regenerate the synthetic dataset
cd detector
python3 generate_sample_data.py

# run the detector
python3 anomaly_detector.py ../data/sample_traffic.csv
```

Sample output:

```
4 anomalies detected:

[BEACONING] 10.20.0.77 -> 185.220.101.42
    90 connections, avg interval 300.0s, CV=0.017 (< 0.15 threshold)

[VOLUME_OUTLIER] 10.20.0.55 -> 45.61.33.90
    482,000,000 bytes sent to 45.61.33.90 (z-score 28.44, threshold 3.0)

[PORT_SCAN] 10.20.0.91 -> 10.20.0.5
    120 distinct ports contacted on 10.20.0.5 within 60s starting 2026-09-20 05:02:00
```

A full CSV report is written to `reports/anomaly_report.csv`.

## Repo Structure

```
.
├── README.md
├── requirements.txt
├── data/
│   └── sample_traffic.csv          # synthetic flow log (generated)
├── detector/
│   ├── generate_sample_data.py     # builds the synthetic dataset
│   └── anomaly_detector.py         # the three detectors
├── docs/
│   └── methodology.md              # technique explanations + results
└── reports/
    └── anomaly_report.csv          # output of the last detector run
```

## Tool Stack

Python · pandas · numpy · statistical anomaly detection (z-score, CV) ·
NetFlow/Zeek-style flow log analysis

