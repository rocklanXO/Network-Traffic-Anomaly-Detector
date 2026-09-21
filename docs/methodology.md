# Methodology

This project analyzes flow-level connection logs (fields matching common
NetFlow/Zeek `conn.log` exports: timestamp, src/dst IP, port, protocol,
bytes sent/received, duration) rather than raw packets — this is the same
data shape a SOC analyst typically triages in a SIEM.

Three detectors run against `data/sample_traffic.csv`, a synthetic dataset
of 811 flow records built by `detector/generate_sample_data.py`: ~600
records of normal browsing traffic, plus three embedded attack patterns.

## 1. Beaconing Detection

**Technique:** Group flows by (source, destination). For pairs with enough
history, compute the time deltas between consecutive connections, then the
coefficient of variation (`CV = stdev / mean`). Human-driven and
application traffic is bursty — CV is high. Malware beacons on a fixed
timer (even with jitter) — CV stays low.

**Threshold used:** CV < 0.15, with at least 10 events.

**Result on sample data:**
- `10.20.0.77 → 185.220.101.42`: 90 connections, ~300s interval, CV = 0.017
  — classic C2 beacon signature.
- `10.20.0.91 → 10.20.0.5`: also flagged (CV = 0.000) — this is actually
  the port-scan traffic below, caught a second time because a fixed
  250ms scan interval is *also* mathematically "regular." This is a good
  illustration of why a single detector's output should always be
  corroborated with others before a verdict, not read in isolation.

## 2. Volume Outlier Detection

**Technique:** Z-score of `bytes_sent` across all flows. Flags any single
transfer that is statistically extreme relative to the rest of the
traffic — the classic signature of data staging/exfiltration.

**Threshold used:** z-score > 3.0.

**Result on sample data:**
- `10.20.0.55 → 45.61.33.90`: 482,000,000 bytes sent, z-score 28.44 —
  roughly two orders of magnitude beyond even the threshold, and occurring
  at 03:14, outside normal business hours in this dataset.

## 3. Port Scan Detection

**Technique:** For each (source, destination) pair, bucket flows into
fixed time windows and count distinct destination ports contacted. A
normal client touches one or a handful of ports per target; a scanner
touches many, fast.

**Threshold used:** > 20 distinct ports within a 60-second window.

**Result on sample data:**
- `10.20.0.91 → 10.20.0.5`: 120 distinct ports in under 30 seconds —
  unambiguous horizontal/vertical scan behavior against an internal host.

## Tuning Notes

These thresholds (CV, z-score, port count/window) are intentionally
conservative starting points for a lab dataset. In a real environment they
should be tuned per-network using a baseline period, and beaconing
detection in particular benefits from also checking payload-size
consistency (not just timing) to cut false positives from legitimate
polling services (health checks, NTP, telemetry agents).
