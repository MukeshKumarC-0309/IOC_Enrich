# Evaluation report

Fixtures captured: `2026-08-25T14:46:14+00:00`  ·  58 indicators

Metrics are computed offline by replaying captured raw source responses through the project's real aggregation logic (`ioc_enrich.aggregate`), so they are fully reproducible.

## 1. Baseline — full pipeline (flagged = malicious or suspicious)

Positive class = known-malicious. "Flagged" reflects the tool's recall-favouring triage purpose (surface anything not clean).

| | predicted flagged | predicted clean |
|---|---|---|
| **actual malicious** | 36 (TP) | 1 (FN) |
| **actual benign** | 0 (FP) | 21 (TN) |

- Precision: **1.000**
- Recall: **0.973**
- F1: **0.986**
- Accuracy: **0.983**  (58 scored, 0 errored/excluded)

Confident-malicious view (predicted verdict is exactly `malicious`): 31 of 37 known-malicious reached `malicious`; 0 benign were called `malicious` (false alarms).

## 2. Feodo Tracker subset (confirmed C2 ground truth)

These are high-confidence botnet C2 IPs. The verdict distribution shows the two-source-coverage limitation: C2 IPs not on URLhaus and scored low by AbuseIPDB land at `suspicious`, not `malicious`.

- malicious: 0
- suspicious: 4
- clean: 1  (missed entirely)
- error: 0

## 3. Per-source threshold sweeps

Each source evaluated as a standalone malicious-vs-benign classifier over the indicators it has data for. This shows each source's discriminative power in isolation — and why aggregation is needed.

### AbuseIPDB — vary the score threshold (flag if score > t)

| t (score >) | precision | recall | F1 |
|---|---|---|---|
| 0 | 1.00 | 0.79 | 0.88 |
| 10 | 1.00 | 0.39 | 0.57 |
| 20 | 1.00 | 0.27 | 0.43 |
| 30 | 1.00 | 0.15 | 0.26 |
| 40 | 1.00 | 0.12 | 0.22 |
| 50 | 1.00 | 0.09 | 0.17 |
| 60 | 1.00 | 0.06 | 0.11 |
| 70 | 1.00 | 0.06 | 0.11 |
| 80 | 1.00 | 0.06 | 0.11 |
| 90 | 1.00 | 0.06 | 0.11 |

_(§2 default is score > 75. The low recall at that cutoff is the point: many real malware hosts carry low AbuseIPDB scores.)_

### VirusTotal — vary the malicious-ratio threshold (flag if ratio ≥ r)

| r (ratio ≥) | precision | recall | F1 |
|---|---|---|---|
| 0% | 0.64 | 1.00 | 0.78 |
| 2% | 0.97 | 0.97 | 0.97 |  ← near default suspicious floor (3%)
| 4% | 1.00 | 0.92 | 0.96 |
| 6% | 1.00 | 0.81 | 0.90 |
| 8% | 1.00 | 0.70 | 0.83 |
| 10% | 1.00 | 0.43 | 0.60 |  ← default malicious (§2)
| 12% | 1.00 | 0.41 | 0.58 |
| 14% | 1.00 | 0.32 | 0.49 |
| 16% | 1.00 | 0.19 | 0.32 |
| 18% | 1.00 | 0.11 | 0.20 |
| 20% | 1.00 | 0.05 | 0.10 |

_(§2 defaults: ≥10% → malicious, ≥3% → suspicious. VirusTotal shows far better separation than AbuseIPDB on this set.)_

