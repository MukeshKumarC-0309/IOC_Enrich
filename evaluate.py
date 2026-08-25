#!/usr/bin/env python3
"""Evaluation harness — measure the tool against a labelled indicator set.

Two subcommands:

  capture   Query the live sources ONCE and snapshot each source's raw response
            to a fixtures file (eval_fixtures.json). Paces requests for
            VirusTotal's ~4 req/min free tier.

  report    Replay the fixtures OFFLINE (no network) through the real
            aggregation logic and compute metrics: a confusion matrix,
            precision / recall / F1, and per-source threshold sweeps. Writes a
            markdown report (EVAL.md).

Separating capture from report makes the metrics deterministic and reproducible
— re-running `report` always yields the same numbers, and threshold sweeps cost
nothing (no API calls). The baseline metrics use the project's real
`aggregate.aggregate()`; only the sweeps vary thresholds, applied to the
captured raw values.

Usage:
    python evaluate.py capture [csv] [--delay SECONDS]
    python evaluate.py report  [--fixtures eval_fixtures.json]
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
import time
from datetime import datetime, timezone

from ioc_enrich.aggregate import aggregate
from ioc_enrich.clients import abuseipdb, urlhaus, virustotal
from ioc_enrich.indicator import IP, classify

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

FIXTURES = "eval_fixtures.json"
REPORT = "EVAL.md"
STRICT_SOURCE = "Feodo Tracker"


# --------------------------------------------------------------------------- #
# capture
# --------------------------------------------------------------------------- #
def cmd_capture(args) -> int:
    with open(args.csv, newline="", encoding="utf-8") as f:
        rows = [r for r in csv.DictReader(f) if r.get("indicator", "").strip()]

    total = len(rows)
    est = (total - 1) * args.delay / 60 if total else 0
    print(f"Capturing {total} indicators (delay {args.delay}s -> ~{est:.0f} min)\n")

    captured = []
    for i, row in enumerate(rows, 1):
        raw = row["indicator"].strip()
        try:
            indicator_type, target = classify(raw)
        except ValueError:
            print(f"[{i}/{total}] SKIP invalid: {raw}", file=sys.stderr)
            continue

        abuse = abuseipdb.check(target) if indicator_type == IP else None
        vt = virustotal.check(target, indicator_type)
        uh = urlhaus.check(target)

        captured.append(
            {
                "indicator": target,
                "type": indicator_type,
                "expected": row["expected_category"].strip(),
                "source": row.get("source", "").strip(),
                "abuse": abuse,
                "vt": vt,
                "urlhaus": uh,
            }
        )
        print(f"[{i:2}/{total}] captured {target}")
        if i < total:
            time.sleep(args.delay)

    payload = {
        "captured_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "count": len(captured),
        "indicators": captured,
    }
    with open(FIXTURES, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)
    print(f"\nWrote {len(captured)} fixtures to {FIXTURES}")
    return 0


# --------------------------------------------------------------------------- #
# metrics helpers
# --------------------------------------------------------------------------- #
def _prf(tp: int, fp: int, fn: int):
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return precision, recall, f1


def _vt_ratio(vt: dict):
    if vt and vt["ok"]:
        raw = vt["raw"]
        if raw["total"]:
            return raw["malicious"] / raw["total"]
    return None


# --------------------------------------------------------------------------- #
# report
# --------------------------------------------------------------------------- #
def cmd_report(args) -> int:
    with open(args.fixtures, encoding="utf-8") as f:
        data = json.load(f)
    rows = data["indicators"]

    lines = []  # markdown report body

    def out(s=""):
        print(s)
        lines.append(s)

    out(f"# Evaluation report")
    out()
    out(f"Fixtures captured: `{data.get('captured_at', '?')}`  ·  "
        f"{data.get('count', len(rows))} indicators")
    out()
    out("Metrics are computed offline by replaying captured raw source "
        "responses through the project's real aggregation logic "
        "(`ioc_enrich.aggregate`), so they are fully reproducible.")
    out()

    # --- Baseline: full-pipeline verdict vs label -------------------------- #
    # Positive class = expected "malicious". "Flagged" = verdict malicious OR
    # suspicious (the tool's recall-favouring triage stance). Errors excluded.
    tp = fp = fn = tn = err = 0
    strict_tp = strict_fp = 0            # confident-malicious (verdict == malicious)
    feodo = {"malicious": 0, "suspicious": 0, "clean": 0, "error": 0}

    for r in rows:
        agg = aggregate(r["type"], r["abuse"], r["vt"], r["urlhaus"])
        verdict = agg.verdict
        expected = r["expected"]

        if r["source"] == STRICT_SOURCE:
            feodo[verdict if verdict else "error"] += 1

        if verdict is None:
            err += 1
            continue
        flagged = verdict in ("malicious", "suspicious")
        if expected == "malicious":
            if flagged:
                tp += 1
            else:
                fn += 1
            if verdict == "malicious":
                strict_tp += 1
        else:  # benign
            if flagged:
                fp += 1
            else:
                tn += 1
            if verdict == "malicious":
                strict_fp += 1

    precision, recall, f1 = _prf(tp, fp, fn)
    scored = tp + fp + fn + tn
    accuracy = (tp + tn) / scored if scored else 0.0

    out("## 1. Baseline — full pipeline (flagged = malicious or suspicious)")
    out()
    out("Positive class = known-malicious. \"Flagged\" reflects the tool's "
        "recall-favouring triage purpose (surface anything not clean).")
    out()
    out("| | predicted flagged | predicted clean |")
    out("|---|---|---|")
    out(f"| **actual malicious** | {tp} (TP) | {fn} (FN) |")
    out(f"| **actual benign** | {fp} (FP) | {tn} (TN) |")
    out()
    out(f"- Precision: **{precision:.3f}**")
    out(f"- Recall: **{recall:.3f}**")
    out(f"- F1: **{f1:.3f}**")
    out(f"- Accuracy: **{accuracy:.3f}**  ({scored} scored, {err} errored/excluded)")
    out()
    out(f"Confident-malicious view (predicted verdict is exactly `malicious`): "
        f"{strict_tp} of {tp + fn} known-malicious reached `malicious`; "
        f"{strict_fp} benign were called `malicious` (false alarms).")
    out()

    # --- Feodo Tracker strict subset --------------------------------------- #
    if sum(feodo.values()):
        out("## 2. Feodo Tracker subset (confirmed C2 ground truth)")
        out()
        out("These are high-confidence botnet C2 IPs. The verdict distribution "
            "shows the two-source-coverage limitation: C2 IPs not on URLhaus and "
            "scored low by AbuseIPDB land at `suspicious`, not `malicious`.")
        out()
        out(f"- malicious: {feodo['malicious']}")
        out(f"- suspicious: {feodo['suspicious']}")
        out(f"- clean: {feodo['clean']}  (missed entirely)")
        out(f"- error: {feodo['error']}")
        out()

    # --- Per-source threshold sweeps --------------------------------------- #
    out("## 3. Per-source threshold sweeps")
    out()
    out("Each source evaluated as a standalone malicious-vs-benign classifier "
        "over the indicators it has data for. This shows each source's "
        "discriminative power in isolation — and why aggregation is needed.")
    out()

    # AbuseIPDB: flag if score > t. Only IPs with a successful AbuseIPDB result.
    out("### AbuseIPDB — vary the score threshold (flag if score > t)")
    out()
    out("| t (score >) | precision | recall | F1 |")
    out("|---|---|---|---|")
    for t in range(0, 100, 10):
        a_tp = a_fp = a_fn = 0
        for r in rows:
            ab = r["abuse"]
            if not (ab and ab["ok"]):
                continue
            score = ab["raw"]["score"]
            flag = score > t
            if r["expected"] == "malicious":
                a_tp += flag
                a_fn += not flag
            else:
                a_fp += flag
        p, rc, fx = _prf(a_tp, a_fp, a_fn)
        mark = "  ← default (§2)" if t == 75 else ""
        out(f"| {t} | {p:.2f} | {rc:.2f} | {fx:.2f} |{mark}")
    out()
    out("_(§2 default is score > 75. The low recall at that cutoff is the point: "
        "many real malware hosts carry low AbuseIPDB scores.)_")
    out()

    # VirusTotal: flag if ratio >= r. All indicators with a successful VT result.
    out("### VirusTotal — vary the malicious-ratio threshold (flag if ratio ≥ r)")
    out()
    out("| r (ratio ≥) | precision | recall | F1 |")
    out("|---|---|---|---|")
    for pct in range(0, 21, 2):
        r_thresh = pct / 100
        v_tp = v_fp = v_fn = 0
        for r in rows:
            ratio = _vt_ratio(r["vt"])
            if ratio is None:
                continue
            flag = ratio >= r_thresh
            if r["expected"] == "malicious":
                v_tp += flag
                v_fn += not flag
            else:
                v_fp += flag
        p, rc, fx = _prf(v_tp, v_fp, v_fn)
        mark = ""
        if pct == 10:
            mark = "  ← default malicious (§2)"
        elif pct == 2:
            mark = "  ← near default suspicious floor (3%)"
        out(f"| {pct}% | {p:.2f} | {rc:.2f} | {fx:.2f} |{mark}")
    out()
    out("_(§2 defaults: ≥10% → malicious, ≥3% → suspicious. VirusTotal shows "
        "far better separation than AbuseIPDB on this set.)_")
    out()

    with open(REPORT, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print(f"\nWrote report to {REPORT}")
    return 0


# --------------------------------------------------------------------------- #
def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Evaluation harness")
    sub = parser.add_subparsers(dest="cmd", required=True)

    cap = sub.add_parser("capture", help="snapshot live source responses to fixtures")
    cap.add_argument("csv", nargs="?", default="phase4_test_indicators.csv")
    cap.add_argument("--delay", type=float, default=15.0,
                     help="seconds between indicators (VT ~4 req/min)")
    cap.set_defaults(func=cmd_capture)

    rep = sub.add_parser("report", help="compute metrics offline from fixtures")
    rep.add_argument("--fixtures", default=FIXTURES)
    rep.set_defaults(func=cmd_report)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
