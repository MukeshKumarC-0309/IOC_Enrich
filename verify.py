#!/usr/bin/env python3
"""Phase 4 verification harness.

Runs the enrichment tool against a labelled CSV of known indicators and reports
pass/fail against expected verdicts. Paces requests for VirusTotal's ~4 req/min
free tier. READ-ONLY — does not modify aggregate.py / attack.py; it only reports.

Pass rule (DESIGN's recall-favouring posture):
  * expected == "malicious"  -> pass if actual in {malicious, suspicious}
  * expected == "benign"     -> pass if actual in {clean, suspicious}
                                (fail on "malicious")
  * EXCEPTION source == "Feodo Tracker" -> STRICT: pass ONLY on exact
    "malicious" (confirmed high-confidence botnet C2 ground truth).

An indicator whose sources all failed (aggregated_verdict is null / status
"error") is reported as ERROR and counted separately from PASS/FAIL — that is a
tooling/network outcome (e.g. missing key, rate limit, host gone offline), not a
verdict miss, and lumping it into FAIL would hide the distinction.

Usage:
    python verify.py [csv_path] [--delay SECONDS]
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
import time

from ioc_enrich import enrich

# Make em-dashes etc. in recommendation strings printable on any console.
try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

STRICT_SOURCE = "Feodo Tracker"


def verdict_passes(expected: str, actual, source: str):
    """Return True/False for pass, or None if the row errored (actual is null)."""
    if actual is None:
        return None  # no usable data — reported as ERROR, not a verdict miss
    if source == STRICT_SOURCE:
        return actual == "malicious"
    if expected == "malicious":
        return actual in ("malicious", "suspicious")
    if expected == "benign":
        return actual in ("clean", "suspicious")
    return None  # unrecognised expected label


def voters_disagree(report: dict) -> bool:
    """True when AbuseIPDB and VT both voted and their verdicts differ.

    Covers every off-diagonal truth-table cell (adjacent and opposite ends),
    which is what's useful for hand-tracing against DESIGN §10.B.
    """
    ab = report["sources"]["abuseipdb"]
    vt = report["sources"]["virustotal"]
    if ab.get("status") == "ok" and vt.get("status") == "ok":
        return ab.get("verdict") != vt.get("verdict")
    return False


def main() -> int:
    ap = argparse.ArgumentParser(description="Phase 4 verification harness")
    ap.add_argument("csv", nargs="?", default="phase4_test_indicators.csv")
    ap.add_argument(
        "--delay",
        type=float,
        default=15.0,
        help="seconds between indicators (VT free tier ~4 req/min -> 15s)",
    )
    args = ap.parse_args()

    with open(args.csv, newline="", encoding="utf-8") as f:
        rows = [r for r in csv.DictReader(f) if r.get("indicator", "").strip()]

    total = len(rows)
    mal = sum(1 for r in rows if r["expected_category"].strip() == "malicious")
    ben = sum(1 for r in rows if r["expected_category"].strip() == "benign")
    est_min = (total - 1) * args.delay / 60 if total else 0
    print(
        f"Loaded {total} indicators ({mal} malicious / {ben} benign) from "
        f"{args.csv}\nDelay {args.delay}s between calls -> ~{est_min:.0f} min "
        f"total.\n"
    )

    results = []        # dicts: indicator, type, expected, actual, outcome, source
    disagreements = []  # full enrich() reports

    for i, row in enumerate(rows, 1):
        indicator = row["indicator"].strip()
        expected = row["expected_category"].strip()
        source = row.get("source", "").strip()

        try:
            report = enrich(indicator)
            actual = report["aggregated_verdict"]
        except Exception as exc:  # never let one row kill the run
            report, actual = None, None
            print(f"[{i}/{total}] EXC   {indicator}: {exc}", file=sys.stderr)

        passed = verdict_passes(expected, actual, source)
        outcome = "ERROR" if passed is None else ("PASS" if passed else "FAIL")
        results.append(
            {
                "indicator": indicator,
                "type": row["type"].strip(),
                "expected": expected,
                "actual": actual,
                "outcome": outcome,
                "source": source,
            }
        )
        if report is not None and voters_disagree(report):
            disagreements.append(report)

        strict = " [STRICT]" if source == STRICT_SOURCE else ""
        print(
            f"[{i:2}/{total}] {outcome:5} {indicator:24} "
            f"exp={expected:9} act={str(actual):10}{strict}"
        )

        if i < total:
            time.sleep(args.delay)

    _print_table(results)
    _print_summary(results, total)
    _print_disagreements(disagreements)
    return 0


def _print_table(results: list) -> None:
    print("\n" + "=" * 78)
    print("PER-INDICATOR RESULTS")
    print("=" * 78)
    print(f"{'#':>2}  {'RESULT':6} {'INDICATOR':24} {'TYPE':6} {'EXPECTED':9} {'ACTUAL':10} SOURCE")
    print("-" * 78)
    for i, r in enumerate(results, 1):
        flag = " *" if r["source"] == STRICT_SOURCE else ""
        print(
            f"{i:>2}  {r['outcome']:6} {r['indicator']:24} {r['type']:6} "
            f"{r['expected']:9} {str(r['actual']):10} {r['source']}{flag}"
        )
    print("(* = strict Feodo Tracker rule: exact 'malicious' required)")


def _print_summary(results: list, total: int) -> None:
    passed = sum(1 for r in results if r["outcome"] == "PASS")
    failed = sum(1 for r in results if r["outcome"] == "FAIL")
    errored = sum(1 for r in results if r["outcome"] == "ERROR")
    print("\n" + "=" * 78)
    print("SUMMARY")
    print("=" * 78)
    print(f"  PASSED : {passed}/{total}")
    print(f"  FAILED : {failed}/{total}")
    print(f"  ERRORED: {errored}/{total}  (no usable data — network/key/offline)")

    fails = [r for r in results if r["outcome"] == "FAIL"]
    if fails:
        print("\n  Failures:")
        for r in fails:
            print(
                f"    {r['indicator']:24} exp={r['expected']:9} "
                f"act={str(r['actual']):10} ({r['source']})"
            )
    errs = [r for r in results if r["outcome"] == "ERROR"]
    if errs:
        print("\n  Errored (excluded from pass/fail):")
        for r in errs:
            print(f"    {r['indicator']:24} ({r['source']})")


def _print_disagreements(disagreements: list) -> None:
    print("\n" + "=" * 78)
    print(f"AbuseIPDB vs VirusTotal DISAGREEMENTS ({len(disagreements)})")
    print("full raw enrich() output — for hand-tracing against DESIGN §10.B")
    print("=" * 78)
    if not disagreements:
        print("(none — no IP had both voters return differing verdicts)")
        return
    for rep in disagreements:
        ab = rep["sources"]["abuseipdb"].get("verdict")
        vt = rep["sources"]["virustotal"].get("verdict")
        print(f"\n--- {rep['indicator']}: AbuseIPDB={ab} vs VirusTotal={vt} "
              f"-> aggregated={rep['aggregated_verdict']} "
              f"(disagreement={rep['disagreement']}, confidence={rep['confidence']}) ---")
        print(json.dumps(rep, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    raise SystemExit(main())
