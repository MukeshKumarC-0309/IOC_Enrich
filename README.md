# IOC Enrichment & Triage Tool

A single-indicator (IP or domain) threat-intelligence enrichment tool. It
queries three sources — AbuseIPDB, VirusTotal, and URLhaus — aggregates their
verdicts with deterministic rules (no ML, no agent), maps findings to MITRE
ATT&CK techniques, and prints an analyst-readable triage recommendation.

## Features

- **Three-source enrichment** — AbuseIPDB (community abuse score), VirusTotal
  (AV-engine ratio), URLhaus (curated malware/C2 blocklist).
- **Deterministic aggregation** — a fixed truth table and override rules, fully
  documented in `DESIGN.md`. No verdict is ever produced by a model.
- **Disagreement flagging** — when sources conflict, the verdict is downgraded
  to `suspicious` and flagged, never silently resolved to `clean`.
- **MITRE ATT&CK mapping** — rule-based tagging of T1110 (Brute Force) and
  T1071 (Application Layer Protocol / C2).
- **Human or JSON output** — a formatted, color-coded terminal view by default;
  raw JSON with `--json` for scripting.

## Requirements

- **Python 3.9+**
- Internet access
- Free API keys for all three sources:
  - AbuseIPDB — <https://www.abuseipdb.com/account/api>
  - VirusTotal — <https://www.virustotal.com/gui/my-apikey>
  - URLhaus (abuse.ch Auth-Key) — <https://auth.abuse.ch/>

## Installation

```bash
# 1. Clone
git clone <your-repo-url> ioc_enrich && cd ioc_enrich

# 2. Create and activate a virtual environment
python -m venv .venv
# macOS/Linux:
source .venv/bin/activate
# Windows (PowerShell):
.venv\Scripts\Activate.ps1

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure API keys
cp .env.example .env      # then edit .env and paste in your three keys
```

`.env` is gitignored and must never be committed. Verify your keys loaded
(prints only True/False, never the values):

```bash
python -c "from ioc_enrich import config as c; print({'abuseipdb': bool(c.ABUSEIPDB_API_KEY), 'virustotal': bool(c.VIRUSTOTAL_API_KEY), 'urlhaus': bool(c.URLHAUS_AUTH_KEY)})"
```

## Usage

```bash
python -m ioc_enrich <indicator> [--json] [--no-color]
```

Examples:

```bash
python -m ioc_enrich 8.8.8.8
python -m ioc_enrich evil-domain.example --json
python -m ioc_enrich 1.2.3.4 --no-color
```

Flags:

| Flag | Effect |
|------|--------|
| `--json` | Emit the raw JSON report instead of the human view (pipe-to-`jq` friendly) |
| `--no-color` | Disable ANSI color (also honors the `NO_COLOR` env var; color is off automatically when output is piped) |

Exit codes reflect whether the **tool** succeeded, not what verdict it found
(a `malicious` result is still a successful run → exit 0):

| Code | Meaning |
|------|---------|
| `0` | Assessment produced (malicious / suspicious / clean) |
| `1` | `status: "error"` — sources unreachable, no assessment possible |
| `2` | Invalid input — not a valid IP or domain |

## Output

The default human view shows the aggregated verdict, confidence, flags, ATT&CK
techniques, a per-source breakdown, and the recommendation. With `--json` you
get the full structured record (schema documented in `DESIGN.md` §7). Every
source carries a `status` field; `not_applicable` (no data by design) is kept
distinct from `error` / `query_error` (tried and failed).

## How it works

1. **Classify** the indicator as an IP or domain.
2. **Query** the sources (AbuseIPDB is IP-only and is skipped for domains).
3. **Score** each source against fixed thresholds (`DESIGN.md` §2).
4. **Aggregate** deterministically: a URLhaus blocklist match overrides to
   `malicious`; otherwise AbuseIPDB and VirusTotal are combined via the truth
   table in `DESIGN.md` §10.B, with conflicts downgraded to `suspicious`.
5. **Map** to ATT&CK techniques from the raw source signals (`DESIGN.md` §10.C).
6. **Recommend** via a deterministic situation → string lookup (`DESIGN.md`
   §10.E).

The full, locked design rationale lives in [`DESIGN.md`](DESIGN.md).

## Limitations

- **Provisional URLhaus high-volume threshold.** A URLhaus match with
  `url_count >= 750` is treated as shared-hosting/CDN noise and does not drive
  the verdict or the T1071 tag. The 750 cutoff was calibrated on a single
  observed false positive (github.com, 7930) plus one collateral downgrade of a
  real malware host (91.92.242.236, 853); it needs more shared-hosting samples
  to calibrate properly. Known limitation, not resolved in v1.
- **T1110 mapping is recall-favoring by design** — any reported
  brute-force-category signal fires the tag regardless of overall verdict, which
  can produce a clean verdict alongside a T1110 tag on high-reputation
  infrastructure with stale or low-volume abuse reports (observed on 8.8.8.8).
- **Two-source coverage for confident "malicious".** Confirmed C2 IPs that are
  not on URLhaus and that AbuseIPDB scores low will land at `suspicious`, not
  `malicious` (observed on Feodo Tracker C2 IPs). The tool still surfaces them
  for review; it just won't assert `malicious` without a blocklist hit or
  AbuseIPDB corroboration.
- **Domains have one voter.** AbuseIPDB has no domain endpoint, so a domain is
  assessed by VirusTotal (plus the URLhaus override) alone, reported with
  `single_source: true`, and T1110 is structurally unreachable for domains.

## Project structure

```
ioc_enrich/
├── __main__.py        # `python -m ioc_enrich` entry point
├── cli.py             # argparse, exit codes, output selection
├── render.py          # human-readable formatted view (+ color)
├── config.py          # .env loading, API keys, endpoints
├── indicator.py       # classify input as ip | domain
├── clients/           # one HTTP client per source (raw fields only)
│   ├── abuseipdb.py
│   ├── virustotal.py
│   └── urlhaus.py
├── verdicts.py        # per-source threshold logic (DESIGN §2)
├── aggregate.py       # deterministic aggregation (DESIGN §3 / §10)
├── attack.py          # rule-based ATT&CK mapping (DESIGN §6 / §10.C)
├── recommend.py       # situation → recommendation lookup (DESIGN §5 / §10.E)
├── report.py          # output-schema assembly (DESIGN §7)
└── pipeline.py        # orchestrator: enrich(indicator) → report dict

DESIGN.md              # full design specification (source of truth)
verify.py              # Phase 4 verification harness
phase4_test_indicators.csv   # labelled known-good / known-bad indicators
```

## Verification

A verification harness runs the tool against a labelled set of known-malicious
and known-benign indicators and reports pass/fail:

```bash
python verify.py phase4_test_indicators.csv
```

It paces requests for VirusTotal's ~4 req/min free-tier limit, so a full run
takes several minutes.
