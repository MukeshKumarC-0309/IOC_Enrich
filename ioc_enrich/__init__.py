"""IOC Enrichment & Triage Tool.

Single-indicator (IP or domain) enrichment that queries three threat-intel
sources (AbuseIPDB, VirusTotal, URLhaus), aggregates their verdicts with
deterministic rules (no ML/agent), maps findings to MITRE ATT&CK techniques
(T1110, T1071), and emits a structured triage recommendation.

Full design: DESIGN.md (§1-9 locked; §10 = Phase-2 clarifications).

Package map:
    config.py        — .env loading, API keys, endpoints, timeouts
    indicator.py     — classify input as ip | domain (DESIGN §1, §10.A)
    clients/         — one HTTP client per source; return raw fields only
    verdicts.py      — DESIGN §2 threshold logic (the ONLY place thresholds live)
    aggregate.py     — DESIGN §3/§4/§10.B/§10.D decision logic  [Batch 2]
    attack.py        — DESIGN §6/§10.C ATT&CK mapping           [Phase 3 stub]
    recommend.py     — DESIGN §5/§10.E recommendation lookup    [Batch 2]
    report.py        — DESIGN §7/§10.F output assembly          [Batch 2]
    pipeline.py      — orchestrator: run one indicator end-to-end
"""

from .pipeline import enrich

__version__ = "0.1.0"
__all__ = ["enrich"]
