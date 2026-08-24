"""Per-source verdict thresholds — the ONLY place DESIGN §2 thresholds live.

Clients return raw fields; this module converts them into verdicts, so every
threshold is auditable in one file and can be hand-traced against DESIGN §2.
Do not scatter these numbers elsewhere.

URLhaus has no verdict function here: it is a blocklist override, not a scored
voter (DESIGN §3/§4). Its listed/not-listed state is handled by the aggregator.
"""
from __future__ import annotations

# Voting-source verdict labels.
MALICIOUS = "malicious"
SUSPICIOUS = "suspicious"
CLEAN = "clean"


def abuseipdb_verdict(score: int) -> str:
    """AbuseIPDB ``abuseConfidenceScore`` -> verdict (DESIGN §2).

    - score > 75          -> malicious
    - 25 <= score <= 75   -> suspicious
    - score < 25          -> clean
    """
    if score > 75:
        return MALICIOUS
    if score >= 25:
        return SUSPICIOUS
    return CLEAN


def virustotal_verdict(malicious: int, total: int) -> str:
    """VirusTotal malicious/total ratio -> verdict (DESIGN §2).

    - ratio >= 10%        -> malicious
    - 3% <= ratio < 10%   -> suspicious
    - ratio < 3%          -> clean

    The caller guarantees ``total > 0`` (a total of 0 is handled upstream in
    the client as a non-vote).
    """
    ratio = malicious / total
    if ratio >= 0.10:
        return MALICIOUS
    if ratio >= 0.03:
        return SUSPICIOUS
    return CLEAN
