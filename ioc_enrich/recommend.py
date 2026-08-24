"""Recommendation lookup — situation -> analyst instruction string.

Implements DESIGN §5 / §10.E: a deterministic lookup over the *situation*,
evaluated as **ordered guard clauses** (most-authoritative first) so the error
case is branched on as a distinct precondition and a ``null`` verdict/
confidence never reaches the confidence lookup at the bottom.

Guard order (DESIGN §10.E):
    status == "error"  ->  urlhaus_override  ->  single_source  ->  confidence

The recommendation is the analyst *instruction*; it names data only when that
data changes the instruction (so the single-source row names its lone source,
but the override rows stay silent on voters — those are already in the
`sources` block).
"""
from __future__ import annotations

from .aggregate import HIGH, LOW, MEDIUM, STATUS_ERROR, AggregationResult

# Recommendation strings — one per situation (DESIGN §10.E).
REC_ERROR = "Insufficient data — sources unavailable; retry or investigate manually"
REC_OVERRIDE_NO_VOTERS = (
    "Malicious per URLhaus blocklist; reputation sources unavailable — "
    "verdict rests on blocklist alone"
)
REC_OVERRIDE_WITH_VOTERS = "Confirmed malicious — listed on URLhaus blocklist"
REC_SINGLE_SOURCE = "Single-source signal ({source} only) — corroborate before escalation"
REC_HIGH = "Consistent signal across sources"
REC_MEDIUM = "Partial signal — review before escalation"
REC_LOW = "Sources disagree — manual review required before action"

# Human-readable source names for the single-source recommendation.
_SOURCE_NAMES = {"abuseipdb": "AbuseIPDB", "virustotal": "VirusTotal"}


def recommend(agg: AggregationResult) -> str:
    """Return the analyst recommendation string for an aggregated result."""
    # 1. Error — checked FIRST, before any verdict/confidence is read (§10.E).
    if agg.status == STATUS_ERROR:
        return REC_ERROR

    # 2. URLhaus override — a confirmed blocklist hit drives the recommendation
    #    regardless of how many voters ran (§3.1 / §10.E rows 2-3).
    if agg.urlhaus_override:
        if _voter_count(agg) == 0:
            return REC_OVERRIDE_NO_VOTERS
        return REC_OVERRIDE_WITH_VOTERS

    # 3. Single voter (domain, or one voter errored) — name the lone source.
    if agg.single_source:
        return REC_SINGLE_SOURCE.format(source=_single_source_name(agg))

    # 4. Two voters — pure confidence lookup. Reachable only when status is ok
    #    and both voters produced verdicts, so confidence is never None here.
    return {HIGH: REC_HIGH, MEDIUM: REC_MEDIUM, LOW: REC_LOW}[agg.confidence]


def _voter_count(agg: AggregationResult) -> int:
    """Number of voting sources that produced a verdict (0, 1, or 2)."""
    return sum(
        v is not None for v in (agg.abuseipdb_verdict, agg.virustotal_verdict)
    )


def _single_source_name(agg: AggregationResult) -> str:
    """Human-readable name of the lone voter (single_source case)."""
    source = "abuseipdb" if agg.abuseipdb_verdict is not None else "virustotal"
    return _SOURCE_NAMES[source]
