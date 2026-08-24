"""Output assembly — build the final report object (DESIGN §7 / §10.F).

Pure formatter: takes the pieces produced by the pipeline (client results, the
aggregation result, the ATT&CK list, the recommendation) and assembles the
§7 schema dict. No decision logic lives here.

Every source carries a unified ``status`` field (§10.F). Distinct states are
kept distinct: ``not_applicable`` (no data by design — AbuseIPDB on a domain)
is never conflated with ``error`` (a voter tried and failed) or, for URLhaus,
``query_error`` (the blocklist lookup itself failed).
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from .aggregate import AggregationResult
from .indicator import IP

_ABUSEIPDB_NA_REASON = "AbuseIPDB does not support domain lookups"


def build_report(
    indicator: str,
    indicator_type: str,
    abuse_result: Optional[dict],
    vt_result: Optional[dict],
    urlhaus_result: Optional[dict],
    agg: AggregationResult,
    mitre_technique: list,
    recommendation: str,
    timestamp: Optional[str] = None,
) -> dict:
    """Assemble the final §7 report dict. ``timestamp`` defaults to now (UTC)."""
    return {
        "indicator": indicator,
        "indicator_type": indicator_type,
        "sources": {
            "abuseipdb": _abuseipdb_entry(
                indicator_type, abuse_result, agg.abuseipdb_verdict
            ),
            "virustotal": _virustotal_entry(vt_result, agg.virustotal_verdict),
            "urlhaus": _urlhaus_entry(urlhaus_result),
        },
        "status": agg.status,
        "aggregated_verdict": agg.verdict,
        "urlhaus_override": agg.urlhaus_override,
        "urlhaus_high_volume_host": agg.urlhaus_high_volume_host,
        "disagreement": agg.disagreement,
        "single_source": agg.single_source,
        "mitre_technique": mitre_technique,
        "confidence": agg.confidence,
        "recommendation": recommendation,
        "timestamp": timestamp or _utc_now(),
    }


def _abuseipdb_entry(
    indicator_type: str, result: Optional[dict], verdict: Optional[str]
) -> dict:
    # Domain (or no result) → structurally not applicable (§10.A), distinct
    # from a failed lookup.
    if indicator_type != IP or result is None:
        return {"status": "not_applicable", "reason": _ABUSEIPDB_NA_REASON}
    if result["ok"]:
        return {"status": "ok", "score": result["raw"]["score"], "verdict": verdict}
    return {"status": "error", "reason": result["error"]}


def _virustotal_entry(result: Optional[dict], verdict: Optional[str]) -> dict:
    if result is not None and result["ok"]:
        raw = result["raw"]
        return {
            "status": "ok",
            "malicious_ratio": f"{raw['malicious']}/{raw['total']}",
            "verdict": verdict,
        }
    reason = result["error"] if result is not None else "http_error"
    return {"status": "error", "reason": reason}


def _urlhaus_entry(result: Optional[dict]) -> dict:
    # URLhaus is a blocklist, not a voter: match / not_found / query_error.
    if result is not None and result["ok"]:
        if result["raw"]["listed"]:
            return {"status": "match", "url_count": result["raw"]["url_count"]}
        return {"status": "not_found"}
    reason = result["error"] if result is not None else "http_error"
    return {"status": "query_error", "reason": reason}


def _utc_now() -> str:
    """ISO-8601 UTC timestamp with a trailing Z, second precision."""
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )
