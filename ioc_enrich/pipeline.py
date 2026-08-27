"""Orchestrator — run one indicator through the full enrichment pipeline.

Linear, no decision logic of its own (all decisions live in the modules it
calls):

    classify -> query sources -> aggregate -> ATT&CK map -> recommend -> report

AbuseIPDB is queried only for IPs (§10.A); for a domain it is passed through as
``None`` and rendered ``not_applicable`` by :mod:`ioc_enrich.report`.
"""
from __future__ import annotations

import logging
import time

from .aggregate import aggregate
from .attack import map_techniques
from .clients import abuseipdb, urlhaus, virustotal
from .indicator import IP, NotEnrichableError, classify, is_non_routable
from .recommend import recommend
from .report import build_report

_log = logging.getLogger("ioc_enrich.pipeline")


def enrich(indicator: str) -> dict:
    """Enrich a single IP or domain and return the §7 report dict.

    Raises ``ValueError`` if ``indicator`` is neither a valid IP nor domain,
    and ``NotEnrichableError`` for a private/reserved IP (§10.I).
    """
    indicator_type, target = classify(indicator)

    # Private/reserved IPs are out of scope and must never be sent to
    # third-party APIs (data exposure + wasted quota) — refuse before querying.
    if indicator_type == IP and is_non_routable(target):
        raise NotEnrichableError(
            f"{target} is a private/reserved address; enrichment applies only "
            f"to routable indicators"
        )

    # --- Query the sources ---------------------------------------------------
    started = time.monotonic()
    _log.info("enriching %s (type=%s)", target, indicator_type)
    # AbuseIPDB is IP-only; skip it for domains (§10.A).
    abuse_result = abuseipdb.check(target) if indicator_type == IP else None
    vt_result = virustotal.check(target, indicator_type)
    urlhaus_result = urlhaus.check(target)
    for name, res in (("abuseipdb", abuse_result), ("virustotal", vt_result),
                      ("urlhaus", urlhaus_result)):
        if res is None:
            _log.debug("%-11s not queried", name)
        else:
            _log.debug("%-11s %s", name, "ok" if res["ok"] else res["error"])

    # --- Aggregate (verdict / confidence / flags) ----------------------------
    agg = aggregate(indicator_type, abuse_result, vt_result, urlhaus_result)
    _log.info("verdict=%s status=%s confidence=%s (%.2fs)",
              agg.verdict, agg.status, agg.confidence, time.monotonic() - started)

    # --- ATT&CK mapping ------------------------------------------------------
    # Evaluated on RAW source signals only — fully decoupled from aggregate.py
    # (§10.C Rule 3). urlhaus_match is read straight from the raw URLhaus
    # result, NOT from agg.urlhaus_override, even though they coincide.
    categories = (
        abuse_result["raw"]["categories"]
        if abuse_result is not None and abuse_result["ok"]
        else []
    )
    urlhaus_match = bool(
        urlhaus_result is not None
        and urlhaus_result["ok"]
        and urlhaus_result["raw"]["listed"]
    )
    urlhaus_url_count = urlhaus_result["raw"]["url_count"] if urlhaus_match else 0
    techniques = map_techniques(categories, urlhaus_match, urlhaus_url_count)

    # --- Recommendation + final report ---------------------------------------
    recommendation = recommend(agg)
    return build_report(
        indicator=target,
        indicator_type=indicator_type,
        abuse_result=abuse_result,
        vt_result=vt_result,
        urlhaus_result=urlhaus_result,
        agg=agg,
        mitre_technique=techniques,
        recommendation=recommendation,
    )
