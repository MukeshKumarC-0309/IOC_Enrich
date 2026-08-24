"""VirusTotal v3 client (IP and domain reputation).

Returns the raw ``last_analysis_stats`` counts; the ratio thresholds live in
:mod:`ioc_enrich.verdicts` (DESIGN §2). Works for both IPs and domains, so it
is the sole voter on the domain path (DESIGN §10.A).
"""
from __future__ import annotations

import requests

from .. import config
from ..indicator import IP
from . import (
    ERR_HTTP,
    ERR_INVALID_KEY,
    ERR_MALFORMED,
    ERR_TIMEOUT,
    err_result,
    ok_result,
    status_error,
)

_SOURCE = "virustotal"


def check(indicator: str, indicator_type: str) -> dict:
    """Query VirusTotal for an IP or domain.

    On success, ``raw`` = ``{"malicious": int, "total": int}`` where ``total``
    is the sum of every ``last_analysis_stats`` bucket. A ``total`` of 0 (no
    engine data) is returned as a ``malformed`` non-vote, since the DESIGN §2
    ratio is undefined without engines.
    """
    if not config.VIRUSTOTAL_API_KEY:
        return err_result(_SOURCE, ERR_INVALID_KEY)

    if indicator_type == IP:
        url = config.VIRUSTOTAL_IP_URL.format(indicator=indicator)
    else:
        url = config.VIRUSTOTAL_DOMAIN_URL.format(indicator=indicator)

    headers = {"x-apikey": config.VIRUSTOTAL_API_KEY}
    try:
        resp = requests.get(url, headers=headers, timeout=config.HTTP_TIMEOUT)
    except requests.Timeout:
        return err_result(_SOURCE, ERR_TIMEOUT)
    except requests.RequestException:
        return err_result(_SOURCE, ERR_HTTP)

    err = status_error(resp.status_code)
    if err:
        return err_result(_SOURCE, err)

    try:
        stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
        malicious = int(stats.get("malicious", 0))
        total = sum(int(v) for v in stats.values())
    except (ValueError, KeyError, TypeError, AttributeError):
        return err_result(_SOURCE, ERR_MALFORMED)

    if total == 0:
        # No engines returned data — the §2 ratio is undefined. Treat as a
        # non-vote rather than inventing a verdict.  [see FLAG in chat: §2 edge]
        return err_result(_SOURCE, ERR_MALFORMED)

    return ok_result(_SOURCE, {"malicious": malicious, "total": total})
