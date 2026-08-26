"""AbuseIPDB /check client (IP reputation).

Returns raw fields only — the ``abuseConfidenceScore`` and the set of reported
category IDs. Threshold interpretation lives in :mod:`ioc_enrich.verdicts`
(DESIGN §2); ATT&CK category mapping lives in :mod:`ioc_enrich.attack`
(DESIGN §6/§10.C).

AbuseIPDB supports **IPs only** — the orchestrator must not call this for
domains (DESIGN §10.A: domains fall back to the VirusTotal-sole-voter path).
"""
from __future__ import annotations

import requests

from .. import config
from . import (
    ERR_HTTP,
    ERR_INVALID_KEY,
    ERR_MALFORMED,
    ERR_TIMEOUT,
    err_result,
    ok_result,
    request_with_retries,
    status_error,
)

_SOURCE = "abuseipdb"


def check(ip: str) -> dict:
    """Query AbuseIPDB for an IP.

    On success, ``raw`` = ``{"score": int, "categories": [int, ...]}`` where
    ``categories`` is the sorted union of distinct category IDs across all
    reports within the lookback window.
    """
    if not config.ABUSEIPDB_API_KEY:
        return err_result(_SOURCE, ERR_INVALID_KEY)

    headers = {"Key": config.ABUSEIPDB_API_KEY, "Accept": "application/json"}
    params = {
        "ipAddress": ip,
        "maxAgeInDays": config.ABUSEIPDB_MAX_AGE_DAYS,
        "verbose": "",  # include the reports array (needed for category IDs)
    }
    try:
        resp = request_with_retries(
            lambda: requests.get(
                config.ABUSEIPDB_URL,
                headers=headers,
                params=params,
                timeout=config.HTTP_TIMEOUT,
            ),
            retries=config.HTTP_RETRIES,
        )
    except requests.Timeout:
        return err_result(_SOURCE, ERR_TIMEOUT)
    except requests.RequestException:
        return err_result(_SOURCE, ERR_HTTP)

    err = status_error(resp.status_code)
    if err:
        return err_result(_SOURCE, err)

    try:
        data = resp.json()["data"]
        score = int(data["abuseConfidenceScore"])
        categories = _collect_categories(data.get("reports", []))
    except (ValueError, KeyError, TypeError):
        return err_result(_SOURCE, ERR_MALFORMED)

    return ok_result(_SOURCE, {"score": score, "categories": categories})


def _collect_categories(reports: list) -> list:
    """Return the sorted union of distinct category IDs across all reports."""
    cats: set[int] = set()
    for report in reports or []:
        for cat in report.get("categories", []) or []:
            cats.add(int(cat))
    return sorted(cats)
