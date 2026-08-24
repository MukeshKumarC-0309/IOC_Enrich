"""API client subpackage.

Each client (:mod:`abuseipdb`, :mod:`virustotal`, :mod:`urlhaus`) performs one
HTTP call, parses the response, and returns a **uniform result dict**. Verdict
/ threshold logic is deliberately kept OUT of these modules (see
:mod:`ioc_enrich.verdicts`, DESIGN §2) so every threshold lives in one
auditable place.

Uniform result shape::

    {"source": str, "ok": bool, "error": str | None, "raw": dict | None}

``error`` is ``None`` when ``ok`` is True; otherwise it is one of the DESIGN
§10.D non-vote categories below. A non-ok result means "this source did not
vote" and is handled by the aggregator, never raised.
"""
from __future__ import annotations

# Error categories — a source returning any of these "did not vote" (§10.D).
ERR_INVALID_KEY = "invalid_key"  # missing/rejected credentials (HTTP 401/403)
ERR_RATE_LIMIT = "rate_limit"    # HTTP 429
ERR_TIMEOUT = "timeout"          # request timed out
ERR_HTTP = "http_error"          # other non-200 / connection error
ERR_MALFORMED = "malformed"      # 200 but unparseable / unexpected shape


def status_error(status: int) -> str | None:
    """Map an HTTP status code to a §10.D error category (None if OK)."""
    if status == 200:
        return None
    if status in (401, 403):
        return ERR_INVALID_KEY
    if status == 429:
        return ERR_RATE_LIMIT
    return ERR_HTTP


def ok_result(source: str, raw: dict) -> dict:
    """Build a successful uniform result."""
    return {"source": source, "ok": True, "error": None, "raw": raw}


def err_result(source: str, error: str) -> dict:
    """Build a non-vote uniform result."""
    return {"source": source, "ok": False, "error": error, "raw": None}
