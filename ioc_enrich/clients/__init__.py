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

import logging
import time

import requests

_log = logging.getLogger("ioc_enrich.retry")

# Transient HTTP statuses worth retrying (rate limit + server errors).
_RETRYABLE_STATUS = frozenset({429, 500, 502, 503, 504})

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


def request_with_retries(
    do_request,
    *,
    retries: int = 2,
    base_delay: float = 1.0,
    max_delay: float = 8.0,
    sleep=time.sleep,
):
    """Call ``do_request()`` (a zero-arg callable returning a ``requests``
    Response), retrying transient failures with exponential backoff.

    Retries on connection/timeout errors and on 429/5xx responses, up to
    ``retries`` extra attempts. Honors a numeric ``Retry-After`` header on a
    retryable response (capped at ``max_delay``). Returns the final Response, or
    re-raises the last transport exception once retries are exhausted.

    Transport-agnostic and ``sleep``-injectable, so it is unit-testable with a
    fake callable and no real network or waits.
    """
    attempt = 0
    while True:
        try:
            resp = do_request()
        except (requests.Timeout, requests.ConnectionError) as exc:
            if attempt >= retries:
                raise
            delay = _backoff(attempt, base_delay, max_delay)
            _log.info("transient %s, retrying in %.1fs", type(exc).__name__, delay)
            sleep(delay)
            attempt += 1
            continue
        if resp.status_code in _RETRYABLE_STATUS and attempt < retries:
            delay = _retry_delay(resp, attempt, base_delay, max_delay)
            _log.info("HTTP %s, retrying in %.1fs", resp.status_code, delay)
            sleep(delay)
            attempt += 1
            continue
        return resp


def _backoff(attempt: int, base: float, cap: float) -> float:
    return min(base * (2 ** attempt), cap)


def _retry_delay(resp, attempt: int, base: float, cap: float) -> float:
    retry_after = resp.headers.get("Retry-After", "")
    if isinstance(retry_after, str) and retry_after.isdigit():
        return min(int(retry_after), cap)
    return _backoff(attempt, base, cap)
