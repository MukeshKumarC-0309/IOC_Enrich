"""URLhaus host-lookup client (abuse.ch).

URLhaus is a curated **blocklist**, not a scorer (DESIGN §2): a host is either
listed (match) or not. It acts as an *override* signal, not a voter (DESIGN §3
step 1 / §4), so this module reports only listed / not-listed / non-vote.

Result mapping (see DESIGN §2 URLhaus states):
    ok + raw["listed"] is True   -> "match"      (blocklist hit)
    ok + raw["listed"] is False  -> "not_found"  (informative, NOT clean)
    non-ok                        -> "query_error" (no information gained)
"""
from __future__ import annotations

import requests

from .. import config
from . import (
    ERR_HTTP,
    ERR_MALFORMED,
    ERR_TIMEOUT,
    err_result,
    ok_result,
)

_SOURCE = "urlhaus"


def check(host: str) -> dict:
    """Query URLhaus for a host (IP or domain).

    On success, ``raw`` = ``{"listed": bool, "url_count": int}``. A non-ok
    result corresponds to DESIGN's URLhaus ``query_error`` state.
    """
    headers = {}
    if config.URLHAUS_AUTH_KEY:
        headers["Auth-Key"] = config.URLHAUS_AUTH_KEY

    try:
        resp = requests.post(
            config.URLHAUS_HOST_URL,
            headers=headers,
            data={"host": host},
            timeout=config.HTTP_TIMEOUT,
        )
    except requests.Timeout:
        return err_result(_SOURCE, ERR_TIMEOUT)
    except requests.RequestException:
        return err_result(_SOURCE, ERR_HTTP)

    if resp.status_code != 200:
        return err_result(_SOURCE, ERR_HTTP)

    try:
        body = resp.json()
        query_status = body.get("query_status")
    except (ValueError, TypeError):
        return err_result(_SOURCE, ERR_MALFORMED)

    if query_status == "ok":
        return ok_result(
            _SOURCE,
            {"listed": True, "url_count": int(body.get("url_count", 0) or 0)},
        )
    if query_status == "no_results":
        return ok_result(_SOURCE, {"listed": False, "url_count": 0})

    # Any other query_status (e.g. invalid host, missing auth) — treat as a
    # query_error: no information gained.
    return err_result(_SOURCE, ERR_MALFORMED)
