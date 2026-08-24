"""MITRE ATT&CK mapping — rule-based technique tagging.

DESIGN §6 / §10.C. A separate, swappable module: matching is fully decoupled
from aggregation (it reads **raw** source signals, never aggregate.py's verdict
or override), and matches directly on AbuseIPDB **numeric category IDs**.

Two rules (minimum viable set, §6):
  * any AbuseIPDB category in ``T1110_CATEGORIES`` -> T1110 (Brute Force /
    Credential Access)
  * a URLhaus blocklist match with ``url_count < 750`` -> T1071 (Application
    Layer Protocol / Command and Control). A high-volume match (>= 750) is a
    shared-hosting host and is **skipped** — the SAME reliability threshold as
    the §3.1 override. A match too unreliable to drive the verdict is too
    unreliable to drive technique attribution. This shares §3.1's signal-
    reliability threshold, NOT aggregation's verdict, so Rule 3 (independence
    from the verdict) still holds.
No rule matches -> empty list (never a forced guess, §6).

Known limitation (§10.C): **T1110 is structurally unreachable for domains** —
AbuseIPDB does not run on domains, so there are no categories to match. This is
documented, not worked around; no substitute domain-pattern signal is invented.
"""
from __future__ import annotations

# Shared signal-reliability threshold (defined with the §3.1 override logic).
# Importing the constant — not any verdict decision — keeps Rule 3 intact.
from .aggregate import URLHAUS_HIGH_VOLUME_THRESHOLD

# Technique IDs (bare strings — the JSON schema uses these).
T1110 = "T1110"
T1071 = "T1071"

# AbuseIPDB numeric category IDs that map to T1110. Matched directly on IDs
# (not string labels — §10.C); each ID documented. 21 (Web App Attack) is
# deliberately excluded: it is not a credential-access signal.
T1110_CATEGORIES = {
    5,   # FTP Brute-Force
    18,  # Brute-Force
    22,  # SSH
}

# Display-only technique -> readable-name lookup. NOT used by the matching
# logic below; the JSON report keeps bare technique IDs (§10.F).
TECHNIQUE_NAMES = {
    T1110: "Brute Force",
    T1071: "Application Layer Protocol",
}


def map_techniques(
    abuseipdb_categories: list,
    urlhaus_match: bool,
    urlhaus_url_count: int = 0,
) -> list:
    """Map raw source signals to ATT&CK technique IDs (DESIGN §6 / §10.C).

    Args:
        abuseipdb_categories: distinct AbuseIPDB category IDs for the
            indicator (empty for domains, or when AbuseIPDB did not vote).
        urlhaus_match: True when URLhaus returned a blocklist match.
        urlhaus_url_count: number of URLs on that match. A high-volume match
            (``>= URLHAUS_HIGH_VOLUME_THRESHOLD``, i.e. 750) is a shared-hosting
            host and does NOT drive T1071 — the same reliability judgement the
            §3.1 override applies (not a Rule-3 violation: it gates on the
            signal's reliability, never on the aggregated verdict).

    Returns matched technique IDs in a deterministic order (T1110 before
    T1071), or ``[]`` when no rule matches. Evaluated on raw data only, so a
    single surviving source still produces a mapping — ``[]`` results only when
    no source yielded a usable signal.
    """
    techniques = []
    if any(category in T1110_CATEGORIES for category in abuseipdb_categories):
        techniques.append(T1110)
    if urlhaus_match and urlhaus_url_count < URLHAUS_HIGH_VOLUME_THRESHOLD:
        techniques.append(T1071)
    return techniques


def technique_names(technique_ids: list) -> list:
    """Display helper: render technique IDs as ``"ID (Readable Name)"`` strings.

    For CLI / human-readable output only; the JSON report keeps bare IDs.
    """
    return [f"{tid} ({TECHNIQUE_NAMES[tid]})" for tid in technique_ids]
