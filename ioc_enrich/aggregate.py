"""Deterministic verdict aggregation — the core decision logic.

Implements DESIGN §3 (aggregation), §4 (confidence), §3.3 (disagreement), and
the Phase-2 clarifications §10.A (single-voter/domain path), §10.B (the full
AbuseIPDB x VirusTotal truth table), and §10.D (voter-count / zero-voter
handling). No ML, no heuristics — a pure function of the three source results.

Inputs are the uniform client result dicts from :mod:`ioc_enrich.clients`
(``{"source", "ok", "error", "raw"}``). For a domain, ``abuse_result`` is
``None`` (AbuseIPDB is never queried — §10.A); it is shown as an explicit N/A
entry by :mod:`ioc_enrich.report`, not omitted here.

Design invariants worth stating up front:
  * URLhaus is an OVERRIDE, never a voter (§3.1 / §4). A match forces the
    verdict to malicious; it is excluded from the confidence tally.
  * Confidence measures cross-source AGREEMENT only (§4) — never single-source
    signal strength. A lone voter is therefore a flat ``medium`` + the
    ``single_source`` flag (§10.A), regardless of how strong its own verdict is.
  * ``error`` is NOT a verdict. When there is no usable data the verdict is
    ``None`` and ``status`` is ``"error"`` (never a 4th enum value).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from .indicator import IP
from .verdicts import CLEAN, MALICIOUS, SUSPICIOUS, abuseipdb_verdict, virustotal_verdict

# Confidence tiers (DESIGN §4).
HIGH = "high"
MEDIUM = "medium"
LOW = "low"

# Aggregation status.
STATUS_OK = "ok"
STATUS_ERROR = "error"

# URLhaus override is SUPPRESSED for a match carrying this many URLs or more
# (§3.1, added Phase 4). Such a host is a shared-hosting / CDN domain that
# merely hosts others' malicious content (e.g. github.com), not a malicious
# host itself. Provisional: calibrated on a single case (github.com, 7930).
URLHAUS_HIGH_VOLUME_THRESHOLD = 750


@dataclass(frozen=True)
class AggregationResult:
    """The aggregated decision, ready for :mod:`ioc_enrich.report` to render.

    Attributes:
        verdict: "malicious" | "suspicious" | "clean", or ``None`` in the
            error case (§10.D). Never the string "error".
        status: "ok" or "error". "error" == no usable data (§10.D).
        confidence: "high" | "medium" | "low", or ``None`` in the error case.
        disagreement: True only for the two-voter, non-override, opposite-ends
            downgrade (§3.3).
        urlhaus_override: True when a URLhaus blocklist match forced the
            verdict to malicious (§3.1).
        single_source: True when exactly one voter produced a verdict (§10.A) —
            i.e. a domain (VT only), or an IP where one voter errored (§10.D).
        abuseipdb_verdict: the per-source voter verdict, or ``None`` if
            AbuseIPDB did not vote (domain, or errored).
        virustotal_verdict: the per-source voter verdict, or ``None`` if VT
            did not vote (errored).
        urlhaus_high_volume_host: True when URLhaus matched but with
            ``url_count >= 750`` — a shared-hosting/CDN host whose override was
            suppressed (§3.1). Records the match without driving the verdict.
    """

    verdict: Optional[str]
    status: str
    confidence: Optional[str]
    disagreement: bool
    urlhaus_override: bool
    single_source: bool
    abuseipdb_verdict: Optional[str]
    virustotal_verdict: Optional[str]
    urlhaus_high_volume_host: bool = False


def aggregate(
    indicator_type: str,
    abuse_result: Optional[dict],
    vt_result: Optional[dict],
    urlhaus_result: Optional[dict],
) -> AggregationResult:
    """Combine the three source results into a single verdict (DESIGN §3)."""

    # --- Step 0: derive the voter verdicts -----------------------------------
    # AbuseIPDB only votes for IPs, and only when it returned usable data.
    # (indicator_type guard enforces §10.A even if a stray result is passed.)
    abuse_verdict: Optional[str] = None
    if indicator_type == IP and abuse_result is not None and abuse_result["ok"]:
        abuse_verdict = abuseipdb_verdict(abuse_result["raw"]["score"])

    # VirusTotal votes for both IPs and domains when it returned usable data.
    vt_verdict: Optional[str] = None
    if vt_result is not None and vt_result["ok"]:
        vt_verdict = virustotal_verdict(
            vt_result["raw"]["malicious"], vt_result["raw"]["total"]
        )

    voters = [v for v in (abuse_verdict, vt_verdict) if v is not None]
    voter_count = len(voters)

    # URLhaus override: a blocklist match (and only a match) forces malicious
    # (§3.1) — EXCEPT high-volume hosts. A match carrying url_count >= 750 is a
    # shared-hosting / CDN domain that merely *hosts* others' malicious content
    # (e.g. github.com), so its override is suppressed and the verdict falls
    # through to normal voting; the flag preserves the suppressed match (§3.1).
    urlhaus_listed = bool(
        urlhaus_result is not None
        and urlhaus_result["ok"]
        and urlhaus_result["raw"]["listed"]
    )
    urlhaus_url_count = urlhaus_result["raw"]["url_count"] if urlhaus_listed else 0
    urlhaus_high_volume_host = (
        urlhaus_listed and urlhaus_url_count >= URLHAUS_HIGH_VOLUME_THRESHOLD
    )
    urlhaus_override = urlhaus_listed and not urlhaus_high_volume_host

    # Exactly one voter → single-source path (§10.A). Zero or two → not.
    single_source = voter_count == 1

    # --- Step 1: verdict + status --------------------------------------------
    if urlhaus_override:
        # §3.1 — override outranks everything; the truth table is NOT consulted.
        verdict: Optional[str] = MALICIOUS
        status = STATUS_OK
    elif voter_count == 0:
        # §10.D — no override and no voter produced data: no usable assessment.
        verdict = None
        status = STATUS_ERROR
    elif voter_count == 2:
        verdict = _table_verdict(abuse_verdict, vt_verdict)  # §10.B
        status = STATUS_OK
    else:  # exactly one voter — its verdict IS the aggregate (§10.A)
        verdict = voters[0]
        status = STATUS_OK

    # --- Step 2: confidence (cross-source AGREEMENT only, §4) -----------------
    # Computed independently of the URLhaus override: §4 excludes URLhaus from
    # the tally, so an override never changes confidence (§10.A domain case).
    if status == STATUS_ERROR:
        # No data measured → agreement is undefined.  [see chat FLAG: null vs low]
        confidence: Optional[str] = None
    elif voter_count == 2:
        confidence = _agreement_confidence(abuse_verdict, vt_verdict)
    elif voter_count == 1:
        # Flat tier — NOT derived from the lone voter's signal strength (§10.A).
        confidence = MEDIUM
    else:  # voter_count == 0 but status ok → URLhaus override with no voters
        confidence = LOW  # §10.D: 0 voters + URLhaus match → low

    # --- Step 3: disagreement (the §3.3 downgrade event) ---------------------
    # Only the two-voter, non-override, opposite-ends case downgrades to
    # suspicious and flags disagreement. Under an override there is no
    # downgrade, so this stays False (confidence=low + urlhaus_override carries
    # the "voters contradicted" signal instead — §10.E).
    disagreement = (
        not urlhaus_override
        and voter_count == 2
        and _is_opposite_ends(abuse_verdict, vt_verdict)
    )

    return AggregationResult(
        verdict=verdict,
        status=status,
        confidence=confidence,
        disagreement=disagreement,
        urlhaus_override=urlhaus_override,
        single_source=single_source,
        abuseipdb_verdict=abuse_verdict,
        virustotal_verdict=vt_verdict,
        urlhaus_high_volume_host=urlhaus_high_volume_host,
    )


# --- Truth-table helpers (DESIGN §10.B / §4) ---------------------------------

def _table_verdict(a: str, b: str) -> str:
    """AbuseIPDB x VT -> aggregated verdict (DESIGN §10.B, order-independent).

    Collapsed rule (verified cell-by-cell against §10.B):
      1. both clean                         -> clean
      2. opposite ends (malicious + clean)  -> suspicious   (§3.3 downgrade)
      3. >=1 malicious, neither clean       -> malicious
      4. otherwise (some suspicious)        -> suspicious
    """
    pair = {a, b}
    if pair == {CLEAN}:
        return CLEAN
    if pair == {MALICIOUS, CLEAN}:
        return SUSPICIOUS
    if MALICIOUS in pair:  # and CLEAN not in pair (excluded above)
        return MALICIOUS
    return SUSPICIOUS


def _agreement_confidence(a: str, b: str) -> str:
    """Two-voter confidence from verdict agreement (DESIGN §4).

      * identical verdicts        -> high
      * opposite ends (mal+clean) -> low
      * adjacent                  -> medium
    """
    if a == b:
        return HIGH
    if _is_opposite_ends(a, b):
        return LOW
    return MEDIUM


def _is_opposite_ends(a: str, b: str) -> bool:
    """True iff one verdict is malicious and the other clean (§3.3 / §4)."""
    return {a, b} == {MALICIOUS, CLEAN}
