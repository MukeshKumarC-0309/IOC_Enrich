"""Indicator classification: decide whether the input is an IP or a domain.

Per DESIGN §1 only IPs and domains are supported (hashes are deferred). This
gate also drives the single-voter path in DESIGN §10.A: a *domain* means
AbuseIPDB cannot be queried, so VirusTotal becomes the sole voter.
"""
from __future__ import annotations

import ipaddress
import re

# Indicator type constants (imported by clients / orchestrator).
IP = "ip"
DOMAIN = "domain"

# Basic RFC-1035-style domain check: dot-separated labels of letters/digits/
# hyphens (no leading/trailing hyphen), at least two labels, max 253 chars.
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)"
    r"(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)


def classify(value: str) -> tuple[str, str]:
    """Classify a raw indicator string.

    Returns ``(indicator_type, normalized_value)`` where indicator_type is
    :data:`IP` or :data:`DOMAIN`. Domains are lower-cased; IPs are returned in
    their canonical form.

    Raises ``ValueError`` if the input is neither a valid IP nor a valid
    domain.
    """
    candidate = value.strip()
    if not candidate:
        raise ValueError("empty indicator")

    # Try IP first (covers both IPv4 and IPv6).
    try:
        return IP, str(ipaddress.ip_address(candidate))
    except ValueError:
        pass

    lowered = candidate.lower()
    if _DOMAIN_RE.match(lowered):
        return DOMAIN, lowered

    raise ValueError(f"{value!r} is not a valid IP or domain")
