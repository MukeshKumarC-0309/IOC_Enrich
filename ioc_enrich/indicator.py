"""Indicator classification: decide whether the input is an IP or a domain.

Per DESIGN §1 only IPs and domains are supported (hashes are deferred). This
gate also drives the single-voter path in DESIGN §10.A: a *domain* means
AbuseIPDB cannot be queried, so VirusTotal becomes the sole voter.

Inputs are "refanged" first: analysts routinely share indicators *defanged*
(``evil[.]com``, ``hxxp://bad[.]site``) so nobody clicks them by accident, so
those forms are normalised before validation (DESIGN §10.H). Refanging is
conservative — anything it doesn't recognise passes through untouched, so
genuine inputs are unaffected.
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

# Defang patterns analysts use to neutralise live indicators.
_DEFANG_DOT = re.compile(r"[\[\(\{]\s*(?:\.|dot)\s*[\]\)\}]", re.IGNORECASE)
_DEFANG_COLON = re.compile(r"[\[\(\{]\s*:\s*[\]\)\}]")
_SCHEME = re.compile(r"^[a-z][a-z0-9+.\-]*://", re.IGNORECASE)
_TRAILING_PORT = re.compile(r"^([^:]+):\d{1,5}$")


def _refang(value: str) -> str:
    """Normalise a defanged indicator into its real form.

    Handles the common analyst defang styles — bracketed dots/colons
    (``[.]``, ``(.)``, ``{dot}``, ``[:]``), ``hxxp``/``hxxps`` scheme mangling,
    a URL scheme + path, and a trailing ``:port`` — then removes whitespace
    (no valid IP or domain contains any). Leaves unrecognised input unchanged.
    """
    s = value.strip().strip("<>\"'`")
    # hxxp / hxxps -> http / https, so the scheme strip below applies.
    s = re.sub(r"hxxp", "http", s, flags=re.IGNORECASE)
    # Bracketed separators: evil[.]com, bad(dot)site, host[:]port.
    s = _DEFANG_DOT.sub(".", s)
    s = _DEFANG_COLON.sub(":", s)
    # Drop any whitespace (safe: no valid indicator contains spaces).
    s = re.sub(r"\s+", "", s)
    # Strip a URL scheme and anything from the first path/query/fragment char.
    s = _SCHEME.sub("", s)
    s = re.split(r"[/?#]", s, maxsplit=1)[0]
    # Strip a trailing :port when the host has no colon (i.e. not IPv6).
    m = _TRAILING_PORT.match(s)
    if m:
        s = m.group(1)
    # Strip a trailing FQDN root dot.
    return s.rstrip(".")


def classify(value: str) -> tuple[str, str]:
    """Classify a raw (possibly defanged) indicator string.

    Returns ``(indicator_type, normalized_value)`` where indicator_type is
    :data:`IP` or :data:`DOMAIN`. Domains are lower-cased; IPs are returned in
    their canonical form.

    Raises ``ValueError`` if the input is neither a valid IP nor a valid
    domain.
    """
    candidate = _refang(value)
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
