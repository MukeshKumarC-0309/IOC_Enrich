"""Human-readable rendering of a report dict (DESIGN §7) for the CLI.

Produces the formatted "IOC TRIAGE" view. ANSI color is applied only when the
caller passes ``color=True`` (the CLI enables it for interactive terminals and
disables it when piped / on ``--no-color`` / ``NO_COLOR``). Only verdict words
are colored — everything else stays the terminal's default.
"""
from __future__ import annotations

from .attack import technique_names

_WIDTH = 60
_LINE = "─" * _WIDTH

_RESET = "\033[0m"
_BOLD = "\033[1m"
_COLORS = {
    "malicious": "\033[31m",   # red
    "suspicious": "\033[33m",  # amber
    "clean": "\033[32m",       # green
    "_error": "\033[35m",      # magenta (null / error verdict)
}


def _verdict_key(verdict) -> str:
    return verdict if verdict in ("malicious", "suspicious", "clean") else "_error"


def _c(text: str, key: str, color: bool, bold: bool = False) -> str:
    if not color:
        return text
    code = _COLORS.get(key, "")
    if not code:
        return text
    return f"{(_BOLD + code) if bold else code}{text}{_RESET}"


def _pad_verdict(verdict: str, width: int, color: bool) -> str:
    """Color the verdict word but pad by its PLAIN length (ANSI codes are
    zero-width to the terminal, so pad before the escape codes are added)."""
    colored = _c(verdict, _verdict_key(verdict), color)
    return colored + " " * max(1, width - len(verdict))


def _abuse(s: dict, color: bool) -> str:
    if s["status"] == "ok":
        return f'{_pad_verdict(s["verdict"], 12, color)}score {s["score"]}'
    if s["status"] == "not_applicable":
        return "n/a         (domains unsupported)"
    return f'error       ({s.get("reason")})'


def _vt(s: dict, color: bool) -> str:
    if s["status"] == "ok":
        return f'{_pad_verdict(s["verdict"], 12, color)}{s["malicious_ratio"]}'
    return f'error       ({s.get("reason")})'


def _urlhaus(s: dict) -> str:
    st = s["status"]
    if st == "match":
        return f'match       {s["url_count"]} URLs'
    if st == "not_found":
        return "not_found"
    return f'error       ({s.get("reason")})'


def render_human(report: dict, color: bool = False) -> str:
    """Render a report dict as the formatted human triage view."""
    r = report
    verdict_disp = (r["aggregated_verdict"] or "error / no data").upper()
    verdict_col = _c(verdict_disp, _verdict_key(r["aggregated_verdict"]), color, bold=True)
    verdict_pad = " " * max(1, 22 - len(verdict_disp))
    confidence = r["confidence"] or "—"

    flags = []
    if r["disagreement"]:
        flags.append("disagreement")
    if r["urlhaus_override"]:
        flags.append("urlhaus_override")
    if r.get("urlhaus_high_volume_host"):
        flags.append("high_volume_host")
    if r["single_source"]:
        flags.append("single_source")
    flags_s = ", ".join(flags) if flags else "—"

    techniques = r["mitre_technique"]
    tech_s = ", ".join(technique_names(techniques)) if techniques else "—"

    lines = [
        _LINE,
        f'  IOC TRIAGE   ·   {r["indicator"]}  ({r["indicator_type"]})',
        _LINE,
        f'  VERDICT       {verdict_col}{verdict_pad}confidence: {confidence}',
        f'  FLAGS         {flags_s}',
        f'  ATT&CK        {tech_s}',
        "",
        "  SOURCES",
        f'    AbuseIPDB    {_abuse(r["sources"]["abuseipdb"], color)}',
        f'    VirusTotal   {_vt(r["sources"]["virustotal"], color)}',
        f'    URLhaus      {_urlhaus(r["sources"]["urlhaus"])}',
        "",
        "  RECOMMENDATION",
        f'    {r["recommendation"]}',
        "",
        f'  queried {r["timestamp"]}',
        _LINE,
    ]
    return "\n".join(lines)
