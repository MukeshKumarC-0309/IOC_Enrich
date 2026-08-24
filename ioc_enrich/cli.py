"""Command-line interface — single indicator in, structured triage out.

Usage:
    python -m ioc_enrich <indicator> [--json] [--no-color]

Exit codes reflect whether the TOOL succeeded, not what verdict it found
(a malicious result is still a successful run -> exit 0):
    0  assessment produced (malicious / suspicious / clean)
    1  status "error" — sources unreachable, no assessment possible
    2  invalid input — not a valid IP or domain
"""
from __future__ import annotations

import argparse
import json
import os
import sys

from .pipeline import enrich
from .render import render_human


def _color_enabled(no_color_flag: bool) -> bool:
    """Color only for an interactive terminal, unless disabled by flag or the
    NO_COLOR convention (https://no-color.org)."""
    if no_color_flag or os.environ.get("NO_COLOR"):
        return False
    return sys.stdout.isatty()


def _enable_windows_ansi() -> None:
    """Best-effort: turn on ANSI processing for legacy Windows consoles.
    Modern terminals already support it; failure here just means no color."""
    if os.name != "nt":
        return
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        # -11 = STD_OUTPUT_HANDLE; 7 = existing modes | VIRTUAL_TERMINAL_PROCESSING
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
    except Exception:
        pass


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="ioc-enrich",
        description="Enrich and triage a single IP or domain across "
        "AbuseIPDB, VirusTotal, and URLhaus.",
    )
    parser.add_argument("indicator", help="an IP address or domain to look up")
    parser.add_argument(
        "--json",
        action="store_true",
        help="emit the raw JSON report instead of the human-readable view",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="disable ANSI color in the human-readable view",
    )
    args = parser.parse_args(argv)

    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

    # Invalid input (classify raises ValueError) -> exit 2, before any output.
    try:
        report = enrich(args.indicator)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        color = _color_enabled(args.no_color)
        if color:
            _enable_windows_ansi()
        print(render_human(report, color=color))

    # Exit code reflects tool success, not the verdict.
    return 1 if report["status"] == "error" else 0
