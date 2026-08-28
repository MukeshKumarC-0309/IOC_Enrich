"""Command-line interface — single indicator in, structured triage out.

Usage:
    python -m ioc_enrich <indicator> [--json] [--no-color] [--verbose]

Exit codes reflect whether the TOOL succeeded, not what verdict it found
(a malicious result is still a successful run -> exit 0):
    0  assessment produced (malicious / suspicious / clean)
    1  status "error" — sources unreachable, no assessment possible
    2  invalid input — not a valid IP or domain
    3  not enrichable — a private/reserved IP (well-formed but out of scope)
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys

from .indicator import NotEnrichableError
from .pipeline import enrich
from .render import render_human


def _configure_logging(verbose: bool) -> None:
    """Send ioc_enrich logs to stderr when --verbose is set (stdout stays clean
    for the report). Silent by default."""
    if not verbose:
        return
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("%(levelname)s %(name)s: %(message)s"))
    logger = logging.getLogger("ioc_enrich")
    logger.setLevel(logging.DEBUG)
    logger.addHandler(handler)


def _emit_error(indicator: str, as_json: bool, code: str, message: str, exit_code: int) -> int:
    """Report a refusal: a JSON error object on stdout under --json (so a
    scripting consumer always gets JSON), else a plain message on stderr."""
    if as_json:
        print(json.dumps(
            {"indicator": indicator, "error": code, "message": message},
            ensure_ascii=False,
        ))
    else:
        print(f"error: {message}", file=sys.stderr)
    return exit_code


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
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="log source queries, retries, and timing to stderr",
    )
    args = parser.parse_args(argv)

    _configure_logging(args.verbose)

    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

    # Refusals happen before any output: private/reserved IP -> 3, malformed -> 2.
    try:
        report = enrich(args.indicator)
    except NotEnrichableError as exc:
        return _emit_error(args.indicator, args.json, "not_enrichable", str(exc), 3)
    except ValueError as exc:
        return _emit_error(args.indicator, args.json, "invalid_input", str(exc), 2)

    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        color = _color_enabled(args.no_color)
        if color:
            _enable_windows_ansi()
        print(render_human(report, color=color))

    # Exit code reflects tool success, not the verdict.
    return 1 if report["status"] == "error" else 0
