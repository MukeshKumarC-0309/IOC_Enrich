"""Command-line interface — single indicator in, structured triage out.

Usage:
    python -m ioc_enrich <indicator> [--json | --quiet] [--no-color] [--verbose]

Exit codes reflect whether the TOOL succeeded, not what verdict it found
(a malicious result is still a successful run -> exit 0):
    0    assessment produced (malicious / suspicious / clean)
    1    status "error" — sources unreachable, no assessment possible
    2    invalid input — not a valid IP or domain
    3    not enrichable — a private/reserved IP (well-formed but out of scope)
    130  interrupted (Ctrl+C)
"""
from __future__ import annotations

import argparse
import json
import logging
import sys

from rich.console import Console

from . import config
from .indicator import NotEnrichableError
from .pipeline import enrich
from .render import build_view, make_console


def _run_enrich(indicator: str, verbose: bool) -> dict:
    """Run enrich() behind a spinner shown on stderr. Skipped under --verbose
    (logging is the feedback then); rich auto-suppresses when stderr is not a
    terminal, so piped/redirected runs stay clean."""
    if verbose:
        return enrich(indicator)
    with Console(stderr=True).status(f"Enriching {indicator}…", spinner="dots"):
        return enrich(indicator)


def _maybe_key_hint(report: dict) -> None:
    """On an all-sources-failed result, if any API key is unset, nudge the user
    toward configuring .env — the common first-run confusion."""
    if report["status"] != "error":
        return
    missing = [
        name
        for name, value in (
            ("ABUSEIPDB_API_KEY", config.ABUSEIPDB_API_KEY),
            ("VIRUSTOTAL_API_KEY", config.VIRUSTOTAL_API_KEY),
            ("URLHAUS_AUTH_KEY", config.URLHAUS_AUTH_KEY),
        )
        if not value
    ]
    if missing:
        print(
            f"hint: no API key set for {', '.join(missing)} — copy .env.example "
            f"to .env and add your keys (see the README).",
            file=sys.stderr,
        )


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


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="ioc-enrich",
        description="Enrich and triage a single IP or domain across "
        "AbuseIPDB, VirusTotal, and URLhaus.",
    )
    parser.add_argument("indicator", help="an IP address or domain to look up")
    output = parser.add_mutually_exclusive_group()
    output.add_argument(
        "--json",
        action="store_true",
        help="emit the raw JSON report instead of the human-readable view",
    )
    output.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="print a single tab-separated '<indicator>\\t<verdict>' line",
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
        report = _run_enrich(args.indicator, args.verbose)
    except KeyboardInterrupt:
        print("\naborted", file=sys.stderr)
        return 130
    except NotEnrichableError as exc:
        return _emit_error(args.indicator, args.json, "not_enrichable", str(exc), 3)
    except ValueError as exc:
        return _emit_error(args.indicator, args.json, "invalid_input", str(exc), 2)

    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    elif args.quiet:
        print(f"{report['indicator']}\t{report['aggregated_verdict'] or 'error'}")
    else:
        make_console(args.no_color).print(build_view(report))

    # Exit code reflects tool success, not the verdict.
    if report["status"] == "error":
        _maybe_key_hint(report)
        return 1
    return 0
