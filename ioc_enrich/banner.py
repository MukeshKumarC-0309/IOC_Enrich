"""Startup wordmark banner (rich).

Printed once to stderr on CLI startup, so it never contaminates stdout (the
report / JSON / --quiet line). Degrades gracefully:

* not a TTY, or NO_COLOR set -> rich emits no color (styles are passed as-is
  and stripped automatically; nothing is forced);
* a console/encoding that can't render the full-block glyph (e.g. a legacy
  Windows code page) -> a compact ASCII text panel instead, never a
  UnicodeEncodeError;
* the tool name is always printed as plain text in the tagline, so it is
  present for screen readers and testable even when the art renders.

Dependency-light: only `rich`. The art is a static constant — no figlet.
"""
from __future__ import annotations

from typing import Optional

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

_NAME = "ioc-enrich"
_TAGLINE = "ioc-enrich · multi-source IP & domain threat-intel triage"
_HINT = "-h for help · Ctrl+C to quit"

# Block-letter wordmark for "IOC ENRICH" (full block, U+2588). Static constant.
_LOGO = (
    "  ███████  █████   ██████     ███████ ██   ██ ██████  ███████  ██████ ██   ██",
    "    ███   ██   ██ ██          ██      ███  ██ ██   ██   ███   ██      ██   ██",
    "    ███   ██   ██ ██          █████   ██ █ ██ ██████    ███   ██      ███████",
    "    ███   ██   ██ ██          ██      ██  ███ ██  ██    ███   ██      ██   ██",
    "  ███████  █████   ██████     ███████ ██   ██ ██   ██ ███████  ██████ ██   ██",
)
# Cyan -> blue vertical gradient, one style per logo line.
_STYLES = ("bold bright_cyan", "bold cyan", "bold cyan", "cyan", "blue")

_BLOCK = "█"


def _can_encode_block(console: Console) -> bool:
    """Whether the console's stream can encode the block glyph (predicts the
    same encoding rich's writer will use, so we avoid a UnicodeEncodeError)."""
    encoding = getattr(console.file, "encoding", None) or "utf-8"
    try:
        _BLOCK.encode(encoding)
        return True
    except (UnicodeEncodeError, LookupError):
        return False


def print_banner(console: Optional[Console] = None) -> None:
    """Print the wordmark banner once through a single shared Console
    (stderr by default)."""
    console = console or Console(stderr=True)

    if _can_encode_block(console):
        try:
            for line, style in zip(_LOGO, _STYLES):
                console.print(Text(line, style=style))
        except UnicodeEncodeError:
            _print_fallback(console)
            return
    else:
        _print_fallback(console)
        return

    console.print(Text(_TAGLINE, style="cyan"))
    console.print(Text(_HINT, style="dim"))


def _print_fallback(console: Console) -> None:
    """Compact, encoding-safe fallback when the block glyph can't render."""
    console.print(Panel(Text(_NAME, style="bold cyan"), box=box.ASCII, expand=False))
    console.print(Text(_TAGLINE, style="cyan"))
    console.print(Text(_HINT, style="dim"))
