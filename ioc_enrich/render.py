"""Human-readable rendering of a report dict (DESIGN §7) for the CLI.

Uses `rich` for a themed, boxed terminal view: a panel whose border is coloured
by severity, a verdict line, and an aligned sources table. Colour is applied
only for a real terminal — rich auto-detects, degrades to plain text when
piped, and honours the ``NO_COLOR`` convention. The ``--json`` path never
touches this module.
"""
from __future__ import annotations

from rich import box
from rich.console import Console, Group, RenderableType
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.theme import Theme

from .attack import technique_names

# One cohesive theme: verdict severities, structural labels, and accents.
THEME = Theme(
    {
        "malicious": "bold red",
        "suspicious": "bold yellow",
        "clean": "bold green",
        "unknown": "bold magenta",
        "label": "bold cyan",
        "muted": "dim",
        "flag": "yellow",
        "tech": "bright_blue",
        "rec": "italic",
    }
)

_BORDER = {"malicious": "red", "suspicious": "yellow", "clean": "green"}


def make_console(no_color: bool = False) -> Console:
    """A console bound to the theme. rich handles TTY detection / NO_COLOR;
    ``no_color=True`` forces plain output."""
    return Console(theme=THEME, no_color=no_color, highlight=False)


def _style(verdict) -> str:
    return verdict if verdict in ("malicious", "suspicious", "clean") else "unknown"


def _sources_table(report: dict) -> Table:
    table = Table(box=box.SIMPLE_HEAD, show_edge=False, pad_edge=False, expand=False)
    table.add_column("Source", style="muted", no_wrap=True)
    table.add_column("Verdict", no_wrap=True)
    table.add_column("Detail", style="muted")
    s = report["sources"]

    ab = s["abuseipdb"]
    if ab["status"] == "ok":
        table.add_row("AbuseIPDB", Text(ab["verdict"], style=_style(ab["verdict"])),
                      f"score {ab['score']}")
    elif ab["status"] == "not_applicable":
        table.add_row("AbuseIPDB", Text("n/a", style="muted"), "domains unsupported")
    else:
        table.add_row("AbuseIPDB", Text("error", style="unknown"), f"({ab.get('reason')})")

    vt = s["virustotal"]
    if vt["status"] == "ok":
        table.add_row("VirusTotal", Text(vt["verdict"], style=_style(vt["verdict"])),
                      vt["malicious_ratio"])
    else:
        table.add_row("VirusTotal", Text("error", style="unknown"), f"({vt.get('reason')})")

    uh = s["urlhaus"]
    if uh["status"] == "match":
        table.add_row("URLhaus", Text("match", style="malicious"), f"{uh['url_count']} URLs")
    elif uh["status"] == "not_found":
        table.add_row("URLhaus", Text("not_found", style="muted"), "")
    else:
        table.add_row("URLhaus", Text("error", style="unknown"), f"({uh.get('reason')})")

    return table


def build_view(report: dict) -> RenderableType:
    """Build the themed panel for a report dict."""
    verdict = report["aggregated_verdict"]
    verdict_disp = (verdict or "error / no data").upper()
    confidence = report["confidence"] or "—"

    flags = []
    if report["disagreement"]:
        flags.append("disagreement")
    if report["urlhaus_override"]:
        flags.append("urlhaus_override")
    if report.get("urlhaus_high_volume_host"):
        flags.append("high_volume_host")
    if report["single_source"]:
        flags.append("single_source")
    flags_text = Text(", ".join(flags), style="flag") if flags else Text("—", style="muted")

    techs = report["mitre_technique"]
    tech_text = (Text(" · ".join(technique_names(techs)), style="tech")
                 if techs else Text("—", style="muted"))

    header = Table.grid(padding=(0, 2))
    header.add_column(style="label", justify="left")
    header.add_column()
    header.add_row("VERDICT", Text.assemble(
        Text("• ", style=_style(verdict)),
        Text(verdict_disp, style=_style(verdict)),
        Text(f"    confidence: {confidence}", style="muted"),
    ))
    header.add_row("FLAGS", flags_text)
    header.add_row("ATT&CK", tech_text)

    recommendation = Text.assemble(
        Text("» ", style=_style(verdict)),
        Text(report["recommendation"], style="rec"),
    )

    body = Group(header, "", _sources_table(report), "", recommendation)

    title = Text.assemble(
        Text("IOC TRIAGE", style="label"),
        Text("  ·  "),
        Text(report["indicator"], style="bold"),
        Text(f"  ({report['indicator_type']})", style="muted"),
    )
    subtitle = Text(f"queried {report['timestamp']}", style="muted")

    return Panel(
        body,
        title=title,
        subtitle=subtitle,
        border_style=_BORDER.get(verdict, "magenta"),
        box=box.ROUNDED,
        padding=(1, 2),
        width=66,
    )
