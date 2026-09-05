"""Smoke tests for the themed rich renderer — offline, no console needed."""
import io

from rich.console import Console

from ioc_enrich.render import THEME, build_view, make_console


def _text(report):
    console = Console(theme=THEME, width=70, file=io.StringIO(),
                      record=True, force_terminal=True)
    console.print(build_view(report))
    return console.export_text()


def _report(**overrides):
    base = {
        "indicator": "1.2.3.4", "indicator_type": "ip",
        "sources": {
            "abuseipdb": {"status": "ok", "score": 61, "verdict": "suspicious"},
            "virustotal": {"status": "ok", "malicious_ratio": "14/91", "verdict": "malicious"},
            "urlhaus": {"status": "match", "url_count": 4},
        },
        "status": "ok", "aggregated_verdict": "malicious",
        "urlhaus_override": True, "urlhaus_high_volume_host": False,
        "disagreement": False, "single_source": False,
        "mitre_technique": ["T1110", "T1071"], "confidence": "medium",
        "recommendation": "Confirmed malicious — listed on URLhaus blocklist",
        "timestamp": "2026-01-01T00:00:00Z",
    }
    base.update(overrides)
    return base


def test_renders_malicious():
    text = _text(_report())
    assert "1.2.3.4" in text
    assert "MALICIOUS" in text
    assert "T1110" in text


def test_renders_domain_not_applicable():
    text = _text(_report(
        indicator="evil.com", indicator_type="domain",
        sources={
            "abuseipdb": {"status": "not_applicable", "reason": "x"},
            "virustotal": {"status": "ok", "malicious_ratio": "0/90", "verdict": "clean"},
            "urlhaus": {"status": "not_found"},
        },
        aggregated_verdict="clean", urlhaus_override=False, single_source=True,
        mitre_technique=[], confidence="medium",
        recommendation="Single-source signal (VirusTotal only) — corroborate before escalation",
    ))
    assert "evil.com" in text
    assert "n/a" in text
    assert "CLEAN" in text


def test_renders_error():
    text = _text(_report(
        sources={
            "abuseipdb": {"status": "error", "reason": "timeout"},
            "virustotal": {"status": "error", "reason": "timeout"},
            "urlhaus": {"status": "query_error", "reason": "http_error"},
        },
        aggregated_verdict=None, status="error", confidence=None,
        urlhaus_override=False, mitre_technique=[],
        recommendation="Insufficient data — sources unavailable; retry or investigate manually",
    ))
    assert "ERROR" in text


def test_make_console_no_color():
    assert make_console(no_color=True).no_color is True
