"""CLI-level behavior: exit codes and structured --json error output."""
import json

import pytest

from ioc_enrich.cli import main


def test_private_ip_json_error(capsys):
    code = main(["10.0.0.1", "--json"])
    data = json.loads(capsys.readouterr().out)
    assert code == 3
    assert data["error"] == "not_enrichable"
    assert data["indicator"] == "10.0.0.1"


def test_invalid_input_json_error(capsys):
    code = main(["not!!valid", "--json"])
    data = json.loads(capsys.readouterr().out)
    assert code == 2
    assert data["error"] == "invalid_input"


def test_private_ip_text_error_goes_to_stderr(capsys):
    code = main(["10.0.0.1"])
    captured = capsys.readouterr()
    assert code == 3
    assert captured.out == ""  # nothing on stdout in the human path
    assert "private/reserved" in captured.err


def _error_report():
    return {
        "indicator": "1.2.3.4", "indicator_type": "ip",
        "sources": {
            "abuseipdb": {"status": "error", "reason": "invalid_key"},
            "virustotal": {"status": "error", "reason": "invalid_key"},
            "urlhaus": {"status": "query_error", "reason": "http_error"},
        },
        "status": "error", "aggregated_verdict": None, "urlhaus_override": False,
        "urlhaus_high_volume_host": False, "disagreement": False,
        "single_source": False, "mitre_technique": [], "confidence": None,
        "recommendation": "Insufficient data — sources unavailable; retry or investigate manually",
        "timestamp": "t",
    }


def test_key_hint_when_keys_missing(capsys, monkeypatch):
    import ioc_enrich.cli as cli
    monkeypatch.setattr(cli, "enrich", lambda i: _error_report())
    monkeypatch.setattr(cli.config, "ABUSEIPDB_API_KEY", "")
    monkeypatch.setattr(cli.config, "VIRUSTOTAL_API_KEY", "")
    monkeypatch.setattr(cli.config, "URLHAUS_AUTH_KEY", "")
    code = cli.main(["1.2.3.4"])
    assert code == 1
    assert "no API key set" in capsys.readouterr().err


def test_no_key_hint_when_keys_present(capsys, monkeypatch):
    import ioc_enrich.cli as cli
    monkeypatch.setattr(cli, "enrich", lambda i: _error_report())
    monkeypatch.setattr(cli.config, "ABUSEIPDB_API_KEY", "x")
    monkeypatch.setattr(cli.config, "VIRUSTOTAL_API_KEY", "x")
    monkeypatch.setattr(cli.config, "URLHAUS_AUTH_KEY", "x")
    code = cli.main(["1.2.3.4"])
    assert code == 1
    assert "hint:" not in capsys.readouterr().err


def test_quiet_output(capsys, monkeypatch):
    import ioc_enrich.cli as cli
    monkeypatch.setattr(cli, "enrich", lambda i: {
        "indicator": "1.2.3.4", "aggregated_verdict": "malicious", "status": "ok"})
    code = cli.main(["1.2.3.4", "--quiet"])
    assert code == 0
    assert capsys.readouterr().out.strip() == "1.2.3.4\tmalicious"


def test_quiet_error(capsys, monkeypatch):
    import ioc_enrich.cli as cli
    monkeypatch.setattr(cli, "enrich", lambda i: _error_report())
    code = cli.main(["1.2.3.4", "--quiet"])
    assert code == 1
    assert capsys.readouterr().out.strip() == "1.2.3.4\terror"


def test_json_and_quiet_are_mutually_exclusive():
    with pytest.raises(SystemExit):
        main(["1.2.3.4", "--json", "--quiet"])


def test_keyboard_interrupt_exits_130(capsys, monkeypatch):
    import ioc_enrich.cli as cli

    def boom(indicator):
        raise KeyboardInterrupt

    monkeypatch.setattr(cli, "enrich", boom)
    code = cli.main(["1.2.3.4"])
    assert code == 130
    assert "aborted" in capsys.readouterr().err
