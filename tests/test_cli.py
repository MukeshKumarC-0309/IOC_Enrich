"""CLI-level behavior: exit codes and structured --json error output."""
import json

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
