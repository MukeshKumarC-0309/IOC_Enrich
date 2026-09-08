"""Startup wordmark banner (ioc_enrich.banner)."""
from ioc_enrich import banner
from ioc_enrich.banner import print_banner


def test_banner_shows_name_on_stderr(capsys):
    # Default console is stderr; under capture it's not a TTY, so no color/art
    # styling is emitted — but the tool name is always present as plain text.
    print_banner()
    captured = capsys.readouterr()
    assert "ioc-enrich" in captured.err
    assert captured.out == ""  # never contaminates stdout


def test_banner_fallback_is_safe(capsys, monkeypatch):
    # Force the "can't encode the block glyph" path — it must not raise and must
    # still show the tool name.
    monkeypatch.setattr(banner, "_can_encode_block", lambda console: False)
    print_banner()
    assert "ioc-enrich" in capsys.readouterr().err
