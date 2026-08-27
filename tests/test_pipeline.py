"""Private/reserved IP refusal (DESIGN §10.I) — no network is touched."""
import pytest

from ioc_enrich import enrich
from ioc_enrich.indicator import NotEnrichableError, is_non_routable


@pytest.mark.parametrize(
    "ip",
    ["10.0.0.1", "192.168.1.1", "172.16.5.4", "127.0.0.1", "169.254.0.1",
     "0.0.0.0", "224.0.0.1", "::1", "fe80::1"],
)
def test_non_routable_detected(ip):
    assert is_non_routable(ip) is True


@pytest.mark.parametrize("ip", ["8.8.8.8", "1.1.1.1", "162.243.103.246"])
def test_public_is_routable(ip):
    assert is_non_routable(ip) is False


@pytest.mark.parametrize(
    "raw", ["10.0.0.1", "127.0.0.1", "192.168.1.1", "10[.]0[.]0[.]1"]
)
def test_enrich_refuses_private(raw):
    # Raised before any API call, so this runs fully offline.
    with pytest.raises(NotEnrichableError):
        enrich(raw)


def test_enrich_logs(caplog, monkeypatch):
    from ioc_enrich.clients import abuseipdb, urlhaus, virustotal

    monkeypatch.setattr(abuseipdb, "check", lambda ip: {
        "source": "abuseipdb", "ok": True, "error": None,
        "raw": {"score": 0, "categories": []}})
    monkeypatch.setattr(virustotal, "check", lambda i, t: {
        "source": "virustotal", "ok": True, "error": None,
        "raw": {"malicious": 0, "total": 90}})
    monkeypatch.setattr(urlhaus, "check", lambda h: {
        "source": "urlhaus", "ok": True, "error": None,
        "raw": {"listed": False, "url_count": 0}})

    with caplog.at_level("INFO", logger="ioc_enrich.pipeline"):
        enrich("8.8.8.8")
    assert any("enriching" in rec.getMessage() for rec in caplog.records)
