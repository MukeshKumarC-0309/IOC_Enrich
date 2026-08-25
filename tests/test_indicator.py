"""Indicator classification + defang normalisation (DESIGN §1 / §10.H)."""
import pytest

from ioc_enrich.indicator import DOMAIN, IP, classify


def test_ipv4():
    assert classify("1.2.3.4") == (IP, "1.2.3.4")


def test_ipv6():
    kind, value = classify("2001:db8::1")
    assert kind == IP


def test_domain_is_lowercased():
    assert classify("Evil.COM") == (DOMAIN, "evil.com")


@pytest.mark.parametrize("bad", ["not!!valid", "   ", "", "http://", "just some words"])
def test_rejects_invalid(bad):
    with pytest.raises(ValueError):
        classify(bad)


@pytest.mark.parametrize(
    "raw,kind,value",
    [
        ("evil[.]com", DOMAIN, "evil.com"),
        ("evil(.)com", DOMAIN, "evil.com"),
        ("evil[dot]com", DOMAIN, "evil.com"),
        ("evil [.] com", DOMAIN, "evil.com"),
        ("hxxp://bad[.]site", DOMAIN, "bad.site"),
        ("hXXps://bad[.]site/path?q=1", DOMAIN, "bad.site"),
        ("bad.site:8080", DOMAIN, "bad.site"),
        ("evil.com.", DOMAIN, "evil.com"),
        ("1[.]2[.]3[.]4", IP, "1.2.3.4"),
        ("hxxp[:]//1[.]2[.]3[.]4", IP, "1.2.3.4"),
        ("http://1.2.3.4/", IP, "1.2.3.4"),
        ("  8.8.8.8  ", IP, "8.8.8.8"),
    ],
)
def test_defang_normalisation(raw, kind, value):
    assert classify(raw) == (kind, value)
