"""Deterministic aggregation (DESIGN §3 / §4 / §10.B / §10.D)."""
import pytest

from ioc_enrich.aggregate import aggregate


def ab(score):
    return {"source": "abuseipdb", "ok": True, "error": None,
            "raw": {"score": score, "categories": []}}


def vt(malicious, total):
    return {"source": "virustotal", "ok": True, "error": None,
            "raw": {"malicious": malicious, "total": total}}


def uh(listed, url_count=0):
    return {"source": "urlhaus", "ok": True, "error": None,
            "raw": {"listed": listed, "url_count": url_count}}


def err(source):
    return {"source": source, "ok": False, "error": "timeout", "raw": None}


NOT_FOUND = uh(False)
# score -> verdict: 80 malicious, 50 suspicious, 10 clean
S = {"m": 80, "s": 50, "c": 10}
# (malicious, total) -> verdict: mal 20%, susp 5%, clean 1%
V = {"m": (20, 100), "s": (5, 100), "c": (1, 100)}


@pytest.mark.parametrize(
    "a,v,verdict,confidence,disagreement",
    [
        ("m", "m", "malicious", "high", False),
        ("m", "s", "malicious", "medium", False),
        ("m", "c", "suspicious", "low", True),
        ("s", "m", "malicious", "medium", False),
        ("s", "s", "suspicious", "high", False),
        ("s", "c", "suspicious", "medium", False),
        ("c", "m", "suspicious", "low", True),
        ("c", "s", "suspicious", "medium", False),
        ("c", "c", "clean", "high", False),
    ],
)
def test_two_voter_truth_table(a, v, verdict, confidence, disagreement):
    r = aggregate("ip", ab(S[a]), vt(*V[v]), NOT_FOUND)
    assert r.verdict == verdict
    assert r.confidence == confidence
    assert r.disagreement == disagreement
    assert r.status == "ok"


def test_urlhaus_override_forces_malicious():
    r = aggregate("ip", ab(10), vt(1, 100), uh(True, 4))
    assert r.verdict == "malicious"
    assert r.urlhaus_override is True
    assert r.disagreement is False


def test_high_volume_match_suppresses_override():
    r = aggregate("ip", ab(10), vt(1, 100), uh(True, 750))
    assert r.urlhaus_override is False
    assert r.urlhaus_high_volume_host is True
    assert r.verdict == "clean"  # falls through to voting


def test_domain_is_single_voter():
    r = aggregate("domain", None, vt(5, 100), NOT_FOUND)
    assert r.single_source is True
    assert r.confidence == "medium"
    assert r.abuseipdb_verdict is None


def test_one_errored_voter_is_single_source():
    r = aggregate("ip", ab(50), err("virustotal"), NOT_FOUND)
    assert r.single_source is True
    assert r.verdict == "suspicious"
    assert r.confidence == "medium"


def test_zero_voters_no_urlhaus_is_error():
    r = aggregate("ip", err("abuseipdb"), err("virustotal"), NOT_FOUND)
    assert r.status == "error"
    assert r.verdict is None
    assert r.confidence is None


def test_zero_voters_urlhaus_match_still_malicious():
    r = aggregate("ip", err("abuseipdb"), err("virustotal"), uh(True, 3))
    assert r.verdict == "malicious"
    assert r.urlhaus_override is True
    assert r.confidence == "low"
    assert r.status == "ok"
