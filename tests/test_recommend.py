"""Recommendation lookup — the 7 guard-ordered situations (DESIGN §5 / §10.E)."""
from ioc_enrich.aggregate import AggregationResult
from ioc_enrich.recommend import recommend


def make(**overrides):
    base = dict(
        verdict="malicious", status="ok", confidence="high",
        disagreement=False, urlhaus_override=False, single_source=False,
        abuseipdb_verdict="malicious", virustotal_verdict="malicious",
        urlhaus_high_volume_host=False,
    )
    base.update(overrides)
    return AggregationResult(**base)


def test_error_situation():
    r = recommend(make(verdict=None, status="error", confidence=None,
                        abuseipdb_verdict=None, virustotal_verdict=None))
    assert "Insufficient data" in r


def test_override_zero_voters():
    r = recommend(make(urlhaus_override=True, confidence="low",
                       abuseipdb_verdict=None, virustotal_verdict=None))
    assert "reputation sources unavailable" in r


def test_override_with_voters():
    # Override must be checked before single_source (the domain+match bug).
    r = recommend(make(urlhaus_override=True, confidence="medium",
                       single_source=True, abuseipdb_verdict=None,
                       virustotal_verdict="clean"))
    assert r.startswith("Confirmed malicious")


def test_single_source_names_the_lone_voter():
    r = recommend(make(verdict="suspicious", confidence="medium",
                       single_source=True, abuseipdb_verdict=None,
                       virustotal_verdict="suspicious"))
    assert "VirusTotal only" in r


def test_two_voter_high():
    assert recommend(make(confidence="high")) == "Consistent signal across sources"


def test_two_voter_medium():
    r = recommend(make(confidence="medium", abuseipdb_verdict="malicious",
                       virustotal_verdict="suspicious"))
    assert r.startswith("Partial signal")


def test_two_voter_low():
    r = recommend(make(verdict="suspicious", confidence="low", disagreement=True,
                       abuseipdb_verdict="malicious", virustotal_verdict="clean"))
    assert r.startswith("Sources disagree")
