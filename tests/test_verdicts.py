"""Per-source threshold logic (DESIGN §2)."""
from ioc_enrich.verdicts import (
    CLEAN,
    MALICIOUS,
    SUSPICIOUS,
    abuseipdb_verdict,
    virustotal_verdict,
)


def test_abuseipdb_boundaries():
    # >75 malicious | 25-75 suspicious | <25 clean
    assert abuseipdb_verdict(76) == MALICIOUS
    assert abuseipdb_verdict(75) == SUSPICIOUS
    assert abuseipdb_verdict(25) == SUSPICIOUS
    assert abuseipdb_verdict(24) == CLEAN
    assert abuseipdb_verdict(0) == CLEAN


def test_virustotal_boundaries():
    # >=10% malicious | 3-10% suspicious | <3% clean
    assert virustotal_verdict(10, 100) == MALICIOUS
    assert virustotal_verdict(9, 100) == SUSPICIOUS
    assert virustotal_verdict(3, 100) == SUSPICIOUS
    assert virustotal_verdict(2, 100) == CLEAN
    assert virustotal_verdict(0, 100) == CLEAN
