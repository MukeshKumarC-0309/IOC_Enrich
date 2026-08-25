"""ATT&CK mapping rules (DESIGN §6 / §10.C)."""
from ioc_enrich.attack import T1071, T1110, map_techniques


def test_t1110_from_mapped_categories():
    for cat in (5, 18, 22):
        assert map_techniques([cat], False, 0) == [T1110]


def test_excluded_categories_do_not_map():
    for cat in (21, 16, 14):  # web-app attack, sqli, port-scan
        assert map_techniques([cat], False, 0) == []


def test_any_reported_category_matches():
    # A single qualifying category among several is enough (recall-favouring).
    assert map_techniques([14, 19, 18], False, 0) == [T1110]


def test_t1071_on_urlhaus_match_below_threshold():
    assert map_techniques([], True, 100) == [T1071]
    assert map_techniques([], True, 749) == [T1071]


def test_t1071_suppressed_for_high_volume_host():
    assert map_techniques([], True, 750) == []
    assert map_techniques([], True, 7930) == []


def test_both_techniques_deterministic_order():
    assert map_techniques([18], True, 4) == [T1110, T1071]


def test_no_rule_matches():
    assert map_techniques([], False, 0) == []
