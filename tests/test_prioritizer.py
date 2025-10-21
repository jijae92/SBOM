from scanner.core import prioritizer


def test_prioritise_orders_by_score():
    findings = [
        {"cve": "CVE-1", "severity": "LOW", "cvss": 2.0, "layer": "app", "fix_state": "not-fixed", "type": "app"},
        {"cve": "CVE-2", "severity": "HIGH", "cvss": 7.0, "layer": "base", "fix_state": "fixed", "type": "os"},
    ]
    ranked = prioritizer.prioritise(findings)
    assert ranked[0]["cve"] == "CVE-2"
    assert ranked[0]["priority_score"] > ranked[1]["priority_score"]


def test_priority_score_applies_weight_components():
    baseline = {
        "cve": "BASE",
        "severity": "HIGH",
        "cvss": 0.0,
        "layer": "base",
        "fix_state": "not-fixed",
        "type": "os",
    }
    improved = {
        "cve": "IMPROVED",
        "severity": "HIGH",
        "cvss": 8.0,
        "layer": "app",
        "fix_state": "fixed",
        "type": "app",
    }

    ranked = prioritizer.prioritise([baseline, improved])
    base_score = next(item["priority_score"] for item in ranked if item["cve"] == "BASE")
    improved_score = next(item["priority_score"] for item in ranked if item["cve"] == "IMPROVED")

    assert base_score == 3  # severity HIGH (3) + no bonuses
    assert improved_score == 6  # severity 3 + fix 1 + type 1 + layer 1
    assert improved_score > base_score


def test_tie_breaker_uses_cvss_then_name():
    findings = [
        {"cve": "A", "severity": "MEDIUM", "cvss": 6.0, "layer": "app", "fix_state": "not-fixed", "type": "app", "name": "alpha"},
        {"cve": "B", "severity": "MEDIUM", "cvss": 7.5, "layer": "app", "fix_state": "not-fixed", "type": "app", "name": "bravo"},
        {"cve": "C", "severity": "MEDIUM", "cvss": 7.5, "layer": "app", "fix_state": "not-fixed", "type": "app", "name": "charlie"},
    ]

    ranked = prioritizer.prioritise(findings)
    assert [item["cve"] for item in ranked] == ["B", "C", "A"]
