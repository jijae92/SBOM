import datetime as dt
from pathlib import Path

from scanner.core import ignore_rules


def test_ignore_rule_expired(tmp_path: Path):
    cfg_path = tmp_path / "ignore.yml"
    cfg_path.write_text(
        """
rules:
  - ids: [CVE-1]
    packages: [pkg]
    until: 2024-01-01
  - ids: [CVE-2]
""".strip()
    )
    rules = ignore_rules.load_rules(cfg_path)
    findings = [
        {"cve": "CVE-1", "name": "pkg"},
        {"cve": "CVE-2", "name": "pkg"},
    ]
    filtered = ignore_rules.filter_findings(findings, rules, reference_date=dt.date(2025, 1, 1))
    assert len(filtered) == 1
    assert filtered[0]["cve"] == "CVE-1"


def test_ignore_rule_filters_before_expiry(tmp_path: Path):
    cfg_path = tmp_path / "ignore.yml"
    cfg_path.write_text(
        """
rules:
  - ids: [CVE-9]
    packages: [pkg]
    until: 2030-01-01
""".strip()
    )
    rules = ignore_rules.load_rules(cfg_path)
    findings = [
        {"cve": "CVE-9", "name": "pkg"},
        {"cve": "CVE-10", "name": "pkg"},
    ]
    filtered = ignore_rules.filter_findings(findings, rules, reference_date=dt.date(2029, 6, 1))
    assert len(filtered) == 1
    assert filtered[0]["cve"] == "CVE-10"
