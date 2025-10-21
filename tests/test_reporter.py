from pathlib import Path

from scanner.core import reporter
from scanner import cli


def test_reporter_writes_files(tmp_path: Path):
    findings = [
        {
            "cve": "CVE-1",
            "severity": "HIGH",
            "name": "pkg",
            "version": "1.0",
            "priority_score": 10.0,
            "layer": "app",
            "fix_state": "fixed",
            "purl": "pkg:pypi/pkg@1.0",
        }
    ]
    summary = reporter.build_summary(findings)
    paths = reporter.write_reports(
        summary,
        findings,
        output_dir=tmp_path,
        json_path=tmp_path / "summary.json",
        sarif_path=tmp_path / "summary.sarif",
    )
    assert paths.json_path and paths.json_path.exists()
    assert paths.markdown_path and paths.markdown_path.exists()
    assert paths.html_path and paths.html_path.exists()
    assert paths.sarif_path and paths.sarif_path.exists()
    data = paths.json_path.read_text()
    assert "CVE-1" in data


def test_build_summary_counts_and_top_sections():
    findings = [
        {"cve": "C1", "severity": "CRITICAL", "name": "pkgA", "purl": "pkg:pypi/pkga@1", "layer": "app", "fix_state": "fixed"},
        {"cve": "C2", "severity": "MEDIUM", "name": "pkgB", "purl": "pkg:pypi/pkgb@1", "layer": "base", "fix_state": "not-fixed"},
    ]
    summary = reporter.build_summary(findings, top_n=2)
    assert summary["total"] == 2
    assert summary["critical"] == 1
    assert summary["medium"] == 1
    assert summary["fixed_available"] == 1
    assert summary["top_packages"]
    assert summary["top_cves"]


def test_cli_threshold_helper():
    findings = [
        {"severity": "LOW"},
        {"severity": "MEDIUM"},
    ]
    assert cli._passes_threshold(findings, "HIGH") is True
    assert cli._passes_threshold(findings, "MEDIUM") is False
