import json
from pathlib import Path

from scanner.core import sbom_loader, vuln_loader


def _write_sbom(tmp_path: Path) -> Path:
    sbom = {
        "bomFormat": "CycloneDX",
        "components": [
            {
                "name": "pkg",
                "version": "1.0.0",
                "purl": "pkg:pypi/pkg@1.0.0",
                "properties": [
                    {"name": "syft:package:type", "value": "python"},
                    {"name": "layer", "value": "application"},
                ],
            }
        ],
    }
    path = tmp_path / "sample.sbom.json"
    path.write_text(json.dumps(sbom))
    return path


def test_load_grype_report(tmp_path: Path):
    sbom_dir = tmp_path / "sbom"
    vuln_dir = tmp_path / "vuln"
    sbom_dir.mkdir()
    vuln_dir.mkdir()
    _write_sbom(sbom_dir)

    grype_report = {
        "matches": [
            {
                "vulnerability": {
                    "id": "CVE-1",
                    "severity": "HIGH",
                    "cvss": [{"metrics": {"baseScore": 7.5}}],
                    "fix": {"state": "fixed"},
                    "urls": ["https://example.com"],
                },
                "artifact": {
                    "name": "pkg",
                    "version": "1.0.0",
                    "purl": "pkg:pypi/pkg@1.0.0",
                },
            }
        ]
    }
    vuln_path = vuln_dir / "report.vuln.json"
    vuln_path.write_text(json.dumps(grype_report))

    components = sbom_loader.load_directory(sbom_dir)
    findings = vuln_loader.load_directory(vuln_dir, components)

    assert len(findings) == 1
    finding = findings[0]
    assert finding["cve"] == "CVE-1"
    assert finding["severity"] == "HIGH"
    assert finding["purl"] == "pkg:pypi/pkg@1.0.0"
