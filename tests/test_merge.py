from typing import Dict, Any

from scanner.core import vuln_loader
from scanner.core.sbom_loader import Component, ComponentIndex


def _component_index() -> ComponentIndex:
    component = Component(
        purl="pkg:pypi/pkg@1.0.0",
        name="pkg",
        version="1.0.0",
        component_type="app",
        layer="app",
        package_path="/usr/src/pkg",
        raw={},
    )
    return ComponentIndex([component])


def test_merge_grype_and_trivy_findings_share_schema():
    components = _component_index()

    grype_report: Dict[str, Any] = {
        "matches": [
            {
                "vulnerability": {
                    "id": "CVE-GRYPE",
                    "severity": "HIGH",
                    "cvss": [{"metrics": {"baseScore": 7.5}}],
                    "fix": {"state": "fixed"},
                    "urls": ["https://example.com/grype"],
                },
                "artifact": {
                    "name": "pkg",
                    "version": "1.0.0",
                    "purl": "pkg:pypi/pkg@1.0.0",
                },
            }
        ]
    }

    trivy_report: Dict[str, Any] = {
        "Results": [
            {
                "Target": "pkg",
                "PURL": "pkg:pypi/pkg@1.0.0",
                "InstalledVersion": "1.0.0",
                "Class": "language-pkgs",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-TRIVY",
                        "Severity": "medium",
                        "InstalledVersion": "1.0.0",
                        "FixedVersion": "1.0.1",
                        "References": ["https://example.com/trivy"],
                        "CVSS": {"nvd": {"V3Score": 5.0}},
                    }
                ],
            }
        ]
    }

    grype_findings = vuln_loader.parse_report(grype_report, components)
    trivy_findings = vuln_loader.parse_report(trivy_report, components)

    combined = grype_findings + trivy_findings
    assert {finding["source"] for finding in combined} == {"grype", "trivy"}

    expected_keys = {
        "source",
        "cve",
        "severity",
        "cvss",
        "fix_state",
        "purl",
        "name",
        "version",
        "type",
        "layer",
        "references",
        "package_path",
        "epss",
    }

    for finding in combined:
        assert expected_keys <= finding.keys()
        assert finding["purl"] == "pkg:pypi/pkg@1.0.0"
        assert finding["name"] == "pkg"
        assert finding["layer"] == "app"
        assert isinstance(finding["references"], list)
        assert isinstance(finding["cvss"], float)
