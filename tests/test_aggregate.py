import json
from pathlib import Path

from scanner import cli


def test_cli_generates_summary(tmp_path: Path):
    reports_dir = tmp_path / "reports"
    sbom_dir = reports_dir / "sbom"
    vuln_dir = reports_dir / "vuln"
    sbom_dir.mkdir(parents=True)
    vuln_dir.mkdir()

    sbom_dir.joinpath("image.sbom.json").write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "components": [
                    {
                        "name": "pkg",
                        "version": "1.0.0",
                        "purl": "pkg:pypi/pkg@1.0.0",
                        "properties": [
                            {"name": "syft:package:type", "value": "python"},
                            {"name": "layer", "value": "app"},
                        ],
                    }
                ],
            }
        )
    )

    vuln_dir.joinpath("image.vuln.json").write_text(
        json.dumps(
            {
                "matches": [
                    {
                        "vulnerability": {
                            "id": "CVE-1234",
                            "severity": "HIGH",
                            "cvss": [{"metrics": {"baseScore": 7.8}}],
                            "fix": {"state": "fixed"},
                            "urls": ["https://example.com/cve-1234"],
                        },
                        "artifact": {
                            "name": "pkg",
                            "version": "1.0.0",
                            "purl": "pkg:pypi/pkg@1.0.0",
                        },
                    }
                ]
            }
        )
    )

    out_path = reports_dir / "summary.json"
    rc = cli.main([
        "--collect",
        str(reports_dir),
        "--out",
        str(out_path),
        "--fail-on",
        "CRITICAL",
    ])
    assert rc == 0
    data = json.loads(out_path.read_text())
    assert data["total"] == 1
    assert data["high"] == 1
