"""Load and normalise vulnerability reports."""

from __future__ import annotations

import json
import pathlib
from typing import Dict, Iterable, List

from scanner.core.sbom_loader import ComponentIndex
from scanner.runners import grype as grype_parser
from scanner.runners import trivy as trivy_parser


def load_directory(vuln_dir: pathlib.Path, components: ComponentIndex) -> List[Dict[str, object]]:
    findings: List[Dict[str, object]] = []
    if not vuln_dir.exists():
        return findings
    for path in sorted(vuln_dir.glob("*.json")):
        report = json.loads(path.read_text())
        findings.extend(parse_report(report, components))
    return findings


def parse_report(report: Dict[str, object], components: ComponentIndex) -> List[Dict[str, object]]:
    if "matches" in report:
        return grype_parser.parse(report, components)
    if "Results" in report:
        return trivy_parser.parse(report, components)
    return []
