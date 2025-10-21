"""Parser helpers for Trivy JSON reports."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from scanner.core.sbom_loader import Component, ComponentIndex


def parse(report: Dict[str, Any], components: ComponentIndex) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    for result in report.get("Results", []) or []:
        component = _match_component(result, components)
        for vuln in result.get("Vulnerabilities", []) or []:
            results.append(_normalise_vulnerability(result, vuln, component))
    return results


def _match_component(result: Dict[str, Any], components: ComponentIndex) -> Optional[Component]:
    purl = result.get("PURL") or result.get("ArtifactName")
    name = result.get("Target") or result.get("ArtifactName")
    version = result.get("InstalledVersion") or result.get("Version")
    return components.lookup(purl, name, version)


def _normalise_vulnerability(result: Dict[str, Any], vuln: Dict[str, Any], component: Optional[Component]) -> Dict[str, Any]:
    installed = vuln.get("InstalledVersion") or result.get("InstalledVersion") or (component.version if component else None)
    fix_state = "fixed" if vuln.get("FixedVersion") else "not-fixed"
    references = vuln.get("References") or []
    if isinstance(references, dict):
        references = list(references.values())
    return {
        "source": "trivy",
        "cve": vuln.get("VulnerabilityID", "UNKNOWN"),
        "severity": (vuln.get("Severity") or "INFO").upper(),
        "cvss": _pick_cvss(vuln),
        "fix_state": fix_state,
        "purl": (component.purl if component else vuln.get("Purl")) or vuln.get("PkgPath"),
        "name": component.name if component else vuln.get("PkgName") or result.get("Target"),
        "version": installed,
        "type": component.component_type if component else (result.get("Class") or "app"),
        "layer": component.layer if component else ("base" if result.get("Type") == "os-pkgs" else "app"),
        "references": references,
        "package_path": component.package_path if component else result.get("Target"),
        "epss": float(vuln.get("epssScore") or 0.0),
    }


def _pick_cvss(vuln: Dict[str, Any]) -> float:
    cvss = vuln.get("CVSS")
    if isinstance(cvss, dict):
        for source in ("nvd", "redhat", "github"):
            entry = cvss.get(source)
            if isinstance(entry, dict) and entry.get("V3Score"):
                try:
                    return float(entry["V3Score"])
                except (TypeError, ValueError):
                    continue
        for value in cvss.values():
            if isinstance(value, dict) and value.get("Score"):
                try:
                    return float(value["Score"])
                except (TypeError, ValueError):
                    continue
    score = vuln.get("CVSS3Score") or vuln.get("CVSS2Score")
    if isinstance(score, (int, float)):
        return float(score)
    try:
        return float(score)
    except (TypeError, ValueError):
        return 0.0
