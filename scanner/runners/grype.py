"""Parser for Grype JSON reports."""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional

from scanner.core.sbom_loader import Component, ComponentIndex


def parse(report: Dict[str, Any], components: ComponentIndex) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    matches = report.get("matches") or []
    for match in matches:
        vuln = match.get("vulnerability", {})
        artifact = match.get("artifact", {})
        locations = artifact.get("locations") or []
        purl = artifact.get("purl") or artifact.get("package", {}).get("purl")
        name = artifact.get("name") or artifact.get("package", {}).get("name")
        version = artifact.get("version") or artifact.get("package", {}).get("version")
        component = components.lookup(purl, name, version)
        finding = {
            "source": "grype",
            "cve": _primary_cve(vuln),
            "severity": (vuln.get("severity") or "INFO").upper(),
            "cvss": _select_cvss_score(vuln.get("cvss") or []),
            "fix_state": _normalise_fix_state(vuln.get("fix", {})),
            "purl": component.purl if component else purl,
            "name": component.name if component else name,
            "version": component.version if component else version,
            "type": component.component_type if component else "app",
            "layer": component.layer if component else "app",
            "references": _extract_references(vuln),
            "package_path": _first_location(locations) or (component.package_path if component else None),
            "epss": 0.0,
        }
        findings.append(finding)
    return findings


def _primary_cve(vuln: Dict[str, Any]) -> str:
    if vuln.get("id"):
        return str(vuln["id"])
    related = vuln.get("relatedVulnerabilities") or []
    for entry in related:
        if entry.get("id"):
            return str(entry["id"])
    return "UNKNOWN"


def _select_cvss_score(cvss_list: Iterable[Dict[str, Any]]) -> float:
    best = 0.0
    for entry in cvss_list:
        metrics = entry.get("metrics") or {}
        score = metrics.get("baseScore") or entry.get("score") or 0.0
        try:
            best = max(best, float(score))
        except (TypeError, ValueError):
            continue
    return best


def _normalise_fix_state(fix: Dict[str, Any]) -> str:
    state = (fix.get("state") or "").lower()
    if state in {"fixed", "not-fixed", "wont-fix", "unknown"}:
        return state
    versions = fix.get("versions") or []
    if versions:
        return "fixed"
    return "not-fixed"


def _extract_references(vuln: Dict[str, Any]) -> List[str]:
    references: List[str] = []
    for ref in vuln.get("urls") or []:
        if isinstance(ref, str):
            references.append(ref)
    for ref in vuln.get("references") or []:
        url = ref.get("url") if isinstance(ref, dict) else None
        if url:
            references.append(url)
    return list(dict.fromkeys(references))


def _first_location(locations: Iterable[Dict[str, Any]]) -> Optional[str]:
    for location in locations:
        if isinstance(location, dict) and location.get("path"):
            return str(location["path"])
    return None
