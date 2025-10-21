"""Priority scoring for vulnerability findings."""

from __future__ import annotations

from typing import Any, Dict, Iterable, List

SEVERITY_ORDER = {
    "INFO": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


def prioritise(findings: Iterable[Dict[str, Any]], epss_weight: float = 0.0) -> List[Dict[str, Any]]:
    ranked: List[Dict[str, Any]] = []
    for finding in findings:
        score = _priority_score(finding, epss_weight)
        enriched = dict(finding)
        enriched["priority_score"] = score
        ranked.append(enriched)
    ranked.sort(
        key=lambda item: (
            -item["priority_score"],
            -float(item.get("cvss") or 0.0),
            str(item.get("name") or item.get("purl") or ""),
        )
    )
    return ranked


def _priority_score(finding: Dict[str, Any], epss_weight: float) -> float:
    severity = str(finding.get("severity", "INFO")).upper()
    severity_score = SEVERITY_ORDER.get(severity, 0)

    fix_state = str(finding.get("fix_state", "")).lower()
    fix_bonus = 1 if fix_state == "fixed" else 0

    component_type = str(finding.get("type", "")).lower()
    type_bonus = 1 if component_type == "app" else 0

    layer = str(finding.get("layer", "")).lower()
    layer_bonus = 1 if layer == "app" else 0

    return severity_score + fix_bonus + type_bonus + layer_bonus
