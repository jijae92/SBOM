"""Report rendering utilities."""

from __future__ import annotations

import json
import pathlib
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Sequence

import datetime as dt

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


@dataclass
class ReportPaths:
    json_path: pathlib.Path | None
    markdown_path: pathlib.Path | None
    html_path: pathlib.Path | None
    sarif_path: pathlib.Path | None


def build_summary(findings: Iterable[Dict[str, Any]], top_n: int = 10) -> Dict[str, Any]:
    items = list(findings)
    counts = {level.lower(): 0 for level in SEVERITY_ORDER}
    package_counter: Dict[str, Dict[str, Any]] = {}
    cve_counter: Dict[str, Dict[str, Any]] = {}
    fixed_available = 0
    for item in items:
        severity = str(item.get("severity", "INFO")).upper()
        severity = severity if severity in SEVERITY_ORDER else "INFO"
        counts[severity.lower()] += 1
        package_key = item.get("purl") or item.get("name") or "unknown"
        package_counter.setdefault(package_key, {"count": 0, "severity": severity})
        package_counter[package_key]["count"] += 1
        if SEVERITY_ORDER.index(severity) < SEVERITY_ORDER.index(package_counter[package_key]["severity"]):
            package_counter[package_key]["severity"] = severity
        cve_key = item.get("cve") or "UNKNOWN"
        cve_counter.setdefault(cve_key, {"count": 0, "severity": severity})
        cve_counter[cve_key]["count"] += 1
        if SEVERITY_ORDER.index(severity) < SEVERITY_ORDER.index(cve_counter[cve_key]["severity"]):
            cve_counter[cve_key]["severity"] = severity
        if str(item.get("fix_state", "")).lower() in {"fixed", "available", "upgrade"}:
            fixed_available += 1
    summary = {
        "generated_at": dt.datetime.now(dt.UTC).isoformat(),
        "total": len(items),
        "fixed_available": fixed_available,
        "top_packages": _top_entries(package_counter, top_n),
        "top_cves": _top_entries(cve_counter, top_n),
        "items": items[:top_n],
    }
    summary.update({level.lower(): counts[level.lower()] for level in SEVERITY_ORDER})
    return summary


def write_reports(
    summary: Dict[str, Any],
    items: Sequence[Dict[str, Any]],
    output_dir: pathlib.Path,
    json_path: pathlib.Path | None = None,
    sarif_path: pathlib.Path | None = None,
    formats: Sequence[str] | None = None,
) -> ReportPaths:
    output_dir.mkdir(parents=True, exist_ok=True)
    formats = [fmt.lower() for fmt in (formats or ["json", "md", "html"])]

    resolved_json = json_path or (output_dir / "summary.json")
    resolved_markdown = output_dir / "summary.md" if "md" in formats else None
    resolved_html = output_dir / "summary.html" if "html" in formats else None

    if "json" in formats:
        resolved_json.parent.mkdir(parents=True, exist_ok=True)
        resolved_json.write_text(json.dumps(summary, indent=2, sort_keys=True))
    else:
        resolved_json = None

    if resolved_markdown:
        resolved_markdown.write_text(render_markdown(summary, items))

    if resolved_html:
        resolved_html.write_text(render_html(summary, items))

    resolved_sarif = None
    if sarif_path:
        sarif_path.parent.mkdir(parents=True, exist_ok=True)
        sarif_path.write_text(json.dumps(render_sarif(items), indent=2))
        resolved_sarif = sarif_path

    return ReportPaths(json_path=resolved_json, markdown_path=resolved_markdown, html_path=resolved_html, sarif_path=resolved_sarif)


def render_markdown(summary: Dict[str, Any], items: Sequence[Dict[str, Any]]) -> str:
    lines: List[str] = ["# Vulnerability Summary", ""]
    lines.append(f"Generated: {summary['generated_at']}")
    lines.append("")
    lines.append("## Counts")
    for level in SEVERITY_ORDER:
        lines.append(f"- {level.title()}: {summary.get(level.lower(), 0)}")
    lines.append(f"- Total: {summary.get('total', 0)}")
    lines.append(f"- Fix Available: {summary.get('fixed_available', 0)}")
    lines.append("")
    if summary.get("top_packages"):
        lines.append("## Top Packages")
        for entry in summary["top_packages"]:
            lines.append(f"- {entry['name']} ({entry['count']} findings, worst {entry['severity']})")
        lines.append("")
    if summary.get("top_cves"):
        lines.append("## Top CVEs")
        for entry in summary["top_cves"]:
            lines.append(f"- {entry['name']} ({entry['count']} occurrences, worst {entry['severity']})")
        lines.append("")
    if items:
        lines.append("## Top Findings")
        for item in items:
            lines.append(
                f"- {item.get('cve')} | {item.get('severity')} | {item.get('name')} {item.get('version')} | layer={item.get('layer')} | fix={item.get('fix_state')}"
            )
    return "\n".join(lines)


def render_html(summary: Dict[str, Any], items: Sequence[Dict[str, Any]]) -> str:
    counts = "".join(
        f"<li>{level.title()}: {summary.get(level.lower(), 0)}</li>" for level in SEVERITY_ORDER
    )
    counts += f"<li>Total: {summary.get('total', 0)}</li><li>Fix Available: {summary.get('fixed_available', 0)}</li>"
    rows = []
    for item in items:
        rows.append(
            "<tr>"
            f"<td>{item.get('cve')}</td>"
            f"<td>{item.get('severity')}</td>"
            f"<td>{item.get('name')}</td>"
            f"<td>{item.get('version')}</td>"
            f"<td>{item.get('layer')}</td>"
            f"<td>{item.get('fix_state')}</td>"
            f"<td>{item.get('priority_score', '')}</td>"
            "</tr>"
        )
    table = "".join(rows)
    return (
        "<html><head><title>SBOM Vulnerability Summary</title></head><body>"
        "<h1>SBOM Vulnerability Summary</h1>"
        f"<p>Generated: {summary['generated_at']}</p>"
        f"<ul>{counts}</ul>"
        "<h2>Top Findings</h2>"
        "<table border='1' cellpadding='4' cellspacing='0'>"
        "<thead><tr><th>CVE</th><th>Severity</th><th>Package</th><th>Version</th><th>Layer</th><th>Fix State</th><th>Priority</th></tr></thead>"
        f"<tbody>{table}</tbody>"
        "</table>"
        "</body></html>"
    )


def render_sarif(items: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    results = []
    for item in items:
        results.append(
            {
                "ruleId": item.get("cve") or "UNKNOWN",
                "level": _to_sarif_level(item.get("severity")),
                "message": {"text": f"{item.get('name')} {item.get('version')}".strip()},
                "properties": {
                    "severity": item.get("severity"),
                    "cvss": item.get("cvss"),
                    "fix_state": item.get("fix_state"),
                    "layer": item.get("layer"),
                    "purl": item.get("purl"),
                },
            }
        )
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "sbom-sentinel", "version": "0.1.0"}},
                "results": results,
            }
        ],
    }


def _top_entries(counter: Dict[str, Dict[str, Any]], limit: int) -> List[Dict[str, Any]]:
    sorted_items = sorted(
        counter.items(),
        key=lambda kv: (kv[1]["count"], -SEVERITY_ORDER.index(kv[1]["severity"])),
        reverse=True,
    )
    return [
        {"name": name, "count": payload["count"], "severity": payload["severity"]}
        for name, payload in sorted_items[:limit]
    ]


def _to_sarif_level(severity: Any) -> str:
    sev = str(severity or "INFO").upper()
    if sev in {"CRITICAL", "HIGH"}:
        return "error"
    if sev == "MEDIUM":
        return "warning"
    return "note"
