"""Command-line interface for SBOM vulnerability summarisation."""

from __future__ import annotations

import argparse
import pathlib
from typing import Iterable, List

from scanner.core import gitmeta, ignore_rules, prioritizer, reporter, sbom_loader, vuln_loader

SEVERITY_LEVELS = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Aggregate SBOM vulnerability reports")
    parser.add_argument("--collect", type=pathlib.Path, default=pathlib.Path("reports"), help="Base directory containing sbom/ and vuln/ subdirectories")
    parser.add_argument("--sbom-dir", type=pathlib.Path, help="Directory containing SBOM JSON files", default=None)
    parser.add_argument("--vuln-dir", type=pathlib.Path, help="Directory containing vulnerability JSON files", default=None)
    parser.add_argument("--ignore", type=pathlib.Path, default=pathlib.Path("config/.vuln-ignore.yml"), help="Ignore rules YAML file")
    parser.add_argument("--fail-on", choices=SEVERITY_LEVELS, default="HIGH", help="Severity threshold that fails the command")
    parser.add_argument("--out", type=pathlib.Path, default=pathlib.Path("reports/summary.json"), help="Path for the summary JSON output")
    parser.add_argument("--sarif", type=pathlib.Path, help="Optional SARIF output path")
    parser.add_argument("--format", action="append", choices=["json", "md", "html"], help="Additional formats to emit (defaults to all)")
    parser.add_argument("--top", type=int, default=10, help="Number of top findings to include in outputs")
    parser.add_argument("--epss-weight", type=float, default=0.0, help="Weight to apply to EPSS values when prioritising")
    return parser


def main(argv: List[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    sbom_dir = args.sbom_dir or args.collect / "sbom"
    vuln_dir = args.vuln_dir or args.collect / "vuln"

    components = sbom_loader.load_directory(sbom_dir)
    findings = vuln_loader.load_directory(vuln_dir, components)

    rules = ignore_rules.load_rules(args.ignore)
    filtered = ignore_rules.filter_findings(findings, rules)

    ranked = prioritizer.prioritise(filtered, epss_weight=args.epss_weight)

    summary = reporter.build_summary(ranked, top_n=args.top)
    summary.update(
        {
            "fail_on": args.fail_on,
            "git": gitmeta.collect_git_metadata(),
            "reports_root": str(args.collect.resolve()),
        }
    )

    formats = args.format or ["json", "md", "html"]
    output_dir = args.out.parent
    report_paths = reporter.write_reports(
        summary,
        ranked[: args.top],
        output_dir=output_dir,
        json_path=args.out,
        sarif_path=args.sarif,
        formats=formats,
    )

    exit_code = 0 if _passes_threshold(ranked, args.fail_on) else 1

    print(
        "Generated summary at "
        f"JSON={report_paths.json_path or 'skipped'} "
        f"MD={report_paths.markdown_path or 'skipped'} "
        f"HTML={report_paths.html_path or 'skipped'}"
    )
    if args.sarif:
        print(f"SARIF={report_paths.sarif_path}")
    if exit_code:
        print(f"Failing due to findings at or above {args.fail_on}")
    return exit_code


def _passes_threshold(findings: Iterable[dict], threshold: str) -> bool:
    threshold_value = SEVERITY_LEVELS.index(threshold.upper())
    for finding in findings:
        severity = str(finding.get("severity", "INFO")).upper()
        if SEVERITY_LEVELS.index(severity) >= threshold_value:
            return False
    return True


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
