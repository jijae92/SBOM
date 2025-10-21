"""Ignore rule handling for vulnerability filtering."""

from __future__ import annotations

import datetime as dt
import pathlib
from dataclasses import dataclass
from typing import Iterable, List, Optional, Sequence

import yaml


@dataclass
class IgnoreRule:
    ids: Sequence[str]
    packages: Sequence[str]
    until: Optional[dt.date]
    reason: Optional[str]

    def matches(self, finding: dict, reference_date: dt.date) -> bool:
        if self.until and reference_date > self.until:
            return False
        if self.ids and finding.get("cve") not in self.ids:
            return False
        if self.packages:
            package_keys = {finding.get("purl"), finding.get("name")}
            if not any(pkg in package_keys for pkg in self.packages):
                return False
        return True


def load_rules(path: pathlib.Path) -> Sequence[IgnoreRule]:
    if not path.exists():
        return []
    data = yaml.safe_load(path.read_text()) or {}
    entries = data.get("rules") or []
    rules: List[IgnoreRule] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        until = _parse_date(entry.get("until") or entry.get("expires"))
        ids = _ensure_sequence(entry.get("ids") or entry.get("cves") or entry.get("id"), cast_to_list=True)
        packages = _ensure_sequence(entry.get("packages") or entry.get("package"), cast_to_list=True)
        rules.append(IgnoreRule(ids=ids, packages=packages, until=until, reason=entry.get("reason")))
    return rules


def filter_findings(
    findings: Iterable[dict],
    rules: Sequence[IgnoreRule],
    reference_date: Optional[dt.date] = None,
) -> List[dict]:
    today = reference_date or dt.date.today()
    if not rules:
        return list(findings)
    filtered: List[dict] = []
    for finding in findings:
        if any(rule.matches(finding, today) for rule in rules):
            continue
        filtered.append(finding)
    return filtered


def _parse_date(value: object) -> Optional[dt.date]:
    if isinstance(value, dt.date):
        return value
    if isinstance(value, str) and value:
        try:
            return dt.date.fromisoformat(value)
        except ValueError:
            return None
    return None


def _ensure_sequence(value: object, cast_to_list: bool = False) -> List[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return [str(item) for item in value]
    if cast_to_list:
        return [str(value)]
    return [str(value)]
