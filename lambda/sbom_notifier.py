"""Lambda handler that summarizes SBOM uploads and emits alerts."""

from __future__ import annotations

import json
import logging
import os
import urllib.request
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional

import boto3

_LOG = logging.getLogger(__name__)
_LOG.setLevel(logging.INFO)

_SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
_ENV_ALERT_MIN = os.environ.get("ALERT_MIN_SEVERITY", "HIGH").upper()
_ENV_SLACK = os.environ.get("SLACK_WEBHOOK_URL")
_ENV_SNS = os.environ.get("SNS_TOPIC_ARN")
_REGION = os.environ.get("AWS_REGION", "us-east-1")


@dataclass
class SummaryEnvelope:
    bucket: str
    key: str
    data: Dict[str, Any]

    @property
    def counts(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for level in _SEVERITY_ORDER:
            counts[level.lower()] = int(self.data.get(level.lower(), 0))
        return counts

    @property
    def fail_on(self) -> str:
        return str(self.data.get("fail_on", _ENV_ALERT_MIN)).upper()

    @property
    def repo(self) -> str:
        git_meta = self.data.get("git") or {}
        return str(self.data.get("repo") or git_meta.get("repository") or git_meta.get("remote" ) or "unknown")

    @property
    def commit(self) -> str:
        git_meta = self.data.get("git") or {}
        return str(self.data.get("commit_sha") or git_meta.get("commit") or "unknown")

    @property
    def top_cves(self) -> List[Dict[str, Any]]:
        entries = self.data.get("top_cves") or []
        return _normalise_top_entries(entries)[:3]

    @property
    def top_packages(self) -> List[Dict[str, Any]]:
        entries = self.data.get("top_packages") or []
        return _normalise_top_entries(entries)[:3]

    @property
    def console_url(self) -> str:
        return (
            "https://s3.console.aws.amazon.com/s3/object/"
            f"{self.bucket}?region={_REGION}&prefix={self.key}"
        )

    def triggered(self, threshold: str) -> bool:
        threshold_idx = _SEVERITY_ORDER.index(threshold)
        for level in _SEVERITY_ORDER[: threshold_idx + 1]:
            if self.counts.get(level.lower(), 0) > 0:
                return True
        return False


def handler(event: Dict[str, Any], _context: Any) -> Dict[str, Any]:
    records = event.get("Records", [])
    processed: List[Dict[str, Any]] = []
    for record in records:
        envelope = _extract_envelope(record)
        if not envelope:
            continue

        payload = _build_payload(envelope)
        if not payload:
            continue

        processed.append(payload)
        _publish(payload)
        _notify_slack(payload)

    return {"processed": len(processed)}


def _extract_envelope(record: Dict[str, Any]) -> Optional[SummaryEnvelope]:
    s3_data = record.get("s3") or {}
    bucket = (s3_data.get("bucket") or {}).get("name")
    key = (s3_data.get("object") or {}).get("key")
    if not bucket or not key:
        _LOG.warning("Record missing bucket/key: %s", record)
        return None

    if not _should_process(key):
        _LOG.debug("Skipping non-summary key %s", key)
        return None

    data = _load_json(bucket, key)
    if not data:
        _LOG.warning("No usable data in %s/%s", bucket, key)
        return None

    if key.endswith(".vuln.json"):
        data = _summarise_vuln_report(data)

    return SummaryEnvelope(bucket=bucket, key=key, data=data)


def _should_process(key: str) -> bool:
    if key.endswith("reports/summary.json"):
        return True
    return key.endswith(".vuln.json")


def _load_json(bucket: str, key: str) -> Dict[str, Any]:
    client = boto3.client("s3")
    try:
        response = client.get_object(Bucket=bucket, Key=key)
    except Exception as exc:  # pragma: no cover - network/permission failure
        _LOG.exception("Failed to fetch %s/%s: %s", bucket, key, exc)
        return {}
    try:
        body = response["Body"].read()
        return json.loads(body)
    except Exception as exc:  # pragma: no cover
        _LOG.exception("Failed to parse JSON for %s/%s: %s", bucket, key, exc)
        return {}


def _summarise_vuln_report(report: Dict[str, Any]) -> Dict[str, Any]:
    matches = report.get("matches") or []
    top_cves: Dict[str, Dict[str, Any]] = {}
    top_packages: Dict[str, Dict[str, Any]] = {}
    counts = {level.lower(): 0 for level in _SEVERITY_ORDER}
    for match in matches:
        vuln = match.get("vulnerability", {})
        artifact = match.get("artifact", {})
        severity = str(vuln.get("severity") or "INFO").upper()
        severity = severity if severity in _SEVERITY_ORDER else "INFO"
        counts[severity.lower()] += 1
        cve = vuln.get("id") or "UNKNOWN"
        top_cves.setdefault(cve, {"name": cve, "count": 0})
        top_cves[cve]["count"] += 1
        pkg = artifact.get("purl") or artifact.get("name") or "unknown"
        top_packages.setdefault(pkg, {"name": pkg, "count": 0})
        top_packages[pkg]["count"] += 1
    summary = {
        **counts,
        "total": sum(counts.values()),
        "top_cves": sorted(top_cves.values(), key=lambda x: x["count"], reverse=True),
        "top_packages": sorted(top_packages.values(), key=lambda x: x["count"], reverse=True),
        "fail_on": _ENV_ALERT_MIN,
    }
    return summary


def _build_payload(envelope: SummaryEnvelope) -> Optional[Dict[str, Any]]:
    counts = envelope.counts
    fail_on = envelope.fail_on
    if not counts:
        _LOG.warning("Summary missing counts: %s", envelope)
        return None

    payload = {
        "repo": envelope.repo,
        "commit_sha": envelope.commit,
        "counts": counts,
        "s3_key": envelope.key,
        "console_url": envelope.console_url,
        "top_cves": envelope.top_cves,
        "top_packages": envelope.top_packages,
        "fail_on": fail_on,
        "alert_min_severity": _ENV_ALERT_MIN,
    }

    if not envelope.triggered(_severity_index_key(_ENV_ALERT_MIN)):
        _LOG.info("No severities at or above %s for %s", _ENV_ALERT_MIN, envelope.key)
    return payload


def _severity_index_key(severity: str) -> str:
    if severity not in _SEVERITY_ORDER:
        return _ENV_ALERT_MIN
    return severity


def _publish(payload: Dict[str, Any]) -> None:
    if not _ENV_SNS:
        _LOG.warning("SNS_TOPIC_ARN unset; skipping publish")
        return
    try:
        boto3.client("sns").publish(
            TopicArn=_ENV_SNS,
            Message=json.dumps(payload),
            Subject="SBOM Vulnerability Summary",
        )
    except Exception as exc:  # pragma: no cover - network failure
        _LOG.exception("SNS publish failed: %s", exc)


def _notify_slack(payload: Dict[str, Any]) -> None:
    if not _ENV_SLACK:
        return
    message = {
        "text": _format_slack_text(payload),
    }
    req = urllib.request.Request(
        _ENV_SLACK,
        data=json.dumps(message).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    try:
        urllib.request.urlopen(req, timeout=5)
    except Exception as exc:  # pragma: no cover - network failure
        _LOG.warning("Slack notification failed: %s", exc)


def _format_slack_text(payload: Dict[str, Any]) -> str:
    counts = payload["counts"]
    lines = [
        f"*SBOM Alert* repo={payload['repo']} sha={payload['commit_sha']} fail_on={payload['fail_on']}",
        f"S3: {payload['console_url']}",
        "Counts:",
    ]
    for level in _SEVERITY_ORDER:
        lines.append(f"- {level.title()}: {counts.get(level.lower(), 0)}")
    if payload["top_cves"]:
        lines.append(
            "Top CVEs: "
            + ", ".join(f"{entry['name']} ({entry.get('count', '?')})" for entry in payload["top_cves"])
        )
    if payload["top_packages"]:
        lines.append(
            "Top Packages: "
            + ", ".join(
                f"{entry['name']} ({entry.get('count', '?')})" for entry in payload["top_packages"]
            )
        )
    return "\n".join(lines)


def _normalise_top_entries(entries: Iterable[Any]) -> List[Dict[str, Any]]:
    normalised: List[Dict[str, Any]] = []
    for entry in entries:
        if isinstance(entry, dict):
            name = entry.get("name") or entry.get("cve") or entry.get("package")
            if not name:
                continue
            normalised.append({
                "name": str(name),
                "count": int(entry.get("count", entry.get("occurrences", 0) or 0)),
                "severity": entry.get("severity"),
            })
        elif isinstance(entry, str):
            normalised.append({"name": entry, "count": 0})
    return normalised
