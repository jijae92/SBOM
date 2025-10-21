import json
from pathlib import Path

import pytest

from scanner.detectors import engine
from scanner.detectors.allowlist import Allowlist
from scanner.detectors.git_io import DiffLine, GitPatch, parse_unified_diff
from scanner.detectors.result_schema import Finding, Location, Range, Severity


def test_allowlist_loads_and_filters(tmp_path: Path):
    allow_config = {
        "paths": ["ignored.txt"],
        "patterns": ["demo-secret"],
        "expires": "2099-12-31",
        "reasons": ["test"],
    }
    (tmp_path / ".secrets-allow.json").write_text(json.dumps(allow_config), encoding="utf-8")
    allowlist = Allowlist.load(tmp_path)

    assert allowlist.is_path_allowed("ignored.txt") is True
    assert allowlist.is_pattern_allowed("demo-secret-value") is True
    assert allowlist.line_has_inline_allow("token = 'foo'  # secrets-allow: demo; until=2099-01-01") is True
    assert allowlist.should_allow("ignored.txt", "token", "demo-secret-value") is True


def test_scan_paths_detects_aws_pair(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    target = tmp_path / "creds.env"
    target.write_text(
        "\n".join(
            [
                "aws_access_key_id = 'AKIA1234567890ABCD12'",
                "aws_secret_access_key = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'",
            ]
        ),
        encoding="utf-8",
    )

    monkeypatch.setattr(engine.git_io, "get_repo_root", lambda: tmp_path)

    findings = engine.scan_paths([str(target)])
    assert findings
    critical = [f for f in findings if f["severity"] == "CRITICAL"]
    assert critical, "AWS key pair should be escalated to CRITICAL"


def test_scan_paths_respects_gitignore_and_allowlist(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    (tmp_path / ".gitignore").write_text("ignored.txt\n", encoding="utf-8")
    ignored = tmp_path / "ignored.txt"
    ignored.write_text("token=ghp_abcdefghijklmnopqrstuvwxyz1234567890", encoding="utf-8")
    aloud = tmp_path / "tracked.txt"
    aloud.write_text("token=ghp_abcdefghijklmnopqrstuvwxyz1234567890", encoding="utf-8")

    allow_config = {"paths": ["tracked.txt"], "expires": "2099-01-01"}
    (tmp_path / ".secrets-allow.json").write_text(json.dumps(allow_config), encoding="utf-8")

    monkeypatch.setattr(engine.git_io, "get_repo_root", lambda: tmp_path)

    findings = engine.scan_paths([str(tmp_path)])
    assert findings == [], "gitignore and allowlist should filter all findings"


def test_scan_git_diff_uses_patches(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    monkeypatch.setattr(engine.git_io, "get_repo_root", lambda: tmp_path)

    patch = GitPatch(
        path=tmp_path / "app.py",
        added_lines=[
            DiffLine(line_number=10, content="api_key = 'ghp_abcdefghijklmnopqrstuvwxyz123456789012'"),
        ],
    )
    monkeypatch.setattr(engine.git_io, "get_added_patches", lambda **_: [patch])

    findings = engine.scan_git_diff()
    assert findings
    assert findings[0]["ruleId"] in {"secret.github.token", "secret.generic.api_key"}


def test_parse_unified_diff_extracts_added_lines():
    diff_text = (
        "diff --git a/app.py b/app.py\n"
        "--- a/app.py\n"
        "+++ b/app.py\n"
        "@@ -0,0 +1,2 @@\n"
        "+token = 'abc'\n"
        "+print(token)\n"
    )
    patches = parse_unified_diff(diff_text)
    assert len(patches) == 1
    patch = patches[0]
    assert patch.path.name == "app.py"
    assert [line.content for line in patch.added_lines] == ["token = 'abc'", "print(token)"]


def test_result_schema_serialisation():
    finding = Finding(
        rule_id="demo.rule",
        message="Example",
        severity=Severity.HIGH,
        location=Location(path="app.py", range=Range(1, 1, 1, 5)),
        metadata={"detectors": ["regex"]},
        recommendation="Rotate credentials",
    )
    payload = finding.to_dict()
    assert payload["ruleId"] == "demo.rule"
    assert payload["severity"] == "HIGH"
    assert payload["recommendation"] == "Rotate credentials"
