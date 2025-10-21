import json
from pathlib import Path

import pytest

from scanner import __main__ as entrypoint
from scanner.core import s3util, sbom_loader
from scanner.detectors import git_io
from scanner.runners import grype as grype_parser
from scanner.runners import trivy as trivy_parser


def test_entrypoint_delegates_to_cli(monkeypatch: pytest.MonkeyPatch):
    captured: dict[str, object] = {}

    def fake_main(argv):  # pragma: no cover - exercised in test
        captured["argv"] = argv
        return 42

    monkeypatch.setattr(entrypoint.cli, "main", fake_main)
    result = entrypoint.main(["--version"])
    assert result == 42
    assert captured["argv"] == ["--version"]


class DummyS3Client:
    def __init__(self) -> None:
        self.put_calls: list[tuple[str, str, bytes]] = []
        self.download_calls: list[tuple[str, str, str]] = []

    def put_object(self, Bucket: str, Key: str, Body: bytes) -> None:  # noqa: N803 (boto style)
        self.put_calls.append((Bucket, Key, Body))

    def download_file(self, Bucket: str, Key: str, Filename: str) -> None:  # noqa: N803
        self.download_calls.append((Bucket, Key, Filename))
        Path(Filename).write_text("data", encoding="utf-8")


def test_s3util_upload_and_download(tmp_path: Path):
    client = DummyS3Client()
    payload = {"hello": "world"}
    s3util.upload_json("bucket", "key.json", payload, client=client)
    assert client.put_calls
    bucket, key, body = client.put_calls[0]
    assert bucket == "bucket"
    assert key == "key.json"
    assert json.loads(body.decode("utf-8")) == payload

    destination = tmp_path / "file.txt"
    s3util.download_file("bucket", "key.json", destination, client=client)
    assert destination.read_text(encoding="utf-8") == "data"


def test_sbom_loader_supports_multiple_formats(tmp_path: Path):
    cyclonedx = {
        "bomFormat": "CycloneDX",
        "components": [
            {
                "name": "pkg",
                "version": "1.2.3",
                "purl": "pkg:pypi/pkg@1.2.3",
                "properties": [
                    {"name": "syft:package:type", "value": "python"},
                    {"name": "layer", "value": "app"},
                ],
            }
        ],
    }
    spdx = {
        "spdxVersion": "SPDX-2.3",
        "packages": [
            {
                "name": "libpkg",
                "versionInfo": "4.5.6",
                "externalRefs": [
                    {"referenceType": "purl", "referenceLocator": "pkg:deb/debian/libpkg@4.5.6"},
                    {"referenceType": "package-path", "referenceLocator": "/usr/lib/libpkg"},
                ],
            }
        ],
    }

    cyclonedx_path = tmp_path / "sbom.cdx.json"
    cyclonedx_path.write_text(json.dumps(cyclonedx), encoding="utf-8")
    spdx_path = tmp_path / "sbom.spdx.json"
    spdx_path.write_text(json.dumps(spdx), encoding="utf-8")

    components = sbom_loader.load_directory(tmp_path)
    assert len(components) == 2
    assert components.lookup("pkg:pypi/pkg@1.2.3", "pkg", "1.2.3") is not None
    assert components.lookup("pkg:deb/debian/libpkg@4.5.6", "libpkg", "4.5.6") is not None


def test_git_io_helpers(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    class DummyCompleted:
        def __init__(self, stdout: str):
            self.stdout = stdout

    monkeypatch.setattr(git_io.subprocess, "run", lambda *a, **k: DummyCompleted(str(tmp_path)))
    assert git_io.get_repo_root() == tmp_path

    monkeypatch.setattr(
        git_io.subprocess,
        "run",
        lambda cmd, check, capture_output, text: DummyCompleted("diff output"),
    )
    assert git_io.get_unified_diff(rev_range="HEAD~1..HEAD", staged_only=True) == "diff output"


def test_grype_helpers_cover_branches():
    assert grype_parser._primary_cve({"relatedVulnerabilities": [{"id": "CVE-ALT"}]}) == "CVE-ALT"
    assert grype_parser._select_cvss_score([{"score": "8.2"}]) == 8.2
    assert grype_parser._normalise_fix_state({"versions": ["1.0.1"]}) == "fixed"
    assert grype_parser._extract_references({"urls": ["https://a"], "references": [{"url": "https://b"}]}) == [
        "https://a",
        "https://b",
    ]
    assert grype_parser._first_location([{"path": "app/file"}]) == "app/file"


def test_trivy_helper_branches():
    vuln = {
        "CVSS": {"github": {"Score": 6.1}},
        "CVSS3Score": None,
    }
    assert trivy_parser._pick_cvss(vuln) == 6.1
