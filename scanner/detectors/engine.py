# SPDX-License-Identifier: Apache-2.0
"""Secret scanning engine integrating regex, entropy, and allowlist handling."""

from __future__ import annotations

import collections
import math
import os
import re
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Dict, Iterable, Iterator, List, Optional, Sequence, Set, Tuple

from .allowlist import Allowlist
from . import git_io
from .result_schema import Finding, Location, Range, Severity


MAX_FILE_BYTES = 2 * 1024 * 1024
"""Maximum file size scanned to prevent excessive memory usage (2 MiB)."""

ENTROPY_MIN_LENGTH = 16
ENTROPY_MIN_THRESHOLD = 3.0
LINE_PREVIEW_LIMIT = 160
AWS_PAIR_LINE_DISTANCE = 5

ENTROPY_TOKEN = re.compile(r"(?<![A-Za-z0-9+/=_-])([A-Za-z0-9+/=_-]{16,512})(?![A-Za-z0-9+/=_-])")
SENSITIVE_KEYWORD = re.compile(
    r"(?i)(secret|password|token|apikey|api_key|bearer|aws_secret_access_key|private)"
)
JWT_PATTERN = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")

SEVERITY_RANK = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}


@dataclass(slots=True)
class SecretPattern:
    """Static regular-expression based rule."""

    name: str
    regex: re.Pattern[str]
    severity: Severity
    message: str
    rule_id: str
    tags: Tuple[str, ...] = ()
    group: int = 0


@dataclass(slots=True)
class LineContext:
    """Container holding a single line's text and number."""

    number: int
    text: str


@dataclass(slots=True)
class RawFinding:
    """Intermediate representation for findings prior to schema conversion."""

    path: str
    line: int
    start: int
    end: int
    line_text: str
    severity: Severity
    message: str
    rule_id: str
    detectors: Set[str] = field(default_factory=set)
    tags: Set[str] = field(default_factory=set)
    entropy: Optional[float] = None

    def merge(self, other: "RawFinding") -> None:
        """Merge an overlapping finding into this one."""

        if other.line != self.line or other.path != self.path:
            raise ValueError("Cannot merge findings from different locations")
        self.start = min(self.start, other.start)
        self.end = max(self.end, other.end)
        if SEVERITY_RANK.get(other.severity, 0) > SEVERITY_RANK.get(self.severity, 0):
            self.severity = other.severity
            self.message = other.message
            self.rule_id = other.rule_id
        self.detectors.update(other.detectors)
        self.tags.update(other.tags)
        if other.entropy is not None:
            if self.entropy is None or other.entropy > self.entropy:
                self.entropy = other.entropy

    @property
    def secret(self) -> str:
        """Return the captured secret substring."""

        start = max(self.start, 0)
        end = max(start, self.end)
        return self.line_text[start:end]

    def to_finding(self) -> Finding:
        """Convert the raw finding to the standardized schema."""

        location = Location(
            path=self.path,
            range=Range(
                start_line=self.line,
                start_column=self.start + 1,
                end_line=self.line,
                end_column=self.end + 1,
            ),
        )
        metadata: Dict[str, object] = {
            "detectors": sorted(self.detectors),
            "tags": sorted(self.tags),
            "evidence": {"redacted": redact_secret(self.secret)},
            "linePreview": truncate_line(self.line_text),
        }
        if self.entropy is not None:
            metadata["entropy"] = round(self.entropy, 3)
        return Finding(
            rule_id=self.rule_id,
            message=self.message,
            severity=self.severity,
            location=location,
            metadata=metadata,
        )


@dataclass(slots=True)
class GitignorePattern:
    """Represents a single gitignore rule."""

    pattern: str
    negated: bool
    dir_only: bool


class GitignoreMatcher:
    """Minimal gitignore matcher suitable for secret scanning."""

    def __init__(self, root: Path):
        self.root = root
        self._patterns: List[GitignorePattern] = []
        self._load_patterns()

    def _load_patterns(self) -> None:
        path = self.root / ".gitignore"
        if not path.is_file():
            return
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except OSError:
            return
        for raw_line in lines:
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            negated = line.startswith("!")
            if negated:
                line = line[1:]
            dir_only = line.endswith("/")
            normalized = self._normalize_pattern(line)
            self._patterns.append(
                GitignorePattern(pattern=normalized, negated=negated, dir_only=dir_only)
            )

    @staticmethod
    def _normalize_pattern(pattern: str) -> str:
        pattern = pattern.strip()
        if pattern.startswith("./"):
            pattern = pattern[2:]
        if pattern.startswith("/"):
            pattern = pattern[1:]
        if pattern.endswith("/"):
            pattern = pattern + "**"
        return pattern or "**"

    def is_ignored(self, path: Path, is_dir: bool = False) -> bool:
        """Return ``True`` when the path is ignored by gitignore rules."""

        try:
            relative = path.relative_to(self.root)
        except ValueError:
            return False
        subject = PurePosixPath(relative.as_posix())
        matched = False
        for rule in self._patterns:
            pattern = rule.pattern
            if rule.dir_only and not pattern.endswith("/**"):
                pattern = pattern.rstrip("/") + "/**"
            if subject.match(pattern):
                matched = not rule.negated
        return matched


SECRET_PATTERNS: Tuple[SecretPattern, ...] = (
    SecretPattern(
        name="private_key",
        regex=re.compile(r"-----BEGIN (?:RSA|DSA|EC|OPENSSH|PGP) PRIVATE KEY-----"),
        severity=Severity.CRITICAL,
        message="Private key material detected",
        rule_id="secret.private_key",
        tags=("private-key",),
    ),
    SecretPattern(
        name="aws_access_key",
        regex=re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
        severity=Severity.HIGH,
        message="AWS access key ID detected",
        rule_id="secret.aws.access_key",
        tags=("aws_access_key",),
    ),
    SecretPattern(
        name="aws_secret_key",
        regex=re.compile(
            r"(?i)aws(?:_|-|\s)*secret(?:_|-|\s)*access(?:_|-|\s)*key\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})"
        ),
        severity=Severity.HIGH,
        message="AWS secret access key detected",
        rule_id="secret.aws.secret_key",
        tags=("aws_secret_key",),
        group=1,
    ),
    SecretPattern(
        name="github_token",
        regex=re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36}\b"),
        severity=Severity.HIGH,
        message="GitHub personal access token detected",
        rule_id="secret.github.token",
        tags=("github_token",),
    ),
    SecretPattern(
        name="github_fine_grained",
        regex=re.compile(r"\bgithub_pat_[A-Za-z0-9_]{82}\b"),
        severity=Severity.HIGH,
        message="GitHub fine-grained personal access token detected",
        rule_id="secret.github.fine_grained",
        tags=("github_token",),
    ),
    SecretPattern(
        name="slack_token",
        regex=re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,48}\b"),
        severity=Severity.HIGH,
        message="Slack token detected",
        rule_id="secret.slack.token",
        tags=("slack_token",),
    ),
    SecretPattern(
        name="jwt",
        regex=JWT_PATTERN,
        severity=Severity.HIGH,
        message="JSON Web Token detected",
        rule_id="secret.jwt",
        tags=("jwt",),
    ),
    SecretPattern(
        name="generic_api_key",
        regex=re.compile(
            r"(?i)(?:api|secret|token)[_-]?(?:key|token)?\s*[:=]\s*['\"]?([A-Za-z0-9_-]{16,})"
        ),
        severity=Severity.MEDIUM,
        message="Potential API secret detected",
        rule_id="secret.generic.api_key",
        tags=("hinted_token",),
        group=1,
    ),
)


def scan_paths(paths: List[str], respect_gitignore: bool = True) -> List[Dict[str, object]]:
    """Scan the provided paths and return findings."""

    repo_root = git_io.get_repo_root()
    allowlist = Allowlist.load(repo_root)
    gitignore = GitignoreMatcher(repo_root) if respect_gitignore else None

    findings: List[Finding] = []
    visited: Set[Path] = set()

    for raw_path in paths:
        target = Path(raw_path)
        if not target.is_absolute():
            target = (repo_root / target).resolve()
        else:
            target = target.resolve()
        if target in visited:
            continue
        visited.add(target)
        if target.is_dir():
            for file_path in iterate_files(target, repo_root, gitignore):
                rel_path = relative_path(file_path, repo_root)
                if allowlist.is_path_allowed(rel_path):
                    continue
                file_findings = scan_file(file_path, rel_path, allowlist)
                findings.extend(file_findings)
        elif target.is_file():
            rel_path = relative_path(target, repo_root)
            if allowlist.is_path_allowed(rel_path):
                continue
            findings.extend(scan_file(target, rel_path, allowlist))

    return [finding.to_dict() for finding in findings]


def scan_git_diff(
    rev_range: Optional[str] = None, staged_only: bool = False
) -> List[Dict[str, object]]:
    """Scan secrets within the git diff for the given revision range."""

    repo_root = git_io.get_repo_root()
    allowlist = Allowlist.load(repo_root)
    patches = git_io.get_added_patches(rev_range=rev_range, staged_only=staged_only, context_lines=3)

    findings: List[Finding] = []
    for patch in patches:
        rel_path = relative_path(patch.path.resolve(), repo_root)
        if allowlist.is_path_allowed(rel_path):
            continue
        lines = [LineContext(number=line.line_number, text=line.content) for line in patch.added_lines]
        findings.extend(scan_lines(rel_path, lines, allowlist))

    return [finding.to_dict() for finding in findings]


def iterate_files(target: Path, repo_root: Path, gitignore: Optional[GitignoreMatcher]) -> Iterator[Path]:
    """Yield files under ``target`` honoring gitignore when requested."""

    for dirpath, dirnames, filenames in os.walk(target, followlinks=False):
        current_dir = Path(dirpath)
        if gitignore and gitignore.is_ignored(current_dir, is_dir=True):
            dirnames[:] = []
            continue
        skip_dirs = {".git", ".hg", ".svn", "__pycache__"}
        dirnames[:] = [
            name
            for name in dirnames
            if name not in skip_dirs
            and not (gitignore and gitignore.is_ignored(current_dir / name, is_dir=True))
        ]
        for filename in filenames:
            file_path = current_dir / filename
            if gitignore and gitignore.is_ignored(file_path, is_dir=False):
                continue
            yield file_path


def scan_file(path: Path, rel_path: str, allowlist: Allowlist) -> List[Finding]:
    """Scan a single file path."""

    text = read_text_file(path)
    if text is None:
        return []
    lines = [LineContext(number=i + 1, text=line) for i, line in enumerate(text.splitlines())]
    return scan_lines(rel_path, lines, allowlist)


def scan_lines(path: str, lines: Sequence[LineContext], allowlist: Allowlist) -> List[Finding]:
    """Scan a set of line contexts for secrets."""

    if not lines:
        return []
    raw_matches: List[RawFinding] = []
    for line in lines:
        if allowlist.line_has_inline_allow(line.text):
            continue
        raw_matches.extend(detect_line(path, line))

    if not raw_matches:
        return []

    apply_aws_pairing(raw_matches)
    merged = coalesce_matches(raw_matches)
    filtered = [
        match
        for match in merged
        if not allowlist.should_allow(path, match.line_text, match.secret)
    ]

    return [match.to_finding() for match in filtered]


def detect_line(path: str, line: LineContext) -> List[RawFinding]:
    """Detect secret candidates within a single line."""

    findings: List[RawFinding] = []
    text = line.text.rstrip("\n\r")

    for pattern in SECRET_PATTERNS:
        for match in pattern.regex.finditer(text):
            try:
                token = match.group(pattern.group)
            except IndexError:
                continue
            if not token:
                continue
            start = match.start(pattern.group)
            end = match.end(pattern.group)
            severity = pattern.severity
            message = pattern.message
            rule_id = pattern.rule_id
            entropy: Optional[float] = None
            tags = set(pattern.tags)
            if "jwt" in tags:
                entropy = shannon_entropy(token)
                if entropy >= 3.5:
                    severity = Severity.CRITICAL
                    message = "High entropy JWT detected"
                    rule_id = "secret.jwt.high_entropy"
            finding = RawFinding(
                path=path,
                line=line.number,
                start=start,
                end=end,
                line_text=text,
                severity=severity,
                message=message,
                rule_id=rule_id,
                detectors={f"regex:{pattern.name}"},
                tags=tags,
                entropy=entropy,
            )
            findings.append(finding)

    for token, start, end, entropy in iter_entropy_candidates(text):
        severity, rule_id, message, tags = classify_entropy_match(token, entropy, text)
        detection_tags = set(tags)
        if "aws_secret_context" in detection_tags:
            detection_tags.remove("aws_secret_context")
            if len(token) >= 40:
                detection_tags.add("aws_secret_key")
            else:
                detection_tags.add("hinted_token")
        finding = RawFinding(
            path=path,
            line=line.number,
            start=start,
            end=end,
            line_text=text,
            severity=severity,
            message=message,
            rule_id=rule_id,
            detectors={"entropy"},
            tags=detection_tags,
            entropy=entropy,
        )
        findings.append(finding)

    return findings


def iter_entropy_candidates(line: str) -> Iterator[Tuple[str, int, int, float]]:
    """Yield entropy candidates present in a line."""

    for match in ENTROPY_TOKEN.finditer(line):
        token = match.group(1)
        if len(token) < ENTROPY_MIN_LENGTH:
            continue
        entropy = shannon_entropy(token)
        if entropy < ENTROPY_MIN_THRESHOLD and not SENSITIVE_KEYWORD.search(line):
            continue
        yield token, match.start(1), match.end(1), entropy


def classify_entropy_match(
    token: str, entropy: float, line: str
) -> Tuple[Severity, str, str, Set[str]]:
    """Classify an entropy candidate into severity, rule, and message."""

    tags: Set[str] = {"entropy"}
    if JWT_PATTERN.fullmatch(token):
        tags.add("jwt")
        if entropy >= 3.5:
            return Severity.CRITICAL, "secret.jwt.high_entropy", "High entropy JWT detected", tags
        return Severity.HIGH, "secret.jwt", "JSON Web Token detected", tags

    length = len(token)
    lowered = line.lower()
    if "aws_secret_access_key" in lowered or "aws-secret-access-key" in lowered:
        tags.add("aws_secret_context")
    if length >= 45 and entropy >= 4.0:
        severity = Severity.HIGH
        rule_id = "secret.entropy.high"
        message = "High entropy credential detected"
    elif length >= 32 and entropy >= 3.5:
        severity = Severity.MEDIUM
        rule_id = "secret.entropy.medium"
        message = "Suspicious medium entropy token detected"
    else:
        severity = Severity.LOW
        rule_id = "secret.entropy.low"
        message = "Potential credential candidate"

    if SENSITIVE_KEYWORD.search(line) and SEVERITY_RANK[severity] < SEVERITY_RANK[Severity.MEDIUM]:
        severity = Severity.MEDIUM
        rule_id = "secret.entropy.keyword_hint"
        message = "Token adjacent to sensitive keyword"
        tags.add("hinted_token")

    if "aws_secret_context" in tags:
        if length >= 40 and SEVERITY_RANK[severity] < SEVERITY_RANK[Severity.HIGH]:
            severity = Severity.HIGH
        if length >= 40:
            rule_id = "secret.aws.secret_key"
            message = "AWS secret access key candidate detected"

    return severity, rule_id, message, tags


def apply_aws_pairing(matches: List[RawFinding]) -> None:
    """Elevate severity when AWS access/secret key pairs are co-located."""

    access = [m for m in matches if "aws_access_key" in m.tags]
    secrets = [m for m in matches if "aws_secret_key" in m.tags]
    for access_match in access:
        for secret_match in secrets:
            if access_match.path != secret_match.path:
                continue
            if abs(access_match.line - secret_match.line) > AWS_PAIR_LINE_DISTANCE:
                continue
            if SEVERITY_RANK[access_match.severity] < SEVERITY_RANK[Severity.CRITICAL]:
                access_match.severity = Severity.CRITICAL
                access_match.message = "AWS access/secret key pair detected"
                access_match.rule_id = "secret.aws.key_pair"
                access_match.tags.add("aws_key_pair")
            if SEVERITY_RANK[secret_match.severity] < SEVERITY_RANK[Severity.CRITICAL]:
                secret_match.severity = Severity.CRITICAL
                secret_match.message = "AWS access/secret key pair detected"
                secret_match.rule_id = "secret.aws.key_pair"
                secret_match.tags.add("aws_key_pair")


def coalesce_matches(matches: List[RawFinding]) -> List[RawFinding]:
    """Merge overlapping findings per line to avoid duplicates."""

    if not matches:
        return []
    matches.sort(key=lambda m: (m.path, m.line, m.start))
    merged: List[RawFinding] = []
    current = matches[0]
    for match in matches[1:]:
        if match.path == current.path and match.line == current.line and match.start <= current.end:
            current.merge(match)
        else:
            merged.append(current)
            current = match
    merged.append(current)
    return merged


def redact_secret(secret: str, prefix: int = 4, suffix: int = 4) -> str:
    """Redact a secret to avoid exposing full values."""

    if not secret:
        return ""
    if len(secret) <= prefix + suffix:
        return "*" * len(secret)
    return f"{secret[:prefix]}{'*' * (len(secret) - prefix - suffix)}{secret[-suffix:]}"


def truncate_line(line: str, limit: int = LINE_PREVIEW_LIMIT) -> str:
    """Return a truncated preview of a line."""

    if len(line) <= limit:
        return line
    return f"{line[: limit - 3]}..."


def shannon_entropy(token: str) -> float:
    """Compute the Shannon entropy of a token."""

    if not token:
        return 0.0
    counts = collections.Counter(token)
    length = len(token)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def read_text_file(path: Path) -> Optional[str]:
    """Read a text file safely, skipping binaries and large files."""

    try:
        data = path.read_bytes()
    except OSError:
        return None
    if len(data) > MAX_FILE_BYTES:
        return None
    if is_probably_binary(data):
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("utf-8", errors="ignore")


def is_probably_binary(data: bytes) -> bool:
    """Heuristic check for binary content."""

    if b"\x00" in data:
        return True
    sample = data[:1024]
    if not sample:
        return False
    non_text = sum(1 for byte in sample if byte < 9 or (13 < byte < 32))
    return (non_text / len(sample)) > 0.3


def relative_path(path: Path, root: Path) -> str:
    """Return a POSIX-style path relative to ``root`` when possible."""

    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()
