# SPDX-License-Identifier: Apache-2.0
"""Utilities for interacting with Git diffs."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional
import re


@dataclass(slots=True)
class DiffLine:
    """Represents a single added line in a diff hunk."""

    line_number: int
    content: str


@dataclass(slots=True)
class GitPatch:
    """Represents the added lines for a file within a diff."""

    path: Path
    added_lines: List[DiffLine]


HUNK_HEADER = re.compile(
    r"@@ -(?P<old_start>\d+)(?:,\d+)? \+(?P<new_start>\d+)(?:,\d+)? @@"
)


def get_repo_root() -> Path:
    """Return the git repository root, falling back to ``Path.cwd()``."""

    try:
        completed = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            check=True,
            capture_output=True,
            text=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        return Path.cwd()
    return Path(completed.stdout.strip() or ".").resolve()


def get_unified_diff(
    rev_range: Optional[str] = None,
    staged_only: bool = False,
    context_lines: int = 3,
) -> str:
    """Return the unified diff text for the requested revision range."""

    cmd = ["git", "diff", f"--unified={context_lines}", "--no-color"]
    if staged_only:
        cmd.append("--cached")
    if rev_range:
        cmd.append(rev_range)
    try:
        completed = subprocess.run(
            cmd,
            check=True,
            capture_output=True,
            text=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        return ""
    return completed.stdout


def parse_unified_diff(diff_text: str) -> List[GitPatch]:
    """Parse unified diff text into structured patches."""

    patches: List[GitPatch] = []
    current_patch: Optional[GitPatch] = None
    new_line_number: Optional[int] = None

    for raw_line in diff_text.splitlines():
        if raw_line.startswith("diff --git "):
            if current_patch and current_patch.added_lines:
                patches.append(current_patch)
            current_patch = None
            new_line_number = None
            continue

        if raw_line.startswith("+++ "):
            target = raw_line[4:].strip()
            if target == "/dev/null":
                current_patch = None
                continue
            if target.startswith("b/"):
                target = target[2:]
            current_patch = GitPatch(path=Path(target), added_lines=[])
            new_line_number = None
            continue

        if current_patch is None:
            continue

        if raw_line.startswith("Binary files "):
            current_patch = None
            new_line_number = None
            continue

        if raw_line.startswith("@@"):
            match = HUNK_HEADER.match(raw_line)
            if not match:
                new_line_number = None
                continue
            new_line_number = int(match.group("new_start"))
            continue

        if new_line_number is None:
            continue

        if raw_line.startswith("+"):
            content = raw_line[1:]
            current_patch.added_lines.append(
                DiffLine(line_number=new_line_number, content=content)
            )
            new_line_number += 1
            continue

        if raw_line.startswith("-"):
            # Removed lines do not advance the new line number.
            continue

        # Context line.
        new_line_number += 1

    if current_patch and current_patch.added_lines:
        patches.append(current_patch)

    return patches


def get_added_patches(
    rev_range: Optional[str] = None, staged_only: bool = False, context_lines: int = 3
) -> List[GitPatch]:
    """Convenience wrapper returning parsed patches for a diff command."""

    diff_text = get_unified_diff(rev_range=rev_range, staged_only=staged_only, context_lines=context_lines)
    return parse_unified_diff(diff_text)

