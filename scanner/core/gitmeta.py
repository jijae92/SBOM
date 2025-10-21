"""Collect basic git metadata for reports."""

from __future__ import annotations

import pathlib
import subprocess
from typing import Dict


def collect_git_metadata(repo_root: str | pathlib.Path = ".") -> Dict[str, str]:
    root = pathlib.Path(repo_root)
    def _run_git(args: list[str]) -> str:
        try:
            result = subprocess.run(
                ["git", *args],
                cwd=root,
                check=True,
                capture_output=True,
                text=True,
            )
            return result.stdout.strip()
        except Exception:
            return ""

    return {
        "branch": _run_git(["rev-parse", "--abbrev-ref", "HEAD"]),
        "commit": _run_git(["rev-parse", "HEAD"]),
        "dirty": "true" if _run_git(["status", "--short"]) else "false",
    }
