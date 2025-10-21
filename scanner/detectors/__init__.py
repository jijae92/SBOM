# SPDX-License-Identifier: Apache-2.0
"""Secret scanning detectors package."""

from .engine import scan_git_diff, scan_paths

__all__ = ["scan_paths", "scan_git_diff"]

