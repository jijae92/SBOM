# SPDX-License-Identifier: Apache-2.0
"""Allowlist management for the secret scanning engine."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path, PurePosixPath
from typing import Iterable, List, Optional, Pattern


def _parse_date(value: str) -> Optional[date]:
    """Parse a YYYY-MM-DD date string safely."""

    try:
        return datetime.strptime(value, "%Y-%m-%d").date()
    except (TypeError, ValueError):
        return None


@dataclass(slots=True)
class AllowlistEntry:
    """Represents a single allowlist rule set."""

    path_patterns: List[str]
    pattern_regexes: List[Pattern[str]]
    expires: Optional[date]
    reasons: List[str]

    def is_active(self, today: Optional[date] = None) -> bool:
        """Determine whether the entry is currently active."""

        current = today or date.today()
        return self.expires is None or self.expires >= current


class Allowlist:
    """Composite allowlist supporting file, pattern, and inline exclusions."""

    INLINE_COMMENT = re.compile(
        r"#\s*secrets-allow:\s*(?P<reason>[^;]+);\s*until=(?P<until>\d{4}-\d{2}-\d{2})",
        re.IGNORECASE,
    )

    def __init__(self, entries: Iterable[AllowlistEntry]):
        self._entries = list(entries)

    @classmethod
    def load(cls, root: Path) -> "Allowlist":
        """Load allowlist configuration from ``.secrets-allow.json`` if present."""

        config_path = root / ".secrets-allow.json"
        if not config_path.is_file():
            return cls(entries=[])

        try:
            raw = json.loads(config_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return cls(entries=[])

        if isinstance(raw, dict):
            raw_entries = [raw]
        elif isinstance(raw, list):
            raw_entries = [entry for entry in raw if isinstance(entry, dict)]
        else:
            raw_entries = []

        entries: List[AllowlistEntry] = []
        for entry in raw_entries:
            path_patterns = [str(p) for p in entry.get("paths", []) if isinstance(p, str)]
            path_patterns = [cls._normalize_path_pattern(p) for p in path_patterns]
            pattern_values = [str(p) for p in entry.get("patterns", []) if isinstance(p, str)]
            compiled_patterns: List[re.Pattern[str]] = []
            for pattern in pattern_values:
                try:
                    compiled_patterns.append(re.compile(pattern))
                except re.error:
                    continue
            expires = _parse_date(entry.get("expires"))
            reasons = [str(r) for r in entry.get("reasons", []) if isinstance(r, str)]
            entries.append(
                AllowlistEntry(
                    path_patterns=path_patterns or ["**"],
                    pattern_regexes=compiled_patterns,
                    expires=expires,
                    reasons=reasons,
                )
            )
        return cls(entries=entries)

    @staticmethod
    def _normalize_path_pattern(pattern: str) -> str:
        pattern = pattern.strip()
        if pattern.startswith("./"):
            pattern = pattern[2:]
        if pattern.startswith("/"):
            pattern = pattern[1:]
        if pattern.endswith("/"):
            pattern = pattern + "**"
        return pattern or "**"

    def is_path_allowed(self, relative_path: str) -> bool:
        """Return ``True`` when the entire file path is allowlisted."""

        normalized = self._normalize_path(relative_path)
        subject = PurePosixPath(normalized)
        for entry in self._entries:
            if not entry.is_active():
                continue
            for pattern in entry.path_patterns:
                if subject.match(pattern):
                    return True
        return False

    def is_pattern_allowed(self, token: str) -> bool:
        """Return ``True`` when a token matches an allowlisted pattern."""

        for entry in self._entries:
            if not entry.is_active():
                continue
            for pattern in entry.pattern_regexes:
                if pattern.search(token):
                    return True
        return False

    def line_has_inline_allow(self, line: str) -> bool:
        """Check whether a source line contains a valid inline allow marker."""

        match = self.INLINE_COMMENT.search(line)
        if not match:
            return False
        expires = _parse_date(match.group("until"))
        if expires is None:
            return False
        return expires >= date.today()

    def should_allow(self, relative_path: str, line_text: str, token: str) -> bool:
        """Determine if a finding should be filtered by the allowlist."""

        if line_text and self.line_has_inline_allow(line_text):
            return True
        if self.is_path_allowed(relative_path):
            return True
        if token and self.is_pattern_allowed(token):
            return True
        return False

    @staticmethod
    def _normalize_path(path: str) -> str:
        return str(PurePosixPath(path))


DEFAULT_ALLOWLIST = Allowlist(entries=[])
