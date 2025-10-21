# SPDX-License-Identifier: Apache-2.0
"""Result schema utilities for secret scanning findings."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Optional


class Severity(str, Enum):
    """Enumeration of supported finding severities."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass(slots=True)
class Range:
    """Represents a range in a text document."""

    start_line: int
    start_column: int
    end_line: int
    end_column: int

    def to_dict(self) -> Dict[str, int]:
        """Serialize the range for JSON output."""

        return {
            "startLine": self.start_line,
            "startColumn": self.start_column,
            "endLine": self.end_line,
            "endColumn": self.end_column,
        }


@dataclass(slots=True)
class Location:
    """Location of a finding within a file."""

    path: str
    range: Range

    def to_dict(self) -> Dict[str, Any]:
        """Serialize the location for JSON output."""

        return {"path": self.path, "range": self.range.to_dict()}


@dataclass(slots=True)
class Finding:
    """Standardized representation of a secret scanning finding."""

    rule_id: str
    message: str
    severity: Severity
    location: Location
    category: str = "secret"
    detector: str = "secret-scanner"
    metadata: Dict[str, Any] = field(default_factory=dict)
    recommendation: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Serialize the finding to a dictionary."""

        payload: Dict[str, Any] = {
            "ruleId": self.rule_id,
            "message": self.message,
            "severity": self.severity.value,
            "category": self.category,
            "detector": self.detector,
            "location": self.location.to_dict(),
            "metadata": self.metadata,
        }
        if self.recommendation:
            payload["recommendation"] = self.recommendation
        return payload

