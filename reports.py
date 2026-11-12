"""Common report structures, finding IDs, and formatting helpers for henry-mcp.

All reports separate observed data from inferred conclusions. Finding IDs are
stable within a single analysis session so henry_explain_finding can reference
them.
"""

from __future__ import annotations

import uuid
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field, asdict


@dataclass
class Finding:
    """A single observed or inferred fact from static analysis."""

    id: str
    type: str  # "observation" | "inference" | "warning" | "error"
    file: str
    field: str
    observed_value: Any
    inferred_value: Optional[str] = None
    confidence: str = "low"  # low | medium | high
    evidence: List[str] = field(default_factory=list)
    notes: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Report:
    """Top-level analysis report."""

    summary: str
    format: str
    file: str
    findings: List[Finding] = field(default_factory=list)
    pagination: Dict[str, int] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "summary": self.summary,
            "format": self.format,
            "file": self.file,
            "findings": [f.to_dict() for f in self.findings],
            "pagination": self.pagination,
            "warnings": self.warnings,
            "limitations": self.limitations,
        }


class ReportStore:
    """In-memory store of reports keyed by session, for henry_explain_finding."""

    def __init__(self) -> None:
        self._reports: Dict[str, Report] = {}
        self._findings: Dict[str, Finding] = {}

    def add_report(self, session_id: str, report: Report) -> None:
        self._reports[session_id] = report
        for f in report.findings:
            self._findings[f.id] = f

    def get_finding(self, finding_id: str) -> Optional[Finding]:
        return self._findings.get(finding_id)

    def list_sessions(self) -> List[str]:
        return list(self._reports.keys())


def paginate(items: List[Any], limit: int, offset: int) -> Dict[str, Any]:
    """Return paginated slice plus metadata."""
    limit = max(1, min(limit, 1000))
    offset = max(0, offset)
    total = len(items)
    page = items[offset : offset + limit]
    return {
        "items": page,
        "total": total,
        "offset": offset,
        "limit": limit,
        "returned": len(page),
        "has_more": offset + limit < total,
    }


def new_finding_id() -> str:
    return uuid.uuid4().hex[:12]
