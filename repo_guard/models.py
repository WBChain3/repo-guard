from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class Severity(Enum):
    """
    Severity levels for scan findings and module results.

    Ordered CLEAN < INFO < WARNING < CRITICAL. This ordering is used
    to derive the overall severity of a scan (highest wins).

    Usage:
        severity = Severity.CRITICAL
        if severity >= Severity.WARNING:
            print("Flag this")
    """
    CLEAN = "CLEAN"
    INFO = "INFO"
    WARNING = "WARNING"
    CRITICAL = "CRITICAL"

    # Comparison operators so max() works and we can do severity >= WARNING.
    # Enum members are compared by their position in this explicit order,
    # NOT by the alphabetical value of their strings.

    def __lt__(self, other: Severity) -> bool:
        order = [Severity.CLEAN, Severity.INFO, Severity.WARNING, Severity.CRITICAL]
        return order.index(self) < order.index(other)

    def __le__(self, other: Severity) -> bool:
        return self == other or self < other

    def __gt__(self, other: Severity) -> bool:
        order = [Severity.CLEAN, Severity.INFO, Severity.WARNING, Severity.CRITICAL]
        return order.index(self) > order.index(other)

    def __ge__(self, other: Severity) -> bool:
        return self == other or self > other


def highest_severity(severities: list[Severity]) -> Severity:
    """
    Return the highest (most severe) level from a list of Severity values.

    Used by cli.py to aggregate module-level severities into an overall
    ScanResult. Returns CLEAN for an empty list (no modules = nothing bad).
    """
    if not severities:
        return Severity.CLEAN
    return max(severities)


@dataclass
class Finding:
    """
    A single finding produced by a scan module.

    Each module returns zero or more Findings. Every Finding carries its own
    severity, allowing a module to report both warnings and critical issues
    within the same scan.

    Attributes:
        message:  Human-readable description of the finding.
        severity: How serious this finding is.
        details:  Arbitrary structured data (JSON paths, matched patterns, etc.)
                  surfaced in --json output and useful for debugging.
    """
    message: str
    severity: Severity
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class ModuleResult:
    """
    The result of running one scan module.

    Every module (trust_score, hook_scanner, etc.) returns exactly one of
    these. The reporter and CLI consume ModuleResult objects only — they
    never inspect raw module output.

    Attributes:
        module_name: Short identifier like "trust_score" or "hook_scanner".
        severity:    Aggregated severity for this module (the highest of its
                     findings, or CLEAN if no findings).
        findings:    Individual findings produced by the module.
        raw_data:    All raw data collected by the module (account stats, file
                     contents, etc.). Included in --json output for auditability.
    """
    module_name: str
    severity: Severity
    findings: list[Finding] = field(default_factory=list)
    raw_data: dict[str, Any] = field(default_factory=dict)


@dataclass
class ScanResult:
    """
    Top-level result of an entire repo-guard scan.

    Aggregates all ModuleResults into a single report. The overall_severity
    is the highest severity across all modules.

    Attributes:
        repo_url:         The GitHub URL the user passed (e.g.
                          "https://github.com/owner/repo").
        repo_owner:       Extracted owner name (e.g. "octocat").
        repo_name:        Extracted repo name (e.g. "Hello-World").
        scanned_at:       Timestamp of when the scan was performed.
        overall_severity: Highest severity across all modules.
        modules:          One ModuleResult per module that ran.
    """
    repo_url: str
    repo_owner: str
    repo_name: str
    scanned_at: datetime
    overall_severity: Severity
    modules: list[ModuleResult] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """
        Serialize this ScanResult to a JSON-compatible dictionary.

        Used by reporter.py when --json is passed. The datetime is converted
        to ISO 8601 string, and all Severity enums are unwrapped to their
        string values so the output is clean and pipeable.
        """
        return {
            "repo_url": self.repo_url,
            "repo_owner": self.repo_owner,
            "repo_name": self.repo_name,
            "scanned_at": self.scanned_at.isoformat(),
            "overall_severity": self.overall_severity.value,
            "modules": [
                {
                    "module_name": m.module_name,
                    "severity": m.severity.value,
                    "findings": [
                        {
                            "message": f.message,
                            "severity": f.severity.value,
                            "details": f.details,
                        }
                        for f in m.findings
                    ],
                    "raw_data": m.raw_data,
                }
                for m in self.modules
            ],
        }
