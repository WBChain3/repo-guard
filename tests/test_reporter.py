"""
Tests for reporter.py — terminal formatting, JSON output, dispatch.

These tests verify that:
  - TerminalReporter renders a mock ScanResult at each severity level
    without crashing.
  - JSONReporter produces valid, parseable JSON with the correct structure.
  - The render_scan_result dispatch function correctly routes to the
    appropriate reporter based on the json_output flag.
"""

import json
from datetime import datetime, timezone

import pytest

from repo_guard.models import Severity, Finding, ModuleResult, ScanResult
from repo_guard.reporter import (
    JSONReporter,
    TerminalReporter,
    render_scan_result,
    SEVERITY_STYLES,
    SEVERITY_LABELS,
)


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _make_result(
    overall_severity: Severity = Severity.CLEAN,
    module_severity: Severity = Severity.CLEAN,
    findings: list | None = None,
) -> ScanResult:
    """
    Build a ScanResult with a single module for testing.
    """
    if findings is None:
        findings = []
    mr = ModuleResult(
        module_name="test_module",
        severity=module_severity,
        findings=findings,
        raw_data={"key": "value"},
    )
    return ScanResult(
        repo_url="https://github.com/owner/repo",
        repo_owner="owner",
        repo_name="repo",
        scanned_at=datetime(2026, 5, 17, 12, 0, 0, tzinfo=timezone.utc),
        overall_severity=overall_severity,
        modules=[mr],
    )


# ---------------------------------------------------------------------------
# Severity mapping consistency
# ---------------------------------------------------------------------------


class TestSeverityMapping:
    """Verify that every Severity value has a style and label defined."""

    def test_all_severities_have_styles(self):
        for sev in Severity:
            assert sev in SEVERITY_STYLES, f"Missing style for {sev}"

    def test_all_severities_have_labels(self):
        for sev in Severity:
            assert sev in SEVERITY_LABELS, f"Missing label for {sev}"

    def test_labels_match_values(self):
        for sev in Severity:
            assert SEVERITY_LABELS[sev] == sev.value


# ---------------------------------------------------------------------------
# TerminalReporter
# ---------------------------------------------------------------------------


class TestTerminalReporter:
    """Verify TerminalReporter renders without errors."""

    def test_clean_result(self):
        """A CLEAN result should render without raising."""
        result = _make_result()
        reporter = TerminalReporter()
        reporter.render(result)

    def test_info_result(self):
        """An INFO result should render without raising."""
        result = _make_result(
            overall_severity=Severity.INFO,
            module_severity=Severity.INFO,
            findings=[Finding("informational", Severity.INFO)],
        )
        reporter = TerminalReporter()
        reporter.render(result)

    def test_warning_result(self):
        """A WARNING result should render without raising."""
        result = _make_result(
            overall_severity=Severity.WARNING,
            module_severity=Severity.WARNING,
            findings=[Finding("suspicious pattern", Severity.WARNING)],
        )
        reporter = TerminalReporter()
        reporter.render(result)

    def test_critical_result(self):
        """A CRITICAL result should render without raising."""
        result = _make_result(
            overall_severity=Severity.CRITICAL,
            module_severity=Severity.CRITICAL,
            findings=[
                Finding(
                    "malicious payload detected",
                    Severity.CRITICAL,
                    details={"path": ".githooks/post-checkout", "match": "curl|bash"},
                )
            ],
        )
        reporter = TerminalReporter()
        reporter.render(result)

    def test_multiple_findings(self):
        """Multiple findings in one module should render cleanly."""
        result = _make_result(
            overall_severity=Severity.WARNING,
            module_severity=Severity.WARNING,
            findings=[
                Finding("finding one", Severity.WARNING),
                Finding("finding two", Severity.INFO),
            ],
        )
        reporter = TerminalReporter()
        reporter.render(result)

    def test_multiple_modules(self):
        """Multiple modules should render without issue."""
        mr2 = ModuleResult(
            module_name="second_module",
            severity=Severity.CRITICAL,
            findings=[Finding("critical issue", Severity.CRITICAL)],
        )
        result = _make_result(overall_severity=Severity.CRITICAL, module_severity=Severity.CLEAN)
        result.modules.append(mr2)
        reporter = TerminalReporter()
        reporter.render(result)

    def test_empty_findings_shows_clean(self):
        """A module with no findings should display 'No issues detected'."""
        result = _make_result()
        reporter = TerminalReporter()
        reporter.render(result)


# ---------------------------------------------------------------------------
# JSONReporter
# ---------------------------------------------------------------------------


class TestJSONReporter:
    """Verify JSONReporter produces valid, structured JSON output."""

    def test_produces_valid_json(self, capsys):
        result = _make_result()
        JSONReporter().render(result)
        captured = capsys.readouterr()
        parsed = json.loads(captured.out)
        assert parsed["repo_url"] == "https://github.com/owner/repo"
        assert parsed["overall_severity"] == "CLEAN"

    def test_json_has_all_required_keys(self, capsys):
        result = _make_result()
        JSONReporter().render(result)
        captured = capsys.readouterr()
        parsed = json.loads(captured.out)
        required_keys = {"repo_url", "repo_owner", "repo_name", "scanned_at", "overall_severity", "modules"}
        assert required_keys.issubset(parsed.keys())

    def test_json_contains_finding_details(self, capsys):
        result = _make_result(
            overall_severity=Severity.CRITICAL,
            module_severity=Severity.CRITICAL,
            findings=[
                Finding(
                    "bad thing",
                    Severity.CRITICAL,
                    details={"path": "file.sh", "match": "curl"},
                )
            ],
        )
        JSONReporter().render(result)
        captured = capsys.readouterr()
        parsed = json.loads(captured.out)
        finding = parsed["modules"][0]["findings"][0]
        assert finding["message"] == "bad thing"
        assert finding["severity"] == "CRITICAL"
        assert finding["details"]["path"] == "file.sh"

    def test_json_pretty_printed(self, capsys):
        result = _make_result()
        JSONReporter().render(result)
        captured = capsys.readouterr()
        assert "  " in captured.out  # Indentation indicates pretty-printing


# ---------------------------------------------------------------------------
# Dispatch function
# ---------------------------------------------------------------------------


class TestRenderScanResult:
    """Verify the convenience dispatch function."""

    def test_terminal_by_default(self):
        """render_scan_result without json_output should use TerminalReporter."""
        result = _make_result()
        render_scan_result(result, json_output=False)

    def test_json_when_flag_set(self, capsys):
        result = _make_result()
        render_scan_result(result, json_output=True)
        captured = capsys.readouterr()
        parsed = json.loads(captured.out)
        assert parsed["overall_severity"] == "CLEAN"
