"""
Tests for models.py — dataclass instantiation, severity ordering, serialization.

These tests ensure that:
  - Severity comparisons work correctly (CLEAN < INFO < WARNING < CRITICAL).
  - highest_severity() picks the right level.
  - Finding, ModuleResult, and ScanResult instantiate and serialize as expected.
  - to_dict() produces valid JSON-compatible structures.
"""

from datetime import datetime, timezone
from repo_guard.models import (
    Severity,
    highest_severity,
    Finding,
    ModuleResult,
    ScanResult,
)


# ---------------------------------------------------------------------------
# Severity ordering
# ---------------------------------------------------------------------------


class TestSeverityOrdering:
    """Verify that Severity members compare in the correct order."""

    def test_clean_is_lowest(self):
        assert Severity.CLEAN < Severity.INFO
        assert Severity.CLEAN < Severity.WARNING
        assert Severity.CLEAN < Severity.CRITICAL

    def test_info_is_second(self):
        assert Severity.INFO > Severity.CLEAN
        assert Severity.INFO < Severity.WARNING
        assert Severity.INFO < Severity.CRITICAL

    def test_warning_is_third(self):
        assert Severity.WARNING > Severity.INFO
        assert Severity.WARNING > Severity.CLEAN
        assert Severity.WARNING < Severity.CRITICAL

    def test_critical_is_highest(self):
        assert Severity.CRITICAL > Severity.WARNING
        assert Severity.CRITICAL > Severity.INFO
        assert Severity.CRITICAL > Severity.CLEAN

    def test_equality(self):
        assert Severity.CLEAN == Severity.CLEAN
        assert Severity.CRITICAL == Severity.CRITICAL
        assert Severity.CLEAN != Severity.CRITICAL

    def test_less_than_or_equal(self):
        assert Severity.CLEAN <= Severity.INFO
        assert Severity.CLEAN <= Severity.CLEAN
        assert not (Severity.CRITICAL <= Severity.WARNING)

    def test_greater_than_or_equal(self):
        assert Severity.CRITICAL >= Severity.WARNING
        assert Severity.CRITICAL >= Severity.CRITICAL
        assert not (Severity.INFO >= Severity.WARNING)

    def test_max_works(self):
        """max() relies on __lt__; verify it picks the correct member."""
        assert max([Severity.CLEAN, Severity.WARNING]) == Severity.WARNING
        assert max([Severity.INFO, Severity.CRITICAL, Severity.CLEAN]) == Severity.CRITICAL


class TestHighestSeverity:
    """Verify the helper function that aggregates severity levels."""

    def test_empty_list_returns_clean(self):
        assert highest_severity([]) == Severity.CLEAN

    def test_single_item(self):
        assert highest_severity([Severity.WARNING]) == Severity.WARNING

    def test_picks_highest(self):
        result = highest_severity([Severity.CLEAN, Severity.INFO, Severity.WARNING, Severity.CRITICAL])
        assert result == Severity.CRITICAL

    def test_clean_when_all_clean(self):
        assert highest_severity([Severity.CLEAN, Severity.CLEAN]) == Severity.CLEAN


# ---------------------------------------------------------------------------
# Finding
# ---------------------------------------------------------------------------


class TestFinding:
    """Verify Finding dataclass fields and defaults."""

    def test_minimal_instantiation(self):
        f = Finding(message="test finding", severity=Severity.WARNING)
        assert f.message == "test finding"
        assert f.severity == Severity.WARNING
        assert f.details == {}

    def test_with_details(self):
        f = Finding(
            message="suspect file",
            severity=Severity.CRITICAL,
            details={"path": ".githooks/post-checkout", "matched": "curl|bash"},
        )
        assert f.details["path"] == ".githooks/post-checkout"

    def test_default_details_is_empty_dict(self):
        f = Finding("msg", Severity.INFO)
        assert f.details == {}


# ---------------------------------------------------------------------------
# ModuleResult
# ---------------------------------------------------------------------------


class TestModuleResult:
    """Verify ModuleResult dataclass fields and defaults."""

    def test_minimal_instantiation(self):
        mr = ModuleResult(module_name="trust_score", severity=Severity.CLEAN)
        assert mr.module_name == "trust_score"
        assert mr.severity == Severity.CLEAN
        assert mr.findings == []
        assert mr.raw_data == {}

    def test_with_findings(self):
        f1 = Finding("signal A", Severity.WARNING)
        f2 = Finding("signal B", Severity.CRITICAL)
        mr = ModuleResult(
            module_name="hook_scanner",
            severity=Severity.CRITICAL,
            findings=[f1, f2],
        )
        assert len(mr.findings) == 2
        assert mr.findings[0].message == "signal A"

    def test_with_raw_data(self):
        mr = ModuleResult(
            module_name="ioc_extractor",
            severity=Severity.INFO,
            raw_data={"urls_found": ["https://evil.com"]},
        )
        assert mr.raw_data["urls_found"] == ["https://evil.com"]


# ---------------------------------------------------------------------------
# ScanResult
# ---------------------------------------------------------------------------


class TestScanResult:
    """Verify ScanResult dataclass and to_dict serialization."""

    def test_minimal_instantiation(self):
        now = datetime.now(timezone.utc)
        sr = ScanResult(
            repo_url="https://github.com/owner/repo",
            repo_owner="owner",
            repo_name="repo",
            scanned_at=now,
            overall_severity=Severity.CLEAN,
        )
        assert sr.repo_owner == "owner"
        assert sr.modules == []

    def test_with_modules(self):
        now = datetime.now(timezone.utc)
        mr = ModuleResult(module_name="trust_score", severity=Severity.CLEAN)
        sr = ScanResult(
            repo_url="https://github.com/owner/repo",
            repo_owner="owner",
            repo_name="repo",
            scanned_at=now,
            overall_severity=Severity.CLEAN,
            modules=[mr],
        )
        assert len(sr.modules) == 1
        assert sr.modules[0].module_name == "trust_score"

    def test_to_dict_structure(self):
        now = datetime(2026, 5, 17, 12, 0, 0, tzinfo=timezone.utc)
        f = Finding("something bad", Severity.CRITICAL, details={"detail_key": "detail_val"})
        mr = ModuleResult(
            module_name="hook_scanner",
            severity=Severity.CRITICAL,
            findings=[f],
            raw_data={"hook_files": [".githooks/post-checkout"]},
        )
        sr = ScanResult(
            repo_url="https://github.com/evil/actor",
            repo_owner="evil",
            repo_name="actor",
            scanned_at=now,
            overall_severity=Severity.CRITICAL,
            modules=[mr],
        )

        d = sr.to_dict()
        assert d["repo_url"] == "https://github.com/evil/actor"
        assert d["overall_severity"] == "CRITICAL"
        assert d["scanned_at"] == "2026-05-17T12:00:00+00:00"
        assert len(d["modules"]) == 1

        module_dict = d["modules"][0]
        assert module_dict["module_name"] == "hook_scanner"
        assert module_dict["severity"] == "CRITICAL"
        assert module_dict["raw_data"]["hook_files"] == [".githooks/post-checkout"]

        finding_dict = module_dict["findings"][0]
        assert finding_dict["message"] == "something bad"
        assert finding_dict["severity"] == "CRITICAL"
        assert finding_dict["details"] == {"detail_key": "detail_val"}

    def test_to_dict_empty_modules(self):
        now = datetime.now(timezone.utc)
        sr = ScanResult(
            repo_url="https://github.com/a/b",
            repo_owner="a",
            repo_name="b",
            scanned_at=now,
            overall_severity=Severity.CLEAN,
        )
        d = sr.to_dict()
        assert d["modules"] == []

    def test_to_dict_all_severity_levels(self):
        """Ensure all severity enum values serialize to their string names."""
        now = datetime.now(timezone.utc)
        for sev in Severity:
            f = Finding("test", sev)
            mr = ModuleResult("test_module", sev, findings=[f])
            sr = ScanResult(
                repo_url="https://github.com/x/y",
                repo_owner="x",
                repo_name="y",
                scanned_at=now,
                overall_severity=sev,
                modules=[mr],
            )
            d = sr.to_dict()
            assert d["overall_severity"] == sev.value
            assert d["modules"][0]["severity"] == sev.value
            assert d["modules"][0]["findings"][0]["severity"] == sev.value
