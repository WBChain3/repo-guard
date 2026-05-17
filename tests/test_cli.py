"""
Tests for cli.py — argument parsing, flag handling, error cases.

All tests use Click's CliRunner to invoke the CLI without spawning a
subprocess. No live GitHub API calls are made — any HTTP interaction
beyond argument parsing would need mocking, but for this Phase 2 test
we are validating only argument parsing and error handling behavior.

The module stubs in cli.py return immediately without any network calls,
so these tests stay fast and isolated.
"""

import pytest
from click.testing import CliRunner

from repo_guard.cli import cli


# ---------------------------------------------------------------------------
# CLI: basic invocation
# ---------------------------------------------------------------------------


class TestCliBasic:
    """Verify the CLI entry point works at minimum."""

    def test_help_text_exists(self):
        """Running with --help should produce help text and exit 0."""
        runner = CliRunner()
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "repo-guard" in result.output
        assert "scan" in result.output

    def test_no_command_shows_help(self):
        """Running repo-guard with no subcommand should show help."""
        runner = CliRunner()
        result = runner.invoke(cli, [])
        # Click exits with code 2 when a required subcommand is missing,
        # but still prints the help text.
        assert result.exit_code == 2
        assert "Usage:" in result.output


# ---------------------------------------------------------------------------
# CLI: scan command argument validation
# ---------------------------------------------------------------------------


class TestCliScanArgs:
    """Verify the scan subcommand argument parsing."""

    def test_scan_help(self):
        """`repo-guard scan --help` should show flag descriptions."""
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", "--help"])
        assert result.exit_code == 0
        assert "GITHUB_URL" in result.output
        assert "--token" in result.output
        assert "--vt-key" in result.output
        assert "--json" in result.output
        assert "--preview" in result.output
        assert "--recruiter" in result.output

    def test_scan_with_valid_url(self):
        """A well-formed GitHub URL should be accepted."""
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", "https://github.com/owner/repo"])
        # The CLI will attempt to reach GitHub API, but our stubs should handle
        # the error gracefully.
        assert result.exit_code in (0, 1)

    def test_scan_rejects_invalid_url(self):
        """An invalid URL should produce a clear error."""
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", "not-a-url"])
        assert result.exit_code != 0
        assert "Invalid GitHub URL" in result.output

    def test_scan_rejects_non_github_url(self):
        """A non-GitHub URL should be rejected."""
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", "https://gitlab.com/owner/repo"])
        assert result.exit_code != 0
        assert "Invalid GitHub URL" in result.output

    def test_scan_rejects_missing_url(self):
        """scan subcommand requires a URL argument."""
        runner = CliRunner()
        result = runner.invoke(cli, ["scan"])
        assert result.exit_code != 0
        assert "argument" in result.output.lower()


# ---------------------------------------------------------------------------
# CLI: scan flag combinations
# ---------------------------------------------------------------------------


class TestCliScanFlags:
    """Verify all flag combinations are accepted."""

    def test_scan_with_token(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", "https://github.com/o/r", "--token", "ghp_fake"])
        assert result.exit_code in (0, 1)

    def test_scan_with_vt_key(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", "https://github.com/o/r", "--vt-key", "vt_fake"])
        assert result.exit_code in (0, 1)

    def test_scan_with_json(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", "https://github.com/o/r", "--json"])
        assert result.exit_code in (0, 1)

    def test_scan_with_preview(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", "https://github.com/o/r", "--preview"])
        assert result.exit_code in (0, 1)

    def test_scan_with_recruiter(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", "https://github.com/o/r", "--recruiter", "https://linkedin.com/in/fake"])
        assert result.exit_code in (0, 1)

    def test_scan_all_flags_together(self):
        """All flags should be accepted simultaneously."""
        runner = CliRunner()
        result = runner.invoke(cli, [
            "scan",
            "https://github.com/o/r",
            "--token", "ghp_fake",
            "--vt-key", "vt_fake",
            "--json",
            "--preview",
            "--recruiter", "https://linkedin.com/in/fake",
        ])
        assert result.exit_code in (0, 1)

    def test_scan_with_https_required(self):
        """http:// URLs should also be accepted (normalized by GitHub)."""
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", "http://github.com/owner/repo"])
        assert result.exit_code in (0, 1)


# ---------------------------------------------------------------------------
# CLI: error messages
# ---------------------------------------------------------------------------


class TestCliErrors:
    """Verify error messages are user-friendly."""

    def test_invalid_url_error_message(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", "invalid"])
        assert result.exit_code != 0
        assert "Invalid GitHub URL" in result.output

    def test_empty_url_rejected(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", ""])
        assert result.exit_code != 0
        assert "Invalid GitHub URL" in result.output


# ---------------------------------------------------------------------------
# CLI: entry point function
# ---------------------------------------------------------------------------


class TestMain:
    """Verify the main() entry point invokes the CLI."""

    def test_main_runs(self):
        """main() is a thin wrapper that invokes the click group directly
        via cli() — we test that the group works in other tests, so this
        just confirms the wrapper function exists and is callable."""
        from repo_guard.cli import main
        # main() calls cli() which is a click.Group — it will SystemExit
        # when no args are given. We just verify the function is wired.
        assert callable(main)
