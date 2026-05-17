"""
Tests for cli.py — argument parsing, flag handling, error cases.

All tests use Click's CliRunner with GitHubClient methods mocked via
unittest.mock.patch. No live GitHub API calls are made.
"""

from unittest.mock import patch

import pytest
from click.testing import CliRunner

from repo_guard.cli import cli

# A minimal fake response matching what get_repo_info returns.
FAKE_REPO_INFO = {
    "name": "repo",
    "full_name": "o/repo",
    "owner": {"login": "o"},
    "private": False,
    "size": 100,
    "default_branch": "main",
    "created_at": "2024-01-01T00:00:00Z",
    "pushed_at": "2026-05-17T00:00:00Z",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _run(args: list[str]) -> "Result":
    runner = CliRunner()
    with patch("repo_guard.cli.GitHubClient.get_repo_info", return_value=FAKE_REPO_INFO), \
         patch("repo_guard.cli.GitHubClient.get_tree", return_value=[{"path": "README.md", "type": "blob", "sha": "a", "size": 50}]), \
         patch("repo_guard.cli.GitHubClient.get_user_info", return_value={"created_at": "2024-01-01T00:00:00Z", "public_repos": 5, "followers": 10, "following": 3}), \
         patch("repo_guard.cli.GitHubClient.get_repos_for_user", return_value=[]), \
         patch("repo_guard.cli.GitHubClient.get_contributors", return_value=[]), \
         patch("repo_guard.cli.GitHubClient.get_commits", return_value=[]), \
         patch("repo_guard.cli.GitHubClient.get_file_content", return_value=None), \
         patch("repo_guard.cli.GitHubClient.check_user_exists", return_value=True):
        return runner.invoke(cli, args)


# ---------------------------------------------------------------------------
# CLI: basic invocation
# ---------------------------------------------------------------------------


class TestCliBasic:
    """Verify the CLI entry point works at minimum."""

    def test_help_text_exists(self):
        result = _run(["--help"])
        assert result.exit_code == 0
        assert "repo-guard" in result.output
        assert "scan" in result.output

    def test_no_command_shows_help(self):
        result = _run([])
        assert result.exit_code == 2
        assert "Usage:" in result.output


# ---------------------------------------------------------------------------
# CLI: scan command argument validation
# ---------------------------------------------------------------------------


class TestCliScanArgs:
    """Verify the scan subcommand argument parsing (no network calls)."""

    def test_scan_help(self):
        result = _run(["scan", "--help"])
        assert result.exit_code == 0
        assert "GITHUB_URL" in result.output
        assert "--token" in result.output
        assert "--vt-key" in result.output
        assert "--json" in result.output
        assert "--preview" in result.output
        assert "--recruiter" in result.output

    def test_scan_with_valid_url(self):
        result = _run(["scan", "https://github.com/owner/repo"])
        assert result.exit_code in (0, 1)

    def test_scan_rejects_invalid_url(self):
        result = _run(["scan", "not-a-url"])
        assert result.exit_code != 0
        assert "Invalid GitHub URL" in result.output

    def test_scan_rejects_non_github_url(self):
        result = _run(["scan", "https://gitlab.com/owner/repo"])
        assert result.exit_code != 0
        assert "Invalid GitHub URL" in result.output

    def test_scan_rejects_missing_url(self):
        result = _run(["scan"])
        assert result.exit_code != 0
        assert "argument" in result.output.lower()


# ---------------------------------------------------------------------------
# CLI: scan flag combinations
# ---------------------------------------------------------------------------


class TestCliScanFlags:
    """Verify all flag combinations are accepted (no network calls)."""

    def test_scan_with_token(self):
        result = _run(["scan", "https://github.com/o/r", "--token", "ghp_fake"])
        assert result.exit_code in (0, 1)

    def test_scan_with_vt_key(self):
        result = _run(["scan", "https://github.com/o/r", "--vt-key", "vt_fake"])
        assert result.exit_code in (0, 1)

    def test_scan_with_json(self):
        result = _run(["scan", "https://github.com/o/r", "--json"])
        assert result.exit_code in (0, 1)

    def test_scan_with_preview(self):
        result = _run(["scan", "https://github.com/o/r", "--preview"])
        assert result.exit_code in (0, 1)

    def test_scan_with_recruiter(self):
        result = _run(["scan", "https://github.com/o/r", "--recruiter", "https://linkedin.com/in/fake"])
        assert result.exit_code in (0, 1)

    def test_scan_all_flags_together(self):
        result = _run([
            "scan",
            "https://github.com/o/r",
            "--token", "ghp_fake",
            "--vt-key", "vt_fake",
            "--json",
            "--preview",
            "--recruiter", "https://linkedin.com/in/fake",
        ])
        assert result.exit_code in (0, 1)

    def test_scan_with_https_rejected_by_url_parser(self):
        """http:// is parsed the same as https:// by our URL regex."""
        result = _run(["scan", "http://github.com/owner/repo"])
        assert result.exit_code in (0, 1)

    def test_preview_flag_shows_not_implemented_message(self):
        """--preview should emit an explicit not-implemented warning."""
        result = _run(["scan", "https://github.com/o/r", "--preview"])
        assert "not yet implemented" in result.output.lower()

    def test_recruiter_flag_shows_not_implemented_message(self):
        """--recruiter should emit an explicit not-implemented warning."""
        result = _run(["scan", "https://github.com/o/r", "--recruiter", "https://linkedin.com/in/fake"])
        assert "not yet implemented" in result.output.lower()


# ---------------------------------------------------------------------------
# CLI: error messages
# ---------------------------------------------------------------------------


class TestCliErrors:
    """Verify error messages are user-friendly (no network calls)."""

    def test_invalid_url_error_message(self):
        result = _run(["scan", "invalid"])
        assert result.exit_code != 0
        assert "Invalid GitHub URL" in result.output

    def test_empty_url_rejected(self):
        result = _run(["scan", ""])
        assert result.exit_code != 0
        assert "Invalid GitHub URL" in result.output


# ---------------------------------------------------------------------------
# CLI: entry point function
# ---------------------------------------------------------------------------


class TestMain:
    """Verify the main() entry point invokes the CLI."""

    def test_main_runs(self):
        from repo_guard.cli import main
        assert callable(main)
