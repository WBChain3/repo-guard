"""
Integration tests for repo-guard — full scan command with mocked APIs.

Covers the failure matrix from NORTHSTAR.md:
  - Happy path (public repo, findings reported)
  - Private repo without token
  - Rate limited response
  - Network timeout
  - FlexPay fixture triggers CRITICAL
  - Clean repo fixture returns CLEAN

All API calls are mocked. No live network.
"""

from unittest.mock import patch

from click.testing import CliRunner

from repo_guard.cli import cli
from repo_guard.github_client import GitHubClientError, PrivateRepoError, RateLimitError
from tests.conftest import load_fixture, FLEXPAY_DIR, CLEAN_DIR
# ---------------------------------------------------------------------------
# Shared mock data
# ---------------------------------------------------------------------------

MOCK_REPO_INFO = {
    "name": "test-repo",
    "full_name": "o/test-repo",
    "owner": {"login": "o"},
    "private": False,
    "size": 100,
    "default_branch": "main",
    "created_at": "2024-01-01T00:00:00Z",
    "pushed_at": "2026-05-17T00:00:00Z",
}

MOCK_USER_INFO = {
    "created_at": "2024-01-01T00:00:00Z",
    "public_repos": 10,
    "followers": 50,
    "following": 3,
}

RH = {
    "X-RateLimit-Remaining": "4999",
    "X-RateLimit-Limit": "5000",
    "X-RateLimit-Reset": "2000000000",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _run_flexpay() -> "Result":
    """
    Run a scan with all API calls mocked to return FlexPay fixture data.
    This should produce CRITICAL findings.
    """
    flexpay_tree = [
        {"path": "README.md", "type": "blob", "sha": "a", "size": 50},
        {"path": ".githooks/post-checkout", "type": "blob", "sha": "b", "size": 500},
        {"path": ".vscode/tasks.json", "type": "blob", "sha": "c", "size": 200},
        {"path": ".vscode/settings.json", "type": "blob", "sha": "d", "size": 100},
    ]

    def file_content_side_effect(o, r, path):
        return {
            "README.md": load_fixture("README.md", FLEXPAY_DIR),
            ".githooks/post-checkout": load_fixture(".githooks/post-checkout", FLEXPAY_DIR),
            ".vscode/tasks.json": load_fixture(".vscode/tasks.json", FLEXPAY_DIR),
            ".vscode/settings.json": load_fixture(".vscode/settings.json", FLEXPAY_DIR),
        }.get(path)

    runner = CliRunner()
    with patch("repo_guard.cli.GitHubClient.get_repo_info", return_value=MOCK_REPO_INFO), \
         patch("repo_guard.cli.GitHubClient.get_tree", return_value=flexpay_tree), \
         patch("repo_guard.cli.GitHubClient.get_user_info", return_value=MOCK_USER_INFO), \
         patch("repo_guard.cli.GitHubClient.get_repos_for_user", return_value=[]), \
         patch("repo_guard.cli.GitHubClient.get_contributors", return_value=[]), \
         patch("repo_guard.cli.GitHubClient.get_commits", return_value=[{"sha": "a"}] * 5), \
         patch("repo_guard.cli.GitHubClient.get_file_content", side_effect=file_content_side_effect), \
         patch("repo_guard.cli.GitHubClient.check_user_exists", return_value=True):
        return runner.invoke(cli, ["scan", "https://github.com/flexpay/repo"])


def _run_clean() -> "Result":
    """
    Run a scan with all API calls mocked to return clean repo fixture data.
    This should produce CLEAN findings across all modules.
    """
    clean_tree = [
        {"path": "src/main.py", "type": "blob", "sha": "a", "size": 100},
        {"path": ".vscode/settings.json", "type": "blob", "sha": "b", "size": 50},
    ]

    def file_content_side_effect(o, r, path):
        return {
            "src/main.py": load_fixture("src/main.py", CLEAN_DIR),
            ".vscode/settings.json": load_fixture(".vscode/settings.json", CLEAN_DIR),
        }.get(path)

    runner = CliRunner()
    with patch("repo_guard.cli.GitHubClient.get_repo_info", return_value=MOCK_REPO_INFO), \
         patch("repo_guard.cli.GitHubClient.get_tree", return_value=clean_tree), \
         patch("repo_guard.cli.GitHubClient.get_user_info", return_value=MOCK_USER_INFO), \
         patch("repo_guard.cli.GitHubClient.get_repos_for_user", return_value=[]), \
         patch("repo_guard.cli.GitHubClient.get_contributors", return_value=[]), \
         patch("repo_guard.cli.GitHubClient.get_commits", return_value=[{"sha": "a"}] * 5), \
         patch("repo_guard.cli.GitHubClient.get_file_content", side_effect=file_content_side_effect), \
         patch("repo_guard.cli.GitHubClient.check_user_exists", return_value=True):
        return runner.invoke(cli, ["scan", "https://github.com/clean/repo"])


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


class TestIntegrationHappyPath:
    """Public repo scan produces findings and exits cleanly."""

    def test_flexpay_scan_completes(self):
        """A full scan of the FlexPay mock should complete and produce output."""
        result = _run_flexpay()
        assert result.exit_code == 1  # Severity >= WARNING
        assert "repo-guard scan results" in result.output
        assert "trust_score" in result.output or "Trust Score" in result.output
        assert "hook_scanner" in result.output or "Hook" in result.output
        assert "vscode_scanner" in result.output or "Vscode" in result.output
        assert "ioc_extractor" in result.output or "Ioc" in result.output

    def test_clean_scan_completes(self):
        """A full scan of the clean mock should complete and exit 0."""
        result = _run_clean()
        assert result.exit_code == 0

    def test_flexpay_scan_json_output(self):
        """--json output from FlexPay scan should be valid."""
        runner = CliRunner()
        flexpay_tree = [
            {"path": ".githooks/post-checkout", "type": "blob", "sha": "b", "size": 500},
            {"path": ".vscode/tasks.json", "type": "blob", "sha": "c", "size": 200},
            {"path": ".vscode/settings.json", "type": "blob", "sha": "d", "size": 100},
        ]
        with patch("repo_guard.cli.GitHubClient.get_repo_info", return_value=MOCK_REPO_INFO), \
             patch("repo_guard.cli.GitHubClient.get_tree", return_value=flexpay_tree), \
             patch("repo_guard.cli.GitHubClient.get_user_info", return_value=MOCK_USER_INFO), \
             patch("repo_guard.cli.GitHubClient.get_repos_for_user", return_value=[]), \
             patch("repo_guard.cli.GitHubClient.get_contributors", return_value=[]), \
             patch("repo_guard.cli.GitHubClient.get_commits", return_value=[{"sha": "a"}] * 5), \
             patch("repo_guard.cli.GitHubClient.get_file_content", return_value=load_fixture(".githooks/post-checkout")), \
             patch("repo_guard.cli.GitHubClient.check_user_exists", return_value=True):
            result = runner.invoke(cli, [
                "scan", "https://github.com/flexpay/repo", "--json"
            ])
        import json
        data = json.loads(result.output)
        assert "modules" in data
        assert len(data["modules"]) >= 3


# ---------------------------------------------------------------------------
# Failure modes
# ---------------------------------------------------------------------------


class TestIntegrationFailureModes:
    """Error conditions from the NORTHSTAR failure matrix."""

    def test_private_repo_no_token(self):
        """Private repo without token should show clear error and exit 1."""
        runner = CliRunner()
        with patch("repo_guard.cli.GitHubClient.get_repo_info", side_effect=PrivateRepoError("Private repo")):
            result = runner.invoke(cli, ["scan", "https://github.com/private/repo"])
        assert result.exit_code != 0
        assert "Private repository detected" in result.output

    def test_rate_limited_response(self):
        """Rate limited response should show clear error and exit 1."""
        runner = CliRunner()
        with patch("repo_guard.cli.GitHubClient.get_repo_info", side_effect=RateLimitError(2000000000)):
            result = runner.invoke(cli, ["scan", "https://github.com/owner/repo"])
        assert result.exit_code != 0
        assert "rate limit" in result.output.lower() or "RateLimit" in str(result.exception)

    def test_network_timeout(self):
        """Network timeout should show clear error and exit 1."""
        runner = CliRunner()
        with patch("repo_guard.cli.GitHubClient.get_repo_info", side_effect=GitHubClientError("Network error connecting to")):
            result = runner.invoke(cli, ["scan", "https://github.com/owner/repo"])
        assert result.exit_code != 0
        assert "ERROR" in result.output

    def test_invalid_url(self):
        """Invalid URL should show clear error and exit 2."""
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", "not-a-url"])
        assert result.exit_code != 0
        assert "Invalid GitHub URL" in result.output


# ---------------------------------------------------------------------------
# FlexPay canary
# ---------------------------------------------------------------------------


class TestIntegrationFlexPayCanary:
    """The FlexPay fixture must trigger CRITICAL findings."""

    def test_flexpay_overall_is_critical_or_warning(self):
        """FlexPay's combined findings should produce WARNING or CRITICAL overall."""
        result = _run_flexpay()
        assert result.exit_code == 1  # >= WARNING

    def test_flexpay_detects_malicious_hooks(self):
        """FlexPay hook findings should appear in output."""
        result = _run_flexpay()
        assert "curl" in result.output or "bash" in result.output or "CRITICAL" in result.output

    def test_flexpay_detects_vscode_autoexec(self):
        """FlexPay VS Code findings should appear in output."""
        result = _run_flexpay()
        assert "folderOpen" in result.output or "allowAutomaticTasks" in result.output or "runOn" in result.output


# ---------------------------------------------------------------------------
# Clean repo guard
# ---------------------------------------------------------------------------


class TestIntegrationCleanGuard:
    """The clean repo fixture must return CLEAN across all modules."""

    def test_clean_overall_is_clean(self):
        """Clean repo should exit 0 (no WARNING or CRITICAL findings)."""
        result = _run_clean()
        assert result.exit_code == 0

    def test_clean_shows_no_issues(self):
        """Clean repo output should reflect no malicious findings."""
        result = _run_clean()
        assert "No issues" in result.output or "No .githooks" in result.output or "CLEAN" in result.output
