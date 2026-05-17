"""
VS Code Scanner Module — Module 3

Detects IDE auto-execution configuration in .vscode/tasks.json and
.vscode/settings.json.

This attack surface is documented but has no accessible defensive tooling.
The FlexPay attack used a tasks.json with runOn: folderOpen to execute
a payload automatically when the victim opened the repo in VS Code.

Files inspected:
  - .vscode/tasks.json
  - .vscode/settings.json

tasks.json flags:
  - "runOn": "folderOpen" present → WARNING
  - "runOn": "folderOpen" + any shell command → CRITICAL
  - "task.allowAutomaticTasks": "on" in settings.json → WARNING
  - Both present together → CRITICAL
  - Output suppression in presentation config (reveal: silent, echo: false,
    focus: false) → escalate to CRITICAL
"""

from __future__ import annotations

import json
from typing import Any

from repo_guard.github_client import GitHubClient, GitHubClientError, NotFoundError
from repo_guard.models import Severity, Finding, ModuleResult


VSCODE_CONTEXT_NOTE = (
    "VS Code 1.109+ (Feb 2026) disables automatic task execution by default. "
    "This configuration would still execute on older versions and may still prompt "
    "on newer versions in ways designed to mislead the user."
)


def _check_tasks_json(tasks_content: str) -> tuple[list[Finding], bool]:
    """
    Parse tasks.json and check for auto-execution flags.

    Returns (findings, has_folder_open) where has_folder_open indicates
    whether any task had runOn: folderOpen.
    """
    findings: list[Finding] = []
    has_folder_open = False

    try:
        tasks_data = json.loads(tasks_content)
    except json.JSONDecodeError as exc:
        findings.append(Finding(
            message=".vscode/tasks.json is not valid JSON and could not be parsed.",
            severity=Severity.INFO,
            details={"error": str(exc)},
        ))
        return findings, False

    tasks = tasks_data.get("tasks", [])
    if not tasks:
        return findings, False

    for task in tasks:
        run_on = task.get("runOn", "")
        command = task.get("command", "")
        task_type = task.get("type", "")
        label = task.get("label", "(unnamed)")
        presentation = task.get("presentation", {})

        # Check runOn: folderOpen.
        if run_on == "folderOpen":
            severity = Severity.WARNING
            details: dict[str, Any] = {
                "task_label": label,
                "runOn": run_on,
            }

            # If there's a shell command, that's critical.
            if command or task_type == "shell":
                severity = Severity.CRITICAL
                details["command"] = command or "(shell type)"

            # Check output suppression in presentation.
            if presentation.get("reveal") == "silent":
                severity = Severity.CRITICAL
                details["presentation_reveal"] = "silent"
            if presentation.get("echo") is False:
                severity = Severity.CRITICAL
                details["presentation_echo"] = False
            if presentation.get("focus") is False:
                severity = Severity.CRITICAL
                details["presentation_focus"] = False

            findings.append(Finding(
                message=f"Task '{label}' has runOn: folderOpen.",
                severity=severity,
                details=details,
            ))
            has_folder_open = True

    return findings, has_folder_open


def _check_settings_json(settings_content: str) -> tuple[list[Finding], bool]:
    """
    Parse settings.json and check for auto-execution flags.

    Returns (findings, has_allow_auto) where has_allow_auto indicates
    whether task.allowAutomaticTasks was enabled.
    """
    findings: list[Finding] = []
    has_allow_auto = False

    try:
        settings_data = json.loads(settings_content)
    except json.JSONDecodeError as exc:
        findings.append(Finding(
            message=".vscode/settings.json is not valid JSON and could not be parsed.",
            severity=Severity.INFO,
            details={"error": str(exc)},
        ))
        return findings, False

    allow_auto = settings_data.get("task.allowAutomaticTasks", "")
    if allow_auto == "on":
        findings.append(Finding(
            message="task.allowAutomaticTasks is enabled (\"on\").",
            severity=Severity.WARNING,
            details={"task.allowAutomaticTasks": allow_auto},
        ))
        has_allow_auto = True

    return findings, has_allow_auto


def scan(client: GitHubClient, owner: str, repo: str) -> ModuleResult:
    """
    Scan the repository for malicious VS Code auto-execution configuration.

    Returns a ModuleResult.
    """
    findings: list[Finding] = []
    raw_data: dict[str, Any] = {}
    has_tasks = False
    has_settings = False
    has_folder_open = False
    has_allow_auto = False

    # ------------------------------------------------------------------
    # 1. Fetch .vscode/tasks.json
    # ------------------------------------------------------------------
    try:
        tasks_content = client.get_file_content(owner, repo, ".vscode/tasks.json")
        if tasks_content is not None:
            raw_data[".vscode/tasks.json"] = tasks_content
            has_tasks = True
            tasks_findings, has_folder_open = _check_tasks_json(tasks_content)
            findings.extend(tasks_findings)
    except NotFoundError:
        pass
    except GitHubClientError as exc:  # GitHubClientError only — never bare Exception
        findings.append(Finding(
            message="Could not fetch .vscode/tasks.json.",
            severity=Severity.INFO,
            details={"error": str(exc)},
        ))

    # ------------------------------------------------------------------
    # 2. Fetch .vscode/settings.json
    # ------------------------------------------------------------------
    try:
        settings_content = client.get_file_content(owner, repo, ".vscode/settings.json")
        if settings_content is not None:
            raw_data[".vscode/settings.json"] = settings_content
            has_settings = True
            settings_findings, has_allow_auto = _check_settings_json(settings_content)
            findings.extend(settings_findings)
            if has_folder_open and has_allow_auto:
                findings.append(Finding(
                    message="Both task.allowAutomaticTasks and runOn: folderOpen present — automatic task execution is fully enabled.",
                    severity=Severity.CRITICAL,
                    details={"note": VSCODE_CONTEXT_NOTE},
                ))
    except NotFoundError:
        pass  # No settings.json — not a flag.
    except GitHubClientError as exc:  # GitHubClientError only — never bare Exception
        findings.append(Finding(
            message="Could not fetch .vscode/settings.json.",
            severity=Severity.INFO,
            details={"error": str(exc)},
        ))

    # ------------------------------------------------------------------
    # 3. If neither file exists, note it.
    # ------------------------------------------------------------------
    if not has_tasks:
        findings.append(Finding(
            message="No .vscode/tasks.json found. No VS Code auto-execution tasks detected.",
            severity=Severity.CLEAN,
            details={"file": ".vscode/tasks.json"},
        ))

    if not has_settings:
        findings.append(Finding(
            message="No .vscode/settings.json found. No VS Code auto-execution settings detected.",
            severity=Severity.CLEAN,
            details={"file": ".vscode/settings.json"},
        ))

    # ------------------------------------------------------------------
    # 4. Determine overall severity
    # ------------------------------------------------------------------
    severity = max((f.severity for f in findings), default=Severity.CLEAN)

    return ModuleResult(
        module_name="vscode_scanner",
        severity=severity,
        findings=findings,
        raw_data=raw_data,
    )
