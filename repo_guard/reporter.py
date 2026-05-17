"""
Terminal and JSON output formatting for repo-guard scan results.

Uses the `rich` library for color-coded terminal output with panels and
tables. The JSON output is a direct serialization of ScanResult.to_dict().

Color scheme (terminal only):
  CRITICAL = red
  WARNING  = yellow
  INFO     = cyan
  CLEAN    = green
"""

from __future__ import annotations

import json
import sys
from datetime import datetime
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from repo_guard.models import Severity, ScanResult


# ---------------------------------------------------------------------------
# Severity-to-style mapping
# ---------------------------------------------------------------------------

SEVERITY_STYLES: dict[Severity, str] = {
    Severity.CRITICAL: "bold red",
    Severity.WARNING: "bold yellow",
    Severity.INFO: "bold cyan",
    Severity.CLEAN: "bold green",
}

SEVERITY_LABELS: dict[Severity, str] = {
    Severity.CRITICAL: "CRITICAL",
    Severity.WARNING: "WARNING",
    Severity.INFO: "INFO",
    Severity.CLEAN: "CLEAN",
}


def _severity_tag(severity: Severity) -> Text:
    """Return a styled Text object representing the severity label."""
    style = SEVERITY_STYLES.get(severity, "")
    label = SEVERITY_LABELS.get(severity, severity.value)
    return Text(f"[{label}]", style=style)


# ---------------------------------------------------------------------------
# Terminal reporter
# ---------------------------------------------------------------------------


class TerminalReporter:
    """
    Renders a ScanResult to the terminal using rich panels and tables.

    Usage:
        reporter = TerminalReporter()
        reporter.render(result)
    """

    def __init__(self) -> None:
        self.console = Console()

    def render(self, result: ScanResult) -> None:
        """
        Print the full scan report to the terminal.

        Output is divided into sections:
          1. Header (repo URL, timestamp)
          2. One panel per module (findings listed with severity tags)
          3. Overall risk summary footer
        """
        self._render_header(result)
        for module in result.modules:
            self._render_module(module)
        self._render_overall(result)

    def _render_header(self, result: ScanResult) -> None:
        """Print the scan header with repo identity and timestamp."""
        header_text = Text.assemble(
            ("repo-guard scan results\n", "bold"),
            (f"{result.repo_url}\n", ""),
            (f"Scanned at: {result.scanned_at.isoformat()}", "dim"),
        )
        self.console.print(Panel(header_text, border_style="blue"))
        self.console.print()  # blank line for spacing

    def _render_module(self, module_result: Any) -> None:
        """
        Print a single module's results as a panel.

        Each finding is shown as a bullet point prefixed with its severity
        tag. If there are no findings, a single CLEAN line is shown.
        """
        module_name = module_result.module_name.replace("_", " ").title()
        severity = module_result.severity
        severity_style = SEVERITY_STYLES.get(severity, "")

        # Build the content as a Table so things align nicely.
        table = Table.grid(padding=(0, 1))
        table.add_column(style="bold")
        table.add_column()

        # Module title row.
        title = Text.assemble(
            ("Module: ", "bold"),
            (module_name, "bold"),
            "  ",
            _severity_tag(severity),
        )

        if not module_result.findings:
            table.add_row("  •", Text("No issues detected", style="green"))
        else:
            for finding in module_result.findings:
                tag = _severity_tag(finding.severity)
                table.add_row("  •", Text(f"{finding.message}", style=""))
                # If the finding has details, show them indented below.
                for key, value in finding.details.items():
                    detail_text = Text(f"    {key}: {value}", style="dim")
                    table.add_row("", detail_text)

        panel = Panel(
            table,
            title=title,
            title_align="left",
            border_style=severity_style if severity in (Severity.CRITICAL, Severity.WARNING) else "blue",
        )
        self.console.print(panel)
        self.console.print()

    def _render_overall(self, result: ScanResult) -> None:
        """Print the overall severity summary at the bottom of the report."""
        overall = result.overall_severity
        style = SEVERITY_STYLES.get(overall, "")
        label = SEVERITY_LABELS.get(overall, overall.value)

        summary = Text.assemble(
            ("OVERALL RISK: ", "bold"),
            (label, style),
        )

        panel = Panel(summary, border_style=style.split()[-1] if style else "blue")
        self.console.print(panel)


# ---------------------------------------------------------------------------
# JSON reporter
# ---------------------------------------------------------------------------


class JSONReporter:
    """
    Renders a ScanResult as pretty-printed JSON to stdout.

    Usage:
        reporter = JSONReporter()
        reporter.render(result)
    """

    def render(self, result: ScanResult) -> None:
        """Serialize the ScanResult to JSON and write to stdout."""
        data = result.to_dict()
        sys.stdout.write(json.dumps(data, indent=2) + "\n")


# ---------------------------------------------------------------------------
# Convenience dispatch
# ---------------------------------------------------------------------------


def render_scan_result(result: ScanResult, json_output: bool = False) -> None:
    """
    Render a ScanResult to the terminal or as JSON.

    This is the primary entry point for cli.py. It dispatches to the
    appropriate reporter based on the json_output flag.
    """
    if json_output:
        JSONReporter().render(result)
    else:
        TerminalReporter().render(result)
