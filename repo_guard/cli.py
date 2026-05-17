"""
CLI entry point for repo-guard.

Defines the `scan` subcommand with all supported flags, orchestrates the
four scan modules in order, and dispatches output to the reporter.

Usage:
    repo-guard scan https://github.com/owner/repo
    repo-guard scan https://github.com/owner/repo --token ghp_xxx --json
    repo-guard scan https://github.com/owner/repo --vt-key vt_xxx --preview
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import click
from rich.console import Console
from rich.syntax import Syntax

from repo_guard.github_client import GitHubClient, GitHubClientError, NotFoundError, PrivateRepoError, parse_github_url
from repo_guard.models import Severity, Finding, ModuleResult, ScanResult, highest_severity
from repo_guard.modules.trust_score import scan as trust_score_scan
from repo_guard.modules.hook_scanner import scan as hook_scanner_scan
from repo_guard.modules.vscode_scanner import scan as vscode_scanner_scan
from repo_guard.modules.ioc_extractor import scan as ioc_extractor_scan
from repo_guard.reporter import render_scan_result


# ---------------------------------------------------------------------------
# Module dispatchers — each receives a GitHubClient and returns ModuleResult
# ---------------------------------------------------------------------------

def _run_trust_score(client: GitHubClient, owner: str, repo: str) -> ModuleResult:
    return trust_score_scan(client, owner, repo)


def _run_hook_scanner(client: GitHubClient, owner: str, repo: str) -> ModuleResult:
    return hook_scanner_scan(client, owner, repo)


def _run_vscode_scanner(client: GitHubClient, owner: str, repo: str) -> ModuleResult:
    return vscode_scanner_scan(client, owner, repo)


def _run_ioc_extractor(
    client: GitHubClient,
    owner: str,
    repo: str,
    vt_key: str | None = None,
) -> ModuleResult:
    return ioc_extractor_scan(client, owner, repo, vt_key=vt_key)


# ---------------------------------------------------------------------------
# Preview helpers
# ---------------------------------------------------------------------------


def _preview_files(
    client: GitHubClient,
    owner: str,
    repo: str,
    module_results: list[ModuleResult],
) -> None:
    """
    Offer to preview suspicious file contents in the terminal.

    Only files that produced findings in hook_scanner or vscode_scanner
    are eligible for preview. Prompts the user interactively.
    """
    # Collect file paths from module findings that have a "file" detail key.
    preview_paths: list[str] = []
    for module in module_results:
        for finding in module.findings:
            file_path = finding.details.get("file", "")
            if file_path and file_path not in preview_paths:
                preview_paths.append(file_path)

    if not preview_paths:
        return

    console = Console()
    answer = input("\nPreview suspicious files? [Y/n] ").strip().lower()
    if answer in ("n", "no"):
        console.print("[dim]Preview skipped.[/dim]")
        return

    console.print()
    for file_path in preview_paths:
        try:
            content = client.get_file_content(owner, repo, file_path)
        except GitHubClientError as exc:
            console.print(f"[red]Could not preview {file_path}: {exc}[/red]")
            continue

        if content is None:
            continue

        # Attempt syntax highlighting; fall back to raw text.
        ext = file_path.rsplit(".", 1)[-1].lower() if "." in file_path else ""
        lexer_map = {
            "py": "python",
            "js": "javascript",
            "ts": "typescript",
            "json": "json",
            "yaml": "yaml",
            "yml": "yaml",
            "md": "markdown",
            "sh": "bash",
            "bash": "bash",
            "zsh": "bash",
            "toml": "toml",
            "ini": "ini",
            "cfg": "ini",
            "conf": "ini",
        }
        language = lexer_map.get(ext, "text")

        try:
            syntax = Syntax(content, language, theme="monokai", line_numbers=True)
            console.print(f"[bold underline]{file_path}[/bold underline]")
            console.print(syntax)
        except Exception:
            # Fallback: raw text if syntax highlighting fails.
            console.print(f"[bold underline]{file_path}[/bold underline]")
            console.print(content)
        console.print()


# ---------------------------------------------------------------------------
# Click command group
# ---------------------------------------------------------------------------


@click.group()
def cli() -> None:
    """
    repo-guard — Pre-clone security scanner for GitHub repositories.

    Inspects repositories for malicious IDE configuration, git hooks,
    and suspicious metadata before you clone. No cloning required.
    """


# ---------------------------------------------------------------------------
# `scan` subcommand
# ---------------------------------------------------------------------------


@cli.command()
@click.argument("github_url")
@click.option("--token", envvar="REPO_GUARD_TOKEN", help="GitHub Personal Access Token (or set REPO_GUARD_TOKEN env var).")
@click.option("--vt-key", envvar="REPO_GUARD_VT_KEY", help="VirusTotal API key for IOC enrichment (or set REPO_GUARD_VT_KEY env var).")
@click.option("--json", "json_output", is_flag=True, help="Output results as JSON (machine-readable).")
@click.option("--preview", is_flag=True, help="Preview suspicious file contents in terminal (no download).")
@click.option("--recruiter", help="Recruiter context: LinkedIn URL or text (for social engineering flag).")
def scan(
    github_url: str,
    token: str | None,
    vt_key: str | None,
    json_output: bool,
    preview: bool,
    recruiter: str | None,
) -> None:
    """
    Scan a GitHub repository for security risks without cloning.

    GITHUB_URL should be a full GitHub repository URL, e.g.:
    https://github.com/owner/repo
    """
    # ------------------------------------------------------------------
    # 1. Parse the URL
    # ------------------------------------------------------------------
    try:
        owner, repo_name = parse_github_url(github_url)
    except ValueError as exc:
        raise click.BadParameter(str(exc), param_hint="GITHUB_URL") from exc

    # ------------------------------------------------------------------
    # 2. Initialize the GitHub API client
    # ------------------------------------------------------------------
    client = GitHubClient(token=token)

    # ------------------------------------------------------------------
    # 3. Warn about unimplemented flags
    # ------------------------------------------------------------------
    if recruiter:
        click.echo(
            f"INFO: --recruiter context is not yet implemented. "
            f"Recruiter info '{recruiter}' will not be used in this version.",
            err=True,
        )

    # ------------------------------------------------------------------
    # 4. Quick reachability check — does the repo exist and is it accessible?
    try:
        repo_info = client.get_repo_info(owner, repo_name)
    except PrivateRepoError:
        click.secho(
            "ERROR: Private repository detected. Re-run with --token to scan "
            "private repositories.",
            fg="red",
            err=True,
        )
        raise SystemExit(1)
    except NotFoundError:
        click.secho(
            f"ERROR: Repository not found: {github_url}. Check the URL and "
            f"ensure it exists (or use --token for private repos).",
            fg="red",
            err=True,
        )
        raise SystemExit(1)
    except GitHubClientError as exc:
        click.secho(
            f"ERROR: GitHub API request failed: {exc}",
            fg="red",
            err=True,
        )
        raise SystemExit(1)

    # If the repo is empty (no default branch), we can still report on metadata.
    # Guard against None since GitHub API could return null for size.
    is_empty = repo_info.get("size") is None or repo_info.get("size", 0) == 0

    # ------------------------------------------------------------------
    # 5. Run modules in order
    # ------------------------------------------------------------------
    module_results: list[ModuleResult] = []

    # Module 1: Trust Score (account/repo metadata)
    module_results.append(_run_trust_score(client, owner, repo_name))

    if not is_empty:
        # Module 2: Hook Scanner (.githooks)
        module_results.append(_run_hook_scanner(client, owner, repo_name))

        # Module 3: VS Code Scanner (.vscode)
        module_results.append(_run_vscode_scanner(client, owner, repo_name))

        # Module 4: IOC Extractor (all text files)
        module_results.append(_run_ioc_extractor(client, owner, repo_name, vt_key))

    # ------------------------------------------------------------------
    # 6. Aggregate results
    # ------------------------------------------------------------------
    overall_severity = highest_severity([m.severity for m in module_results])

    scan_result = ScanResult(
        repo_url=github_url,
        repo_owner=owner,
        repo_name=repo_name,
        scanned_at=datetime.now(timezone.utc),
        overall_severity=overall_severity,
        modules=module_results,
    )

    # ------------------------------------------------------------------
    # 7. Render output
    # ------------------------------------------------------------------
    render_scan_result(scan_result, json_output=json_output)

    # ------------------------------------------------------------------
    # 8. Preview suspicious files (--preview flag)
    # ------------------------------------------------------------------
    if preview and not json_output and overall_severity >= Severity.WARNING:
        _preview_files(client, owner, repo_name, module_results)

    # ------------------------------------------------------------------
    # 9. Exit with status code reflecting severity
    # ------------------------------------------------------------------
    if overall_severity >= Severity.WARNING:
        raise SystemExit(1)


# ---------------------------------------------------------------------------
# Entry point for pyproject.toml [project.scripts]
# ---------------------------------------------------------------------------

def main() -> None:
    """Invoked by the `repo-guard` console script entry point."""
    cli()


if __name__ == "__main__":
    main()
