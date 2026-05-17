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

from repo_guard.github_client import GitHubClient, GitHubClientError, NotFoundError, PrivateRepoError, parse_github_url
from repo_guard.models import Severity, Finding, ModuleResult, ScanResult, highest_severity
from repo_guard.modules.trust_score import scan as trust_score_scan
from repo_guard.modules.hook_scanner import scan as hook_scanner_scan
from repo_guard.modules.vscode_scanner import scan as vscode_scanner_scan
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
    """Stub: placeholder for ioc_extractor module."""
    # TODO: Implement in Phase 3
    return ModuleResult(
        module_name="ioc_extractor",
        severity=Severity.INFO,
        findings=[
            Finding(
                message="IOC extractor module not yet implemented. Skipping.",
                severity=Severity.INFO,
            )
        ],
        raw_data={},
    )


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
    if preview:
        click.echo(
            "INFO: --preview mode is not yet implemented. Suspicious file "
            "contents will not be displayed in this version.",
            err=True,
        )
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
    # 3. Run modules in order
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
    # 4. Aggregate results
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
    # 5. Render output
    # ------------------------------------------------------------------
    render_scan_result(scan_result, json_output=json_output)

    # ------------------------------------------------------------------
    # 6. Exit with status code reflecting severity
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
