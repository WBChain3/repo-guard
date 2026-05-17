"""
Hook Scanner Module — Module 2

Detects malicious payload delivery via git hooks in the .githooks/
directory. This is the most original contribution of this tool — no
existing scanner covers this vector accessibly.

Method:
  1. Fetch the repo tree (recursive) via client.get_tree()
  2. Identify any files under .githooks/
  3. If none found → CLEAN with a note
  4. For each hook file:
     - Fetch content via client.get_file_content()
     - Scan for execution patterns (curl|bash, wget|sh, etc.)
     - Calculate comment-to-code ratio

Execution pattern flags (any match → CRITICAL):
  - curl/wget piped to sh/bash/cmd/zsh
  - External URLs in shell commands
  - Output suppression (> /dev/null 2>&1)
  - nohup (persistence indicator)
  - Base64 encoded commands

Comment-to-code ratio heuristic:
  - Count lines starting with # (comments) vs executable lines
  - If ratio > 70% comments AND network commands present → flag
"""

from __future__ import annotations

import base64
import re
from typing import Any

from repo_guard.github_client import GitHubClient, GitHubClientError, NotFoundError
from repo_guard.models import Severity, Finding, ModuleResult
from repo_guard.modules.ioc_extractor import _extract_base64_blobs


# ---------------------------------------------------------------------------
# Pattern definitions
# ---------------------------------------------------------------------------

# Patterns that indicate a malicious hook execution chain.
# Each pattern is a tuple of (regex, description).
EXECUTION_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"(curl|wget)\s+.*\s*\|\s*(sh|bash|cmd|zsh)"), "Remote payload piped to shell"),
    (re.compile(r">\s*/dev/null\s+2>&1"), "Output suppression (>/dev/null 2>&1)"),
    (re.compile(r"\bnohup\b"), "nohup persistence indicator"),
    (re.compile(r"exec\(.*base64\.b64decode"), "Base64 decode + exec chain"),
    (re.compile(r"urllib\.request|requests\.get.*exec"), "Download + execute pattern"),
]


def _check_execution_patterns(content: str, file_path: str) -> list[Finding]:
    """
    Scan hook content for known malicious execution patterns.

    Returns a list of Findings, one per matched pattern.
    """
    findings: list[Finding] = []
    seen_patterns: set[str] = set()

    for pattern, description in EXECUTION_PATTERNS:
        match = pattern.search(content)
        if match and description not in seen_patterns:
            seen_patterns.add(description)
            findings.append(Finding(
                message=f"Execution pattern detected: {description}",
                severity=Severity.CRITICAL,
                details={
                    "file": file_path,
                    "matched_text": match.group()[:100],
                    "pattern": description,
                },
            ))

    return findings


def _is_url(s: str) -> bool:
    """Check if a string looks like an HTTP/HTTPS URL."""
    return bool(re.match(r"https?://", s.strip()))


def _check_network_commands(content: str, file_path: str) -> list[Finding]:
    """
    Check for network commands (curl, wget) using external URLs.

    Any curl/wget with an external URL is flagged as suspicious.
    """
    findings: list[Finding] = []
    for line in content.splitlines():
        stripped = line.strip()
        # Skip comment lines.
        if stripped.startswith("#"):
            continue
        # Look for curl/wget with a URL. Use non-greedy .*? to skip
        # any flags and non-flag arguments (e.g. curl -s -o file https://evil.com).
        url_match = re.search(r"(curl|wget)\s+.*?(https?://\S+)", stripped)
        if url_match and _is_url(url_match.group(2)):
            findings.append(Finding(
                message=f"Network command with external URL: {url_match.group(1)} to {url_match.group(2)}",
                severity=Severity.CRITICAL,
                details={
                    "file": file_path,
                    "command": url_match.group(1),
                    "url": url_match.group(2),
                    "line": stripped[:200],
                },
            ))
    return findings


def _calculate_comment_ratio(content: str) -> float:
    """
    Calculate the ratio of comment lines to total non-empty lines.

    Returns a float between 0.0 and 1.0.
    """
    lines = content.splitlines()
    if not lines:
        return 0.0
    non_empty = [l for l in lines if l.strip()]
    if not non_empty:
        return 0.0
    comment_lines = sum(1 for l in non_empty if l.strip().startswith("#"))
    return comment_lines / len(non_empty)


def _check_comment_ratio(content: str, file_path: str, has_network: bool) -> list[Finding]:
    """
    Apply the comment-to-code ratio heuristic.

    Flag as suspicious if:
      - Comment ratio > 70%
      - AND the file contains network commands (curl/wget piping)
    """
    findings: list[Finding] = []
    ratio = _calculate_comment_ratio(content)

    if ratio > 0.7 and has_network:
        findings.append(Finding(
            message=f"Suspicious comment-to-code ratio: {ratio:.0%} comments with network commands present",
            severity=Severity.WARNING,
            details={
                "file": file_path,
                "comment_ratio": round(ratio, 2),
                "threshold": 0.7,
            },
        ))

    return findings


def _check_base64_payloads(content: str, file_path: str) -> list[Finding]:
    """
    Decode and inspect base64 blobs in the hook content.

    Uses ioc_extractor's _extract_base64_blobs for detection and validation,
    then checks decoded content for execution chains.
    """
    findings: list[Finding] = []
    blobs = _extract_base64_blobs(content)

    for b64_str in blobs:
        try:
            decoded_bytes = base64.b64decode(b64_str, validate=True)
            decoded = decoded_bytes.decode("utf-8", errors="replace")
        except (ValueError, UnicodeDecodeError):
            continue

        if any(kw in decoded.lower() for kw in ["import ", "exec(", "os.system", "subprocess", "pwned", "payload"]):
            findings.append(Finding(
                message="Base64 blob decodes to executable payload",
                severity=Severity.CRITICAL,
                details={
                    "file": file_path,
                    "encoded": b64_str[:60],
                    "decoded": decoded[:200],
                },
            ))
    return findings


# ---------------------------------------------------------------------------
# Main scan function
# ---------------------------------------------------------------------------


def scan(client: GitHubClient, owner: str, repo: str) -> ModuleResult:
    """
    Scan the repository for malicious git hooks in .githooks/.

    Returns a ModuleResult with the findings.
    """
    findings: list[Finding] = []
    raw_data: dict[str, Any] = {}

    # ------------------------------------------------------------------
    # 1. Fetch the repo tree and find .githooks files
    # ------------------------------------------------------------------
    try:
        tree = client.get_tree(owner, repo)
        raw_data["tree_entries_count"] = len(tree)
    except GitHubClientError as exc:  # GitHubClientError only — never bare Exception
        return ModuleResult(
            module_name="hook_scanner",
            severity=Severity.INFO,
            findings=[
                Finding(
                    message=f"Could not fetch repository tree: {exc}",
                    severity=Severity.INFO,
                    details={"error": str(exc)},
                )
            ],
            raw_data={"error": str(exc)},
        )

    # Filter for files under .githooks/ — match anywhere in path for nested repos (e.g. packages/backend/.githooks/).
    hook_files = [
        entry["path"] for entry in tree
        if entry.get("type") == "blob"
        and "/.githooks/" in f"/{entry['path']}"
    ]
    raw_data["hook_files"] = hook_files

    if not hook_files:
        return ModuleResult(
            module_name="hook_scanner",
            severity=Severity.CLEAN,
            findings=[
                Finding(
                    message="No .githooks directory found. No hooks to scan.",
                    severity=Severity.CLEAN,
                    details={"hook_files_found": 0},
                )
            ],
            raw_data=raw_data,
        )

    # ------------------------------------------------------------------
    # 2. Scan each hook file
    # ------------------------------------------------------------------
    for hook_path in sorted(hook_files):
        try:
            content = client.get_file_content(owner, repo, hook_path)
        except NotFoundError:
            continue
        except GitHubClientError as exc:  # GitHubClientError only — never bare Exception
            findings.append(Finding(
                message=f"Could not fetch hook file {hook_path}: {exc}",
                severity=Severity.INFO,
                details={"file": hook_path, "error": str(exc)},
            ))
            continue

        if content is None:
            continue

        file_findings: list[Finding] = []
        raw_data["file_contents"] = raw_data.get("file_contents", {})
        raw_data["file_contents"][hook_path] = content

        # Check execution patterns.
        file_findings.extend(_check_execution_patterns(content, hook_path))

        # Check network commands.
        network_findings = _check_network_commands(content, hook_path)
        file_findings.extend(network_findings)
        has_network = len(network_findings) > 0

        # Check base64 payloads.
        file_findings.extend(_check_base64_payloads(content, hook_path))

        # Check comment ratio heuristic (only relevant if network commands exist).
        file_findings.extend(_check_comment_ratio(content, hook_path, has_network))

        findings.extend(file_findings)

    # ------------------------------------------------------------------
    # 3. Determine overall severity for this module
    # ------------------------------------------------------------------
    if not findings:
        # Hook files exist but nothing suspicious — that's still notable.
        severity = Severity.CLEAN
        findings.append(Finding(
            message=f"Scanned {len(hook_files)} hook file(s), no suspicious patterns detected.",
            severity=Severity.CLEAN,
            details={"files_scanned": len(hook_files)},
        ))
    else:
        # Severity is the highest across all findings.
        severity = max(f.severity for f in findings)

    return ModuleResult(
        module_name="hook_scanner",
        severity=severity,
        findings=findings,
        raw_data=raw_data,
    )
