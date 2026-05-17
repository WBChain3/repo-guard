"""
Trust Score Module — Module 1

Scores a GitHub repository and its owner account on a 0–100 scale
based on metadata signals. A low score is not a block — it provides
context for the other modules' findings.

Scoring starts at 100 and subtracts for each suspicious signal.
Floor at 0. Higher = more trustworthy.

Data sources (all via GitHubClient, no scraping):
  - Account creation date
  - Public repo count
  - Follower / following counts
  - Contributor list (checks each for suspension/deletion)
  - Commit history (count, date range, force-push indicators)
  - Repo creation date vs first commit date
"""

from __future__ import annotations

from datetime import datetime, timezone

from repo_guard.github_client import GitHubClient, GitHubClientError
from repo_guard.models import Severity, Finding, ModuleResult


def _days_ago(dt_str: str | None) -> int | None:
    """
    Calculate the number of days between now and a date string.

    Returns None if the date string is missing or unparseable.
    """
    if not dt_str:
        return None
    try:
        dt = datetime.fromisoformat(dt_str.replace("Z", "+00:00"))
        return (datetime.now(timezone.utc) - dt).days
    except (ValueError, TypeError):
        return None


def _score_to_severity(score: int) -> Severity:
    """
    Map a trust score (0–100) to a severity level.

    0–49  → CRITICAL
    50–69 → WARNING
    70–89 → INFO
    90–100 → CLEAN
    """
    if score <= 49:
        return Severity.CRITICAL
    if score <= 69:
        return Severity.WARNING
    if score <= 89:
        return Severity.INFO
    return Severity.CLEAN


def scan(client: GitHubClient, owner: str, repo: str) -> ModuleResult:
    """
    Run the trust score analysis and return a ModuleResult.

    Collects metadata on the repo owner and the repository itself, then
    applies the scoring rules defined in NORTHSTAR.md.
    """
    findings: list[Finding] = []
    score = 100
    raw_data: dict = {}

    # ------------------------------------------------------------------
    # 1. Account-level signals
    # ------------------------------------------------------------------
    try:
        user_info = client.get_user_info(owner)
        raw_data["user_info"] = user_info
    except GitHubClientError:
        user_info = {}

    account_age_days = _days_ago(user_info.get("created_at"))

    # Account age < 30 days → -30
    if account_age_days is not None and account_age_days < 30:
        score -= 30
        findings.append(Finding(
            message=f"Account age is {account_age_days} days (< 30). New accounts are a major red flag.",
            severity=Severity.CRITICAL,
            details={"account_age_days": account_age_days, "penalty": -30},
        ))
    elif account_age_days is not None and account_age_days < 180:
        score -= 15
        findings.append(Finding(
            message=f"Account age is {account_age_days} days (30–180). Moderately new account.",
            severity=Severity.WARNING,
            details={"account_age_days": account_age_days, "penalty": -15},
        ))

    # Zero followers → -5
    followers = user_info.get("followers", 0)
    if followers == 0:
        score -= 5
        findings.append(Finding(
            message="Account has zero followers.",
            severity=Severity.INFO,
            details={"followers": followers, "penalty": -5},
        ))

    # Public repo count < 3 → -5
    public_repos = user_info.get("public_repos", 0)
    if public_repos < 3:
        score -= 5
        findings.append(Finding(
            message=f"Account has only {public_repos} public repo(s) (< 3).",
            severity=Severity.INFO,
            details={"public_repos": public_repos, "penalty": -5},
        ))

    # ------------------------------------------------------------------
    # 2. Contributor checks — suspended or deleted accounts
    # ------------------------------------------------------------------
    try:
        contributors = client.get_contributors(owner, repo)
        raw_data["contributors"] = contributors
    except GitHubClientError:
        contributors = []

    for contributor in contributors[:10]:  # Cap at 10 — large repos can have hundreds of contributors, each requiring an API call
        login = contributor.get("login", "")
        if login:
            exists = client.check_user_exists(login)
            if not exists:
                score -= 25
                findings.append(Finding(
                    message=f"Contributor '{login}' appears to be suspended or deleted.",
                    severity=Severity.WARNING,
                    details={"contributor": login, "penalty": -25},
                ))

    if len(contributors) > 10:
        findings.append(Finding(
            message=f"Contributor check limited to first 10 of {len(contributors)} total contributors. Remaining {len(contributors) - 10} were not verified to avoid excessive API calls.",
            severity=Severity.INFO,
            details={"total_contributors": len(contributors), "checked": 10},
        ))

    # ------------------------------------------------------------------
    # 3. Repository-level signals
    # ------------------------------------------------------------------
    try:
        repo_info = client.get_repo_info(owner, repo)
        raw_data["repo_info"] = repo_info
    except GitHubClientError:
        repo_info = {}

    repo_age_days = _days_ago(repo_info.get("created_at"))

    # Repo age < 30 days → -20
    if repo_age_days is not None and repo_age_days < 30:
        score -= 20
        findings.append(Finding(
            message=f"Repository age is {repo_age_days} days (< 30). Very new repository.",
            severity=Severity.WARNING,
            details={"repo_age_days": repo_age_days, "penalty": -20},
        ))

    # ------------------------------------------------------------------
    # 4. Commit history signals
    # ------------------------------------------------------------------
    try:
        commits = client.get_commits(owner, repo)
        raw_data["commits"] = commits
    except GitHubClientError:  # GitHubClientError only — never bare Exception
        commits = []

    # Single commit → -15
    if len(commits) == 1:
        score -= 15
        findings.append(Finding(
            message="Repository has only a single commit.",
            severity=Severity.WARNING,
            details={"commit_count": len(commits), "penalty": -15},
        ))

    # Force-push detection → -20
    # Compare repo's pushed_at vs created_at. If the repo was created
    # long ago but the most recent push is very recent, it may indicate
    # a force-push or history rewrite.
    pushed_at = _days_ago(repo_info.get("pushed_at"))
    created_at = _days_ago(repo_info.get("created_at"))
    if pushed_at is not None and created_at is not None and created_at > 30:
        # Repo is > 30 days old but pushed_at is very recent — possible rewrite.
        # Use a heuristic: if pushed_at <= 1 day ago on an old repo, flag it.
        if pushed_at <= 1:
            score -= 20
            findings.append(Finding(
                message="Repository is old but was pushed to very recently — possible force-push or history rewrite.",
                severity=Severity.WARNING,
                details={
                    "pushed_at_days_ago": pushed_at,
                    "created_at_days_ago": created_at,
                    "penalty": -20,
                },
            ))

    # ------------------------------------------------------------------
    # 5. Finalize
    # ------------------------------------------------------------------
    score = max(0, score)
    severity = _score_to_severity(score)

    raw_data["score"] = score

    return ModuleResult(
        module_name="trust_score",
        severity=severity,
        findings=findings,
        raw_data=raw_data,
    )
