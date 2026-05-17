"""
Tests for trust_score module — Module 1.

All GitHubClient API calls are mocked. No live network.
Test fixtures cover: old accounts, new accounts, single-commit repos,
suspended contributors, force-push heuristics.
"""

from datetime import datetime, timezone
from unittest.mock import Mock

from repo_guard.models import Severity
from repo_guard.modules.trust_score import scan, _days_ago, _score_to_severity


# ---------------------------------------------------------------------------
# Helper: build a mock GitHubClient
# ---------------------------------------------------------------------------


def _mock_client(
    user_info: dict | None = None,
    repo_info: dict | None = None,
    contributors: list[dict] | None = None,
    commits: list[dict] | None = None,
    check_user_exists_result: bool = True,
) -> Mock:
    """Build a mock GitHubClient with controllable return values."""
    client = Mock()
    client.get_user_info.return_value = user_info or {
        "created_at": "2024-01-01T00:00:00Z",
        "public_repos": 5,
        "followers": 10,
        "following": 3,
    }
    client.get_repo_info.return_value = repo_info or {
        "name": "test-repo",
        "created_at": "2026-04-01T00:00:00Z",
        "pushed_at": datetime.now(timezone.utc).isoformat(),
    }
    client.get_contributors.return_value = contributors or []
    client.get_commits.return_value = commits or [
        {"sha": "abc123", "commit": {"author": {"date": "2026-05-01T00:00:00Z"}}},
        {"sha": "def456", "commit": {"author": {"date": "2026-05-15T00:00:00Z"}}},
    ]
    client.check_user_exists.return_value = check_user_exists_result
    return client


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


class TestDaysAgo:
    def test_valid_date(self):
        result = _days_ago("2024-01-01T00:00:00Z")
        assert result is not None
        assert result > 365  # Should be well over a year

    def test_none_returns_none(self):
        assert _days_ago(None) is None

    def test_empty_string_returns_none(self):
        assert _days_ago("") is None

    def test_bad_string_returns_none(self):
        assert _days_ago("not-a-date") is None


class TestScoreToSeverity:
    def test_0_returns_critical(self):
        assert _score_to_severity(0) == Severity.CRITICAL
        assert _score_to_severity(25) == Severity.CRITICAL
        assert _score_to_severity(49) == Severity.CRITICAL

    def test_50_returns_warning(self):
        assert _score_to_severity(50) == Severity.WARNING
        assert _score_to_severity(69) == Severity.WARNING

    def test_70_returns_info(self):
        assert _score_to_severity(70) == Severity.INFO
        assert _score_to_severity(89) == Severity.INFO

    def test_90_returns_clean(self):
        assert _score_to_severity(90) == Severity.CLEAN
        assert _score_to_severity(100) == Severity.CLEAN


# ---------------------------------------------------------------------------
# Trust score scan tests
# ---------------------------------------------------------------------------


class TestTrustScoreBaseline:
    """A well-established account and repo should score CLEAN or INFO."""

    def test_mature_account_returns_clean_or_info(self):
        client = _mock_client()
        result = scan(client, "owner", "repo")
        assert result.module_name == "trust_score"
        assert isinstance(result.raw_data["score"], int)
        # Mature account (2024), >2 repos, >0 followers, >1 commit → high score
        assert result.severity in (Severity.CLEAN, Severity.INFO)
        assert result.raw_data["score"] >= 70


class TestTrustScoreNewAccount:
    """Brand-new accounts should lose significant points."""

    def test_account_under_30_days_loses_30_points(self):
        recent = datetime.now(timezone.utc).isoformat()
        user_info = {
            "created_at": recent,
            "public_repos": 10,
            "followers": 5,
            "following": 1,
        }
        client = _mock_client(user_info=user_info)
        result = scan(client, "owner", "repo")
        assert result.raw_data["score"] <= 70  # 100 - 30
        assert result.severity in (Severity.INFO, Severity.WARNING, Severity.CRITICAL)

    def test_account_30_to_180_days_loses_15_points(self):
        # Created 90 days ago
        from datetime import timedelta
        old = (datetime.now(timezone.utc) - timedelta(days=90)).isoformat()
        user_info = {
            "created_at": old,
            "public_repos": 10,
            "followers": 5,
            "following": 1,
        }
        client = _mock_client(user_info=user_info)
        result = scan(client, "owner", "repo")
        # 100 - 15 = 85, minus any other penalties
        assert result.raw_data["score"] <= 85

    def test_zero_followers_loses_5_points(self):
        user_info = {
            "created_at": "2024-01-01T00:00:00Z",
            "public_repos": 10,
            "followers": 0,
            "following": 1,
        }
        client = _mock_client(user_info=user_info)
        result = scan(client, "owner", "repo")
        finding_messages = [f.message for f in result.findings]
        assert any("zero followers" in m.lower() for m in finding_messages)

    def test_fewer_than_3_repos_loses_5_points(self):
        user_info = {
            "created_at": "2024-01-01T00:00:00Z",
            "public_repos": 1,
            "followers": 10,
            "following": 1,
        }
        client = _mock_client(user_info=user_info)
        result = scan(client, "owner", "repo")
        finding_messages = [f.message for f in result.findings]
        assert any("only 1 public repo" in m.lower() for m in finding_messages)


class TestTrustScoreRepoSignals:
    """Repository-level signals."""

    def test_repo_under_30_days_loses_20_points(self):
        recent = datetime.now(timezone.utc).isoformat()
        repo_info = {
            "name": "new-repo",
            "created_at": recent,
            "pushed_at": recent,
        }
        client = _mock_client(repo_info=repo_info)
        result = scan(client, "owner", "repo")
        finding_messages = [f.message for f in result.findings]
        assert any("younger than 30 days" in m.lower() or "< 30" in m for m in finding_messages)

    def test_single_commit_loses_15_points(self):
        commits = [{"sha": "abc", "commit": {"author": {"date": "2026-05-01T00:00:00Z"}}}]
        client = _mock_client(commits=commits)
        result = scan(client, "owner", "repo")
        finding_messages = [f.message for f in result.findings]
        assert any("single commit" in m.lower() for m in finding_messages)


class TestTrustScoreContributors:
    """Suspended or deleted contributors."""

    def test_suspended_contributor_loses_25_points(self):
        contributors = [{"login": "alice"}, {"login": "bob"}]
        client = _mock_client(contributors=contributors, check_user_exists_result=False)
        result = scan(client, "owner", "repo")
        # Two contributors, both suspended = 2 * 25
        finding_messages = [f.message for f in result.findings]
        suspended = [m for m in finding_messages if "suspended or deleted" in m.lower()]
        assert len(suspended) == 2

    def test_healthy_contributors_no_penalty(self):
        contributors = [{"login": "alice"}, {"login": "bob"}]
        client = _mock_client(contributors=contributors, check_user_exists_result=True)
        result = scan(client, "owner", "repo")
        finding_messages = [f.message for f in result.findings]
        suspended = [m for m in finding_messages if "suspended or deleted" in m.lower()]
        assert len(suspended) == 0

    def test_no_contributors_no_penalty(self):
        client = _mock_client(contributors=[])
        result = scan(client, "owner", "repo")
        finding_messages = [f.message for f in result.findings]
        suspended = [m for m in finding_messages if "suspended or deleted" in m.lower()]
        assert len(suspended) == 0


class TestTrustScoreForcePush:
    """Force-push heuristic: old repo, very recent push."""

    def test_old_repo_recent_push_triggers_force_push_flag(self):
        from datetime import timedelta
        created = (datetime.now(timezone.utc) - timedelta(days=100)).isoformat()
        pushed = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        repo_info = {
            "name": "suspicious-repo",
            "created_at": created,
            "pushed_at": pushed,
        }
        client = _mock_client(repo_info=repo_info)
        result = scan(client, "owner", "repo")
        finding_messages = [f.message for f in result.findings]
        assert any("force-push" in m.lower() for m in finding_messages)

    def test_normal_push_no_flag(self):
        repo_info = {
            "name": "normal-repo",
            "created_at": "2024-01-01T00:00:00Z",
            "pushed_at": "2025-06-01T00:00:00Z",  # Old push, old repo, normal
        }
        client = _mock_client(repo_info=repo_info)
        result = scan(client, "owner", "repo")
        finding_messages = [f.message for f in result.findings]
        force_push_flags = [m for m in finding_messages if "force-push" in m.lower()]
        assert len(force_push_flags) == 0


class TestTrustScoreEdgeCases:
    """Edge cases: API failures, missing data, etc."""

    def test_api_failure_on_user_info_does_not_crash(self):
        """If get_user_info raises, the module should handle it gracefully."""
        client = Mock()
        client.get_user_info.side_effect = Exception("API error")
        client.get_repo_info.return_value = {}
        client.get_contributors.return_value = []
        client.get_commits.return_value = []
        client.check_user_exists.return_value = True

        result = scan(client, "owner", "repo")
        assert result.module_name == "trust_score"
        assert isinstance(result.raw_data["score"], int)

    def test_score_floor_is_zero(self):
        """Score should never go below 0."""
        user_info = {
            "created_at": datetime.now(timezone.utc).isoformat(),
            "public_repos": 0,
            "followers": 0,
            "following": 0,
        }
        contributors = [{"login": f"sus{i}"} for i in range(10)]
        client = _mock_client(
            user_info=user_info,
            contributors=contributors,
            check_user_exists_result=False,
            commits=[{"sha": "abc", "commit": {"author": {"date": "2026-05-01T00:00:00Z"}}}],
        )
        result = scan(client, "owner", "repo")
        assert result.raw_data["score"] >= 0
