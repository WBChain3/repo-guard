"""
Tests for github_client.py — URL parsing, API calls, error handling.

All HTTP responses are mocked using the `responses` library. No live
GitHub API calls are made in this test suite.
"""

import json

import pytest
import requests
import responses

# Shared mock rate-limit headers used across all test classes.
RH = {
    "X-RateLimit-Remaining": "4999",
    "X-RateLimit-Limit": "5000",
    "X-RateLimit-Reset": "2000000000",
}

from repo_guard.github_client import (
    GitHubClient,
    GitHubClientError,
    NotFoundError,
    PrivateRepoError,
    RateLimitError,
    parse_github_url,
)


# ---------------------------------------------------------------------------
# URL parsing
# ---------------------------------------------------------------------------


class TestParseGithubUrl:
    """Verify parse_github_url handles all expected URL formats."""

    def test_standard_url(self):
        owner, repo = parse_github_url("https://github.com/octocat/Hello-World")
        assert owner == "octocat"
        assert repo == "Hello-World"

    def test_with_git_suffix(self):
        owner, repo = parse_github_url("https://github.com/octocat/Hello-World.git")
        assert owner == "octocat"
        assert repo == "Hello-World"

    def test_with_trailing_path(self):
        owner, repo = parse_github_url("https://github.com/octocat/Hello-World/tree/main/src")
        assert owner == "octocat"
        assert repo == "Hello-World"

    def test_with_blob_path(self):
        owner, repo = parse_github_url("https://github.com/octocat/Hello-World/blob/main/README.md")
        assert owner == "octocat"
        assert repo == "Hello-World"

    def test_rejects_invalid_url(self):
        with pytest.raises(ValueError, match="Invalid GitHub URL"):
            parse_github_url("https://gitlab.com/owner/repo")

    def test_rejects_missing_repo(self):
        with pytest.raises(ValueError, match="Invalid GitHub URL"):
            parse_github_url("https://github.com/octocat")

    def test_rejects_empty_string(self):
        with pytest.raises(ValueError, match="Invalid GitHub URL"):
            parse_github_url("")

    def test_allows_dots_and_dashes(self):
        owner, repo = parse_github_url("https://github.com/org.team/my-repo_123")
        assert owner == "org.team"
        assert repo == "my-repo_123"


# ---------------------------------------------------------------------------
# GitHubClient
# ---------------------------------------------------------------------------

MOCK_API_BASE = "https://api.github.com"


class TestGitHubClientInit:
    """Verify client initialization defaults."""

    def test_default_base_url(self):
        client = GitHubClient()
        assert client.base_url == "https://api.github.com"

    def test_custom_base_url(self):
        client = GitHubClient(base_url="http://localhost:9999")
        assert client.base_url == "http://localhost:9999"

    def test_token_stored(self):
        client = GitHubClient(token="ghp_fake_token")
        assert client.token == "ghp_fake_token"

    def test_session_is_lazy(self):
        client = GitHubClient()
        assert client._session is None
        _ = client.session
        assert client._session is not None


class TestGitHubClientGetRepoInfo:
    """Test the get_repo_info endpoint with mocked HTTP."""

    @responses.activate
    def test_success(self):
        client = GitHubClient(base_url=MOCK_API_BASE)
        mock_response = {
            "id": 1,
            "name": "Hello-World",
            "full_name": "octocat/Hello-World",
            "owner": {"login": "octocat", "id": 1},
            "private": False,
            "description": "A test repo",
            "created_at": "2024-01-01T00:00:00Z",
            "pushed_at": "2024-06-01T00:00:00Z",
            "size": 100,
            "default_branch": "main",
        }
        responses.get(
            f"{MOCK_API_BASE}/repos/octocat/Hello-World",
            json=mock_response,
            status=200,
            headers={"X-RateLimit-Remaining": "4999", "X-RateLimit-Limit": "5000", "X-RateLimit-Reset": "2000000000"},
        )

        result = client.get_repo_info("octocat", "Hello-World")
        assert result["name"] == "Hello-World"
        assert result["owner"]["login"] == "octocat"
        assert client.rate_limit is not None
        assert client.rate_limit.remaining == 4999

    @responses.activate
    def test_404_raises_not_found(self):
        client = GitHubClient(base_url=MOCK_API_BASE)
        responses.get(
            f"{MOCK_API_BASE}/repos/octocat/nonexistent",
            json={"message": "Not Found"},
            status=404,
            headers={"X-RateLimit-Remaining": "4999", "X-RateLimit-Limit": "5000", "X-RateLimit-Reset": "2000000000"},
        )

        with pytest.raises(NotFoundError, match="Resource not found"):
            client.get_repo_info("octocat", "nonexistent")

    @responses.activate
    def test_rate_limit_exhausted(self):
        client = GitHubClient(base_url=MOCK_API_BASE)
        responses.get(
            f"{MOCK_API_BASE}/repos/octocat/Hello-World",
            json={"message": "API rate limit exceeded"},
            status=403,
            headers={
                "X-RateLimit-Remaining": "0",
                "X-RateLimit-Limit": "60",
                "X-RateLimit-Reset": "2000000000",
            },
        )

        with pytest.raises(RateLimitError):
            client.get_repo_info("octocat", "Hello-World")

    @responses.activate
    def test_private_repo_without_token(self):
        client = GitHubClient(base_url=MOCK_API_BASE)
        responses.get(
            f"{MOCK_API_BASE}/repos/octocat/private-repo",
            json={"message": "Not Found"},
            status=403,
            headers={
                "X-RateLimit-Remaining": "58",
                "X-RateLimit-Limit": "60",
                "X-RateLimit-Reset": "2000000000",
            },
        )

        with pytest.raises(PrivateRepoError, match="Private repository detected"):
            client.get_repo_info("octocat", "private-repo")

    @responses.activate
    def test_401_raises_error(self):
        client = GitHubClient(token="ghp_bad", base_url=MOCK_API_BASE)
        responses.get(
            f"{MOCK_API_BASE}/repos/octocat/Hello-World",
            json={"message": "Bad credentials"},
            status=401,
            headers={"X-RateLimit-Remaining": "58", "X-RateLimit-Limit": "60", "X-RateLimit-Reset": "2000000000"},
        )

        with pytest.raises(GitHubClientError, match="Authentication failed"):
            client.get_repo_info("octocat", "Hello-World")

    @responses.activate
    def test_network_error_wrapped(self):
        client = GitHubClient(base_url=MOCK_API_BASE)
        responses.get(
            f"{MOCK_API_BASE}/repos/octocat/Hello-World",
            body=requests.ConnectionError("Connection refused"),
        )

        with pytest.raises(GitHubClientError, match="Network error"):
            client.get_repo_info("octocat", "Hello-World")


class TestGitHubClientTreeAndFiles:
    """Test tree and file content endpoints."""

    @responses.activate
    def test_get_tree_success(self):
        client = GitHubClient(base_url=MOCK_API_BASE)
        repo_info = {
            "default_branch": "main",
            "name": "repo",
        }
        ref_data = {
            "object": {"sha": "commit_sha_abc"}
        }
        commit_data = {
            "tree": {"sha": "tree_sha_xyz"}
        }
        tree_data = {
            "sha": "tree_sha_xyz",
            "tree": [
                {"path": "README.md", "type": "blob", "sha": "abc", "size": 100},
                {"path": ".githooks", "type": "tree", "sha": "def", "size": 0},
                {"path": ".githooks/post-checkout", "type": "blob", "sha": "ghi", "size": 500},
            ],
        }

        responses.get(f"{MOCK_API_BASE}/repos/o/r", json=repo_info, status=200, headers=RH)
        responses.get(f"{MOCK_API_BASE}/repos/o/r/git/ref/heads/main", json=ref_data, status=200, headers=RH)
        responses.get(f"{MOCK_API_BASE}/repos/o/r/git/commits/commit_sha_abc", json=commit_data, status=200, headers=RH)
        responses.get(
            f"{MOCK_API_BASE}/repos/o/r/git/trees/tree_sha_xyz?recursive=1",
            json=tree_data,
            status=200,
            headers=RH,
        )

        tree = client.get_tree("o", "r")
        paths = [entry["path"] for entry in tree]
        assert "README.md" in paths
        assert ".githooks/post-checkout" in paths
        assert len(tree) == 3

    @responses.activate
    def test_get_file_content_success(self):
        import base64
        content_str = "#!/bin/bash\necho 'hello'"
        encoded = base64.b64encode(content_str.encode()).decode()

        client = GitHubClient(base_url=MOCK_API_BASE)
        responses.get(
            f"{MOCK_API_BASE}/repos/o/r/contents/.githooks/post-checkout",
            json={
                "name": "post-checkout",
                "path": ".githooks/post-checkout",
                "content": encoded,
                "encoding": "base64",
            },
            status=200,
            headers=RH,
        )

        content = client.get_file_content("o", "r", ".githooks/post-checkout")
        assert content == content_str

    @responses.activate
    def test_get_file_content_directory_returns_none(self):
        client = GitHubClient(base_url=MOCK_API_BASE)
        responses.get(
            f"{MOCK_API_BASE}/repos/o/r/contents/.githooks",
            json=[
                {"name": "post-checkout", "type": "file"}
            ],
            status=200,
            headers=RH,
        )

        content = client.get_file_content("o", "r", ".githooks")
        assert content is None

    @responses.activate
    def test_get_file_content_not_found(self):
        client = GitHubClient(base_url=MOCK_API_BASE)
        responses.get(
            f"{MOCK_API_BASE}/repos/o/r/contents/nonexistent.py",
            json={"message": "Not Found"},
            status=404,
            headers=RH,
        )

        with pytest.raises(NotFoundError):
            client.get_file_content("o", "r", "nonexistent.py")


class TestGitHubClientUsers:
    """Test user/contributor endpoints."""

    @responses.activate
    def test_get_user_info(self):
        client = GitHubClient(base_url=MOCK_API_BASE)
        responses.get(
            f"{MOCK_API_BASE}/users/octocat",
            json={
                "login": "octocat",
                "id": 1,
                "created_at": "2024-01-01T00:00:00Z",
                "public_repos": 5,
                "followers": 10,
                "following": 3,
            },
            status=200,
            headers=RH,
        )

        user = client.get_user_info("octocat")
        assert user["login"] == "octocat"
        assert user["public_repos"] == 5

    @responses.activate
    def test_get_contributors(self):
        client = GitHubClient(base_url=MOCK_API_BASE)
        responses.get(
            f"{MOCK_API_BASE}/repos/o/r/contributors",
            json=[
                {"login": "alice", "id": 10, "contributions": 42},
                {"login": "bob", "id": 20, "contributions": 13},
            ],
            status=200,
            headers=RH,
        )

        contributors = client.get_contributors("o", "r")
        assert len(contributors) == 2
        assert contributors[0]["login"] == "alice"

    @responses.activate
    def test_check_user_exists_returns_true(self):
        client = GitHubClient(base_url=MOCK_API_BASE)
        responses.get(f"{MOCK_API_BASE}/users/alice", json={"login": "alice"}, status=200, headers=RH)
        assert client.check_user_exists("alice") is True

    @responses.activate
    def test_check_user_exists_returns_false_on_404(self):
        client = GitHubClient(base_url=MOCK_API_BASE)
        responses.get(f"{MOCK_API_BASE}/users/deleted", json={"message": "Not Found"}, status=404, headers=RH)
        assert client.check_user_exists("deleted") is False

    @responses.activate
    def test_check_user_exists_returns_false_on_403(self):
        client = GitHubClient(base_url=MOCK_API_BASE)
        responses.get(
            f"{MOCK_API_BASE}/users/suspended",
            json={"message": "User suspended"},
            status=403,
            headers={"X-RateLimit-Remaining": "50", "X-RateLimit-Limit": "60", "X-RateLimit-Reset": "2000000000"},
        )
        assert client.check_user_exists("suspended") is False



