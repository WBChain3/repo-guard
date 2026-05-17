"""
GitHub API client — single source of truth for all GitHub API calls.

Every module in this project fetches data through this client. It handles
URL parsing, authentication, rate-limit tracking, and error normalization
so that modules never deal with HTTP details.

Usage:
    client = GitHubClient(token="optional_pat")
    repo_info = client.get_repo_info("owner", "repo")
    tree = client.get_tree("owner", "repo")
    content = client.get_file_content("owner", "repo", "path/to/file")
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import requests


# ---------------------------------------------------------------------------
# URL parsing helpers
# ---------------------------------------------------------------------------

GITHUB_URL_PATTERN = re.compile(
    r"^https?://github\.com/(?P<owner>[A-Za-z0-9_.-]+)/(?P<repo>[A-Za-z0-9_.-]+?)(?:\.git)?(?:/.*)?$"
)


def parse_github_url(url: str) -> tuple[str, str]:
    """
    Parse a GitHub URL into (owner, repo).

    Accepts formats:
      - https://github.com/owner/repo
      - https://github.com/owner/repo.git
      - https://github.com/owner/repo/tree/branch/path

    Raises ValueError if the URL doesn't match.
    Returns (owner, repo) with .git suffix stripped from repo name.
    """
    match = GITHUB_URL_PATTERN.match(url.strip())
    if not match:
        raise ValueError(
            f"Invalid GitHub URL: {url!r}. Expected format: "
            f"https://github.com/owner/repo"
        )
    return match.group("owner"), match.group("repo")


# ---------------------------------------------------------------------------
# Custom exceptions so callers can handle errors by type
# ---------------------------------------------------------------------------


class GitHubClientError(Exception):
    """Base exception for all GitHubClient errors."""


class RateLimitError(GitHubClientError):
    """
    Raised when the API rate limit is exhausted.

    Attributes:
        reset_time: Unix timestamp of when the limit resets.
    """

    def __init__(self, reset_time: int, message: str | None = None) -> None:
        self.reset_time = reset_time
        reset_dt = datetime.fromtimestamp(reset_time, tz=timezone.utc)
        msg = message or (
            f"GitHub API rate limit exceeded. Resets at {reset_dt.isoformat()} "
            f"(in {(reset_time - time.time()) / 60:.1f} minutes). "
            f"Re-run with --token for 5000 req/hr."
        )
        super().__init__(msg)


class NotFoundError(GitHubClientError):
    """Raised when the requested resource (repo, user, file) doesn't exist."""


class PrivateRepoError(GitHubClientError):
    """Raised when a private repo is accessed without a valid token."""


# ---------------------------------------------------------------------------
# The client
# ---------------------------------------------------------------------------


@dataclass
class RateLimitInfo:
    """
    Tracks current rate limit state from API response headers.

    Populated after every API call so the CLI can display remaining quota.
    """
    remaining: int
    limit: int
    reset_time: int  # Unix timestamp


class GitHubClient:
    """
    Centralized GitHub API client.

    All HTTP logic lives here. Modules call high-level methods and receive
    parsed dicts or handle typed exceptions.

    Args:
        token: Optional GitHub Personal Access Token. Without it, rate limit
               is 60 requests/hour. With it, 5000 requests/hour.
        base_url: API base URL (default: https://api.github.com). Overridable
                  for testing with a mock server.
        timeout: Request timeout in seconds (default: 15).
    """

    API_BASE = "https://api.github.com"

    def __init__(
        self,
        token: str | None = None,
        base_url: str | None = None,
        timeout: int = 15,
    ) -> None:
        self.token = token
        self.base_url = base_url or self.API_BASE
        self.timeout = timeout
        self._session: requests.Session | None = None

        # Track rate limit info from the most recent response.
        self.rate_limit: RateLimitInfo | None = None

    # ------------------------------------------------------------------
    # Session management (lazy-initialized so we don't create connections
    # until the first API call)
    # ------------------------------------------------------------------

    @property
    def session(self) -> requests.Session:
        if self._session is None:
            self._session = requests.Session()
            if self.token:
                self._session.headers.update(
                    {"Authorization": f"Bearer {self.token}"}
                )
            self._session.headers.update(
                {"Accept": "application/vnd.github.v3+json"}
            )
            # Set a sensible User-Agent so GitHub can identify us.
            self._session.headers.update(
                {"User-Agent": "repo-guard/0.1.0"}
            )
        return self._session

    # ------------------------------------------------------------------
    # Core request method — all public methods route through this
    # ------------------------------------------------------------------

    def _request(self, method: str, path: str, **kwargs: Any) -> Any:
        """
        Perform an API request and return the parsed JSON body.

        Handles:
          - 404 → NotFoundError
          - 403 with rate limit headers → RateLimitError
          - 403 without rate limit (private repo, no token) → PrivateRepoError
          - Network errors → GitHubClientError with details
          - Non-2xx → GitHubClientError

        Stores rate limit info from response headers on self.rate_limit.
        """
        url = f"{self.base_url}{path}"
        try:
            resp = self.session.request(
                method, url, timeout=self.timeout, **kwargs
            )
        except requests.ConnectionError as exc:
            raise GitHubClientError(
                f"Network error connecting to {url}: {exc}"
            ) from exc
        except requests.Timeout as exc:
            raise GitHubClientError(
                f"Request timed out after {self.timeout}s: {url}"
            ) from exc
        except requests.RequestException as exc:
            raise GitHubClientError(
                f"Request failed: {exc}"
            ) from exc

        # Track rate limit from response headers (present on every response).
        self.rate_limit = RateLimitInfo(
            remaining=int(resp.headers.get("X-RateLimit-Remaining", 0)),
            limit=int(resp.headers.get("X-RateLimit-Limit", 0)),
            reset_time=int(resp.headers.get("X-RateLimit-Reset", 0)),
        )

        if resp.status_code == 404:
            raise NotFoundError(f"Resource not found: {url}")

        if resp.status_code == 403:
            remaining = resp.headers.get("X-RateLimit-Remaining", "0")
            if remaining == "0":
                reset_time = int(resp.headers.get("X-RateLimit-Reset", 0))
                raise RateLimitError(reset_time)
            # 403 without rate limit exhaustion usually means private repo.
            raise PrivateRepoError(
                "Private repository detected. Re-run with --token to scan "
                "private repositories."
            )

        if resp.status_code == 401:
            raise GitHubClientError(
                "Authentication failed. Check that your --token is valid "
                "and has not expired."
            )

        if not resp.ok:
            raise GitHubClientError(
                f"GitHub API returned {resp.status_code} for {url}: "
                f"{resp.text[:200]}"
            )

        # Some endpoints (like tree get) may return empty body on 204.
        if resp.status_code == 204:
            return None

        return resp.json()

    def _get(self, path: str, **kwargs: Any) -> Any:
        """Convenience wrapper for GET requests."""
        return self._request("GET", path, **kwargs)

    # ------------------------------------------------------------------
    # Repository metadata
    # ------------------------------------------------------------------

    def get_repo_info(self, owner: str, repo: str) -> dict[str, Any]:
        """
        Fetch repository metadata.

        Returns the full GitHub API response for the /repos/:owner/:repo endpoint.
        Includes created_at, pushed_at, description, language, fork count, etc.
        """
        return self._get(f"/repos/{owner}/{repo}")

    def get_user_info(self, username: str) -> dict[str, Any]:
        """
        Fetch user/account metadata.

        Returns the full GitHub API response for /users/:username.
        Includes created_at, public_repos, followers, following, etc.
        """
        return self._get(f"/users/{username}")

    def get_contributors(self, owner: str, repo: str) -> list[dict[str, Any]]:
        """
        Fetch the list of contributors for a repository.

        Returns a list of user objects (login, id, contributions count, etc.).
        An empty list means the repo has no contributors (possible for brand-new repos).
        """
        # The GET /repos/:owner/:repo/contributors endpoint returns an array.
        return self._get(f"/repos/{owner}/{repo}/contributors")

    def get_commits(self, owner: str, repo: str) -> list[dict[str, Any]]:
        """
        Fetch commit history for a repository.

        Returns a list of commit objects (sha, commit message, author, date, etc.).
        Limited to the most recent 100 commits by default (GitHub API pagination).
        """
        return self._get(f"/repos/{owner}/{repo}/commits?per_page=100")

    def get_repos_for_user(self, username: str) -> list[dict[str, Any]]:
        """
        Fetch all public repositories for a user.

        Used by the trust score module to count how many public repos a user has.
        Returns a list of repo objects.
        """
        return self._get(f"/users/{username}/repos?per_page=100&type=public")

    # ------------------------------------------------------------------
    # Tree / file content (no cloning)
    # ------------------------------------------------------------------

    def get_tree(self, owner: str, repo: str) -> list[dict[str, Any]]:
        """
        Fetch the recursive git tree for the default branch.

        Returns a list of tree entries, each with path, mode, type, sha, size.
        This is the primary way we discover repo structure without cloning.
        The tree is fetched recursively so we see all files.

        NOTE: The Git Trees API requires a tree SHA. We first fetch the repo
        info to get the default branch, then get the tree for that branch's
        latest commit.
        """
        repo_info = self.get_repo_info(owner, repo)
        default_branch = repo_info.get("default_branch", "main")

        # First get the reference to find the latest commit SHA on the default branch.
        ref_data = self._get(f"/repos/{owner}/{repo}/git/ref/heads/{default_branch}")
        commit_sha = ref_data["object"]["sha"]

        # Now get the commit to find the tree SHA.
        commit_data = self._get(f"/repos/{owner}/{repo}/git/commits/{commit_sha}")
        tree_sha = commit_data["tree"]["sha"]

        # Finally, get the recursive tree.
        tree_data = self._get(f"/repos/{owner}/{repo}/git/trees/{tree_sha}?recursive=1")
        return tree_data.get("tree", [])

    def get_file_content(self, owner: str, repo: str, path: str) -> str | None:
        """
        Fetch the contents of a single file via the GitHub Contents API.

        The API returns a base64-encoded payload. We decode it and return
        the UTF-8 string content. Returns None if the path is a directory.

        Raises NotFoundError if the file doesn't exist.
        """
        data = self._get(f"/repos/{owner}/{repo}/contents/{path}")

        # If the response is a list, it's a directory — return None.
        if isinstance(data, list):
            return None

        encoding = data.get("encoding")
        content = data.get("content", "")

        if encoding == "base64":
            import base64
            try:
                decoded = base64.b64decode(content).decode("utf-8")
            except (ValueError, UnicodeDecodeError):
                # Binary file or encoding issue — return raw content indicator.
                return None
            return decoded

        # Fallback for non-base64 content (unusual but handle gracefully).
        return content

    def check_user_exists(self, username: str) -> bool:
        """
        Check if a GitHub user account exists (not suspended or deleted).

        Returns True if the user exists and is active, False if the
        account has been deleted or suspended (404 or certain 403s).
        """
        try:
            self.get_user_info(username)
            return True
        except NotFoundError:
            return False
        except GitHubClientError:
            # A suspended account might return 403; treat as non-existent.
            return False

    # ------------------------------------------------------------------
    # Rate limit check (without consuming a request)
    # ------------------------------------------------------------------

    def get_rate_limit_status(self) -> dict[str, Any]:
        """
        Fetch current rate limit status from the /rate_limit endpoint.

        This call itself consumes one request against the limit, but provides
        detailed info about remaining requests for both authenticated and
        unauthenticated endpoints.

        Use this for display purposes (e.g., --verbose flag) rather than
        before every API call.
        """
        return self._get("/rate_limit")
