"""
Shared test fixtures and helpers for repo-guard tests.

Provides:
  - Path constants for fixture directories
  - load_fixture() helper for reading fixture files from disk
"""

import os

import pytest

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")
FLEXPAY_DIR = os.path.join(FIXTURES_DIR, "flexpay_mock")
CLEAN_DIR = os.path.join(FIXTURES_DIR, "clean_repo")


def load_fixture(relative_path: str, base_dir: str | None = None) -> str:
    """
    Load a fixture file from disk and return its content.

    Args:
        relative_path: Path relative to the fixture directory (e.g. ".githooks/post-checkout").
        base_dir: Base fixture directory. Defaults to flexpay_mock.

    Returns:
        File contents as a string.
    """
    if base_dir is None:
        base_dir = FLEXPAY_DIR
    file_path = os.path.join(base_dir, relative_path)
    with open(file_path, "r") as f:
        return f.read()
