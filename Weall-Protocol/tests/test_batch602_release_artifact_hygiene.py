from __future__ import annotations

from pathlib import Path


def test_reviewer_artifact_pull_package_is_not_tracked_in_repo_root() -> None:
    assert not Path("batch490_reviewer_artifact_pull_package.zip").exists()
