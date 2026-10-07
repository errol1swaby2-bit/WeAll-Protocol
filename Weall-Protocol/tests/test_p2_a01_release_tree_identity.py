from __future__ import annotations

import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _git(*args: str, cwd: Path = ROOT) -> str:
    proc = subprocess.run(
        ["git", *args],
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
    )
    return proc.stdout.strip()


def test_runtime_release_manifest_binds_exact_git_tree() -> None:
    proc = subprocess.run(
        ["python", "scripts/gen_release_evidence_manifest_v1_5.py", "--runtime-json"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["git_head"] == _git("rev-parse", "HEAD")
    assert payload["git_tree"] == _git("rev-parse", "HEAD^{tree}")
    assert len(payload["git_tree"]) == 40
    assert "whole tracked release-tree identity" in payload["release_identity_semantics"]


def test_build_only_tracked_mutation_changes_release_tree_identity(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git("init", "-q", cwd=repo)

    dockerfile = repo / "Dockerfile"
    dockerfile.write_text("FROM python:3.12\n", encoding="utf-8")
    _git("add", "Dockerfile", cwd=repo)
    before = _git("write-tree", cwd=repo)

    dockerfile.write_text("FROM python:3.12\nENV WEALL_BUILD=2\n", encoding="utf-8")
    _git("add", "Dockerfile", cwd=repo)
    after = _git("write-tree", cwd=repo)

    assert before != after


def test_v2_docs_do_not_present_source_digest_as_release_fingerprint() -> None:
    text = (ROOT / "docs" / "V2_SPEC_COMPILER.md").read_text(encoding="utf-8")
    assert "source_tree_digest" in text
    assert "not** a fingerprint of every tracked build" in text
    assert "--runtime-json" in text
    assert "git_tree" in text
