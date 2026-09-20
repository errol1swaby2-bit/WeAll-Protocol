from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = ROOT.parent


def _load_checker_module():
    path = ROOT / "scripts/check_public_claim_freshness.py"
    spec = importlib.util.spec_from_file_location("check_public_claim_freshness_testmod", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_current_document_registry_is_unique_and_resolvable() -> None:
    registry = json.loads(
        (ROOT / "docs/CURRENT_DOCUMENT_REGISTRY.json").read_text(encoding="utf-8")
    )
    assert registry["schema_version"] == 1
    assert registry["coverage_globs"]
    docs = registry["documents"]
    paths = [entry["path"] for entry in docs]
    assert len(paths) == len(set(paths))
    assert any(entry["classification"] == "CURRENT" for entry in docs)
    assert "RELEASE_CHECKLIST.md" in paths
    for entry in docs:
        assert (REPO_ROOT / entry["path"]).is_file()
        if entry.get("claim_scan"):
            assert entry["classification"] == "CURRENT"


def test_claim_freshness_checker_is_registry_driven() -> None:
    text = (ROOT / "scripts/check_public_claim_freshness.py").read_text(encoding="utf-8")
    assert "CURRENT_DOCUMENT_REGISTRY.json" in text
    assert "CURRENT_DOCS =" not in text
    assert "claim_scan=true requires CURRENT classification" in text
    assert "unclassified covered document" in text


def test_coverage_glob_fails_closed_for_unclassified_document(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    checker = _load_checker_module()
    (tmp_path / "README.md").write_text("# current\n", encoding="utf-8")
    (tmp_path / "UNCLASSIFIED.md").write_text("# should fail\n", encoding="utf-8")
    registry = {
        "documents": [{"path": "README.md", "classification": "CURRENT", "claim_scan": True}],
        "coverage_globs": ["*.md"],
        "prefix_classifications": [],
    }
    monkeypatch.setattr(checker, "REPO_ROOT", tmp_path)
    with pytest.raises(SystemExit, match="unclassified covered document: UNCLASSIFIED.md"):
        checker.registered_scan_paths(registry)
