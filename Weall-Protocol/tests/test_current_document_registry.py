from __future__ import annotations

import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = ROOT.parent


def _load_checker_module():
    import importlib.util

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
    assert registry["release_dependency_sources"]
    assert registry["required_current_paths"]
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
    assert "unclassified release dependency document" in text


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


def test_release_dependency_documents_are_explicitly_current() -> None:
    checker = _load_checker_module()
    registry = json.loads(
        (ROOT / "docs/CURRENT_DOCUMENT_REGISTRY.json").read_text(encoding="utf-8")
    )
    exact = {entry["path"]: entry for entry in registry["documents"]}

    for source in registry["release_dependency_sources"]:
        paths = checker._extract_release_dependency_paths(
            REPO_ROOT / source["path"], set(source["constant_names"])
        )
        assert paths
        for raw_path in paths:
            assert raw_path in exact
            assert exact[raw_path]["classification"] == "CURRENT"
            path = REPO_ROOT / raw_path
            if checker._has_current_claim_marker(path):
                assert exact[raw_path]["claim_scan"] is True


def test_release_dependency_fails_closed_when_unclassified(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    checker = _load_checker_module()
    (tmp_path / "Weall-Protocol/docs").mkdir(parents=True)
    (tmp_path / "Weall-Protocol/scripts").mkdir(parents=True)
    (tmp_path / "Weall-Protocol/docs/CURRENT.md").write_text(
        "Current allowed claim: bounded only.\n", encoding="utf-8"
    )
    (tmp_path / "Weall-Protocol/scripts/release_source.py").write_text(
        'REQUIRED_DOCS = {"current": "docs/CURRENT.md"}\nFLOW_DOCS = {}\n',
        encoding="utf-8",
    )
    registry = {
        "documents": [],
        "coverage_globs": ["NO_MATCH_*.md"],
        "prefix_classifications": [],
        "release_dependency_sources": [
            {
                "path": "Weall-Protocol/scripts/release_source.py",
                "constant_names": ["REQUIRED_DOCS", "FLOW_DOCS"],
            }
        ],
        "required_current_paths": [],
    }
    monkeypatch.setattr(checker, "REPO_ROOT", tmp_path)
    with pytest.raises(
        SystemExit,
        match="unclassified release dependency document: Weall-Protocol/docs/CURRENT.md",
    ):
        checker.registered_scan_paths(registry)


def test_release_dependency_current_claim_marker_requires_scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    checker = _load_checker_module()
    (tmp_path / "Weall-Protocol/docs").mkdir(parents=True)
    (tmp_path / "Weall-Protocol/scripts").mkdir(parents=True)
    (tmp_path / "Weall-Protocol/docs/CURRENT.md").write_text(
        "Current allowed claim: bounded only.\n", encoding="utf-8"
    )
    (tmp_path / "Weall-Protocol/scripts/release_source.py").write_text(
        'REQUIRED_DOCS = {"current": "docs/CURRENT.md"}\nFLOW_DOCS = {}\n',
        encoding="utf-8",
    )
    registry = {
        "documents": [
            {
                "path": "Weall-Protocol/docs/CURRENT.md",
                "classification": "CURRENT",
                "claim_scan": False,
            }
        ],
        "coverage_globs": ["NO_MATCH_*.md"],
        "prefix_classifications": [],
        "release_dependency_sources": [
            {
                "path": "Weall-Protocol/scripts/release_source.py",
                "constant_names": ["REQUIRED_DOCS", "FLOW_DOCS"],
            }
        ],
        "required_current_paths": [],
    }
    monkeypatch.setattr(checker, "REPO_ROOT", tmp_path)
    with pytest.raises(
        SystemExit,
        match="release dependency current-claim document must set claim_scan=true",
    ):
        checker.registered_scan_paths(registry)


def test_blocker_count_markdown_table_is_guarded() -> None:
    checker = _load_checker_module()
    assert checker.BLOCKER_COUNT_TABLE.search("| `p0_open_count` | 4 |")


def test_active_source_claim_scan_is_clean() -> None:
    checker = _load_checker_module()
    assert checker.source_claim_findings() == []


def test_source_claim_guard_rejects_affirmative_overclaim(tmp_path: Path) -> None:
    checker = _load_checker_module()
    source_root = tmp_path / "src"
    source_root.mkdir()
    (source_root / "overclaim.py").write_text(
        '"""Module is production-ready; canon-correct."""\n', encoding="utf-8"
    )
    findings = checker.source_claim_findings(source_root)
    assert len(findings) == 1
    assert "affirmative source release-readiness overclaim" in findings[0]


def test_source_claim_guard_allows_explicit_negation(tmp_path: Path) -> None:
    checker = _load_checker_module()
    source_root = tmp_path / "src"
    source_root.mkdir()
    (source_root / "bounded.py").write_text(
        "# This is not a claim that the mechanism\n# is production ready.\n",
        encoding="utf-8",
    )
    assert checker.source_claim_findings(source_root) == []


def test_source_claim_guard_rejects_embedded_canon_version(tmp_path: Path) -> None:
    checker = _load_checker_module()
    source_root = tmp_path / "src"
    source_root.mkdir()
    (source_root / "stale.py").write_text(
        '"""Canon Indexing txs (v1.22.1) = 8:"""\n', encoding="utf-8"
    )
    findings = checker.source_claim_findings(source_root)
    assert len(findings) == 1
    assert "embedded mutable canon-version label" in findings[0]
