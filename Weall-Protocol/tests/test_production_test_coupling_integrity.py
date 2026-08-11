from __future__ import annotations

from pathlib import Path


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _production_source_files() -> list[Path]:
    src = _repo_root() / "src" / "weall"
    return sorted(
        path for path in src.rglob("*.py") if "testing" not in path.relative_to(src).parts
    )


def test_production_source_does_not_detect_pytest() -> None:
    forbidden = (
        "PYTEST_CURRENT_TEST",
        '"pytest" in sys.modules',
        "'pytest' in sys.modules",
        "import pytest",
        "from pytest",
    )
    findings: list[str] = []
    for path in _production_source_files():
        text = path.read_text(encoding="utf-8")
        for token in forbidden:
            if token in text:
                findings.append(f"{path.relative_to(_repo_root())}:{token}")
    assert findings == []


def test_production_source_does_not_import_testing_package() -> None:
    findings = [
        str(path.relative_to(_repo_root()))
        for path in _production_source_files()
        if "weall.testing" in path.read_text(encoding="utf-8")
    ]
    assert findings == []
