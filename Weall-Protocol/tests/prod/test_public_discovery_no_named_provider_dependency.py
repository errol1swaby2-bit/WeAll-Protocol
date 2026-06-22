from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _forbidden_terms() -> list[str]:
    # Construct the removed provider name so this guard does not itself re-add
    # the literal reference it is designed to prevent.
    provider = "Cloud" + "flare"
    return [
        provider,
        provider.lower(),
        provider.lower() + "d",
        "workers" + ".dev",
        "pages" + ".dev",
        "registry.weallprotocol" + ".xyz",
        "orange " + "cloud",
    ]


def _project_files() -> list[Path]:
    skipped_dirs = {".git", ".venv", "__pycache__", ".pytest_cache", "node_modules", "secrets"}
    files: list[Path] = []
    for path in ROOT.parent.rglob("*"):
        if not path.is_file():
            continue
        if any(part in skipped_dirs for part in path.parts):
            continue
        if path.suffix.lower() in {".png", ".jpg", ".jpeg", ".webp", ".zip", ".sqlite", ".db"}:
            continue
        files.append(path)
    return files


def test_project_controlled_files_have_no_named_provider_references() -> None:
    offenders: list[str] = []
    for path in _project_files():
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        rel = path.relative_to(ROOT.parent).as_posix()
        for term in _forbidden_terms():
            if term in text:
                offenders.append(f"{rel}: {term}")
    assert offenders == []
