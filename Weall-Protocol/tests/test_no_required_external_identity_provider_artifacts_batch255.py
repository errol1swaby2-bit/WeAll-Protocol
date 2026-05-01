from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def join(*parts: str) -> str:
    return "".join(parts)


FORBIDDEN_REQUIRED_PATH_MARKERS = (
    join("prod_", "email_", "oracle"),
    join("prod_", "poh_", "email_", "oracle"),
    join("/poh/", "email"),
    join("poh/", "email"),
    join("VITE_", "WEALL_", "EMAIL"),
    join("WEALL_", "EMAIL"),
    join("WEALL_", "SM", "TP"),
    join("WEALL_", "MOCK_", "EMAIL"),
)

SCAN_PATHS = (
    ROOT / "scripts",
    ROOT / "docker-compose.yml",
    ROOT / "src/weall/api/schemas.py",
)


def iter_files(path: Path):
    if path.is_file():
        yield path
        return

    for candidate in path.rglob("*"):
        if candidate.is_file() and candidate.suffix in {
            ".py",
            ".sh",
            ".yml",
            ".yaml",
            ".json",
            ".md",
            ".txt",
        }:
            yield candidate


def test_required_scripts_and_runtime_do_not_reference_external_identity_poh_artifacts() -> None:
    hits: list[str] = []

    for base in SCAN_PATHS:
        if not base.exists():
            continue

        for path in iter_files(base):
            text = path.read_text(encoding="utf-8", errors="replace")
            for marker in FORBIDDEN_REQUIRED_PATH_MARKERS:
                if marker in text:
                    hits.append(
                        f"{path.relative_to(ROOT)} contains removed required external-identity marker {marker!r}"
                    )

    assert not hits, "\n".join(hits[:100])
