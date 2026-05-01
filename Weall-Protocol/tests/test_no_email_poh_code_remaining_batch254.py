from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def join(*parts: str) -> str:
    return "".join(parts)


FORBIDDEN = (
    join("POH_", "EMAIL_", "ATTESTATION_", "SUBMIT"),
    join("ORACLE_", "REGISTER"),
    join("ORACLE_", "SUSPEND"),
    join("ORACLE_", "ROTATE_", "KEY"),
    join("ORACLE_", "UPDATE_", "METADATA"),
    join("email_", "control_", "attestation_", "v1"),
    join("weall.poh.", "email_", "verification"),
    join("weall.runtime.poh.", "email_", "attestation"),
    join("weall.runtime.poh.", "oracle_", "registry"),
    join("weall.poh.", "oracle_", "authority_", "snapshot"),
    join("weall.", "oracle_", "service"),
    join("/poh/", "email"),
    join("poh/", "email"),
    join("WEALL_", "EMAIL"),
    join("WEALL_", "SM", "TP"),
    join("WEALL_", "POH_", "EMAIL"),
    join("WEALL_", "EMAIL_", "ORACLE"),
    join("WEALL_", "POH_", "EMAIL_", "ORACLE"),
    join("VITE_", "WEALL_", "EMAIL"),
)

SKIP_PARTS = {
    ".git",
    ".venv",
    "venv",
    "__pycache__",
    ".pytest_cache",
    "node_modules",
    ".audit",
}

SKIP_FILES = {
    Path("tests/test_no_email_poh_code_remaining_batch254.py"),
    Path("tests/test_tx_canon_no_email_oracle_txs_batch254.py"),
}


def test_removed_external_identity_poh_symbols_are_absent_from_runtime_tree() -> None:
    hits: list[str] = []

    for path in ROOT.rglob("*"):
        if not path.is_file():
            continue
        rel = path.relative_to(ROOT)
        if any(part in SKIP_PARTS for part in rel.parts):
            continue
        if rel in SKIP_FILES:
            continue
        if rel.parts and rel.parts[0] in {"docs"}:
            continue
        if rel.name.endswith((".pyc", ".sqlite", ".db", ".png", ".jpg", ".jpeg", ".webp", ".zip")):
            continue

        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        for marker in FORBIDDEN:
            if marker in text:
                hits.append(f"{rel}: contains removed external-identity marker")

    assert not hits, "\n".join(hits[:200])
