#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "configs" / "chains" / "weall-controlled-devnet.json"
TX_INDEX_PATH = ROOT / "generated" / "tx_index.json"
CONSTITUTION_PATH = ROOT / "docs" / "constitution" / "WEALL_GENESIS_CONSTITUTION_DRAFT_2.md"
TRACEABILITY_PATH = ROOT / "docs" / "constitution" / "CONSTITUTIONAL_TRACEABILITY.md"


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise SystemExit(f"{path} must contain a JSON object")
    return value


def _render(value: dict[str, Any]) -> str:
    return json.dumps(value, indent=2, sort_keys=True) + "\n"


def build_manifest() -> dict[str, Any]:
    manifest = _load_object(MANIFEST_PATH)
    manifest.update(
        {
            "chain_id": "weall-controlled-devnet",
            "mode": "controlled_devnet",
            "profile": "controlled_devnet_service",
            "tx_index_hash": _sha256_file(TX_INDEX_PATH),
            "constitution_version": "draft-2",
            "constitution_hash": _sha256_file(CONSTITUTION_PATH),
            "constitution_traceability_hash": _sha256_file(TRACEABILITY_PATH),
            "constitution_document_path": "docs/constitution/WEALL_GENESIS_CONSTITUTION_DRAFT_2.md",
        }
    )
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Regenerate the pinned controlled-devnet chain manifest commitments."
    )
    parser.add_argument(
        "--check", action="store_true", help="Fail when the checked-in manifest is stale."
    )
    args = parser.parse_args()

    expected = _render(build_manifest())
    current = MANIFEST_PATH.read_text(encoding="utf-8")
    if args.check:
        if current != expected:
            print(f"{MANIFEST_PATH.relative_to(ROOT)} is stale; rerun generator")
            return 1
        print(f"OK: {MANIFEST_PATH.relative_to(ROOT)} is current")
        return 0

    MANIFEST_PATH.write_text(expected, encoding="utf-8")
    print(MANIFEST_PATH)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
