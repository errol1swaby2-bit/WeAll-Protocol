from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = ROOT.parent


def test_current_document_registry_is_unique_and_resolvable() -> None:
    registry = json.loads(
        (ROOT / "docs/CURRENT_DOCUMENT_REGISTRY.json").read_text(encoding="utf-8")
    )
    assert registry["schema_version"] == 1
    docs = registry["documents"]
    paths = [entry["path"] for entry in docs]
    assert len(paths) == len(set(paths))
    assert any(entry["classification"] == "CURRENT" for entry in docs)
    for entry in docs:
        assert (REPO_ROOT / entry["path"]).is_file()
        if entry.get("claim_scan"):
            assert entry["classification"] == "CURRENT"


def test_claim_freshness_checker_is_registry_driven() -> None:
    text = (ROOT / "scripts/check_public_claim_freshness.py").read_text(encoding="utf-8")
    assert "CURRENT_DOCUMENT_REGISTRY.json" in text
    assert "CURRENT_DOCS =" not in text
    assert "claim_scan=true requires CURRENT classification" in text
