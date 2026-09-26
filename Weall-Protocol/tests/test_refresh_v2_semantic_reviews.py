from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "refresh_v2_semantic_reviews.py"


def _module():
    spec = importlib.util.spec_from_file_location("refresh_v2_semantic_reviews", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_failure_stable_id_is_deterministic() -> None:
    module = _module()
    key = "invalid_payload:validator_lifecycle_epoch_must_be_future"
    expected = "FAIL-" + hashlib.sha256(key.encode("utf-8")).hexdigest()[:16].upper()
    assert module._stable_failure_id(key) == expected


def test_refresh_tool_requires_explicit_transaction_selection() -> None:
    source = SCRIPT.read_text(encoding="utf-8")
    assert "at least one --tx-type is required" in source
    assert "never auto-accepts all" in source.lower()


def test_refresh_tool_runs_full_compile_after_review_update() -> None:
    source = SCRIPT.read_text(encoding="utf-8")
    assert "compiler.compile_artifacts()" in source
    assert "compiler._write_artifacts(artifacts)" in source
