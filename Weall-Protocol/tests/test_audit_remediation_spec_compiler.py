from __future__ import annotations

import ast
import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location(
    "weall_compile_v2_spec_audit_test", ROOT / "scripts" / "compile_v2_spec.py"
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def _fn(source: str):
    return ast.parse(source).body[0]


def test_scheduler_evidence_does_not_promote_string_mentions_to_emissions() -> None:
    node = _fn("def consumer():\n    return {'applied': 'STATE_SNAPSHOT_DECLARE'}\n")
    assert MODULE._direct_emitted_system_transactions(node, {"STATE_SNAPSHOT_DECLARE"}) == []


def test_scheduler_evidence_detects_literal_enqueue_tx_type() -> None:
    node = _fn(
        "def producer(state):\n"
        "    enqueue_system_tx(state, tx_type='STATE_SNAPSHOT_DECLARE', payload={}, due_height=1)\n"
    )
    assert MODULE._direct_emitted_system_transactions(node, {"STATE_SNAPSHOT_DECLARE"}) == [
        "STATE_SNAPSHOT_DECLARE"
    ]
