"""Independent reference deepcopy versus bounded-journal execution for all 236 TXs.

This is synthetic fixture parity only. It is NOT prior-chain compatibility,
historical root replay, semantic attestation, or public-testnet authorization.
"""

from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
from typing import Any

import pytest

from weall.runtime.bounded_rollback import JournaledDict, JournaledList
from weall.runtime.domain_apply import (
    apply_tx_atomic_meta_bounded_rollback,
    apply_tx_atomic_meta_deepcopy,
)
from weall.runtime.state_hash import compute_state_root

ROOT = Path(__file__).resolve().parents[1]
ROWS = json.loads(
    (ROOT / "generated" / "tx_semantic_assurance_v1_5.json").read_text(encoding="utf-8")
)["rows"]
TYPES = [str(row["tx_type"]) for row in ROWS]
FIXTURE_PATH = ROOT / "tests" / "test_p2_a02_success_lifecycle_baseline.py"


def _fixture() -> Any:
    spec = importlib.util.spec_from_file_location("pr77_full_236_executor_oracle", FIXTURE_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _assert_no_journaled(value: Any) -> None:
    assert not isinstance(value, (JournaledDict, JournaledList))
    if isinstance(value, dict):
        for child in value.values():
            _assert_no_journaled(child)
    if isinstance(value, list):
        for child in value:
            _assert_no_journaled(child)


def test_inventory_exactly_matches_all_236_unique_transaction_types() -> None:
    assert len(ROWS) == 236
    assert len(set(TYPES)) == 236


@pytest.mark.parametrize("row", ROWS, ids=TYPES)
def test_every_tx_agrees_with_independent_deepcopy_executor(
    row: dict[str, Any],
) -> None:
    """Compare metadata, full state and roots from identical prepared inputs."""
    fixture = _fixture()
    staged = fixture._base_state()
    envelope = fixture._prepared_envelope(staged, row)
    staged_root = compute_state_root(staged)

    bounded = copy.deepcopy(staged)
    oracle = copy.deepcopy(staged)
    meta_bounded = apply_tx_atomic_meta_bounded_rollback(bounded, copy.deepcopy(envelope))
    meta_oracle = apply_tx_atomic_meta_deepcopy(oracle, copy.deepcopy(envelope))

    assert meta_bounded == meta_oracle
    assert bounded == oracle
    assert compute_state_root(bounded) == compute_state_root(oracle)
    assert compute_state_root(staged) == staged_root
    _assert_no_journaled(bounded)
    _assert_no_journaled(meta_bounded)
