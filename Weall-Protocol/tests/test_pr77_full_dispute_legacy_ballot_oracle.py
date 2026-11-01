"""Adversarial full-transaction replay of a controlled-devnet legacy dispute ballot.

Both engines execute the real DISPUTE_VOTE_SUBMIT dispatcher from identical
prepared lifecycle state. The legacy ballot is seeded as pre-existing state,
not supplied as the transaction envelope. This is *synthetic*, not archived
block history and does not authorize changing hash semantics.
"""

from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
from typing import Any

import pytest

from weall.runtime.ballot_policy import CONTROLLED_TESTNET_BALLOT_PROFILE
from weall.runtime.domain_apply import (
    ApplyError,
    apply_tx_atomic_meta_bounded_rollback,
    apply_tx_atomic_meta_deepcopy,
)
from weall.runtime.state_hash import compute_state_root

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "test_p2_a02_success_lifecycle_baseline.py"
SEMANTIC = ROOT / "generated" / "tx_semantic_assurance_v1_5.json"


def _vote_fixture(*, legacy: bool) -> tuple[dict[str, Any], Any]:
    spec = importlib.util.spec_from_file_location("pr77_strict_dispute_fixture", FIXTURE)
    assert spec is not None and spec.loader is not None
    fixture = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fixture)

    state = fixture._base_state()
    rows = json.loads(SEMANTIC.read_text(encoding="utf-8"))["rows"]
    row = next(row for row in rows if row["tx_type"] == "DISPUTE_VOTE_SUBMIT")
    envelope = fixture._prepared_envelope(state, row)

    # Explicit controlled-devnet profile. Public activation is not enabled.
    state["params"]["m3_civic_governance_strict"] = True
    state["params"]["mode"] = "controlled-testnet"
    state["ballot_profile"] = {
        "profile_id": CONTROLLED_TESTNET_BALLOT_PROFILE,
        "active": True,
    }
    dispute = state["disputes_by_id"]["a"]
    assert dispute["jurors"]["@juror1"]["status"] in {"accepted", "attended", "present"}
    if legacy:
        # Different voter from the transaction signer: exercising migration
        # must not be rejected as a duplicate vote by this juror.
        dispute["votes"] = {
            "@legacy-reviewer": {
                "vote": "yes",
                "height": 9,
                "summary": "migrated legacy resolution",
                "resolution": {
                    "action": "restore",
                    "details": {"source": "previous-vote", "reason": "reconsidered"},
                },
            }
        }
    else:
        dispute["votes"] = {}
    return state, envelope


def _apply_both(legacy: bool) -> tuple[Any, Any, dict[str, Any], dict[str, Any]]:
    prepared, envelope = _vote_fixture(legacy=legacy)
    before = copy.deepcopy(prepared)
    bounded = copy.deepcopy(prepared)
    reference = copy.deepcopy(prepared)
    bounded_meta = apply_tx_atomic_meta_bounded_rollback(bounded, copy.deepcopy(envelope))
    deepcopy_meta = apply_tx_atomic_meta_deepcopy(reference, copy.deepcopy(envelope))
    assert prepared == before
    assert compute_state_root(prepared) == compute_state_root(before)
    return bounded_meta, deepcopy_meta, bounded, reference


def test_strict_dispute_vote_without_legacy_ballots_has_executor_parity() -> None:
    bounded_meta, deepcopy_meta, bounded, reference = _apply_both(legacy=False)
    assert bounded_meta == deepcopy_meta
    assert bounded == reference
    assert compute_state_root(bounded) == compute_state_root(reference)


@pytest.mark.xfail(
    strict=True,
    raises=AssertionError,
    reason="full DISPUTE_VOTE_SUBMIT legacy resolution hashes journaled state incorrectly",
)
def test_strict_dispute_vote_with_legacy_resolution_has_executor_parity() -> None:
    bounded_meta, deepcopy_meta, bounded, reference = _apply_both(legacy=True)
    assert bounded_meta == deepcopy_meta
    assert bounded == reference
    assert compute_state_root(bounded) == compute_state_root(reference)


def test_legacy_migration_identifies_root_and_resolution_option_delta() -> None:
    """Record the reached state-root mismatch without accepting the result."""
    bounded_meta, deepcopy_meta, bounded, reference = _apply_both(legacy=True)
    bounded_root = compute_state_root(bounded)
    reference_root = compute_state_root(reference)
    bounded_options = bounded["disputes_by_id"]["a"].get("resolution_options", {})
    reference_options = reference["disputes_by_id"]["a"].get("resolution_options", {})
    summary = {
        "schema": "weall.pr77.full_dispute_legacy_probe.v1",
        "synthetic_only": True,
        "metadata_equal": bounded_meta == deepcopy_meta,
        "root_equal": bounded_root == reference_root,
        "bounded_state_root": bounded_root,
        "deepcopy_state_root": reference_root,
        "resolution_options_equal": bounded_options == reference_options,
        "bounded_resolution_option_keys": sorted(bounded_options),
        "deepcopy_resolution_option_keys": sorted(reference_options),
        "historical_compatibility_proven": False,
    }
    print(json.dumps(summary, sort_keys=True))
    assert bounded_options != reference_options
    assert bounded_root != reference_root


def test_duplicate_legacy_dispute_vote_rejection_rolls_back_both_engines() -> None:
    """No partial legacy migration survives an apply-stage duplicate rejection."""
    prepared, envelope = _vote_fixture(legacy=True)
    dispute = prepared["disputes_by_id"]["a"]
    dispute["votes"]["@juror1"] = dispute["votes"].pop("@legacy-reviewer")
    before = copy.deepcopy(prepared)
    before_root = compute_state_root(before)

    for engine in (
        apply_tx_atomic_meta_bounded_rollback,
        apply_tx_atomic_meta_deepcopy,
    ):
        state = copy.deepcopy(before)
        with pytest.raises(ApplyError, match="dispute_ballot_already_final"):
            engine(state, copy.deepcopy(envelope))
        assert state == before
        assert compute_state_root(state) == before_root
