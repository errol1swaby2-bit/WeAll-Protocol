"""PR77 read-only characterization of the alternate reputation-floor ban path.

This suite documents existing behavior; passing it is NOT evidence that the
behavior satisfies V2 sanction authorization, due process, or appeal rules.
It intentionally does not change protocol execution or V2 semantic reviews.
Synthetic SYSTEM envelopes are not proof of real producer reachability.
"""

from __future__ import annotations

import ast
import copy
from pathlib import Path

import pytest

import weall.runtime.block_builder as block_builder
from scripts.reputation_delta_origin_review import review_reputation_delta_origin
from weall.runtime.apply.dispute import apply_dispute
from weall.runtime.apply.reputation import REP_MIN_UNITS, apply_reputation_delta_system
from weall.runtime.domain_apply import (
    apply_tx_atomic_meta,
    apply_tx_atomic_meta_deepcopy,
)
from weall.runtime.executor import WeAllExecutor
from weall.runtime.state_hash import compute_state_root
from weall.runtime.system_tx_engine import (
    EPOCH_FINALITY_SINGLE_TX_CHILDREN,
    LINEAGE_WITNESS_PAYLOAD_KEY,
    enqueue_system_tx,
    system_tx_emitter,
    validate_same_block_single_tx_lineage,
    validate_system_tx_queue_binding,
)
from weall.runtime.tx_admission import TxEnvelope, admit_tx
from weall.runtime.tx_contracts import load_default_tx_index


def _state(*, clock_enabled: bool) -> dict:
    return {
        "height": 20,
        "meta": {"constitutional_clock": {"enabled": clock_enabled}},
        "accounts": {
            "@target": {
                "nonce": 0,
                "poh_tier": 2,
                "banned": False,
                "locked": False,
                "reputation": "0",
                "reputation_milli": 0,
                "balance": 0,
                "keys": [],
            }
        },
        "reputation": {"bans": {}},
    }


def _delta_env() -> TxEnvelope:
    return TxEnvelope(
        tx_type="REPUTATION_DELTA_APPLY",
        signer="SYSTEM",
        nonce=21,
        system=True,
        parent="dispute:test-synthetic-parent",
        sig="synthetic-not-authenticated",
        payload={
            "account_id": "@target",
            "delta_milli": int(REP_MIN_UNITS),
            "delta_id": "pr77:reputation-floor-characterization",
            "reason": "synthetic_floor_probe",
        },
    )


@pytest.mark.parametrize("clock_enabled", [False, True], ids=["legacy", "constitutional-clock"])
def test_canonical_reputation_delta_floor_ban_occurs_in_both_modes(
    clock_enabled: bool,
) -> None:
    """Known behavior, NOT an authorization assertion or a desired future contract."""
    baseline = _state(clock_enabled=clock_enabled)
    bounded = copy.deepcopy(baseline)
    reference = copy.deepcopy(baseline)

    bounded_result = apply_tx_atomic_meta(bounded, _delta_env())
    reference_result = apply_tx_atomic_meta_deepcopy(reference, _delta_env())

    assert bounded_result == reference_result
    assert bounded_result["newly_banned"] is True
    assert bounded["accounts"]["@target"]["reputation_milli"] == int(REP_MIN_UNITS)
    assert bounded["accounts"]["@target"]["banned"] is True
    assert bounded["reputation"]["bans"]["@target"]["auto"] is True
    assert bounded == reference
    assert compute_state_root(bounded) == compute_state_root(reference)


@pytest.mark.parametrize("clock_enabled", [False, True], ids=["legacy", "constitutional-clock"])
def test_exported_system_delta_helper_has_same_independent_ban_path(
    clock_enabled: bool,
) -> None:
    """The in-process SYSTEM helper also sets banned without ACCOUNT_BAN."""
    state = _state(clock_enabled=clock_enabled)
    result = apply_reputation_delta_system(
        state,
        account_id="@target",
        delta=-100.0,
        reason="synthetic_floor_probe",
        evidence={"delta_id": "pr77:helper-floor-probe", "source": "synthetic"},
        at_nonce=21,
    )

    assert result["newly_banned"] is True
    assert state["accounts"]["@target"]["reputation_milli"] == int(REP_MIN_UNITS)
    assert state["accounts"]["@target"]["banned"] is True
    assert state["reputation"]["bans"]["@target"]["auto"] is True


@pytest.mark.parametrize("clock_enabled", [False, True], ids=["legacy", "constitutional-clock"])
def test_queue_bound_reputation_floor_ban_remains_distinct_from_account_ban(
    clock_enabled: bool,
) -> None:
    """A valid queue binding is distinct from constitutional source authorization."""
    state = _state(clock_enabled=clock_enabled)
    state["system_queue"] = []
    state["params"] = {}
    canon = load_default_tx_index()

    enqueue_system_tx(
        state,
        tx_type="REPUTATION_DELTA_APPLY",
        payload={
            "account_id": "@target",
            "delta_milli": int(REP_MIN_UNITS),
            "delta_id": "pr77:queue-bound-reputation-floor-characterization",
            "reason": "synthetic_unverified_reputation_source",
        },
        due_height=21,
        signer="SYSTEM",
        once=True,
        parent="dispute:synthetic-unverified-resolution",
        phase="post",
    )
    emitted = system_tx_emitter(state, canon, next_height=21, phase="post")
    assert len(emitted) == 1
    delta = emitted[0]
    assert delta.tx_type == "REPUTATION_DELTA_APPLY"
    assert delta.system is True
    assert delta.parent == "dispute:synthetic-unverified-resolution"
    assert validate_system_tx_queue_binding(state, canon, delta, next_height=21, phase="post") == (
        True,
        "",
    )

    # An invalid queue reference cannot pass the follower's binding check.
    unbound = copy.deepcopy(delta)
    unbound.payload["_system_queue_id"] = "unrecognized-queue-id"
    assert validate_system_tx_queue_binding(
        state, canon, unbound, next_height=21, phase="post"
    ) == (False, "unknown_system_queue_id")

    bounded = copy.deepcopy(state)
    reference = copy.deepcopy(state)
    bounded_result = apply_tx_atomic_meta(bounded, copy.deepcopy(delta))
    reference_result = apply_tx_atomic_meta_deepcopy(reference, copy.deepcopy(delta))
    assert bounded_result == reference_result
    assert bounded_result["applied"] == "REPUTATION_DELTA_APPLY"
    assert bounded_result["newly_banned"] is True
    assert bounded["accounts"]["@target"]["banned"] is True
    assert bounded["reputation"]["bans"]["@target"]["auto"] is True
    assert bounded == reference
    assert compute_state_root(bounded) == compute_state_root(reference)

    # Synthetic queue origin and parent text do NOT prove an authenticated
    # dispute-resolution producer, an allowed severity, or finalized appeal.


def test_dispute_resolve_does_not_produce_reputation_floor_penalty() -> None:
    """A dispute outcome string alone cannot queue a negative reputation delta."""
    state = _state(clock_enabled=False)
    state["system_queue"] = []
    state["disputes_by_id"] = {
        "d:floor": {
            "id": "d:floor",
            "target_type": "account",
            "target_id": "@target",
            "stage": "juror_review",
        }
    }
    outcome = apply_dispute(
        state,
        TxEnvelope(
            tx_type="DISPUTE_RESOLVE",
            signer="SYSTEM",
            system=True,
            nonce=21,
            payload={
                "dispute_id": "d:floor",
                "resolution": {
                    "outcome": "report_upheld",
                    "actions": [
                        {
                            "tx_type": "REPUTATION_DELTA_APPLY",
                            "payload": {
                                "account_id": "@target",
                                "delta_milli": int(REP_MIN_UNITS),
                                "delta_id": "synthetic-disallowed-floor-action",
                            },
                        }
                    ],
                },
            },
        ),
    )
    assert outcome["applied"] == "DISPUTE_RESOLVE"
    assert outcome["enforcement_queued"] == []
    assert outcome["enforcement_applied"] == []
    assert [rec["tx_type"] for rec in state["dispute_enforcement_rejections"]] == [
        "REPUTATION_DELTA_APPLY"
    ]
    assert state["dispute_enforcement_rejections"][0]["reason"] == "unsupported_enforcement_action"
    assert all(rec["tx_type"] != "REPUTATION_DELTA_APPLY" for rec in state["system_queue"])
    assert state["accounts"]["@target"]["banned"] is False
    assert state["accounts"]["@target"]["reputation_milli"] == 0


def test_reputation_delta_cannot_be_submitted_as_public_system_receipt() -> None:
    """Canonical admission forbids public SYSTEM flags and non-SYSTEM origin."""
    state = _state(clock_enabled=True)
    state["accounts"]["@attacker"] = {
        "nonce": 0,
        "poh_tier": 3,
        "banned": False,
        "locked": False,
        "reputation_milli": 0,
    }
    payload = {
        "account_id": "@target",
        "delta_milli": int(REP_MIN_UNITS),
        "delta_id": "synthetic-public-forgery",
        "reason": "synthetic_public_attacker",
    }
    canon = load_default_tx_index()
    before = copy.deepcopy(state)
    for signer, system in (("@attacker", True), ("SYSTEM", True)):
        verdict = admit_tx(
            TxEnvelope(
                tx_type="REPUTATION_DELTA_APPLY",
                signer=signer,
                system=system,
                nonce=1,
                payload=payload,
                sig="synthetic-not-a-signature",
            ),
            state,
            canon=canon,
            context="http",
        )
        assert verdict.ok is False
        assert verdict.code == "system_tx_forbidden"
        assert verdict.reason == "system_only_tx_not_allowed_in_public_ingress"
    assert state == before


def test_source_inventory_has_no_explicit_production_floor_delta_producer() -> None:
    """Conservative AST inventory: no literal queue producer or direct helper call.

    Not a proof against dynamic type strings, indirect imports, or future code.
    """
    source_root = Path(__file__).resolve().parents[1] / "src" / "weall"
    explicit_queue_sites: list[str] = []
    direct_helper_sites: list[str] = []
    for path in sorted(source_root.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for call in ast.walk(tree):
            if not isinstance(call, ast.Call):
                continue
            callable_name = (
                call.func.id
                if isinstance(call.func, ast.Name)
                else call.func.attr
                if isinstance(call.func, ast.Attribute)
                else ""
            )
            if callable_name == "apply_reputation_delta_system":
                direct_helper_sites.append(f"{path.relative_to(source_root)}:{call.lineno}")
            if callable_name != "enqueue_system_tx":
                continue
            tx_arg = next((kw.value for kw in call.keywords if kw.arg == "tx_type"), None)
            if isinstance(tx_arg, ast.Constant) and tx_arg.value == "REPUTATION_DELTA_APPLY":
                explicit_queue_sites.append(f"{path.relative_to(source_root)}:{call.lineno}")
    assert explicit_queue_sites == []
    assert direct_helper_sites == []


@pytest.mark.parametrize("clock_enabled", [False, True], ids=["legacy", "constitutional-clock"])
def test_unwitnessed_reputation_delta_parent_text_is_not_a_causal_dispute_proof(
    clock_enabled: bool,
) -> None:
    """Observe receipt lineage without pretending queue data authenticates a dispute."""
    state = _state(clock_enabled=clock_enabled)
    state["system_queue"] = []
    state["params"] = {}
    canon = load_default_tx_index()
    assert "disputes_by_id" not in state

    enqueue_system_tx(
        state,
        tx_type="REPUTATION_DELTA_APPLY",
        payload={
            "account_id": "@target",
            "delta_milli": int(REP_MIN_UNITS),
            "delta_id": "pr77:unwitnessed-reputation-parent",
            "reason": "synthetic_unwitnessed_penalty",
        },
        due_height=21,
        parent="dispute:never-recorded",
        phase="post",
    )
    emitted = system_tx_emitter(state, canon, next_height=21, phase="post")
    assert len(emitted) == 1
    delta = emitted[0]
    assert LINEAGE_WITNESS_PAYLOAD_KEY not in delta.payload
    assert delta.parent == "dispute:never-recorded"
    assert validate_system_tx_queue_binding(state, canon, delta, next_height=21, phase="post") == (
        True,
        "",
    )
    assert validate_same_block_single_tx_lineage(
        canon,
        delta,
        prior_txs=[],
        required_child_tx_types=EPOCH_FINALITY_SINGLE_TX_CHILDREN,
    ) == (True, "")
    admitted = admit_tx(delta, state, canon=canon, context="block")
    assert admitted.ok is True, (admitted.code, admitted.reason)

    # Queue binding authenticates consistency with the queue's stored parent
    # string. It does not establish that any such dispute was committed.
    changed_parent = copy.deepcopy(delta)
    changed_parent.parent = "dispute:another-unrecorded"
    assert validate_system_tx_queue_binding(
        state, canon, changed_parent, next_height=21, phase="post"
    ) == (False, "system_queue_parent_mismatch")


def test_production_candidate_exercises_synthetic_unwitnessed_floor_delta(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Candidate builder is NOT a signed-BFT or authenticated producer proof."""
    state = _state(clock_enabled=True)
    state.update(
        {
            "height": 0,
            "chain_id": "pr77-synthetic-unwitnessed-floor-candidate",
            "tip": "",
            "tip_hash": "",
            "params": {},
            "system_queue": [],
        }
    )
    enqueue_system_tx(
        state,
        tx_type="REPUTATION_DELTA_APPLY",
        payload={
            "account_id": "@target",
            "delta_milli": int(REP_MIN_UNITS),
            "delta_id": "pr77:unwitnessed-candidate-penalty",
            "reason": "synthetic_queue_origin_not_proved",
        },
        due_height=1,
        parent="dispute:never-committed",
        phase="post",
    )
    root = Path(__file__).resolve().parents[1]
    executor = WeAllExecutor(
        db_path=str(tmp_path / "node.db"),
        node_id="@node",
        chain_id=state["chain_id"],
        tx_index_path=str(root / "generated" / "tx_index.json"),
    )
    executor._ledger_store.write_state_snapshot(copy.deepcopy(state))
    executor.state = executor._ledger_store.read()
    before = copy.deepcopy(executor.state)
    monkeypatch.setattr(block_builder, "runtime_vrf_required", lambda: False)

    block, candidate_state, applied, invalid, error = executor.build_block_candidate(
        max_txs=0, allow_empty=True
    )
    assert block is not None, error
    assert candidate_state is not None
    assert error == ""
    assert invalid == []
    assert applied
    txs = [tx for tx in block["txs"] if tx.get("tx_type") == "REPUTATION_DELTA_APPLY"]
    assert len(txs) == 1
    assert LINEAGE_WITNESS_PAYLOAD_KEY not in txs[0]["payload"]
    assert txs[0]["parent"] == "dispute:never-committed"
    assert candidate_state["accounts"]["@target"]["banned"] is True
    assert candidate_state["reputation"]["bans"]["@target"]["auto"] is True
    assert "disputes_by_id" not in candidate_state
    # Merely building the proposal must not commit the synthetic candidate.
    assert executor.state == before


def _synthetic_origin_review_fixture(*, clock_enabled: bool) -> tuple[dict, dict]:
    state = _state(clock_enabled=clock_enabled)
    state["chain_id"] = "pr77:origin-review-synthetic"
    state["params"] = {}
    state["system_queue"] = []
    enqueue_system_tx(
        state,
        tx_type="REPUTATION_DELTA_APPLY",
        payload={
            "account_id": "@target",
            "dispute_id": "d:unverified",
            "delta_milli": int(REP_MIN_UNITS),
            "delta_id": "pr77:synthetic-review-delta",
            "reason": "synthetic_only",
        },
        due_height=21,
        parent="unverified-resolution-queue-id",
        phase="post",
    )
    delta = system_tx_emitter(state, load_default_tx_index(), next_height=21, phase="post")[
        0
    ].to_json()
    return state, delta


@pytest.mark.parametrize("clock_enabled", [False, True], ids=["legacy", "constitutional-clock"])
def test_read_only_origin_review_queue_bound_without_history_is_never_authority(
    clock_enabled: bool,
) -> None:
    state, delta = _synthetic_origin_review_fixture(clock_enabled=clock_enabled)
    before = copy.deepcopy(state)
    report = review_reputation_delta_origin(
        pre_state=state,
        delta=delta,
        tx_index=load_default_tx_index(),
        supplied_history_blocks=[],
    )
    assert state == before
    assert report["observations"]["receipt_queue_binding_matches_supplied_prestate"]
    assert report["observations"]["receipt_same_block_lineage_shape_valid"]
    assert report["observations"]["parent_queue_reference_present"]
    assert not report["observations"]["exactly_one_parent_resolution_in_supplied_history"]
    assert report["parent_resolution_candidates"] == 0
    assert report["constitutional_authorization"] == "NOT_ESTABLISHED"
    assert report["may_enqueue_reputation_delta"] is False
    assert report["may_ban_account"] is False


def test_read_only_origin_review_matches_only_exact_parent_queue_id_and_case() -> None:
    state, delta = _synthetic_origin_review_fixture(clock_enabled=True)
    parent = {
        "tx_type": "DISPUTE_RESOLVE",
        "system": True,
        "signer": "SYSTEM",
        "nonce": 0,
        "tx_id": "tx:unverified-structural-parent",
        "payload": {
            "_system_queue_id": delta["parent"],
            "dispute_id": "d:unverified",
        },
    }
    block = {
        "height": 20,
        "txs": [parent],
        "receipts": [
            {
                "tx_id": parent["tx_id"],
                "tx_type": "DISPUTE_RESOLVE",
                "ok": True,
            }
        ],
    }
    report = review_reputation_delta_origin(
        pre_state=state,
        delta=delta,
        tx_index=load_default_tx_index(),
        supplied_history_blocks=[block],
    )
    assert report["parent_resolution_candidates"] == 1
    assert report["observations"]["exactly_one_parent_resolution_in_supplied_history"]
    assert report["observations"]["alleged_parent_resolution_precedes_receipt"]
    assert report["observations"]["alleged_parent_success_receipt_unique"]
    assert report["observations"]["alleged_dispute_id_bound_to_parent"]
    assert not report["observations"]["alleged_parent_block_self_commitments_valid"]
    assert report["may_ban_account"] is False

    mismatch = copy.deepcopy(block)
    mismatch["txs"][0]["payload"]["dispute_id"] = "d:other"
    changed = review_reputation_delta_origin(
        pre_state=state,
        delta=delta,
        tx_index=load_default_tx_index(),
        supplied_history_blocks=[mismatch],
    )
    assert not changed["observations"]["alleged_dispute_id_bound_to_parent"]
    assert changed["may_ban_account"] is False


def test_read_only_origin_review_rejects_ambiguous_forged_and_unbound_sources() -> None:
    state, delta = _synthetic_origin_review_fixture(clock_enabled=True)
    forged = {
        "height": 19,
        "txs": [
            {
                "tx_type": "DISPUTE_RESOLVE",
                "system": True,
                "tx_id": "tx:unverified",
                "payload": {"_system_queue_id": delta["parent"], "dispute_id": "d:unverified"},
            }
        ],
        "receipts": [],
    }
    duplicated = review_reputation_delta_origin(
        pre_state=state,
        delta=delta,
        tx_index=load_default_tx_index(),
        supplied_history_blocks=[forged, forged],
    )
    assert duplicated["parent_resolution_candidates"] == 2
    assert not duplicated["observations"]["exactly_one_parent_resolution_in_supplied_history"]
    assert duplicated["may_ban_account"] is False

    altered = copy.deepcopy(delta)
    altered["payload"]["_system_queue_id"] = "forged-queue-id"
    unbound = review_reputation_delta_origin(
        pre_state=state,
        delta=altered,
        tx_index=load_default_tx_index(),
        supplied_history_blocks=[forged],
    )
    assert not unbound["observations"]["receipt_queue_binding_matches_supplied_prestate"]
    assert unbound["may_enqueue_reputation_delta"] is False
