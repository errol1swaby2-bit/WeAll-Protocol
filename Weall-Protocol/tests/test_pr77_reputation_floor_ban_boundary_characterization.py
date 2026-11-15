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

from weall.runtime.apply.dispute import apply_dispute
from weall.runtime.apply.reputation import REP_MIN_UNITS, apply_reputation_delta_system
from weall.runtime.domain_apply import (
    apply_tx_atomic_meta,
    apply_tx_atomic_meta_deepcopy,
)
from weall.runtime.state_hash import compute_state_root
from weall.runtime.system_tx_engine import (
    enqueue_system_tx,
    system_tx_emitter,
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
