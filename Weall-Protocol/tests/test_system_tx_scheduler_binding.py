from __future__ import annotations

from pathlib import Path

from weall.runtime.poh.live_scheduler import schedule_poh_live_system_txs
from weall.runtime.system_tx_engine import build_system_queue_lookup, system_tx_emitter, validate_system_tx_queue_binding
from weall.runtime.tx_admission_types import TxEnvelope
from weall.tx.canon import TxIndex


def _tx_index() -> TxIndex:
    return TxIndex.load_from_file(str(Path(__file__).resolve().parents[1] / "generated" / "tx_index.json"))


def _live_state() -> dict:
    return {
        "height": 22,
        "tip": "c" * 64,
        "accounts": {
            "@target": {"poh_tier": 1, "reputation_milli": 0, "nonce": 1},
            **{f"@j{i}": {"poh_tier": 2, "reputation_milli": 5000, "nonce": 1} for i in range(1, 12)},
        },
        "roles": {"jurors": {"active_set": [f"@j{i}" for i in range(1, 12)]}},
        "params": {"poh": {"live_min_rep_milli": 0}},
        "poh": {
            "live_cases": {
                "case-live": {
                    "case_id": "case-live",
                    "account_id": "@target",
                    "status": "open",
                    "jurors": {},
                }
            }
        },
    }


def test_system_queue_binding_accepts_exact_emitted_live_assignment() -> None:
    state = _live_state()
    canon = _tx_index()
    assert schedule_poh_live_system_txs(state, next_height=23) == 1
    emitted = system_tx_emitter(state, canon, next_height=23, phase="post")
    assert len(emitted) == 1

    ok, why = validate_system_tx_queue_binding(
        state, canon, emitted[0], next_height=23, phase="post"
    )

    assert ok is True
    assert why == ""


def test_system_queue_binding_rejects_missing_queue_id() -> None:
    state = _live_state()
    canon = _tx_index()
    assert schedule_poh_live_system_txs(state, next_height=23) == 1
    emitted = system_tx_emitter(state, canon, next_height=23, phase="post")[0]
    payload = dict(emitted.payload)
    payload.pop("_system_queue_id", None)
    forged = TxEnvelope(
        tx_type=emitted.tx_type,
        signer=emitted.signer,
        nonce=emitted.nonce,
        payload=payload,
        sig=emitted.sig,
        parent=emitted.parent,
        system=True,
    )

    ok, why = validate_system_tx_queue_binding(
        state, canon, forged, next_height=23, phase="post"
    )

    assert ok is False
    assert why == "missing_system_queue_id"


def test_system_queue_binding_rejects_proposer_chosen_live_jurors() -> None:
    state = _live_state()
    canon = _tx_index()
    assert schedule_poh_live_system_txs(state, next_height=23) == 1
    emitted = system_tx_emitter(state, canon, next_height=23, phase="post")[0]
    payload = dict(emitted.payload)
    payload["jurors"] = ["@j1"]
    forged = TxEnvelope(
        tx_type=emitted.tx_type,
        signer=emitted.signer,
        nonce=emitted.nonce,
        payload=payload,
        sig=emitted.sig,
        parent=emitted.parent,
        system=True,
    )

    ok, why = validate_system_tx_queue_binding(
        state, canon, forged, next_height=23, phase="post"
    )

    assert ok is False
    assert why == "system_queue_payload_mismatch"


def test_system_queue_binding_accepts_lookup_validated_live_assignment() -> None:
    state = _live_state()
    canon = _tx_index()
    assert schedule_poh_live_system_txs(state, next_height=23) == 1
    emitted = system_tx_emitter(state, canon, next_height=23, phase="post")
    lookup = build_system_queue_lookup(state)

    ok, why = validate_system_tx_queue_binding(
        state,
        canon,
        emitted[0],
        next_height=23,
        phase="post",
        queue_objects_by_id=lookup,
    )

    assert ok is True
    assert why == ""


def test_system_queue_lookup_preserves_first_match_duplicate_semantics() -> None:
    state = _live_state()
    canon = _tx_index()
    assert schedule_poh_live_system_txs(state, next_height=23) == 1
    emitted = system_tx_emitter(state, canon, next_height=23, phase="post")
    duplicate = dict(state["system_queue"][0])
    duplicate["payload"] = {**duplicate["payload"], "jurors": ["@j1"]}
    state["system_queue"].append(duplicate)
    lookup = build_system_queue_lookup(state)

    ok, why = validate_system_tx_queue_binding(
        state,
        canon,
        emitted[0],
        next_height=23,
        phase="post",
        queue_objects_by_id=lookup,
    )

    assert ok is True
    assert why == ""
