"""CASE admission, rollback, restart and synthetic replay — NO GO authority.

Do not infer a live authorization or historical chain replay from these tests.
The CASE envelope fixtures are synthetic; this module documents current
consensus code behavior without modifying accepted semantic reviews.
"""

from __future__ import annotations

import copy
from pathlib import Path

import pytest

from weall.ledger.state import LedgerView
from weall.runtime.block_admission import admit_block_txs
from weall.runtime.domain_apply import (
    ApplyError,
    apply_tx_atomic_meta_bounded_rollback,
    apply_tx_atomic_meta_deepcopy,
)
from weall.runtime.executor import WeAllExecutor
from weall.runtime.state_hash import compute_state_root
from weall.runtime.system_tx_engine import (
    enqueue_system_tx,
    system_tx_emitter,
    validate_system_tx_queue_binding,
)
from weall.runtime.tx_admission import admit_tx
from weall.runtime.tx_admission_types import TxEnvelope
from weall.tx.canon import load_tx_index_json

ROOT = Path(__file__).resolve().parents[1]
INDEX = ROOT / "generated" / "tx_index.json"
CHAIN = "case-atomic-synthetic-devnet"


def _canon():
    return load_tx_index_json(INDEX)


def _ledger() -> dict:
    return {
        "chain_id": CHAIN,
        "height": 0,
        "params": {"system_signer": "SYSTEM"},
        "accounts": {},
        "system_queue": [],
    }


def _case_env(
    tx_type: str,
    payload: dict,
    *,
    nonce: int = 0,
    signer: str = "SYSTEM",
    system: bool = True,
    parent: str | None = "synthetic:parent",
) -> TxEnvelope:
    return TxEnvelope(
        tx_type=tx_type,
        signer=signer,
        nonce=nonce,
        payload=payload,
        system=system,
        chain_id=CHAIN,
        parent=parent,
    )


@pytest.mark.parametrize(
    ("tx_type", "missing_reason"),
    [
        ("CASE_TYPE_REGISTER", "missing_case_type"),
        ("CASE_BIND_TO_DISPUTE", "missing_dispute_id"),
    ],
)
def test_case_invalid_apply_is_fail_atomic_in_both_executor_wrappers(
    tx_type: str, missing_reason: str
) -> None:
    """Direct handler mutates before reject; canonical bounded apply must not."""
    original = _ledger()
    for apply_fn in (
        apply_tx_atomic_meta_bounded_rollback,
        apply_tx_atomic_meta_deepcopy,
    ):
        state = copy.deepcopy(original)
        with pytest.raises(ApplyError) as error:
            apply_fn(state, _case_env(tx_type, {}))
        assert error.value.code == "invalid_payload"
        assert error.value.reason == missing_reason
        assert state == original
        assert compute_state_root(state) == compute_state_root(original)


@pytest.mark.parametrize(
    ("tx_type", "payload"),
    [
        ("CASE_TYPE_REGISTER", {"case_type": "review"}),
        ("CASE_BIND_TO_DISPUTE", {"case_id": "case-a", "dispute_id": "dispute-a"}),
    ],
)
def test_atomic_wrappers_are_equivalent_for_valid_case_application(
    tx_type: str, payload: dict
) -> None:
    source = _ledger()
    oracle = copy.deepcopy(source)
    env = _case_env(tx_type, payload)
    result = apply_tx_atomic_meta_bounded_rollback(source, env)
    reference = apply_tx_atomic_meta_deepcopy(oracle, env)
    assert result == reference
    assert source == oracle
    assert compute_state_root(source) == compute_state_root(oracle)
    assert result["receipt"] is True


def test_conflicting_duplicate_case_binding_contradiction_survives_atomic_apply() -> None:
    """Known HOLD: rollback fixes rejected writes, not a successful false receipt."""
    states = [copy.deepcopy(_ledger()), copy.deepcopy(_ledger())]
    handlers = [apply_tx_atomic_meta_bounded_rollback, apply_tx_atomic_meta_deepcopy]
    receipts = []
    for state, apply_fn in zip(states, handlers, strict=True):
        first = apply_fn(
            state, _case_env("CASE_BIND_TO_DISPUTE", {"case_id": "case-a", "dispute_id": "d1"})
        )
        second = apply_fn(
            state, _case_env("CASE_BIND_TO_DISPUTE", {"case_id": "case-a", "dispute_id": "d2"})
        )
        stored = state["cases"]["bindings"]["case-a"]["dispute_id"]
        assert first["dispute_id"] == stored == "d1"
        assert second["receipt"] is True
        assert second["dispute_id"] == "d2"
        assert second["dispute_id"] != stored
        receipts.append((first, second))
    assert receipts[0] == receipts[1]
    assert states[0] == states[1]
    assert compute_state_root(states[0]) == compute_state_root(states[1])


@pytest.mark.parametrize("tx_type", ["CASE_TYPE_REGISTER", "CASE_BIND_TO_DISPUTE"])
def test_canonical_public_ingress_rejects_system_cases_without_mutation(
    tx_type: str,
) -> None:
    ledger = _ledger()
    before = copy.deepcopy(ledger)
    payload = {"case_type": "review"} if tx_type == "CASE_TYPE_REGISTER" else {
        "case_id": "case-a",
        "dispute_id": "d1",
    }
    for context in ("mempool", "gossip", "peer", "http", "operator"):
        env = _case_env(tx_type, payload)
        verdict = admit_tx(env, ledger, _canon(), context=context)
        assert not verdict.ok
        assert verdict.code == "system_tx_forbidden"
        assert verdict.reason == "system_only_tx_not_allowed_in_public_ingress"
        assert ledger == before


@pytest.mark.parametrize(
    ("tx_type", "payload"),
    [
        ("CASE_TYPE_REGISTER", {}),
        ("CASE_BIND_TO_DISPUTE", {}),
    ],
)
def test_block_case_missing_required_payload_is_rejected_before_apply(
    tx_type: str, payload: dict
) -> None:
    ledger = _ledger()
    before = copy.deepcopy(ledger)
    env = _case_env(tx_type, payload)
    verdict = admit_tx(env, ledger, _canon(), context="block")
    assert not verdict.ok
    assert verdict.code == "invalid_payload"
    ok, fatal, rejected = admit_block_txs(
        [env], LedgerView.from_ledger(ledger), _canon(), verify_signatures=True
    )
    assert ok is True
    assert fatal is None
    assert rejected[0] is not None
    assert rejected[0].code == "invalid_payload"
    assert ledger == before


def test_block_system_nonce_and_queue_binding_are_fail_closed() -> None:
    ledger = _ledger()
    payload = {"case_id": "case-a", "dispute_id": "d1"}
    wrong_nonce = _case_env("CASE_BIND_TO_DISPUTE", payload, nonce=1)
    _, _, results = admit_block_txs(
        [wrong_nonce], LedgerView.from_ledger(ledger), _canon(), verify_signatures=True
    )
    assert results[0] is not None
    assert results[0].reason == "system_tx_nonce_must_be_zero"

    missing = _case_env("CASE_BIND_TO_DISPUTE", payload)
    valid, reason = validate_system_tx_queue_binding(
        ledger, _canon(), missing, next_height=1, phase="post"
    )
    assert valid is False
    assert reason == "missing_system_queue_id"

    enqueue_system_tx(
        ledger,
        tx_type="CASE_BIND_TO_DISPUTE",
        payload=payload,
        due_height=1,
        signer="SYSTEM",
        parent="synthetic:dispute-open",
        phase="post",
    )
    emitted = system_tx_emitter(ledger, canon=_canon(), next_height=1, phase="post")
    assert len(emitted) == 1
    genuine = emitted[0]
    valid, reason = validate_system_tx_queue_binding(
        ledger, _canon(), genuine, next_height=1, phase="post"
    )
    assert valid is True, reason
    forged = genuine.model_copy(
        update={"payload": {**genuine.payload, "dispute_id": "d2"}}
    )
    valid, reason = validate_system_tx_queue_binding(
        ledger, _canon(), forged, next_height=1, phase="post"
    )
    assert valid is False
    assert reason == "system_queue_payload_mismatch"


@pytest.mark.parametrize("tx_type", ["CASE_TYPE_REGISTER", "CASE_BIND_TO_DISPUTE"])
def test_http_executor_rejects_system_case_before_persistence_and_after_restart(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, tx_type: str
) -> None:
    monkeypatch.setenv("WEALL_MODE", "dev")
    monkeypatch.setenv("WEALL_REQUIRE_VRF", "0")
    db_path = str(tmp_path / ("case-" + tx_type.lower() + ".sqlite"))
    def new_executor() -> WeAllExecutor:
        return WeAllExecutor(
            db_path=db_path,
            node_id="case-synthetic-operator",
            chain_id=CHAIN,
            tx_index_path=str(INDEX),
        )

    ex = new_executor()
    before = ex.read_state()
    payload = {"case_type": "review"} if tx_type == "CASE_TYPE_REGISTER" else {
        "case_id": "case-a",
        "dispute_id": "d1",
    }
    forbidden = ex.submit_tx(_case_env(tx_type, payload).to_json(), ingress="http")
    assert forbidden["ok"] is False
    assert forbidden["error"] == "system_tx_forbidden"
    assert ex.read_state() == before
    assert not ex.read_mempool()
    restarted = new_executor()
    assert restarted.read_state() == before
    assert not restarted.read_mempool()
