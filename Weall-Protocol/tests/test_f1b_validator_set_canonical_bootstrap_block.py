"""Issue #87: queue-bound validator-set update in a real bootstrap block.

The registered validators, system queue, and governance parent below are
explicit test fixtures. No on-chain governance approval or validator promotion
is proven. Bootstrap has BFT disabled (not a QC-less BFT admission bypass).
There is no live network, BFT finality, or external operator attestation.
"""

from __future__ import annotations

import copy
import os
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PrivateKey

from weall.runtime.bft_hotstuff import CONSENSUS_PHASE_SOLO_BOOTSTRAP, validator_set_hash
from weall.runtime.executor import WeAllExecutor
from weall.runtime.state_hash import compute_state_root
from weall.runtime.system_tx_engine import enqueue_system_tx

ROOT = Path(__file__).resolve().parents[1]
CHAIN_ID = "f1b-issue87-bootstrap-queue-block-fixture"
VALIDATORS = ("@f1b1", "@f1b2", "@f1b3", "@f1b4")


def _configure(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in tuple(os.environ):
        if key.startswith("WEALL_"):
            monkeypatch.delenv(key, raising=False)
    for key, value in (
        ("WEALL_MODE", "testnet"),
        ("WEALL_SIGVERIFY", "1"),
        ("WEALL_UNSAFE_DEV", "0"),
        ("WEALL_BFT_ALLOW_QC_LESS_BLOCKS", "0"),
        ("WEALL_BFT_STRICT_EPOCH_BINDING", "1"),
        ("WEALL_BFT_ENABLED", "0"),
        ("WEALL_NET_ENABLED", "0"),
        ("WEALL_NET_LOOP_AUTOSTART", "0"),
        ("WEALL_BLOCK_LOOP_AUTOSTART", "0"),
    ):
        monkeypatch.setenv(key, value)


def _node(root: Path, name: str) -> WeAllExecutor:
    return WeAllExecutor(
        db_path=str(root / f"{name}.sqlite"),
        node_id=name,
        chain_id=CHAIN_ID,
        tx_index_path=str(ROOT / "generated" / "tx_index.json"),
    )


def _governance_fixture(state: dict) -> str:
    keys = {
        name: MLDSA65PrivateKey.generate().public_key().public_bytes_raw().hex()
        for name in VALIDATORS
    }
    state.setdefault("params", {})["validator_candidate_lifecycle_gate_enabled"] = True
    state.setdefault("roles", {}).setdefault("validators", {})["active_set"] = []
    c = state.setdefault("consensus", {})
    c["validator_set"] = {"active_set": [], "epoch": 0, "set_hash": ""}
    c.setdefault("phase", {})["current"] = CONSENSUS_PHASE_SOLO_BOOTSTRAP
    creg = c.setdefault("validators", {}).setdefault("registry", {})
    registry = state.setdefault("validators", {}).setdefault("registry", {})
    for name, pubkey in keys.items():
        registry[name] = {"account": name, "pubkey": pubkey, "status": "eligible"}
        creg[name] = {"pubkey": pubkey, "status": "eligible"}
    return enqueue_system_tx(
        state,
        tx_type="VALIDATOR_SET_UPDATE",
        payload={"active_set": list(VALIDATORS), "activate_at_epoch": 1},
        due_height=int(state.get("height") or 0) + 1,
        parent="test-fixture-gov-execute",
        signer="SYSTEM",
        phase="post",
        once=True,
    )


def test_validator_set_update_canonical_bootstrap_block_and_follower_replay(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure(monkeypatch)
    producer, follower = _node(tmp_path, "producer"), _node(tmp_path, "follower")
    initial = copy.deepcopy(producer.read_state())
    qid = _governance_fixture(initial)
    assert qid
    for node in (producer, follower):
        node._ledger_store.write(copy.deepcopy(initial))
        node.state = node._ledger_store.read()
        assert node._active_validators() == []

    result = producer.produce_block(max_txs=0, allow_empty=True)
    assert result.ok is True, result.error
    block = producer.get_latest_block()
    assert isinstance(block, dict)
    updates = [tx for tx in block.get("txs", []) if tx.get("tx_type") == "VALIDATOR_SET_UPDATE"]
    assert len(updates) == 1
    included = updates[0]
    assert included["system"] is True
    assert included["signer"] == "SYSTEM"
    assert included["payload"]["_system_queue_id"] == qid

    leader_state = producer.read_state()
    vs = leader_state["consensus"]["validator_set"]
    assert vs["active_set"] == []
    assert vs["pending"]["active_set"] == list(VALIDATORS)
    assert vs["pending"]["set_hash"] == validator_set_hash(list(VALIDATORS))
    assert vs["pending"]["activate_at_epoch"] == 1

    replay = follower.apply_block(block)
    assert replay.ok is True, replay.error
    follower_state = follower.read_state()
    assert leader_state["height"] == follower_state["height"]
    assert leader_state["tip"] == follower_state["tip"]
    assert compute_state_root(leader_state) == compute_state_root(follower_state)

    restarted_leader = _node(tmp_path, "producer")
    restarted_follower = _node(tmp_path, "follower")
    assert compute_state_root(restarted_leader.read_state()) == compute_state_root(
        restarted_follower.read_state()
    )
    assert (
        restarted_leader.read_state()["consensus"]["validator_set"]["pending"]
        == restarted_follower.read_state()["consensus"]["validator_set"]["pending"]
    )
    assert restarted_follower._active_validators() == []
