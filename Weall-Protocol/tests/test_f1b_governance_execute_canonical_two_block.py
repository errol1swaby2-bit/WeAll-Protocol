"""Issue #87: GOV_EXECUTE -> VALIDATOR_SET_UPDATE in two real bootstrap blocks.

The tallied governance proposal, validator registry, queue parent, and initial
eligibility remain fixtures. The production block builder/commit and independent
follower replay exercise real system-tx emission, binding and domain execution.
This does not establish a signed governance vote, on-chain operator lifecycle,
four-validator BFT quorum finality, or authenticated transport.
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
CHAIN_ID = "f1b-governance-execute-two-block-fixture"
VALIDATORS = ("@f1b1", "@f1b2", "@f1b3", "@f1b4")
PROPOSAL_ID = "issue87-fixture-validator-election"


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


def _tallied_governance_fixture(state: dict) -> str:
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
    for name, key in keys.items():
        registry[name] = {"account": name, "pubkey": key, "status": "eligible"}
        creg[name] = {"pubkey": key, "status": "eligible"}

    # The proposal's prior votes/tally are deliberately fixture data. The
    # GOV_EXECUTE and its child are genuinely emitted/committed/replayed below.
    state.setdefault("gov_proposals_by_id", {})[PROPOSAL_ID] = {
        "proposal_id": PROPOSAL_ID,
        "stage": "tallied",
        "electorate_scope": "protocol_tier2",
        "rules": {"electorate_scope": "protocol_tier2"},
        "actions": [
            {
                "tx_type": "VALIDATOR_SET_UPDATE",
                "payload": {"active_set": list(VALIDATORS), "activate_at_epoch": 1},
            }
        ],
        "tallies": [{"height": 0, "payload": {"passed": True}}],
    }
    return enqueue_system_tx(
        state,
        tx_type="GOV_EXECUTE",
        payload={"proposal_id": PROPOSAL_ID},
        due_height=int(state.get("height") or 0) + 1,
        parent="test-fixture-vote-not-committed",
        signer="SYSTEM",
        phase="post",
        once=True,
    )


def _assert_same_committed_state(producer: WeAllExecutor, follower: WeAllExecutor) -> None:
    a = producer.read_state()
    b = follower.read_state()
    assert a["height"] == b["height"]
    assert a["tip"] == b["tip"]
    assert compute_state_root(a) == compute_state_root(b)


def test_gov_execute_emits_validator_set_update_into_next_canonical_block(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure(monkeypatch)
    producer, follower = _node(tmp_path, "producer"), _node(tmp_path, "follower")
    initial = copy.deepcopy(producer.read_state())
    gov_queue_id = _tallied_governance_fixture(initial)
    for node in (producer, follower):
        node._ledger_store.write(copy.deepcopy(initial))
        node.state = node._ledger_store.read()
        assert node._active_validators() == []

    first = producer.produce_block(max_txs=0, allow_empty=True)
    assert first.ok is True, first.error
    first_block = producer.get_latest_block()
    assert isinstance(first_block, dict)
    gov_txs = [tx for tx in first_block.get("txs", []) if tx.get("tx_type") == "GOV_EXECUTE"]
    assert len(gov_txs) == 1
    assert gov_txs[0]["system"] is True
    assert gov_txs[0]["payload"]["_system_queue_id"] == gov_queue_id

    first_state = producer.read_state()
    assert first_state["gov_proposals_by_id"][PROPOSAL_ID]["stage"] == "executed"
    assert first_state["consensus"]["validator_set"]["active_set"] == []
    assert not first_state["consensus"]["validator_set"].get("pending")
    queued_actions = [
        item
        for item in first_state.get("system_queue", [])
        if item.get("tx_type") == "VALIDATOR_SET_UPDATE"
    ]
    assert len(queued_actions) == 1
    child_queue_id = queued_actions[0]["queue_id"]
    assert queued_actions[0]["due_height"] == first_state["height"] + 1
    assert queued_actions[0]["parent"] == "test-fixture-vote-not-committed"

    replay_first = follower.apply_block(first_block)
    assert replay_first.ok is True, replay_first.error
    _assert_same_committed_state(producer, follower)

    # The child action is emitted only after committed GOV_EXECUTE has queued it.
    second = producer.produce_block(max_txs=0, allow_empty=True)
    assert second.ok is True, second.error
    second_block = producer.get_latest_block()
    assert isinstance(second_block, dict)
    updates = [
        tx for tx in second_block.get("txs", []) if tx.get("tx_type") == "VALIDATOR_SET_UPDATE"
    ]
    assert len(updates) == 1
    assert updates[0]["system"] is True
    assert updates[0]["payload"]["_system_queue_id"] == child_queue_id

    second_state = producer.read_state()
    pending = second_state["consensus"]["validator_set"]["pending"]
    assert pending["active_set"] == list(VALIDATORS)
    assert pending["set_hash"] == validator_set_hash(list(VALIDATORS))
    assert pending["activate_at_epoch"] == 1
    assert second_state["consensus"]["validator_set"]["active_set"] == []

    replay_second = follower.apply_block(second_block)
    assert replay_second.ok is True, replay_second.error
    _assert_same_committed_state(producer, follower)

    reloaded_producer = _node(tmp_path, "producer")
    reloaded_follower = _node(tmp_path, "follower")
    _assert_same_committed_state(reloaded_producer, reloaded_follower)
    assert (
        reloaded_producer.read_state()["consensus"]["validator_set"]["pending"]
        == reloaded_follower.read_state()["consensus"]["validator_set"]["pending"]
    )
    assert reloaded_follower._active_validators() == []


@pytest.mark.parametrize(
    ("stage", "passed", "expected_reason"),
    [
        ("voting", True, "proposal_not_executable"),
        ("tallied", False, "proposal_did_not_pass"),
    ],
)
def test_gov_execute_refuses_unapproved_validator_set_action(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    stage: str,
    passed: bool,
    expected_reason: str,
) -> None:
    _configure(monkeypatch)
    producer = _node(tmp_path, "unapproved")
    initial = copy.deepcopy(producer.read_state())
    _tallied_governance_fixture(initial)
    proposal = initial["gov_proposals_by_id"][PROPOSAL_ID]
    proposal["stage"] = stage
    proposal["tallies"][-1]["payload"]["passed"] = passed
    producer._ledger_store.write(initial)
    producer.state = producer._ledger_store.read()

    built, candidate_state, _, _, error = producer.build_block_candidate(
        max_txs=0,
        allow_empty=True,
    )
    assert built is None
    assert candidate_state is None
    assert error == f"system_tx_apply_post_failed:forbidden:{expected_reason}"
    assert producer.get_latest_block() is None
    assert producer.read_state()["consensus"]["validator_set"]["active_set"] == []
