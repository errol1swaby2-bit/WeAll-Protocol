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

from weall.crypto.sig import sign_tx_envelope_dict
from weall.runtime.ballot_policy import (
    CONTROLLED_TESTNET_BALLOT_PROFILE,
    ballot_profile_status,
)

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


def test_signed_tier2_governance_proposal_votes_schedule_canonical_validator_set_update(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Run signed civic governance against committed blocks and follower replay.

    The initial Tier-2 identities and validator lifecycle registries are
    expressly seeded fixtures. The proposal, both signed votes, strict ballot
    tally, governance execution and queued validator-set child are not fixtures:
    they must pass the normal HTTP-like transaction admission and real canonical
    producer/follower execution path. This is NOT PoH bootstrap or BFT finality
    proof, and it must not be used as such.
    """
    _configure(monkeypatch)
    monkeypatch.setenv("WEALL_STRICT_TX_SIG_DOMAIN", "1")
    producer, follower = _node(tmp_path, "signed-producer"), _node(tmp_path, "signed-follower")
    initial = copy.deepcopy(producer.read_state())

    voter_keys: dict[str, str] = {}
    voters = ("@civic_voter_a", "@civic_voter_b")
    accounts = initial.setdefault("accounts", {})
    for voter in voters:
        secret = MLDSA65PrivateKey.generate()
        voter_keys[voter] = secret.private_bytes_raw().hex()
        accounts[voter] = {
            "nonce": 0,
            "poh_tier": 2,
            "banned": False,
            "locked": False,
            "reputation_milli": 9000,
            "keys": [
                {
                    "sig_profile": "pq-mldsa-v1",
                    "pubkeys": {"mldsa": secret.public_key().public_bytes_raw().hex()},
                    "active": True,
                }
            ],
        }

    # Keep the checked runtime's constitutional clock and all normal system
    # queue machinery. Seed only pre-existing eligibility and registry keys.
    params = initial.setdefault("params", {})
    params["require_signatures"] = True
    params["m3_civic_governance_strict"] = True
    params["mode"] = "controlled-testnet"
    params["validator_candidate_lifecycle_gate_enabled"] = True
    initial["ballot_profile"] = {
        "profile_id": CONTROLLED_TESTNET_BALLOT_PROFILE,
        "active": True,
    }
    roles = initial.setdefault("roles", {}).setdefault("validators", {})
    roles["active_set"] = []
    consensus = initial.setdefault("consensus", {})
    consensus["validator_set"] = {"active_set": [], "epoch": 0, "set_hash": ""}
    consensus.setdefault("phase", {})["current"] = CONSENSUS_PHASE_SOLO_BOOTSTRAP
    lifecycle = initial.setdefault("validators", {}).setdefault("registry", {})
    consensus_keys = consensus.setdefault("validators", {}).setdefault("registry", {})
    for validator in VALIDATORS:
        pubkey = MLDSA65PrivateKey.generate().public_key().public_bytes_raw().hex()
        lifecycle[validator] = {
            "account": validator,
            "pubkey": pubkey,
            "status": "eligible",
        }
        consensus_keys[validator] = {"pubkey": pubkey, "status": "eligible"}

    assert ballot_profile_status(initial)["active"] is True
    assert ballot_profile_status(initial)["strict"] is True
    for node in (producer, follower):
        node._ledger_store.write(copy.deepcopy(initial))
        node.state = node._ledger_store.read()
    _assert_same_committed_state(producer, follower)

    committed_types: list[str] = []

    def commit_block(*, max_txs: int = 0) -> dict:
        built = producer.produce_block(max_txs=max_txs, allow_empty=True)
        assert built.ok is True, built.error
        block = producer.get_latest_block()
        assert isinstance(block, dict)
        committed_types.extend(
            str(tx.get("tx_type"))
            for tx in block.get("txs", [])
            if isinstance(tx, dict)
        )
        replay = follower.apply_block(block)
        assert replay.ok is True, replay.error
        _assert_same_committed_state(producer, follower)
        return block

    def signed_env(tx_type: str, signer: str, nonce: int, payload: dict) -> dict:
        return sign_tx_envelope_dict(
            tx={
                "chain_id": CHAIN_ID,
                "tx_type": tx_type,
                "signer": signer,
                "nonce": nonce,
                "payload": payload,
            },
            privkey=voter_keys[signer],
            encoding="hex",
        )

    def submit_and_commit(tx: dict) -> dict:
        result = producer.submit_tx(tx, ingress="http")
        assert result.get("ok") is True, result
        commit_block(max_txs=4)
        status = producer.get_tx_status(str(result["tx_id"]))
        assert status.get("status") == "confirmed", status
        return result

    proposal = {
        "proposal_id": "f1b-signed-tier2-validator-set",
        "title": "Authorize four validator identities",
        "body": "Controlled testnet proposal, subject to independent governance review",
        "rules": {
            "start_stage": "draft",
            "electorate_scope": "protocol_tier2",
            "auto_progress_enabled": True,
            "draft_period_blocks": 0,
            "poll_period_blocks": 1,
            "revision_period_blocks": 0,
            "validation_period_blocks": 0,
            "voting_period_blocks": 3,
            "execute_delay_blocks": 0,
            "finalize_delay_blocks": 0,
            "max_voting_rounds": 1,
            "quorum_bps": 10000,
        },
        "actions": [
            {
                "tx_type": "VALIDATOR_SET_UPDATE",
                "payload": {"active_set": list(VALIDATORS), "activate_at_epoch": 1},
            }
        ],
    }
    submitted_create = submit_and_commit(
        signed_env("GOV_PROPOSAL_CREATE", voters[0], 1, proposal)
    )
    assert submitted_create["tx_id"]
    assert "GOV_PROPOSAL_CREATE" in committed_types
    record = producer.read_state()["gov_proposals_by_id"][proposal["proposal_id"]]
    assert record["stage"] == "draft"
    assert record["actions"] == proposal["actions"]
    assert record["electorate_scope"] == "protocol_tier2"
    assert record["eligible_voter_ids"] == list(voters)

    for _ in range(12):
        current = producer.read_state()["gov_proposals_by_id"][proposal["proposal_id"]]
        if current["stage"] == "voting":
            break
        assert current["stage"] in {"draft", "poll", "revision", "validation"}
        commit_block()
    else:
        pytest.fail("scheduled constitutional governance did not reach voting")

    voting = producer.read_state()["gov_proposals_by_id"][proposal["proposal_id"]]
    assert voting["eligible_voter_ids"] == list(voters)
    assert voting["electorate_round"] == 1

    first_vote = signed_env(
        "GOV_VOTE_CAST", voters[0], 2, {"proposal_id": proposal["proposal_id"], "vote": "yes"}
    )
    bad_vote = dict(first_vote)
    bad_vote["sig"] = "00"
    rejected = producer.submit_tx(bad_vote, ingress="http")
    assert rejected.get("ok") is False, rejected

    submit_and_commit(first_vote)
    after_first = producer.read_state()["gov_proposals_by_id"][proposal["proposal_id"]]
    assert after_first["vote_counts"]["yes"] == 1
    assert after_first["votes"] == {}
    assert after_first["stage"] == "voting"

    submit_and_commit(
        signed_env(
            "GOV_VOTE_CAST",
            voters[1],
            1,
            {"proposal_id": proposal["proposal_id"], "vote": "yes"},
        )
    )

    for _ in range(12):
        state = producer.read_state()
        validator_set = state["consensus"]["validator_set"]
        if isinstance(validator_set.get("pending"), dict):
            break
        commit_block()
    else:
        pytest.fail("signed approved governance did not stage validator set")

    final_state = producer.read_state()
    final_prop = final_state["gov_proposals_by_id"][proposal["proposal_id"]]
    assert final_prop["tallies"][-1]["payload"]["passed"] is True
    assert final_prop["tallies"][-1]["payload"]["yes"] == 2
    assert final_prop["tallies"][-1]["payload"]["quorum_met"] is True
    assert final_prop["votes"] == {}
    assert final_prop["executions"]
    assert final_state["consensus"]["validator_set"]["active_set"] == []
    pending = final_state["consensus"]["validator_set"]["pending"]
    assert pending["active_set"] == list(VALIDATORS)
    assert pending["activate_at_epoch"] == 1
    assert pending["set_hash"] == validator_set_hash(list(VALIDATORS))
    for tx_type in (
        "GOV_PROPOSAL_CREATE",
        "GOV_VOTE_CAST",
        "GOV_STAGE_SET",
        "GOV_VOTING_CLOSE",
        "GOV_TALLY_PUBLISH",
        "GOV_EXECUTE",
        "VALIDATOR_SET_UPDATE",
    ):
        assert tx_type in committed_types, (tx_type, committed_types)
    assert committed_types.count("GOV_VOTE_CAST") == 2

    reloaded_producer = _node(tmp_path, "signed-producer")
    reloaded_follower = _node(tmp_path, "signed-follower")
    _assert_same_committed_state(reloaded_producer, reloaded_follower)
    assert (
        reloaded_producer.read_state()["consensus"]["validator_set"]["pending"]
        == reloaded_follower.read_state()["consensus"]["validator_set"]["pending"]
    )
