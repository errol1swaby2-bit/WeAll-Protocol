"""Issue #87: Canonical governance-to-validator-set replay rehearsals.

The original two-block test uses a tallied proposal and registry fixtures. The
signed-governance test additionally submits a real ML-DSA-signed proposal and
ballots through public-style admission and committed producer/follower blocks.
Both still seed initial Tier-2 eligibility and validator registry authority.
Neither proves on-chain PoH, four-validator BFT finality or peer transport.
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
from weall.runtime.bft_hotstuff import (
    CONSENSUS_PHASE_BFT_ACTIVE,
    CONSENSUS_PHASE_SOLO_BOOTSTRAP,
    validator_set_hash,
)
from weall.runtime.domain_apply import ApplyError, apply_tx
from weall.runtime.executor import WeAllExecutor
from weall.runtime.state_hash import compute_state_root
from weall.runtime.system_tx_engine import enqueue_system_tx
from weall.runtime.tx_admission_types import TxEnvelope

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
            str(tx.get("tx_type")) for tx in block.get("txs", []) if isinstance(tx, dict)
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
                "payload": {
                    "active_set": list(VALIDATORS),
                    "activate_at_epoch": 1,
                    "activate_bft_at_epoch": 1,
                },
            }
        ],
    }
    submitted_create = submit_and_commit(signed_env("GOV_PROPOSAL_CREATE", voters[0], 1, proposal))
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
    bad_vote["signature"] = {**first_vote["signature"], "sig": "00"}
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
    assert pending["phase"] == CONSENSUS_PHASE_BFT_ACTIVE
    assert final_state["consensus"].get("epochs", {}).get("current", 0) == 0
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

    # Exercise the existing EPOCH_OPEN domain applier against the *actual*
    # signed-vote-produced and committed pending set. This is intentionally an
    # in-memory activation projection: epoch-open finality/QC and canonical
    # block inclusion remain separate obligations, not simulated proof.
    # In particular, a mere pending four-validator set is never BFT-active.
    projected = [
        copy.deepcopy(reloaded_producer.read_state()),
        copy.deepcopy(reloaded_follower.read_state()),
    ]
    for state in projected:
        assert state["consensus"]["phase"]["current"] == CONSENSUS_PHASE_SOLO_BOOTSTRAP
        assert state["consensus"]["validator_set"]["active_set"] == []

        with pytest.raises(ApplyError) as invalid_epoch:
            apply_tx(
                copy.deepcopy(state),
                TxEnvelope(
                    tx_type="EPOCH_OPEN",
                    signer="SYSTEM",
                    nonce=1,
                    payload={"epoch": 2},
                    sig="",
                    parent="projection:invalid-epoch",
                    system=True,
                ),
            )
        assert "epoch_open_must_advance_sequentially" in str(invalid_epoch.value)

        opened = apply_tx(
            state,
            TxEnvelope(
                tx_type="EPOCH_OPEN",
                signer="SYSTEM",
                nonce=2,
                payload={"epoch": 1},
                sig="",
                parent="projection:canonical-epoch-boundary-not-committed",
                system=True,
            ),
        )
        assert opened is not None
        activated = opened.get("validator_set_activated")
        assert isinstance(activated, dict)
        assert activated["active_set"] == list(VALIDATORS)
        assert activated["activate_at_epoch"] == 1
        assert activated["validator_set_hash"] == validator_set_hash(list(VALIDATORS))
        assert activated["validator_epoch"] == 1
        assert activated["consensus_phase"] == CONSENSUS_PHASE_BFT_ACTIVE
        assert state["consensus"]["epochs"]["current"] == 1
        assert state["roles"]["validators"]["active_set"] == list(VALIDATORS)
        assert state["consensus"]["validator_set"]["active_set"] == list(VALIDATORS)
        assert state["consensus"]["validator_set"]["set_hash"] == validator_set_hash(
            list(VALIDATORS)
        )
        assert "pending" not in state["consensus"]["validator_set"]
        bridge = state["consensus"]["validator_set"]["transition_bridge"]
        assert bridge["schema"] == "weall.validator-set-transition.v1"
        assert bridge["rule"] == "new_set_qc_over_canonical_boundary"
        assert bridge["from_validator_epoch"] == 0
        assert bridge["to_validator_epoch"] == 1
        assert bridge["to_validator_set_hash"] == validator_set_hash(list(VALIDATORS))

    assert compute_state_root(projected[0]) == compute_state_root(projected[1])
    # The projection must never be passed off as a durable canonical epoch
    # event: the reloaded nodes still carry the staged set and solo phase.
    _assert_same_committed_state(reloaded_producer, reloaded_follower)
    assert "pending" in reloaded_producer.read_state()["consensus"]["validator_set"]
    assert (
        reloaded_producer.read_state()["consensus"]["phase"]["current"]
        == CONSENSUS_PHASE_SOLO_BOOTSTRAP
    )

    # A further *committed* bootstrap block must not silently promote a
    # governance-approved pending set. The projection above is deliberately
    # noncanonical; only a properly witnessed, queue-bound EPOCH_OPEN can
    # activate these validator keys and turn on four-validator BFT.
    pending_before = copy.deepcopy(
        reloaded_producer.read_state()["consensus"]["validator_set"]["pending"]
    )
    assert reloaded_producer.read_state()["finalized"] == {"height": 0, "block_id": ""}
    assert not any(
        isinstance(item, dict) and item.get("tx_type") in {"BLOCK_FINALIZE", "EPOCH_OPEN"}
        for item in reloaded_producer.read_state().get("system_queue", [])
    )
    extra = reloaded_producer.produce_block(max_txs=0, allow_empty=True)
    assert extra.ok is True, extra.error
    extra_block = reloaded_producer.get_latest_block()
    assert isinstance(extra_block, dict)
    assert not any(
        isinstance(item, dict) and item.get("tx_type") in {"BLOCK_FINALIZE", "EPOCH_OPEN"}
        for item in extra_block.get("txs", [])
    )
    replay_extra = reloaded_follower.apply_block(extra_block)
    assert replay_extra.ok is True, replay_extra.error
    _assert_same_committed_state(reloaded_producer, reloaded_follower)

    for node in (reloaded_producer, reloaded_follower):
        durable = node.read_state()
        assert durable["consensus"]["validator_set"]["pending"] == pending_before
        assert durable["consensus"]["validator_set"]["active_set"] == []
        assert durable["consensus"]["epochs"]["current"] == 0
        assert durable["consensus"]["phase"]["current"] == CONSENSUS_PHASE_SOLO_BOOTSTRAP
        assert durable["finalized"] == {"height": 0, "block_id": ""}

        # A direct non-SYSTEM EPOCH_OPEN cannot act as a bootstrap shortcut,
        # even when a governance-approved validator set is already pending.
        with pytest.raises(ApplyError, match="system_only"):
            apply_tx(
                copy.deepcopy(durable),
                TxEnvelope(
                    tx_type="EPOCH_OPEN",
                    signer=voters[0],
                    nonce=3,
                    payload={"epoch": 1},
                    sig="",
                    parent="unauthorized-bootstrap-shortcut",
                    system=False,
                ),
            )


def test_genesis_derived_solo_validator_signed_attestation_replays_without_invented_finality(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Prove genesis-derived solo authority can attest, not that finality exists.

    The real genesis bootstrap constructor creates the singleton validator
    identity/key at height zero. Its signed BLOCK_ATTEST must be canonically
    admitted, committed, independently replayed and durable. The existing
    runtime does NOT schedule a BLOCK_FINALIZE from that attestation; this
    regression records the precise missing handoff without manufacturing a
    queued SYSTEM receipt or mutating the consensus validator set.
    """
    _configure(monkeypatch)
    monkeypatch.setenv("WEALL_STRICT_TX_SIG_DOMAIN", "1")
    secret = MLDSA65PrivateKey.generate()
    pubkey = secret.public_key().public_bytes_raw().hex()
    signer = "@f1b-genesis-solo"
    monkeypatch.setenv("WEALL_GENESIS_BOOTSTRAP_ENABLE", "1")
    monkeypatch.setenv("WEALL_GENESIS_BOOTSTRAP_ACCOUNT", signer)
    monkeypatch.setenv("WEALL_GENESIS_BOOTSTRAP_PUBKEY", pubkey)
    monkeypatch.setenv("WEALL_GENESIS_BOOTSTRAP_REPUTATION", "10.0")

    producer = _node(tmp_path, "solo-genesis-producer")
    follower = _node(tmp_path, "solo-genesis-follower")
    for node in (producer, follower):
        genesis = node.read_state()
        assert genesis["height"] == 0
        assert genesis["accounts"][signer]["poh_tier"] == 2
        assert genesis["roles"]["validators"]["active_set"] == [signer]
        assert genesis["consensus"]["validators"]["registry"][signer]["pubkey"] == pubkey
        assert node._active_validators() == [signer]
        assert node._current_consensus_phase() == CONSENSUS_PHASE_SOLO_BOOTSTRAP
        assert node.bft_leader_propose(max_txs=0) is None
    _assert_same_committed_state(producer, follower)

    first = producer.produce_block(max_txs=0, allow_empty=True)
    assert first.ok is True, first.error
    b1 = producer.get_latest_block()
    assert isinstance(b1, dict) and int(b1["height"]) == 1
    applied_first = follower.apply_block(b1)
    assert applied_first.ok is True, applied_first.error
    _assert_same_committed_state(producer, follower)

    attestation = sign_tx_envelope_dict(
        tx={
            "chain_id": CHAIN_ID,
            "tx_type": "BLOCK_ATTEST",
            "signer": signer,
            "nonce": 1,
            "payload": {
                "block_id": b1["block_id"],
                "height": 1,
                "round": 0,
                "attestation": "yes",
            },
        },
        privkey=secret.private_bytes_raw().hex(),
        encoding="hex",
    )
    submitted = producer.submit_tx(attestation, ingress="http")
    assert submitted.get("ok") is True, submitted
    attestation_id = str(submitted["tx_id"])
    second = producer.produce_block(max_txs=1, allow_empty=True)
    assert second.ok is True, second.error
    b2 = producer.get_latest_block()
    assert isinstance(b2, dict)
    matching_receipts = [rec for rec in b2["receipts"] if rec.get("tx_id") == attestation_id]
    assert len(matching_receipts) == 1
    assert matching_receipts[0]["ok"] is True
    assert matching_receipts[0]["tx_type"] == "BLOCK_ATTEST"
    assert follower.apply_block(b2).ok is True
    _assert_same_committed_state(producer, follower)

    # Even after an *additional* committed and replayed successor, the
    # current scheduler has no authorized first-finality witness to emit.
    third = producer.produce_block(max_txs=0, allow_empty=True)
    assert third.ok is True, third.error
    b3 = producer.get_latest_block()
    assert isinstance(b3, dict)
    b3_types = {tx.get("tx_type") for tx in b3.get("txs", []) if isinstance(tx, dict)}
    assert not b3_types.intersection({"BLOCK_FINALIZE", "EPOCH_OPEN"})
    assert follower.apply_block(b3).ok is True
    _assert_same_committed_state(producer, follower)

    for node in (producer, follower):
        state = node.read_state()
        assert state["block_attestations"][b1["block_id"]][signer]["attestation"] == "yes"
        assert state["consensus"].get("epochs", {}).get("current", 0) == 0
        assert node._current_consensus_phase() == CONSENSUS_PHASE_SOLO_BOOTSTRAP
        finalized = state.get("finalized")
        assert not isinstance(finalized, dict) or int(finalized.get("height", 0)) == 0

    restarted = _node(tmp_path, "solo-genesis-follower")
    _assert_same_committed_state(producer, restarted)
    restarted_attestation = restarted.read_state()["block_attestations"][b1["block_id"]][signer]
    assert restarted_attestation["attestation"] == "yes"
    assert restarted._current_consensus_phase() == CONSENSUS_PHASE_SOLO_BOOTSTRAP


@pytest.mark.parametrize(
    ("attack", "expected_reason"),
    [
        ("unknown_block", "unknown_attested_block"),
        ("wrong_height", "attested_block_height_mismatch"),
        ("claimed_other_validator", "validator_mismatch"),
    ],
)
def test_genesis_solo_signed_attestation_rejects_invalid_target_with_one_shot_nonce(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    attack: str,
    expected_reason: str,
) -> None:
    """An included signed rejection consumes a nonce without mutating the attestation."""
    _configure(monkeypatch)
    monkeypatch.setenv("WEALL_STRICT_TX_SIG_DOMAIN", "1")
    secret = MLDSA65PrivateKey.generate()
    signer = "@f1b-solo-attestation-safety"
    monkeypatch.setenv("WEALL_GENESIS_BOOTSTRAP_ENABLE", "1")
    monkeypatch.setenv("WEALL_GENESIS_BOOTSTRAP_ACCOUNT", signer)
    monkeypatch.setenv(
        "WEALL_GENESIS_BOOTSTRAP_PUBKEY",
        secret.public_key().public_bytes_raw().hex(),
    )
    producer = _node(tmp_path, "attestation-safety-producer")
    follower = _node(tmp_path, "attestation-safety-follower")
    _assert_same_committed_state(producer, follower)
    assert producer._active_validators() == [signer]

    assert producer.produce_block(max_txs=0, allow_empty=True).ok is True
    first_block = producer.get_latest_block()
    assert isinstance(first_block, dict)
    assert follower.apply_block(first_block).ok is True
    _assert_same_committed_state(producer, follower)

    payload = {
        "block_id": first_block["block_id"],
        "height": 1,
        "round": 0,
        "attestation": "yes",
    }
    if attack == "unknown_block":
        payload["block_id"] = "not-a-committed-block"
    elif attack == "wrong_height":
        payload["height"] = 2
    else:
        assert attack == "claimed_other_validator"
        payload["validator"] = "@not-the-genesis-signer"
    signed_invalid = sign_tx_envelope_dict(
        tx={
            "chain_id": CHAIN_ID,
            "tx_type": "BLOCK_ATTEST",
            "signer": signer,
            "nonce": 1,
            "payload": payload,
        },
        privkey=secret.private_bytes_raw().hex(),
        encoding="hex",
    )
    submitted = producer.submit_tx(signed_invalid, ingress="http")
    assert submitted.get("ok") is True, submitted
    rejected_tx_id = str(submitted["tx_id"])

    second = producer.produce_block(max_txs=1, allow_empty=True)
    assert second.ok is True, second.error
    second_block = producer.get_latest_block()
    assert isinstance(second_block, dict)
    rejected_receipts = [
        receipt for receipt in second_block["receipts"] if receipt.get("tx_id") == rejected_tx_id
    ]
    assert len(rejected_receipts) == 1
    assert rejected_receipts[0]["ok"] is False
    assert expected_reason in str(rejected_receipts[0].get("reason", ""))
    assert follower.apply_block(second_block).ok is True
    _assert_same_committed_state(producer, follower)

    for node in (producer, follower):
        state = node.read_state()
        assert state["accounts"][signer]["nonce"] == 1
        assert signer not in state.get("block_attestations", {}).get(first_block["block_id"], {})
        assert (
            not isinstance(state.get("finalized"), dict)
            or int(state["finalized"].get("height", 0)) == 0
        )

    # An included rejected receipt is one-shot: the exact signed transaction
    # cannot be submitted a second time, even when its domain apply failed.
    before_replay = compute_state_root(producer.read_state())
    replay = producer.submit_tx(signed_invalid, ingress="http")
    assert replay.get("ok") is False or replay.get("already_known") is True, replay
    assert compute_state_root(producer.read_state()) == before_replay

    # A corrected, newly signed attestation must advance to nonce 2.
    valid = sign_tx_envelope_dict(
        tx={
            "chain_id": CHAIN_ID,
            "tx_type": "BLOCK_ATTEST",
            "signer": signer,
            "nonce": 2,
            "payload": {
                "block_id": first_block["block_id"],
                "height": 1,
                "round": 0,
                "attestation": "yes",
            },
        },
        privkey=secret.private_bytes_raw().hex(),
        encoding="hex",
    )
    accepted = producer.submit_tx(valid, ingress="http")
    assert accepted.get("ok") is True, accepted
    third = producer.produce_block(max_txs=1, allow_empty=True)
    assert third.ok is True, third.error
    third_block = producer.get_latest_block()
    assert isinstance(third_block, dict)
    assert follower.apply_block(third_block).ok is True
    _assert_same_committed_state(producer, follower)
    assert producer.read_state()["accounts"][signer]["nonce"] == 2
    assert (
        producer.read_state()["block_attestations"][first_block["block_id"]][signer]["attestation"]
        == "yes"
    )


def test_genesis_solo_forged_attestation_signature_rejected_before_mempool(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A genesis validator's role and known block do not excuse a bad signature."""
    _configure(monkeypatch)
    monkeypatch.setenv("WEALL_STRICT_TX_SIG_DOMAIN", "1")
    secret = MLDSA65PrivateKey.generate()
    signer = "@f1b-solo-forgery-target"
    monkeypatch.setenv("WEALL_GENESIS_BOOTSTRAP_ENABLE", "1")
    monkeypatch.setenv("WEALL_GENESIS_BOOTSTRAP_ACCOUNT", signer)
    monkeypatch.setenv(
        "WEALL_GENESIS_BOOTSTRAP_PUBKEY",
        secret.public_key().public_bytes_raw().hex(),
    )
    producer = _node(tmp_path, "attestation-forgery-producer")
    follower = _node(tmp_path, "attestation-forgery-follower")
    assert producer.produce_block(max_txs=0, allow_empty=True).ok is True
    first_block = producer.get_latest_block()
    assert isinstance(first_block, dict)
    assert follower.apply_block(first_block).ok is True
    _assert_same_committed_state(producer, follower)

    signed = sign_tx_envelope_dict(
        tx={
            "chain_id": CHAIN_ID,
            "tx_type": "BLOCK_ATTEST",
            "signer": signer,
            "nonce": 1,
            "payload": {
                "block_id": first_block["block_id"],
                "height": 1,
                "round": 0,
                "attestation": "yes",
            },
        },
        privkey=secret.private_bytes_raw().hex(),
        encoding="hex",
    )
    signed["sig"] = "00"
    signed["signature"] = {**signed["signature"], "sig": "00"}
    rejected = producer.submit_tx(signed, ingress="http")
    assert rejected.get("ok") is False, rejected

    assert producer.produce_block(max_txs=0, allow_empty=True).ok is True
    second_block = producer.get_latest_block()
    assert isinstance(second_block, dict)
    assert not any(
        tx.get("tx_type") == "BLOCK_ATTEST"
        for tx in second_block.get("txs", [])
        if isinstance(tx, dict)
    )
    assert follower.apply_block(second_block).ok is True
    _assert_same_committed_state(producer, follower)
    for node in (producer, follower):
        state = node.read_state()
        assert state["accounts"][signer]["nonce"] == 0
        assert not state.get("block_attestations", {}).get(first_block["block_id"])


def test_solo_first_finality_parent_proof_is_committed_signed_receipt_not_state_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Recover the exact prior committed signed parent without authorizing finality.

    BLOCK_ATTEST's consensus-state summary is not itself a signed parent
    certificate. The full signed envelope, successful receipt, and inclusion
    ancestry must be recovered from the canonical block before designing a
    deterministic genesis-first BLOCK_FINALIZE scheduler.
    """
    from weall.runtime.sigverify import verify_tx_signature

    _configure(monkeypatch)
    monkeypatch.setenv("WEALL_STRICT_TX_SIG_DOMAIN", "1")
    key = MLDSA65PrivateKey.generate()
    signer = "@f1b-first-finality-witness"
    monkeypatch.setenv("WEALL_GENESIS_BOOTSTRAP_ENABLE", "1")
    monkeypatch.setenv("WEALL_GENESIS_BOOTSTRAP_ACCOUNT", signer)
    monkeypatch.setenv(
        "WEALL_GENESIS_BOOTSTRAP_PUBKEY",
        key.public_key().public_bytes_raw().hex(),
    )
    producer = _node(tmp_path, "witness-producer")
    follower = _node(tmp_path, "witness-follower")
    _assert_same_committed_state(producer, follower)
    assert producer._active_validators() == [signer]

    made_b1 = producer.produce_block(max_txs=0, allow_empty=True)
    assert made_b1.ok is True, made_b1.error
    b1 = producer.get_latest_block()
    assert isinstance(b1, dict)
    assert follower.apply_block(b1).ok is True
    _assert_same_committed_state(producer, follower)

    signed = sign_tx_envelope_dict(
        tx={
            "chain_id": CHAIN_ID,
            "tx_type": "BLOCK_ATTEST",
            "signer": signer,
            "nonce": 1,
            "payload": {
                "block_id": b1["block_id"],
                "height": 1,
                "round": 0,
                "attestation": "yes",
            },
        },
        privkey=key.private_bytes_raw().hex(),
        encoding="hex",
    )
    result = producer.submit_tx(signed, ingress="http")
    assert result.get("ok") is True, result
    att_tx_id = str(result["tx_id"])
    made_b2 = producer.produce_block(max_txs=1, allow_empty=True)
    assert made_b2.ok is True, made_b2.error
    b2 = producer.get_latest_block()
    assert isinstance(b2, dict)
    assert follower.apply_block(b2).ok is True
    _assert_same_committed_state(producer, follower)

    state = producer.read_state()
    assert state["tip"] == b2["block_id"]
    assert state["blocks"][b1["block_id"]]["height"] == 1
    assert state["blocks"][b2["block_id"]]["prev_block_id"] == b1["block_id"]
    assert b2["prev_block_id"] == b1["block_id"]
    signed_parents = [
        raw
        for raw in b2["txs"]
        if raw.get("tx_type") == "BLOCK_ATTEST" and raw.get("tx_id") == att_tx_id
    ]
    successful_receipts = [
        item for item in b2["receipts"] if item.get("tx_id") == att_tx_id
    ]
    assert len(signed_parents) == 1
    assert len(successful_receipts) == 1
    assert successful_receipts[0]["ok"] is True
    assert verify_tx_signature(state, signed_parents[0]) is True

    summary = state["block_attestations"][b1["block_id"]][signer]
    assert summary["attestation"] == "yes"
    assert summary["payload"]["block_id"] == b1["block_id"]
    assert "sig" not in summary
    assert "tx_id" not in summary
    assert "txs" not in state["blocks"][b2["block_id"]]
    assert "receipts" not in state["blocks"][b2["block_id"]]

    forged_parent = copy.deepcopy(signed_parents[0])
    forged_parent["sig"] = "00"
    forged_parent["signature"] = {**forged_parent["signature"], "sig": "00"}
    assert verify_tx_signature(state, forged_parent) is False

    # Even possession of the exact signed source ID cannot authorize an
    # externally submitted SYSTEM receipt: the scheduler must independently
    # derive it and bind a canonical queue entry on both producer and follower.
    before = compute_state_root(state)
    external_finalize = producer.submit_tx(
        {
            "chain_id": CHAIN_ID,
            "tx_type": "BLOCK_FINALIZE",
            "signer": "SYSTEM",
            "nonce": 0,
            "system": True,
            "parent": att_tx_id,
            "payload": {"block_id": b1["block_id"], "height": 1},
        },
        ingress="http",
    )
    assert external_finalize.get("ok") is False, external_finalize
    assert compute_state_root(producer.read_state()) == before
    assert producer.read_state().get("finalized") == state.get("finalized")

    restarted = _node(tmp_path, "witness-follower")
    _assert_same_committed_state(producer, restarted)
    persisted = restarted.get_latest_block()
    assert isinstance(persisted, dict)
    assert persisted["block_id"] == b2["block_id"]
    assert [
        tx for tx in persisted["txs"] if tx.get("tx_id") == att_tx_id
    ] == signed_parents
    assert [
        item for item in persisted["receipts"] if item.get("tx_id") == att_tx_id
    ] == successful_receipts
