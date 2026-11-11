"""Persisted-block quorum rehearsal on two independently stored executors.

True producer commit_block_candidate, follower apply_block, persisted receipts,
matching state roots, restart, and historical pre-activation compatibility.
Fixture-seeded members/ML-DSA accounts are not real registration proof. No
four-validator QC/BFT network, independent-process transport or finality claim.
"""

from __future__ import annotations

import copy
from pathlib import Path

import pytest

from weall.crypto.sig import sign_tx_envelope_dict
from weall.runtime.apply.groups import apply_groups
from weall.runtime.executor import WeAllExecutor
from weall.runtime.state_hash import compute_state_root
from weall.runtime.tx_admission_types import TxEnvelope
from weall.testing.sigtools import deterministic_mldsa_keypair

CHAIN = "weall-testnet-v1"
VOTERS = [f"@v{i:02d}" for i in range(5)]


def _executor(tmp_path: Path, label: str) -> WeAllExecutor:
    return WeAllExecutor(
        db_path=str(tmp_path / f"{label}.db"),
        node_id=label,
        chain_id=CHAIN,
        tx_index_path=str(Path(__file__).resolve().parents[1] / "generated/tx_index.json"),
    )


def _account(actor: str, tier: int = 2) -> dict:
    public, _ = deterministic_mldsa_keypair(label=actor)
    return {
        "nonce": 0,
        "balance": 1_000_000,
        "poh_tier": tier,
        "reputation": "10.000",
        "reputation_milli": 10_000,
        "banned": False,
        "locked": False,
        "keys": [
            {
                "sig_profile": "pq-mldsa-v1",
                "pubkeys": {"mldsa": public},
                "active": True,
            }
        ],
    }


def _seed(executor: WeAllExecutor, *, activated: bool) -> None:
    state = executor.read_state()
    accounts = state.setdefault("accounts", {})
    for actor in ["@operator", *VOTERS]:
        accounts[actor] = _account(actor, tier=3 if actor == "@operator" else 2)
    params = state.setdefault("params", {})
    if activated:
        params["group_emissary_quorum_activation_height"] = 1
    else:
        params.pop("group_emissary_quorum_activation_height", None)
    apply_groups(
        state,
        TxEnvelope(
            tx_type="GROUP_CREATE",
            signer="@operator",
            nonce=0,
            payload={"group_id": "g:committed", "charter": "test"},
        ),
    )
    state["roles"]["groups_by_id"]["g:committed"]["members"] = {
        actor: {"joined_at_nonce": 1} for actor in VOTERS
    }
    # Pre-first-block synthetic fixtures are intentionally identical across
    # nodes. No same-height state rewrite is allowed after committing blocks.
    executor._ledger_store.write_state_snapshot(state)
    executor.state = executor.read_state()


def _signed(kind: str, signer: str, nonce: int, payload: dict) -> dict:
    _, key = deterministic_mldsa_keypair(label=signer)
    return sign_tx_envelope_dict(
        tx={
            "tx_type": kind,
            "signer": signer,
            "nonce": nonce,
            "payload": payload,
            "chain_id": CHAIN,
            "network_id": CHAIN,
        },
        privkey=key.private_bytes_raw().hex(),
    )


def _commit_and_replay(
    producer: WeAllExecutor, follower: WeAllExecutor, signed: list[dict]
) -> dict:
    for transaction in signed:
        accepted = producer.submit_tx(transaction, ingress="http")
        assert accepted["ok"] is True, accepted
    block, working, applied, invalid, error = producer.build_block_candidate(
        max_txs=len(signed), allow_empty=False
    )
    assert error == ""
    assert isinstance(block, dict)
    assert isinstance(working, dict)
    assert not invalid
    assert len(applied) == len(signed)
    receipts = block.get("receipts")
    assert isinstance(receipts, list)
    assert len(receipts) == len(signed)
    assert all(receipt.get("ok") is True for receipt in receipts)
    assert sorted(receipt.get("tx_type") for receipt in receipts) == sorted(
        tx["tx_type"] for tx in signed
    )
    committed = producer.commit_block_candidate(
        block=block,
        new_state=working,
        applied_ids=applied,
        invalid_ids=invalid,
    )
    assert committed.ok is True
    replayed = follower.apply_block(copy.deepcopy(block))
    assert replayed.ok is True, replayed.error
    assert compute_state_root(producer.state) == compute_state_root(follower.state)
    assert producer.state["height"] == follower.state["height"]
    return block


@pytest.mark.parametrize(
    "turnout,activated",
    [(3, True), (4, True), (1, False)],
    ids=["quorum_3_of_5_no_decision", "quorum_4_of_5_finalized", "historical_one_ballot"],
)
def test_signed_committed_emissary_quorum_replays_and_restarts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, turnout: int, activated: bool
) -> None:
    monkeypatch.setenv("WEALL_MODE", "dev")
    monkeypatch.setenv("WEALL_SIGVERIFY", "1")
    producer = _executor(tmp_path, "producer")
    follower = _executor(tmp_path, "follower")
    _seed(producer, activated=activated)
    _seed(follower, activated=activated)
    assert compute_state_root(producer.state) == compute_state_root(follower.state)

    block_create = _commit_and_replay(
        producer,
        follower,
        [
            _signed(
                "GROUP_EMISSARY_ELECTION_CREATE",
                "@operator",
                1,
                {
                    "group_id": "g:committed",
                    "election_id": "e:committed",
                    "seats": 5,
                    "candidates": VOTERS,
                    "start_height": 1,
                    "end_height": 3,
                },
            )
        ],
    )
    election = producer.state["group_emissary_elections"]["e:committed"]
    if activated:
        assert election["quorum_policy_version"] == 1
        assert election["required_votes"] == 4
        assert election["voter_snapshot"] == VOTERS
    else:
        assert "quorum_policy_version" not in election

    block_ballots = _commit_and_replay(
        producer,
        follower,
        [
            _signed(
                "GROUP_EMISSARY_BALLOT_CAST",
                voter,
                1,
                {"election_id": "e:committed", "ranking": VOTERS},
            )
            for voter in VOTERS[:turnout]
        ],
    )
    original_signers = list(
        producer.state["roles"]["groups_by_id"]["g:committed"]["signers"]
    )
    original_treasury = list(
        producer.state["roles"]["treasuries_by_id"]["group:g:committed:treasury"][
            "signers"
        ]
    )

    block_finalize = _commit_and_replay(
        producer,
        follower,
        [
            _signed(
                "GROUP_EMISSARY_ELECTION_FINALIZE",
                "@operator",
                2,
                {"group_id": "g:committed", "election_id": "e:committed"},
            )
        ],
    )
    assert [block_create["header"]["height"], block_ballots["header"]["height"], block_finalize["header"]["height"]] == [1, 2, 3]
    election = producer.state["group_emissary_elections"]["e:committed"]
    group = producer.state["roles"]["groups_by_id"]["g:committed"]
    treasury = producer.state["roles"]["treasuries_by_id"][group["treasury_id"]]
    if activated and turnout < 4:
        assert election["status"] == "no_decision"
        assert election["no_decision_reason"] == "quorum_unmet"
        assert group["signers"] == original_signers
        assert treasury["signers"] == original_treasury
    else:
        assert election["status"] == "finalized"
        assert group["signers"] == election["winners"]
        assert treasury["signers"] == election["winners"]

    # Restart the follower from persisted SQLite and verify durable block
    # history + immutable, consensus-rooted election and treasury outcomes.
    restarted = _executor(tmp_path, "follower")
    assert restarted.state["height"] == 3
    assert compute_state_root(restarted.state) == compute_state_root(producer.state)
    for height, expected in enumerate((block_create, block_ballots, block_finalize), 1):
        durable = restarted.get_block_by_height(height)
        assert isinstance(durable, dict)
        assert durable["block_id"] == expected["block_id"]
        assert durable["receipts"] == expected["receipts"]
    stored_election = restarted.state["group_emissary_elections"]["e:committed"]
    assert stored_election["status"] == election["status"]
    assert restarted.state["roles"]["treasuries_by_id"][group["treasury_id"]][
        "signers"
    ] == treasury["signers"]
