"""Phase-1 signed account -> content -> flag -> dispute -> replay wiring test.

Uses an explicit controlled local-genesis and *local-dev-only* PoH bootstrap.
This does not prove global humanity, S4 authority, independent BFT, or testnet
readiness. Every transaction passes the actual executor admission/block path.
"""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pytest

from weall.crypto.sig import sign_tx_envelope_dict
from weall.runtime.apply.dispute import DisputeApplyError, apply_dispute
from weall.runtime.executor import WeAllExecutor
from weall.runtime.replay_consistency import (
    _deterministic_replay_fixture_keypair,
    build_replay_manifest,
    compare_replay_manifests,
)
from weall.runtime.reviewer_responsibilities import reviewer_lane_active
from weall.runtime.tx_admission_types import TxEnvelope
from weall.runtime.tx_id import compute_tx_id_from_dict

CHAIN = "weall-controlled-devnet"
POST_ID = "post:@alice:1"
FLAG_ID = "flag:@bob:3"


def _signed(
    *,
    tx_type: str,
    signer: str,
    nonce: int,
    payload: dict,
) -> dict:
    _, secret = _deterministic_replay_fixture_keypair(label=signer)
    return sign_tx_envelope_dict(
        tx={
            "chain_id": CHAIN,
            "tx_type": tx_type,
            "signer": signer,
            "nonce": nonce,
            "payload": payload,
        },
        privkey=secret,
        encoding="hex",
    )


def _commit_signed(
    executor: WeAllExecutor,
    *,
    tx_type: str,
    signer: str,
    nonce: int,
    payload: dict,
) -> tuple[int, str]:
    tx = _signed(tx_type=tx_type, signer=signer, nonce=nonce, payload=payload)
    tx_id = compute_tx_id_from_dict(CHAIN, tx)
    result = executor.submit_tx(tx)
    assert result["ok"] is True, (tx_type, result)
    height = int(executor.read_state()["height"]) + 1
    produced = executor.produce_block(max_txs=1)
    assert produced.ok is True, (tx_type, produced.error)
    block = executor.get_block_by_height(height)
    assert isinstance(block, dict)
    assert tx_id in block["header"]["tx_ids"]
    receipts = [r for r in block["receipts"] if r.get("tx_id") == tx_id]
    assert len(receipts) == 1 and receipts[0]["ok"] is True, (tx_type, receipts)
    return height, tx_id


def test_signed_flag_creates_canonical_dispute_and_replays(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    alice_pub, _ = _deterministic_replay_fixture_keypair(label="@alice")
    bob_pub, _ = _deterministic_replay_fixture_keypair(label="@bob")
    monkeypatch.setenv("WEALL_MODE", "dev")
    monkeypatch.setenv("WEALL_REQUIRE_VRF", "0")
    monkeypatch.setenv("WEALL_GENESIS_BOOTSTRAP_ENABLE", "1")
    monkeypatch.setenv("WEALL_GENESIS_BOOTSTRAP_ACCOUNT", "@alice")
    monkeypatch.setenv("WEALL_GENESIS_BOOTSTRAP_PUBKEY", alice_pub)
    monkeypatch.setenv("WEALL_POH_BOOTSTRAP_OPEN", "1")
    monkeypatch.setenv("WEALL_POH_BOOTSTRAP_MAX_HEIGHT", "50")
    monkeypatch.delenv("WEALL_GENESIS_MODE", raising=False)
    monkeypatch.delenv("WEALL_NODE_ID", raising=False)
    monkeypatch.delenv("WEALL_VALIDATOR_ACCOUNT", raising=False)

    tx_index = Path(__file__).resolve().parents[1] / "generated" / "tx_index.json"
    source = WeAllExecutor(
        db_path=str(tmp_path / "flag-source.sqlite"),
        node_id="phase1-source",
        chain_id=CHAIN,
        tx_index_path=str(tx_index),
    )
    genesis = source.read_state()
    assert genesis["height"] == 0
    assert genesis["accounts"]["@alice"]["poh_tier"] == 2
    assert genesis["params"]["poh_bootstrap_open"] is True
    assert genesis["params"]["block_tx_signature_policy"] == "required"

    _commit_signed(
        source,
        tx_type="ACCOUNT_REGISTER",
        signer="@bob",
        nonce=1,
        payload={"pubkey": bob_pub},
    )
    _commit_signed(
        source,
        tx_type="POH_BOOTSTRAP_TIER2_GRANT",
        signer="@bob",
        nonce=2,
        payload={"account_id": "@bob"},
    )
    assert source.read_state()["accounts"]["@bob"]["poh_tier"] == 2

    _commit_signed(
        source,
        tx_type="CONTENT_POST_CREATE",
        signer="@alice",
        nonce=1,
        payload={"body": "A public synthetic integration post", "visibility": "public"},
    )
    assert source.read_state()["content"]["posts"][POST_ID]["author"] == "@alice"

    _commit_signed(
        source,
        tx_type="CONTENT_FLAG",
        signer="@bob",
        nonce=3,
        payload={"target_id": POST_ID, "reason": "Synthetic report"},
    )
    flagged = source.read_state()
    assert flagged["content"]["flags"][FLAG_ID]["by"] == "@bob"

    # Real system-queue transactions may execute in the proposal following
    # the flag or later, depending on phase/height scheduling. Never simulate
    # escalation by calling an applier directly.
    for _ in range(4):
        state = source.read_state()
        cases = state.get("disputes_by_id") or {}
        if any(d.get("target_id") == POST_ID for d in cases.values()):
            break
        current_height = int(source.read_state()["height"])
        next_block = source.produce_block(max_txs=2, allow_empty=True)
        assert next_block.ok is True, next_block.error
        assert source.read_state()["height"] == current_height + 1

    state = source.read_state()
    matched = [
        case
        for case in (state.get("disputes_by_id") or {}).values()
        if case.get("target_id") == POST_ID
    ]
    assert len(matched) == 1, state.get("disputes_by_id")
    case = matched[0]
    assert case["target_type"] == "content"
    assert case["opened_by"] == "SYSTEM"
    assert case["flagged_by"] == "@bob"
    assert case["target_owner"] == "@alice"
    assert "@alice" not in case.get("assigned_jurors", [])
    assert "@bob" not in case.get("assigned_jurors", [])
    assert case["id"] == state["content"]["moderation"]["targets"][POST_ID]["dispute_id"]
    assert not state["accounts"]["@alice"].get("banned", False)
    assert not state["accounts"]["@bob"].get("banned", False)

    # Escalation must also commit its follow-up receipt. Merely enqueueing a
    # receipt is insufficient to prove the content -> dispute lifecycle.
    for _ in range(4):
        current = source.read_state()
        recent = [source.get_block_by_height(h) for h in range(1, int(current["height"]) + 1)]
        if any(
            receipt.get("tx_type") == "FLAG_ESCALATION_RECEIPT"
            for block in recent
            for receipt in block["receipts"]
        ):
            break
        current_height = int(source.read_state()["height"])
        next_block = source.produce_block(max_txs=2, allow_empty=True)
        assert next_block.ok is True, next_block.error
        assert source.read_state()["height"] == current_height + 1

    state = source.read_state()
    blocks = [source.get_block_by_height(h) for h in range(1, int(state["height"]) + 1)]
    assert all(isinstance(block, dict) for block in blocks)
    matching_receipts = [
        receipt
        for block in blocks
        for receipt in block["receipts"]
        if receipt.get("tx_type") == "CONTENT_ESCALATE_TO_DISPUTE"
    ]
    assert len(matching_receipts) == 1
    assert matching_receipts[0]["ok"] is True
    assert matching_receipts[0]["signer"] == "SYSTEM"
    receipt_audit = [
        receipt
        for block in blocks
        for receipt in block["receipts"]
        if receipt.get("tx_type") == "FLAG_ESCALATION_RECEIPT"
    ]
    assert len(receipt_audit) == 1, {
        "height": state["height"],
        "system_queue": [
            {
                "tx_type": item.get("tx_type"),
                "due_height": item.get("due_height"),
                "emitted_height": item.get("emitted_height"),
                "phase": item.get("phase"),
                "parent": item.get("parent"),
            }
            for item in state.get("system_queue", [])
        ],
        "block_tx_types": [
            [receipt.get("tx_type") for receipt in block["receipts"]] for block in blocks
        ],
    }
    assert receipt_audit[0]["ok"] is True
    assert receipt_audit[0]["signer"] == "SYSTEM"
    assert (
        state["content"]["moderation"]["targets"][POST_ID].get("flag_escalation_receipt_at_nonce")
        is not None
    )

    # A separate signer has to opt into explicit responsibility rather than
    # gaining reviewer duties from Tier-2 or validator/operator identity.
    charlie_pub, _ = _deterministic_replay_fixture_keypair(label="@charlie")
    _commit_signed(
        source,
        tx_type="ACCOUNT_REGISTER",
        signer="@charlie",
        nonce=1,
        payload={"pubkey": charlie_pub},
    )
    _commit_signed(
        source,
        tx_type="POH_BOOTSTRAP_TIER2_GRANT",
        signer="@charlie",
        nonce=2,
        payload={"account_id": "@charlie"},
    )
    assert source.read_state()["disputes_by_id"][case["id"]]["stage"] == "unassigned"

    _commit_signed(
        source,
        tx_type="REVIEWER_LANE_OPT_IN",
        signer="@charlie",
        nonce=3,
        payload={"account_id": "@charlie", "lane": "content_review"},
    )
    assigned = source.read_state()["disputes_by_id"][case["id"]]
    assert assigned["stage"] == "juror_review", assigned
    assert assigned["assigned_jurors"] == ["@charlie"]
    assert assigned["jurors"]["@charlie"]["status"] == "assigned"
    assert assigned["votes"] == {}

    # Check the exact *persisted* post-content-only state in a copy. Even
    # though the content lane assigned this reviewer, it cannot authorize
    # dispute acceptance by itself; the failure must be mutation-free.
    pre_dispute_opt_in = source.read_state()
    assert reviewer_lane_active(pre_dispute_opt_in, "@charlie", "content_review")
    assert not reviewer_lane_active(pre_dispute_opt_in, "@charlie", "dispute_review")
    isolated = deepcopy(pre_dispute_opt_in)
    unauthorized_accept = TxEnvelope.from_any(
        _signed(
            tx_type="DISPUTE_JUROR_ACCEPT",
            signer="@charlie",
            nonce=4,
            payload={"dispute_id": case["id"]},
        )
    )
    with pytest.raises(DisputeApplyError) as denial:
        apply_dispute(isolated, unauthorized_accept)
    assert denial.value.reason == "reviewer_responsibility_not_active"
    assert isolated == pre_dispute_opt_in
    assert source.read_state() == pre_dispute_opt_in

    # The domain currently requires *separate* dispute_review consent for
    # accept/vote even when content_review has assigned a content report.
    # Preserve both explicit consents rather than bypassing the gate.
    _commit_signed(
        source,
        tx_type="REVIEWER_LANE_OPT_IN",
        signer="@charlie",
        nonce=4,
        payload={"account_id": "@charlie", "lane": "dispute_review"},
    )
    roles = source.read_state()["roles"]["jurors"]["by_id"]["@charlie"]
    lanes = roles["responsibilities"]["reviewer"]
    assert lanes["content_review"]["active"] is True
    assert lanes["dispute_review"]["active"] is True

    _commit_signed(
        source,
        tx_type="DISPUTE_JUROR_ACCEPT",
        signer="@charlie",
        nonce=5,
        payload={"dispute_id": case["id"]},
    )
    accepted = source.read_state()["disputes_by_id"][case["id"]]
    assert accepted["jurors"]["@charlie"]["status"] == "accepted"
    assert accepted["jurors"]["@charlie"]["attendance"]["present"] is True

    _commit_signed(
        source,
        tx_type="DISPUTE_VOTE_SUBMIT",
        signer="@charlie",
        nonce=6,
        payload={"dispute_id": case["id"], "vote": "no"},
    )
    state = source.read_state()
    voted = state["disputes_by_id"][case["id"]]
    assert voted["jurors"]["@charlie"]["status"] == "completed"
    assert not state["accounts"]["@alice"].get("banned", False)
    assert not state["accounts"]["@bob"].get("banned", False)
    assert not state["accounts"]["@charlie"].get("banned", False)
    ballot_receipts = [
        r for r in state["dispute_ballot_admission_receipts"] if r["dispute_id"] == case["id"]
    ]
    assert len(ballot_receipts) == 1
    assert ballot_receipts[0]["final"] is True

    # A second distinct signed ballot with a fresh nonce must never count twice.
    # It should be included as a failed block receipt, with no mutation to the
    # existing case, ballot commitments, reviewer status or reputation events.
    before_duplicate = source.read_state()
    before_case = deepcopy(before_duplicate["disputes_by_id"][case["id"]])
    before_ballots = deepcopy(before_duplicate["dispute_ballot_admission_receipts"])
    before_reputation = deepcopy(before_duplicate.get("reputation", {}))
    duplicate = _signed(
        tx_type="DISPUTE_VOTE_SUBMIT",
        signer="@charlie",
        nonce=7,
        payload={"dispute_id": case["id"], "vote": "yes"},
    )
    duplicate_id = compute_tx_id_from_dict(CHAIN, duplicate)
    admitted_duplicate = source.submit_tx(duplicate)
    assert admitted_duplicate["ok"] is True, admitted_duplicate
    next_height = int(before_duplicate["height"]) + 1
    duplicate_block_meta = source.produce_block(max_txs=1)
    assert duplicate_block_meta.ok is True, duplicate_block_meta.error
    duplicate_block = source.get_block_by_height(next_height)
    assert isinstance(duplicate_block, dict)
    assert duplicate_id in duplicate_block["header"]["tx_ids"]
    rejected_ballot = [
        receipt for receipt in duplicate_block["receipts"] if receipt.get("tx_id") == duplicate_id
    ]
    assert len(rejected_ballot) == 1
    assert rejected_ballot[0]["ok"] is False
    assert rejected_ballot[0]["reason"] == "dispute_ballot_already_final", rejected_ballot[0]
    after_duplicate = source.read_state()
    assert after_duplicate["disputes_by_id"][case["id"]] == before_case
    assert after_duplicate["dispute_ballot_admission_receipts"] == before_ballots
    assert after_duplicate.get("reputation", {}) == before_reputation
    assert after_duplicate["accounts"]["@charlie"]["nonce"] == 7
    state = after_duplicate

    # Replay the entire continuation, including failed duplicate admission
    # at application time, not just the pre-review opening blocks.
    blocks = [source.get_block_by_height(h) for h in range(1, int(state["height"]) + 1)]
    assert all(isinstance(block, dict) for block in blocks)

    replay = WeAllExecutor(
        db_path=str(tmp_path / "flag-replay.sqlite"),
        node_id="phase1-fresh-replay",
        chain_id=CHAIN,
        tx_index_path=str(tx_index),
    )
    assert replay.read_state()["height"] == 0
    for block in blocks:
        applied = replay.apply_block(dict(block))
        assert applied.ok is True, applied.error
    expected = build_replay_manifest(source)
    observed = build_replay_manifest(replay)
    assert compare_replay_manifests(expected, observed) == []
    assert replay.read_state()["disputes_by_id"] == state["disputes_by_id"]
    assert (
        replay.read_state()["dispute_ballot_admission_receipts"]
        == state["dispute_ballot_admission_receipts"]
    )
